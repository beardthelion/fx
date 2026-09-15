//! Redirect layer: when the passport backend is enabled, the enumerated
//! ~/.fx state surfaces read and write through the passport instead of the
//! filesystem. When it is disabled, every operation lands on the exact same
//! local file with the exact same IO helpers — byte-for-byte unchanged.
//!
//! Redirect surfaces (rel to ~/.fx):
//!   settings.json          -> config/settings.json
//!   sessions/<...>         -> sessions/<...>
//!   grants/<...>           -> grants/<...>   (recorded permission grants)
//!   memories.json          -> memory/memories.json
//!   history.jsonl          -> config/history.jsonl
//!   mcp.json               -> config/mcp.json
//!
//! Never redirected (always local): auth.json, chatgpt-auth.json,
//! grok-auth.json, api-key, mcp-credentials/, logs/, backups/,
//! recordings/, usage.jsonl, usage-recovery/, locks, and anything else not
//! enumerated above.
//!
//! The seam is one narrow interface — `Backend` — plus this `Store`
//! facade. Existing stores call `Store.readSurface`/`writeSurface`/etc.
//! with the same profile-relative path they use today; the facade decides
//! where the bytes live.

const std = @import("std");
const io_mod = @import("../shared/io.zig");
const profile_paths = @import("../shared/profile_paths.zig");
const client_mod = @import("client.zig");
const config_mod = @import("config.zig");
const identity = @import("identity.zig");

const Allocator = std.mem.Allocator;

const max_surface_bytes: usize = 64 * 1024 * 1024;

/// Where a profile-relative path's bytes live.
pub const Route = union(enum) {
    /// Stays on the filesystem under ~/.fx.
    local,
    /// A passport entry key (owned by the caller's allocator).
    passport: []u8,
};

fn isValidSegment(seg: []const u8) bool {
    if (seg.len == 0) return false;
    if (!std.ascii.isAlphanumeric(seg[0])) return false;
    for (seg) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '.' and ch != '_' and ch != '-')
            return false;
    }
    return true;
}

fn segmentsValid(path: []const u8) bool {
    if (path.len == 0) return false;
    if (path[0] == '/' or path[path.len - 1] == '/') return false;
    if (std.mem.find(u8, path, "..") != null) return false;
    if (std.mem.find(u8, path, "//") != null) return false;
    if (std.mem.findScalar(u8, path, '\\') != null) return false;
    if (std.mem.findScalar(u8, path, 0) != null) return false;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (!isValidSegment(seg)) return false;
    }
    return true;
}

/// Map a profile-relative path (forward slashes, relative to ~/.fx) to its
/// storage route. Unroutable or unlisted paths stay local — a surface that
/// cannot map to a valid entry key is never silently pushed into the
/// passport.
pub fn routePath(alloc: Allocator, rel_path: []const u8) Allocator.Error!Route {
    if (std.mem.eql(u8, rel_path, "settings.json"))
        return .{ .passport = try alloc.dupe(u8, "config/settings.json") };
    if (std.mem.eql(u8, rel_path, "memories.json"))
        return .{ .passport = try alloc.dupe(u8, "memory/memories.json") };
    if (std.mem.eql(u8, rel_path, "history.jsonl"))
        return .{ .passport = try alloc.dupe(u8, "config/history.jsonl") };
    if (std.mem.eql(u8, rel_path, "mcp.json"))
        return .{ .passport = try alloc.dupe(u8, "config/mcp.json") };
    if (std.mem.startsWith(u8, rel_path, "sessions/")) {
        const rest = rel_path["sessions/".len..];
        // sessions/latest/ is the local resume cache, never a session.
        if (std.mem.eql(u8, rest, "latest") or
            std.mem.startsWith(u8, rest, "latest/")) return .local;
        // The sessions surface is exactly sessions/<id>/<seq> (PS-022).
        // Anything else under sessions/ stays local rather than emitting
        // an entry key the store would reject.
        if (!client_mod.isValidEntryKey(rel_path)) return .local;
        return .{ .passport = try alloc.dupe(u8, rel_path) };
    }
    if (std.mem.startsWith(u8, rel_path, "grants/")) {
        if (!client_mod.isValidEntryKey(rel_path)) return .local;
        return .{ .passport = try alloc.dupe(u8, rel_path) };
    }
    return .local;
}

/// Inverse of routePath for the local backend: an entry key back to the
/// profile-relative path it shadows. Only the canonical fixed mappings and
/// the pass-through prefixes are accepted.
fn entryToRelPath(alloc: Allocator, entry_key: []const u8) ![]u8 {
    if (std.mem.eql(u8, entry_key, "config/settings.json"))
        return alloc.dupe(u8, "settings.json");
    if (std.mem.eql(u8, entry_key, "memory/memories.json"))
        return alloc.dupe(u8, "memories.json");
    if (std.mem.eql(u8, entry_key, "config/history.jsonl"))
        return alloc.dupe(u8, "history.jsonl");
    if (std.mem.eql(u8, entry_key, "config/mcp.json"))
        return alloc.dupe(u8, "mcp.json");
    for ([_][]const u8{ "sessions/", "grants/" }) |prefix| {
        if (std.mem.startsWith(u8, entry_key, prefix) and segmentsValid(entry_key))
            return alloc.dupe(u8, entry_key);
    }
    return error.InvalidEntryKey;
}

// ─── Backend interface ──────────────────────────────────────────────────

pub const BackendError = error{
    InvalidEntryKey,
    PassportUnavailable,
    OutOfMemory,
} || client_mod.Error;

/// The narrow interface the stores call. Implementations: LocalBackend
/// (filesystem) and PassportBackend (encrypted remote). Tests substitute
/// their own.
pub const Backend = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Read one entry's plaintext. Null when absent.
        read: *const fn (ptr: *anyopaque, alloc: Allocator, key: []const u8) BackendError!?[]u8,
        /// Write one entry's plaintext.
        write: *const fn (ptr: *anyopaque, alloc: Allocator, key: []const u8, bytes: []const u8) BackendError!void,
        /// Delete one entry. Absent is not an error.
        delete: *const fn (ptr: *anyopaque, alloc: Allocator, key: []const u8) BackendError!void,
        /// Entry keys under a prefix ("memory/", "sessions/"). Caller owns
        /// the slice and its strings.
        list: *const fn (ptr: *anyopaque, alloc: Allocator, prefix: []const u8) BackendError![][]u8,
        /// Optional batched write: keys[i] receives plaintexts[i]. When null
        /// the Store falls back to per-entry writes. The passport backend
        /// uses one manifest transaction for the whole batch.
        write_batch: ?*const fn (
            ptr: *anyopaque,
            alloc: Allocator,
            keys: []const []const u8,
            plaintexts: []const []const u8,
        ) BackendError!void = null,
        /// Optional batched delete. Same fallback rule as write_batch.
        delete_batch: ?*const fn (
            ptr: *anyopaque,
            alloc: Allocator,
            keys: []const []const u8,
        ) BackendError!void = null,
    };

    pub fn read(self: Backend, alloc: Allocator, key: []const u8) BackendError!?[]u8 {
        return self.vtable.read(self.ptr, alloc, key);
    }
    pub fn write(self: Backend, alloc: Allocator, key: []const u8, bytes: []const u8) BackendError!void {
        return self.vtable.write(self.ptr, alloc, key, bytes);
    }
    pub fn delete(self: Backend, alloc: Allocator, key: []const u8) BackendError!void {
        return self.vtable.delete(self.ptr, alloc, key);
    }
    pub fn list(self: Backend, alloc: Allocator, prefix: []const u8) BackendError![][]u8 {
        return self.vtable.list(self.ptr, alloc, prefix);
    }
    pub fn writeBatch(
        self: Backend,
        alloc: Allocator,
        keys: []const []const u8,
        plaintexts: []const []const u8,
    ) BackendError!void {
        std.debug.assert(keys.len == plaintexts.len);
        if (self.vtable.write_batch) |wb| return wb(self.ptr, alloc, keys, plaintexts);
        for (keys, plaintexts) |key, bytes| try self.vtable.write(self.ptr, alloc, key, bytes);
    }
    pub fn deleteBatch(self: Backend, alloc: Allocator, keys: []const []const u8) BackendError!void {
        if (self.vtable.delete_batch) |db| return db(self.ptr, alloc, keys);
        for (keys) |key| try self.vtable.delete(self.ptr, alloc, key);
    }
};

/// Local filesystem backend: entry keys map back to ~/.fx paths through
/// entryToRelPath and use the same IO helpers the stores use today.
pub const LocalBackend = struct {
    /// The home directory (parent of .fx), borrowed.
    home: []const u8,

    pub fn backend(self: *LocalBackend) Backend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Backend.VTable = .{
        .read = readImpl,
        .write = writeImpl,
        .delete = deleteImpl,
        .list = listImpl,
    };

    fn localPath(self: *LocalBackend, alloc: Allocator, key: []const u8) ![]u8 {
        const rel = try entryToRelPath(alloc, key);
        defer alloc.free(rel);
        return std.fs.path.join(alloc, &.{ self.home, profile_paths.root_dir_name, rel });
    }

    fn readImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) BackendError!?[]u8 {
        const self: *LocalBackend = @ptrCast(@alignCast(ptr));
        const path = self.localPath(alloc, key) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidEntryKey,
        };
        defer alloc.free(path);
        return localRead(alloc, path);
    }

    fn writeImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8, bytes: []const u8) BackendError!void {
        const self: *LocalBackend = @ptrCast(@alignCast(ptr));
        const path = self.localPath(alloc, key) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidEntryKey,
        };
        defer alloc.free(path);
        try localWrite(alloc, path, bytes);
    }

    fn deleteImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) BackendError!void {
        const self: *LocalBackend = @ptrCast(@alignCast(ptr));
        const path = self.localPath(alloc, key) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidEntryKey,
        };
        defer alloc.free(path);
        localDelete(path) catch return error.PassportUnavailable;
    }

    fn listImpl(ptr: *anyopaque, alloc: Allocator, prefix: []const u8) BackendError![][]u8 {
        const self: *LocalBackend = @ptrCast(@alignCast(ptr));
        const dir_rel = std.mem.trimEnd(u8, prefix, "/");
        if (dir_rel.len == 0 or !segmentsValid(dir_rel)) return error.InvalidEntryKey;
        const dir_path = try std.fs.path.join(alloc, &.{ self.home, profile_paths.root_dir_name, dir_rel });
        defer alloc.free(dir_path);
        return localList(alloc, dir_rel, dir_path);
    }
};

// Local fs primitives shared by the disabled path and LocalBackend. These
// mirror what the existing stores do today: bounded read, mkdir -p plus
// atomic write, delete ignoring FileNotFound.

fn localRead(alloc: Allocator, path: []const u8) BackendError!?[]u8 {
    var file = io_mod.openExistingRegularFile(std.Io.Dir.cwd(), path, .read_only) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return error.PassportUnavailable,
    };
    defer file.close(io_mod.getIo());
    return io_mod.readFileToEnd(alloc, &file, max_surface_bytes) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.PassportUnavailable,
    };
}

fn localWrite(alloc: Allocator, path: []const u8, bytes: []const u8) BackendError!void {
    if (std.fs.path.dirname(path)) |dir_path| {
        io_mod.makeDirRecursive(dir_path) catch return error.PassportUnavailable;
    }
    io_mod.writeFileAtomic(alloc, path, bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.PassportUnavailable,
    };
}

fn localDelete(path: []const u8) !void {
    std.Io.Dir.deleteFileAbsolute(io_mod.getIo(), path) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

/// Recursively list files under `dir_path`, returning profile-relative
/// paths prefixed by `dir_rel` (e.g. "sessions/<id>/session.json").
fn localList(alloc: Allocator, dir_rel: []const u8, dir_path: []const u8) BackendError![][]u8 {
    const zio = io_mod.getIo();
    var dir = std.Io.Dir.openDirAbsolute(zio, dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return try alloc.alloc([]u8, 0),
        else => return error.PassportUnavailable,
    };
    defer dir.close(zio);

    var walker = dir.walk(alloc) catch return error.PassportUnavailable;
    defer walker.deinit();

    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |s| alloc.free(s);
        out.deinit(alloc);
    }
    while (walker.next(zio) catch return error.PassportUnavailable) |entry| {
        if (entry.kind != .file) continue;
        const rel = try std.fs.path.join(alloc, &.{ dir_rel, entry.path });
        // Normalize separators for the entry-key namespace.
        std.mem.replaceScalar(u8, rel, std.fs.path.sep, '/');
        try out.append(alloc, rel);
    }
    return out.toOwnedSlice(alloc);
}

/// Passport-backed implementation: entries are secret-scanned, encrypted,
/// and pushed through the client (PS-030/032/033/110).
pub const PassportBackend = struct {
    client: *client_mod.Client,

    pub fn backend(self: *PassportBackend) Backend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Backend.VTable = .{
        .read = readImpl,
        .write = writeImpl,
        .delete = deleteImpl,
        .list = listImpl,
        .write_batch = writeBatchImpl,
        .delete_batch = deleteBatchImpl,
    };

    fn readImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) BackendError!?[]u8 {
        const self: *PassportBackend = @ptrCast(@alignCast(ptr));
        _ = alloc;
        return self.client.readEntry(key) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => |e| return e,
        };
    }

    fn writeImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8, bytes: []const u8) BackendError!void {
        const self: *PassportBackend = @ptrCast(@alignCast(ptr));
        const entries = [_]client_mod.Entry{.{ .key = key, .plaintext = bytes }};
        var result = self.client.push(&entries, &.{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return e,
        };
        defer result.deinit(alloc);
    }

    fn deleteImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) BackendError!void {
        const self: *PassportBackend = @ptrCast(@alignCast(ptr));
        const deletions = [_][]const u8{key};
        var result = self.client.push(&.{}, &deletions) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return e,
        };
        defer result.deinit(alloc);
    }

    fn listImpl(ptr: *anyopaque, alloc: Allocator, prefix: []const u8) BackendError![][]u8 {
        const self: *PassportBackend = @ptrCast(@alignCast(ptr));
        const entries = self.client.hashes() catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return e,
        };
        defer {
            for (entries) |e| {
                alloc.free(@constCast(e.key));
                alloc.free(@constCast(e.plaintext));
            }
            alloc.free(entries);
        }
        var out: std.ArrayList([]u8) = .empty;
        errdefer {
            for (out.items) |s| alloc.free(s);
            out.deinit(alloc);
        }
        for (entries) |e| {
            if (std.mem.startsWith(u8, e.key, prefix)) {
                try out.append(alloc, try alloc.dupe(u8, e.key));
            }
        }
        return out.toOwnedSlice(alloc);
    }

    fn writeBatchImpl(
        ptr: *anyopaque,
        alloc: Allocator,
        keys: []const []const u8,
        plaintexts: []const []const u8,
    ) BackendError!void {
        const self: *PassportBackend = @ptrCast(@alignCast(ptr));
        const entries = try alloc.alloc(client_mod.Entry, keys.len);
        defer alloc.free(entries);
        for (keys, plaintexts, 0..) |key, bytes, i| {
            entries[i] = .{ .key = key, .plaintext = bytes };
        }
        var result = self.client.push(entries, &.{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return e,
        };
        defer result.deinit(alloc);
    }

    fn deleteBatchImpl(ptr: *anyopaque, alloc: Allocator, keys: []const []const u8) BackendError!void {
        const self: *PassportBackend = @ptrCast(@alignCast(ptr));
        var result = self.client.push(&.{}, keys) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return e,
        };
        defer result.deinit(alloc);
    }
};

// ─── Store facade ───────────────────────────────────────────────────────

/// The seam existing stores call: profile-relative paths in, bytes out.
/// Open with `open` (resolves config) or `init` with an explicit backend
/// (tests, hosts).
pub const Store = struct {
    alloc: Allocator,
    home: []u8,
    cfg: ?config_mod.Config = null,
    // Heap-allocated so client.transport can point back into the transport
    // and PassportBackend can point at the client without dangling when the
    // Store is returned by value.
    http: ?*client_mod.HttpTransport = null,
    client: ?*client_mod.Client = null,
    /// Kept alive for the Store's lifetime: client.did/genesis_did borrow
    /// the identity's DID allocation.
    identity: ?identity.Identity = null,
    passport_backend: ?PassportBackend = null,
    injected_backend: ?Backend = null,
    local_backend: LocalBackend,

    /// Open the store for a home dir. Disabled (no config) yields a store
    /// whose every operation is plain local filesystem IO.
    pub fn open(alloc: Allocator, home: []const u8) !Store {
        var store = Store{
            .alloc = alloc,
            .home = try alloc.dupe(u8, home),
            .local_backend = .{ .home = home },
        };
        errdefer alloc.free(store.home);

        store.cfg = try config_mod.resolve(alloc, home);
        if (store.cfg) |*cfg| {
            errdefer cfg.deinit(alloc);
            const seed = cfg.seed orelse return error.PassportSecretsMissing;
            const passphrase = cfg.passphrase orelse return error.PassportSecretsMissing;
            var id = try identity.identityFromSeed(alloc, seed);
            errdefer id.deinit(alloc);

            store.http = try alloc.create(client_mod.HttpTransport);
            errdefer alloc.destroy(store.http.?);
            store.http.?.* = client_mod.HttpTransport.init(alloc);

            store.client = try alloc.create(client_mod.Client);
            errdefer alloc.destroy(store.client.?);
            store.client.?.* = try client_mod.Client.init(
                alloc,
                store.http.?.transport(),
                .{
                    .url = cfg.url,
                    .key_pair = id.key_pair,
                    .did = id.did,
                    .genesis_did = id.did,
                    .passphrase = passphrase,
                    .scan_mode = cfg.scan_mode,
                },
            );
            errdefer store.client.?.deinit();
            store.identity = id;

            if (cfg.namespace) |ns| {
                // An explicit namespace pins a genesis DID that differs from
                // the signing key's own DID (post-rotation holder). It must
                // still be a valid encoded namespace (PS-012).
                if (!identity.isValidNamespace(ns)) return error.PassportNamespaceInvalid;
                alloc.free(store.client.?.namespace);
                store.client.?.namespace = try alloc.dupe(u8, ns);
                // Re-derive the encryption key against the real namespace.
                store.client.?.enc_key = try @import("crypto.zig").deriveKey(
                    alloc,
                    passphrase,
                    ns,
                );
            }
            store.passport_backend = .{ .client = store.client.? };
        }
        return store;
    }

    /// Test seam: a store with a caller-provided backend (null = local).
    pub fn init(alloc: Allocator, home: []const u8, backend: ?Backend) !Store {
        return .{
            .alloc = alloc,
            .home = try alloc.dupe(u8, home),
            .injected_backend = backend,
            .local_backend = .{ .home = home },
        };
    }

    pub fn deinit(self: *Store) void {
        if (self.client) |c| {
            c.deinit();
            self.alloc.destroy(c);
        }
        if (self.http) |h| {
            h.deinit();
            self.alloc.destroy(h);
        }
        if (self.cfg) |*cfg| cfg.deinit(self.alloc);
        if (self.identity) |*id| id.deinit(self.alloc);
        self.alloc.free(self.home);
        self.* = undefined;
    }

    /// Whether the passport backend is live.
    pub fn passportEnabled(self: *const Store) bool {
        if (self.injected_backend != null) return true;
        return self.passport_backend != null;
    }

    fn activeBackend(self: *Store) ?Backend {
        if (self.injected_backend) |b| return b;
        if (self.passport_backend) |*b| return b.backend();
        return null;
    }

    /// Read a surface's bytes. Disabled or unrouted surfaces read the local
    /// file; passport surfaces go through the backend.
    pub fn readSurface(self: *Store, alloc: Allocator, rel_path: []const u8) BackendError!?[]u8 {
        if (self.activeBackend()) |b| {
            const route = try routePath(alloc, rel_path);
            switch (route) {
                .local => {},
                .passport => |key| {
                    defer alloc.free(key);
                    return b.read(alloc, key);
                },
            }
        }
        const path = try std.fs.path.join(alloc, &.{ self.home, profile_paths.root_dir_name, rel_path });
        defer alloc.free(path);
        return localRead(alloc, path);
    }

    /// Write a surface's bytes. Local backend uses the same
    /// mkdir-plus-atomic-write the stores use today.
    pub fn writeSurface(self: *Store, alloc: Allocator, rel_path: []const u8, bytes: []const u8) BackendError!void {
        if (self.activeBackend()) |b| {
            const route = try routePath(alloc, rel_path);
            switch (route) {
                .local => {},
                .passport => |key| {
                    defer alloc.free(key);
                    return b.write(alloc, key, bytes);
                },
            }
        }
        const path = try std.fs.path.join(alloc, &.{ self.home, profile_paths.root_dir_name, rel_path });
        defer alloc.free(path);
        try localWrite(alloc, path, bytes);
    }

    /// Delete a surface. Absent is not an error.
    pub fn deleteSurface(self: *Store, alloc: Allocator, rel_path: []const u8) BackendError!void {
        if (self.activeBackend()) |b| {
            const route = try routePath(alloc, rel_path);
            switch (route) {
                .local => {},
                .passport => |key| {
                    defer alloc.free(key);
                    return b.delete(alloc, key);
                },
            }
        }
        const path = try std.fs.path.join(alloc, &.{ self.home, profile_paths.root_dir_name, rel_path });
        defer alloc.free(path);
        localDelete(path) catch return error.PassportUnavailable;
    }

    /// Batched surface write. Passport-routed paths go through one backend
    /// transaction when the backend supports it; local-routed paths still
    /// hit the filesystem.
    pub fn writeSurfaces(
        self: *Store,
        alloc: Allocator,
        rel_paths: []const []const u8,
        plaintexts: []const []const u8,
    ) BackendError!void {
        std.debug.assert(rel_paths.len == plaintexts.len);
        if (self.activeBackend()) |b| {
            var keys: std.ArrayList([]const u8) = .empty;
            defer {
                for (keys.items) |k| alloc.free(k);
                keys.deinit(alloc);
            }
            var vals: std.ArrayList([]const u8) = .empty;
            defer vals.deinit(alloc);
            for (rel_paths, plaintexts) |rel, bytes| {
                const route = try routePath(alloc, rel);
                switch (route) {
                    .passport => |key| {
                        try keys.append(alloc, key);
                        try vals.append(alloc, bytes);
                    },
                    .local => {
                        const path = try std.fs.path.join(
                            alloc,
                            &.{ self.home, profile_paths.root_dir_name, rel },
                        );
                        defer alloc.free(path);
                        try localWrite(alloc, path, bytes);
                    },
                }
            }
            if (keys.items.len > 0) try b.writeBatch(alloc, keys.items, vals.items);
            return;
        }
        for (rel_paths, plaintexts) |rel, bytes| {
            const path = try std.fs.path.join(alloc, &.{ self.home, profile_paths.root_dir_name, rel });
            defer alloc.free(path);
            try localWrite(alloc, path, bytes);
        }
    }

    /// Batched surface delete. Absent entries are not an error.
    pub fn deleteSurfaces(self: *Store, alloc: Allocator, rel_paths: []const []const u8) BackendError!void {
        if (self.activeBackend()) |b| {
            var keys: std.ArrayList([]const u8) = .empty;
            defer {
                for (keys.items) |k| alloc.free(k);
                keys.deinit(alloc);
            }
            for (rel_paths) |rel| {
                const route = try routePath(alloc, rel);
                switch (route) {
                    .passport => |key| try keys.append(alloc, key),
                    .local => {
                        const path = try std.fs.path.join(
                            alloc,
                            &.{ self.home, profile_paths.root_dir_name, rel },
                        );
                        defer alloc.free(path);
                        localDelete(path) catch return error.PassportUnavailable;
                    },
                }
            }
            if (keys.items.len > 0) try b.deleteBatch(alloc, keys.items);
            return;
        }
        for (rel_paths) |rel| {
            const path = try std.fs.path.join(alloc, &.{ self.home, profile_paths.root_dir_name, rel });
            defer alloc.free(path);
            localDelete(path) catch return error.PassportUnavailable;
        }
    }

    /// List entry keys (passport) or profile-relative paths (local) under
    /// a surface prefix such as "sessions" or "sessions/<id>".
    pub fn listSurface(self: *Store, alloc: Allocator, rel_prefix: []const u8) BackendError![][]u8 {
        if (self.activeBackend()) |b| {
            if (try routePrefix(alloc, rel_prefix)) |key_prefix| {
                defer alloc.free(key_prefix);
                return b.list(alloc, key_prefix);
            }
        }
        const dir_rel = std.mem.trimEnd(u8, rel_prefix, "/");
        const dir_path = try std.fs.path.join(alloc, &.{ self.home, profile_paths.root_dir_name, dir_rel });
        defer alloc.free(dir_path);
        return localList(alloc, dir_rel, dir_path);
    }
};

/// The entry-key prefix a profile-relative directory prefix routes to, if
/// the directory is a passport surface at all. Caller frees the result.
fn routePrefix(alloc: Allocator, rel_prefix: []const u8) Allocator.Error!?[]u8 {
    const trimmed = std.mem.trimEnd(u8, rel_prefix, "/");
    if (trimmed.len == 0 or !segmentsValid(trimmed)) return null;
    const routed = std.mem.eql(u8, trimmed, "sessions") or
        std.mem.eql(u8, trimmed, "grants") or
        std.mem.startsWith(u8, trimmed, "sessions/") or
        std.mem.startsWith(u8, trimmed, "grants/");
    if (!routed) return null;
    // sessions/latest/ stays local, matching routePath.
    if (std.mem.startsWith(u8, trimmed, "sessions/")) {
        const rest = trimmed["sessions/".len..];
        if (std.mem.eql(u8, rest, "latest") or std.mem.startsWith(u8, rest, "latest/")) {
            return null;
        }
    }
    return try std.fmt.allocPrint(alloc, "{s}/", .{trimmed});
}

// ─── Tests ──────────────────────────────────────────────────────────────

const MockBackend = struct {
    entries: std.StringHashMapUnmanaged([]u8) = .empty,
    reads: usize = 0,
    writes: usize = 0,
    deletes: usize = 0,

    fn deinit(self: *MockBackend, alloc: Allocator) void {
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            alloc.free(@constCast(kv.key_ptr.*));
            alloc.free(kv.value_ptr.*);
        }
        self.entries.deinit(alloc);
    }

    fn backend(self: *MockBackend) Backend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Backend.VTable = .{
        .read = readImpl,
        .write = writeImpl,
        .delete = deleteImpl,
        .list = listImpl,
    };

    fn readImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) BackendError!?[]u8 {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        self.reads += 1;
        const value = self.entries.get(key) orelse return null;
        return try alloc.dupe(u8, value);
    }

    fn writeImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8, bytes: []const u8) BackendError!void {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        self.writes += 1;
        const owned_key = try alloc.dupe(u8, key);
        errdefer alloc.free(owned_key);
        const owned_value = try alloc.dupe(u8, bytes);
        if (self.entries.fetchRemove(key)) |kv| {
            alloc.free(@constCast(kv.key));
            alloc.free(kv.value);
        }
        try self.entries.put(alloc, owned_key, owned_value);
    }

    fn deleteImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) BackendError!void {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        self.deletes += 1;
        if (self.entries.fetchRemove(key)) |kv| {
            alloc.free(@constCast(kv.key));
            alloc.free(kv.value);
        }
    }

    fn listImpl(ptr: *anyopaque, alloc: Allocator, prefix: []const u8) BackendError![][]u8 {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        var out: std.ArrayList([]u8) = .empty;
        errdefer out.deinit(alloc);
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            if (std.mem.startsWith(u8, kv.key_ptr.*, prefix)) {
                try out.append(alloc, try alloc.dupe(u8, kv.key_ptr.*));
            }
        }
        return out.toOwnedSlice(alloc);
    }
};

test "routePath maps the enumerated surfaces and nothing else" {
    const alloc = std.testing.allocator;

    const cases = [_]struct { path: []const u8, key: []const u8 }{
        .{ .path = "settings.json", .key = "config/settings.json" },
        .{ .path = "memories.json", .key = "memory/memories.json" },
        .{ .path = "history.jsonl", .key = "config/history.jsonl" },
        .{ .path = "mcp.json", .key = "config/mcp.json" },
        .{ .path = "sessions/abc/000001", .key = "sessions/abc/000001" },
        .{ .path = "grants/grant-1.json", .key = "grants/grant-1.json" },
    };
    for (cases) |case| {
        const route = try routePath(alloc, case.path);
        try std.testing.expect(route == .passport);
        try std.testing.expectEqualStrings(case.key, route.passport);
        alloc.free(route.passport);
    }

    const local_cases = [_][]const u8{
        "auth.json",
        "chatgpt-auth.json",
        "grok-auth.json",
        "api-key",
        "mcp-credentials/credentials.json",
        "logs/trace.log",
        "backups/settings.json.bak",
        "recordings/r1.cast",
        "usage.jsonl",
        "sessions", // bare dir, no trailing path
        "sessions/../escape",
        "sessions/bad segment/x",
        // Non-chunk sessions paths are not valid entry keys (PS-022).
        "sessions/abc/session.json",
        "sessions/abc/meta/index.json",
        "sessions/latest/pointer.json",
        "grants/../escape",
        "grants/bad segment/x",
        "grants/",
        "settings.lock",
    };
    for (local_cases) |path| {
        const route = try routePath(alloc, path);
        switch (route) {
            .local => {},
            .passport => |key| {
                std.debug.print("expected local for {s}, got {s}\n", .{ path, key });
                alloc.free(key);
                return error.TestUnexpectedRoute;
            },
        }
    }
}

fn tmpHome(alloc: Allocator, tmp: *std.testing.TmpDir) ![]u8 {
    return io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
}

test "disabled store reads and writes the same local file" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmpHome(alloc, &tmp);
    defer alloc.free(home);

    var store = try Store.init(alloc, home, null);
    defer store.deinit();
    try std.testing.expect(!store.passportEnabled());

    try store.writeSurface(alloc, "memories.json", "[\"a\"]\n");
    const read_back = (try store.readSurface(alloc, "memories.json")).?;
    defer alloc.free(read_back);
    try std.testing.expectEqualStrings("[\"a\"]\n", read_back);

    // The bytes really landed at ~/.fx/memories.json.
    const mem_path = try profile_paths.memoriesPath(alloc, home);
    defer alloc.free(mem_path);
    var file = try std.Io.Dir.openFileAbsolute(std.testing.io, mem_path, .{});
    defer file.close(std.testing.io);
    const disk = try io_mod.readFileToEnd(alloc, &file, 4096);
    defer alloc.free(disk);
    try std.testing.expectEqualStrings("[\"a\"]\n", disk);

    // Absent surfaces read as null, delete ignores absent.
    try std.testing.expect((try store.readSurface(alloc, "settings.json")) == null);
    try store.deleteSurface(alloc, "settings.json");

    try store.deleteSurface(alloc, "memories.json");
    try std.testing.expect((try store.readSurface(alloc, "memories.json")) == null);
}

test "enabled store routes passport surfaces through the backend only" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmpHome(alloc, &tmp);
    defer alloc.free(home);

    var mock = MockBackend{};
    defer mock.deinit(alloc);

    var store = try Store.init(alloc, home, mock.backend());
    defer store.deinit();
    try std.testing.expect(store.passportEnabled());

    // Redirect surface: goes to the backend as its entry key.
    try store.writeSurface(alloc, "memories.json", "[\"m1\"]\n");
    try std.testing.expectEqual(@as(usize, 1), mock.writes);
    try std.testing.expectEqualStrings("[\"m1\"]\n", mock.entries.get("memory/memories.json").?);
    try std.testing.expect(mock.entries.get("memories.json") == null);

    const read_back = (try store.readSurface(alloc, "memories.json")).?;
    defer alloc.free(read_back);
    try std.testing.expectEqualStrings("[\"m1\"]\n", read_back);
    try std.testing.expectEqual(@as(usize, 1), mock.reads);

    // Nothing landed on disk for the redirected surface.
    const local_path = try profile_paths.memoriesPath(alloc, home);
    defer alloc.free(local_path);
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.openFileAbsolute(std.testing.io, local_path, .{}),
    );

    // Session chunk surfaces map under sessions/<id>/<seq> (PS-022).
    try store.writeSurface(alloc, "sessions/s1/000001", "{}");
    try std.testing.expect(mock.entries.get("sessions/s1/000001") != null);
    // Non-chunk sessions paths are not valid entry keys and stay local.
    try store.writeSurface(alloc, "sessions/s1/session.json", "{}");
    try std.testing.expect(mock.entries.get("sessions/s1/session.json") == null);

    // Excluded surfaces stay local even when enabled.
    try store.writeSurface(alloc, "auth.json", "{\"token\":\"x\"}");
    const auth_path = try profile_paths.authPath(alloc, home);
    defer alloc.free(auth_path);
    var auth_file = try std.Io.Dir.openFileAbsolute(std.testing.io, auth_path, .{});
    defer auth_file.close(std.testing.io);
    const auth_disk = try io_mod.readFileToEnd(alloc, &auth_file, 4096);
    defer alloc.free(auth_disk);
    try std.testing.expectEqualStrings("{\"token\":\"x\"}", auth_disk);
    try std.testing.expect(mock.entries.get("auth.json") == null);

    // Delete routes to the backend for passport surfaces.
    try store.deleteSurface(alloc, "memories.json");
    try std.testing.expectEqual(@as(usize, 1), mock.deletes);
    try std.testing.expect((try store.readSurface(alloc, "memories.json")) == null);

    // List on the backend sees passport keys under the prefix.
    const session_keys = try store.listSurface(alloc, "sessions/");
    defer {
        for (session_keys) |k| alloc.free(k);
        alloc.free(session_keys);
    }
    try std.testing.expectEqual(@as(usize, 1), session_keys.len);
    try std.testing.expectEqualStrings("sessions/s1/000001", session_keys[0]);
}
