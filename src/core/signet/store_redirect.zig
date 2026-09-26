//! Redirect layer: when the signet backend is enabled, the enumerated
//! ~/.fx state surfaces read and write through the signet instead of the
//! filesystem. When it is disabled, every operation lands on the exact same
//! local file with the exact same IO helpers — byte-for-byte unchanged.
//!
//! Redirect surfaces (rel to ~/.fx):
//!   settings.json          -> config/settings.json
//!   sessions/<...>         -> sessions/<...>
//!   grants/<...>           -> grants/<...>   (recorded permission grants)
//!   memories.json          -> memory/memories.json
//!   memory/<type>/<slug>.md -> memory/<...>  (learned entries, SN-120/KTD8)
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
const debug_trace = @import("../shared/debug_trace.zig");
const client_mod = @import("client.zig");
const config_mod = @import("config.zig");
const identity = @import("identity.zig");
const secretscan = @import("secretscan.zig");

const Allocator = std.mem.Allocator;

const max_surface_bytes: usize = 64 * 1024 * 1024;

/// Where a profile-relative path's bytes live.
const Route = union(enum) {
    /// Stays on the filesystem under ~/.fx.
    local,
    /// A signet entry key (owned by the caller's allocator).
    signet: []u8,
};

/// Map a profile-relative path (forward slashes, relative to ~/.fx) to its
/// storage route. Unroutable or unlisted paths stay local — a surface that
/// cannot map to a valid entry key is never silently pushed into the
/// signet.
fn routePath(alloc: Allocator, rel_path: []const u8) Allocator.Error!Route {
    if (std.mem.eql(u8, rel_path, "settings.json"))
        return .{ .signet = try alloc.dupe(u8, "config/settings.json") };
    if (std.mem.eql(u8, rel_path, "memories.json"))
        return .{ .signet = try alloc.dupe(u8, "memory/memories.json") };
    if (std.mem.eql(u8, rel_path, "history.jsonl"))
        return .{ .signet = try alloc.dupe(u8, "config/history.jsonl") };
    if (std.mem.eql(u8, rel_path, "mcp.json"))
        return .{ .signet = try alloc.dupe(u8, "config/mcp.json") };
    if (std.mem.startsWith(u8, rel_path, "sessions/")) {
        const rest = rel_path["sessions/".len..];
        // sessions/latest/ is the local resume cache, never a session.
        if (std.mem.eql(u8, rest, "latest") or
            std.mem.startsWith(u8, rest, "latest/")) return .local;
        // The sessions surface is exactly sessions/<id>/<seq> (SN-022).
        // Anything else under sessions/ stays local rather than emitting
        // an entry key the store would reject.
        if (!client_mod.isValidEntryKey(rel_path)) return .local;
        return .{ .signet = try alloc.dupe(u8, rel_path) };
    }
    if (std.mem.startsWith(u8, rel_path, "grants/")) {
        if (!client_mod.isValidEntryKey(rel_path)) return .local;
        return .{ .signet = try alloc.dupe(u8, rel_path) };
    }
    if (std.mem.startsWith(u8, rel_path, "memory/")) {
        // Learned entries live under memory/<type>/<slug>.md (KTD8).
        if (!client_mod.isValidEntryKey(rel_path)) return .local;
        return .{ .signet = try alloc.dupe(u8, rel_path) };
    }
    return .local;
}

// ─── Backend interface ──────────────────────────────────────────────────

pub const BackendError = error{
    InvalidEntryKey,
    SignetUnavailable,
    OutOfMemory,
} || client_mod.Error;

/// The narrow interface the stores call. The production implementation
/// is SignetBackend (encrypted remote); the disabled path uses the
/// localRead/localWrite/localDelete free functions directly. Tests
/// substitute their own.
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
        /// Optional batched read: results[i] answers keys[i], null when
        /// absent. Caller owns the slice and each non-null element. When
        /// null the Store falls back to per-entry reads. The signet
        /// backend verifies the manifest once for the whole batch.
        read_batch: ?*const fn (
            ptr: *anyopaque,
            alloc: Allocator,
            keys: []const []const u8,
        ) BackendError![]?[]u8 = null,
        /// Optional batched write: keys[i] receives plaintexts[i]. When null
        /// the Store falls back to per-entry writes. The signet backend
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
        /// Optional pre-upload scan of assembled plaintext under `key`
        /// (the real file or surface name). Backends that chunk content
        /// before pushing need this: the per-entry scan inside push sees
        /// each chunk in isolation, so a credential straddling a chunk
        /// boundary would evade it (SN-110). Null means no assembled
        /// scan; callers may skip the call entirely when local.
        scan: ?*const fn (
            ptr: *anyopaque,
            alloc: Allocator,
            key: []const u8,
            bytes: []const u8,
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
    /// Batched read: results[i] answers keys[i], null when absent.
    /// Caller owns the slice and each non-null element.
    pub fn readBatch(self: Backend, alloc: Allocator, keys: []const []const u8) BackendError![]?[]u8 {
        if (self.vtable.read_batch) |rb| return rb(self.ptr, alloc, keys);
        const results = try alloc.alloc(?[]u8, keys.len);
        @memset(results, null);
        errdefer {
            for (results) |r| if (r) |b| alloc.free(b);
            alloc.free(results);
        }
        for (keys, 0..) |key, i| {
            results[i] = try self.vtable.read(self.ptr, alloc, key);
        }
        return results;
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
    /// Scan assembled plaintext the way the backend would before upload.
    /// A null vtable entry means the backend performs no assembled scan.
    pub fn scan(self: Backend, alloc: Allocator, key: []const u8, bytes: []const u8) BackendError!void {
        if (self.vtable.scan) |s| return s(self.ptr, alloc, key, bytes);
    }
};

// Local fs primitives for the disabled path. These mirror what the
// existing stores do today: bounded read, mkdir -p plus atomic write,
// delete ignoring FileNotFound.

fn localRead(alloc: Allocator, path: []const u8) BackendError!?[]u8 {
    var file = io_mod.openExistingRegularFile(std.Io.Dir.cwd(), path, .read_only) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return error.SignetUnavailable,
    };
    defer file.close(io_mod.getIo());
    return io_mod.readFileToEnd(alloc, &file, max_surface_bytes) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.SignetUnavailable,
    };
}

fn localWrite(alloc: Allocator, path: []const u8, bytes: []const u8) BackendError!void {
    if (std.fs.path.dirname(path)) |dir_path| {
        io_mod.makeDirRecursive(dir_path) catch return error.SignetUnavailable;
    }
    io_mod.writeFileAtomic(alloc, path, bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.SignetUnavailable,
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
        else => return error.SignetUnavailable,
    };
    defer dir.close(zio);

    var walker = dir.walk(alloc) catch return error.SignetUnavailable;
    defer walker.deinit();

    var out: std.ArrayList([]u8) = .empty;
    errdefer {
        for (out.items) |s| alloc.free(s);
        out.deinit(alloc);
    }
    while (walker.next(zio) catch return error.SignetUnavailable) |entry| {
        if (entry.kind != .file) continue;
        const rel = try std.fs.path.join(alloc, &.{ dir_rel, entry.path });
        // Normalize separators for the entry-key namespace.
        std.mem.replaceScalar(u8, rel, std.fs.path.sep, '/');
        try out.append(alloc, rel);
    }
    return out.toOwnedSlice(alloc);
}

/// Signet-backed implementation: entries are secret-scanned, encrypted,
/// and pushed through the client (SN-030/032/033/110).
pub const SignetBackend = struct {
    client: *client_mod.Client,

    pub fn backend(self: *SignetBackend) Backend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Backend.VTable = .{
        .read = readImpl,
        .write = writeImpl,
        .delete = deleteImpl,
        .list = listImpl,
        .read_batch = readBatchImpl,
        .write_batch = writeBatchImpl,
        .delete_batch = deleteBatchImpl,
        .scan = scanImpl,
    };

    fn readImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) BackendError!?[]u8 {
        const self: *SignetBackend = @ptrCast(@alignCast(ptr));
        const bytes = self.client.readEntry(key) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return e,
        };
        const remote = bytes orelse return null;
        // readEntry allocates on the client's allocator; the contract is
        // caller-allocator-owned memory.
        defer self.client.alloc.free(remote);
        return try alloc.dupe(u8, remote);
    }

    /// One manifest fetch+verify covers the whole batch (SN-041).
    fn readBatchImpl(ptr: *anyopaque, alloc: Allocator, keys: []const []const u8) BackendError![]?[]u8 {
        const self: *SignetBackend = @ptrCast(@alignCast(ptr));
        return self.client.readEntries(alloc, keys);
    }

    /// A stale-base (409) verdict only means the remote manifest moved
    /// mid-commit: the push re-fetches and retries, bounded so a
    /// contested namespace cannot spin the caller forever.
    const stale_base_max_attempts: u8 = 4;

    fn pushWithRetry(
        self: *SignetBackend,
        entries: []const client_mod.Entry,
        deletions: []const []const u8,
    ) client_mod.Error!client_mod.PushResult {
        var attempt: u8 = 1;
        while (true) {
            return self.client.push(entries, deletions) catch |err| switch (err) {
                error.SignetStaleBase => {
                    if (attempt >= stale_base_max_attempts)
                        return error.SignetStaleBase;
                    debug_trace.logf(
                        "signet",
                        "event=stale_base_retry attempt={d}",
                        .{attempt},
                    );
                    attempt += 1;
                    continue;
                },
                else => |e| return e,
            };
        }
    }

    fn writeImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8, bytes: []const u8) BackendError!void {
        const self: *SignetBackend = @ptrCast(@alignCast(ptr));
        _ = alloc;
        const entries = [_]client_mod.Entry{.{ .key = key, .plaintext = bytes }};
        var result = self.pushWithRetry(&entries, &.{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return e,
        };
        // push allocates on the client's allocator.
        defer result.deinit(self.client.alloc);
        self.traceWarnFindings();
    }

    fn deleteImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) BackendError!void {
        const self: *SignetBackend = @ptrCast(@alignCast(ptr));
        _ = alloc;
        const deletions = [_][]const u8{key};
        var result = self.pushWithRetry(&.{}, &deletions) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return e,
        };
        defer result.deinit(self.client.alloc);
    }

    /// Assembled-file scan for chunked uploaders (session mirroring):
    /// enforces the client's scan mode on the whole plaintext under the
    /// real file name, before the caller splits it into chunk entries
    /// that would each scan clean around a boundary-straddling secret.
    fn scanImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8, bytes: []const u8) BackendError!void {
        const self: *SignetBackend = @ptrCast(@alignCast(ptr));
        if (self.client.scan_mode == .off) return;
        const entries = [_]secretscan.Entry{.{ .key = key, .text = bytes }};
        var findings: std.ArrayList(secretscan.Finding) = .empty;
        defer {
            for (findings.items) |*f| f.deinit(alloc);
            findings.deinit(alloc);
        }
        const blocked = if (secretscan.enforce(
            alloc,
            &entries,
            self.client.scan_mode,
            &findings,
        )) |_|
            false
        else |err| switch (err) {
            error.SecretFound => true,
            else => |e| return e,
        };
        for (findings.items) |f| {
            debug_trace.logf(
                "signet",
                "event=secret_scan_{s} key={s} rule={s} line={d} match={s}",
                .{ if (blocked) "block" else "warn", f.entry_key, f.rule, f.line, f.match },
            );
        }
        if (blocked) return error.SecretFound;
    }

    /// Warn-mode secret scan reports into debug_trace so a committed
    /// credential shape is visible without blocking the write (SN-110).
    fn traceWarnFindings(self: *SignetBackend) void {
        if (self.client.scan_mode != .warn) return;
        const findings = self.client.scanFindings() orelse return;
        for (findings) |f| {
            debug_trace.logf(
                "signet",
                "event=secret_scan_warn key={s} rule={s} line={d} match={s}",
                .{ f.entry_key, f.rule, f.line, f.match },
            );
        }
    }

    fn listImpl(ptr: *anyopaque, alloc: Allocator, prefix: []const u8) BackendError![][]u8 {
        const self: *SignetBackend = @ptrCast(@alignCast(ptr));
        const entries = self.client.hashes() catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return e,
        };
        defer {
            // hashes() allocates on the client's allocator.
            for (entries) |e| {
                self.client.alloc.free(@constCast(e.key));
                self.client.alloc.free(@constCast(e.plaintext));
            }
            self.client.alloc.free(entries);
        }
        var out: std.ArrayList([]u8) = .empty;
        errdefer {
            for (out.items) |s| alloc.free(s);
            out.deinit(alloc);
        }
        for (entries) |e| {
            if (std.mem.startsWith(u8, e.key, prefix)) {
                const owned = try alloc.dupe(u8, e.key);
                errdefer alloc.free(owned);
                try out.append(alloc, owned);
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
        const self: *SignetBackend = @ptrCast(@alignCast(ptr));
        const entries = try alloc.alloc(client_mod.Entry, keys.len);
        defer alloc.free(entries);
        for (keys, plaintexts, 0..) |key, bytes, i| {
            entries[i] = .{ .key = key, .plaintext = bytes };
        }
        var result = self.pushWithRetry(entries, &.{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return e,
        };
        defer result.deinit(self.client.alloc);
        self.traceWarnFindings();
    }

    fn deleteBatchImpl(ptr: *anyopaque, alloc: Allocator, keys: []const []const u8) BackendError!void {
        const self: *SignetBackend = @ptrCast(@alignCast(ptr));
        _ = alloc;
        var result = self.pushWithRetry(&.{}, keys) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => |e| return e,
        };
        defer result.deinit(self.client.alloc);
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
    // and SignetBackend can point at the client without dangling when the
    // Store is returned by value.
    http: ?*client_mod.HttpTransport = null,
    client: ?*client_mod.Client = null,
    /// Kept alive for the Store's lifetime: client.did/genesis_did borrow
    /// the identity's DID allocation.
    identity: ?identity.Identity = null,
    /// Namespace-derived genesis DID (post-rotation holder, SN-012). Kept
    /// alive because client.genesis_did borrows the slice.
    genesis_did: ?[]u8 = null,
    /// Verified rotation chain loaded at open. Kept alive because
    /// client.attestations borrows the slice.
    rotation_chain: []identity.RotationAttestation = &.{},
    signet_backend: ?SignetBackend = null,
    injected_backend: ?Backend = null,

    /// Open the store for a home dir. Disabled (no config) yields a store
    /// whose every operation is plain local filesystem IO.
    pub fn open(alloc: Allocator, home: []const u8) !Store {
        var store = Store{
            .alloc = alloc,
            .home = try alloc.dupe(u8, home),
        };
        errdefer alloc.free(store.home);

        store.cfg = try config_mod.resolve(alloc, home);
        if (store.cfg) |*cfg| {
            errdefer cfg.deinit(alloc);
            const seed = cfg.seed orelse return error.SignetSecretsMissing;
            const passphrase = cfg.passphrase orelse return error.SignetSecretsMissing;
            var id = try identity.identityFromSeed(alloc, seed);
            errdefer id.deinit(alloc);

            var genesis_did: []const u8 = id.did;
            if (cfg.namespace) |ns| {
                // An explicit namespace pins the genesis DID it was
                // derived from — post-rotation the holder key and the
                // namespace owner differ, so decoding the namespace is
                // the only honest way to recover the chain anchor.
                if (!identity.isValidNamespace(ns)) return error.SignetNamespaceInvalid;
                store.genesis_did = (try identity.didFromNamespace(alloc, ns)) orelse
                    return error.SignetNamespaceInvalid;
                genesis_did = store.genesis_did.?;
            }

            // Restore the persisted anti-rollback cursor so a restarted
            // client still enforces the seq floor (SN-041).
            const state_path = try std.fs.path.join(
                alloc,
                &.{ home, profile_paths.root_dir_name, "signet", "manifest-state.json" },
            );
            defer alloc.free(state_path);
            var state_seq: u64 = 0;
            var state_hash: ?[]u8 = null;
            defer if (state_hash) |h| alloc.free(h);
            if (try loadManifestState(alloc, state_path)) |state| {
                state_seq = state.seq;
                state_hash = state.canonical_sha256;
            }

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
                    .genesis_did = genesis_did,
                    // The override rides into init so the entry key is
                    // derived once, against the effective namespace.
                    .namespace = cfg.namespace,
                    .passphrase = passphrase,
                    .scan_mode = cfg.scan_mode,
                    .last_seq = state_seq,
                    .last_manifest_hash = state_hash,
                    .manifest_state_path = state_path,
                },
            );
            errdefer store.client.?.deinit();
            store.identity = id;

            if (cfg.namespace != null) {
                // A pinned namespace may point at a signet whose holder
                // rotated keys: rebuild and verify the chain, then adopt
                // it for auth and manifest signer checks (SN-051/052).
                store.rotation_chain = try store.client.?.loadRotationChain(alloc);
                errdefer {
                    for (store.rotation_chain) |*att| {
                        alloc.free(@constCast(att.genesis_did));
                        alloc.free(@constCast(att.new_did));
                        alloc.free(@constCast(att.prev_hash));
                        alloc.free(@constCast(att.sig));
                    }
                    alloc.free(store.rotation_chain);
                }
                const current_did: []const u8 = if (store.rotation_chain.len > 0)
                    store.rotation_chain[store.rotation_chain.len - 1].new_did
                else
                    genesis_did;
                // A namespace we cannot act on (our key is neither the
                // genesis nor the current successor) is a misconfigured
                // enabled state: fail closed, not local fallback.
                if (!std.mem.eql(u8, current_did, id.did))
                    return error.SignetNamespaceInvalid;
                store.client.?.attestations = store.rotation_chain;
            }

            store.signet_backend = .{ .client = store.client.? };
        }
        return store;
    }

    /// Test seam: a store with a caller-provided backend (null = local).
    pub fn init(alloc: Allocator, home: []const u8, backend: ?Backend) !Store {
        return .{
            .alloc = alloc,
            .home = try alloc.dupe(u8, home),
            .injected_backend = backend,
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
        if (self.genesis_did) |did| self.alloc.free(did);
        for (self.rotation_chain) |*att| {
            self.alloc.free(@constCast(att.genesis_did));
            self.alloc.free(@constCast(att.new_did));
            self.alloc.free(@constCast(att.prev_hash));
            self.alloc.free(@constCast(att.sig));
        }
        if (self.rotation_chain.len > 0) self.alloc.free(self.rotation_chain);
        self.alloc.free(self.home);
        self.* = undefined;
    }

    /// Whether the signet backend is live.
    pub fn signetEnabled(self: *const Store) bool {
        if (self.injected_backend != null) return true;
        return self.signet_backend != null;
    }

    /// The holder DID the signet client signs with, when the remote
    /// backend is live. Null on a local or injected-backend store.
    pub fn holderDid(self: *const Store) ?[]const u8 {
        const client = self.client orelse return null;
        return client.did;
    }

    fn activeBackend(self: *Store) ?Backend {
        if (self.injected_backend) |b| return b;
        if (self.signet_backend) |*b| return b.backend();
        return null;
    }

    /// Whether a backend error means the remote is unreachable rather
    /// than refusing or untrustworthy: transport failures and 5xx answers
    /// degrade to the local surface, while 4xx rejections, integrity
    /// failures, and decrypt failures stay fail-closed (SN-041 posture).
    /// An injected test backend has no client status, so its SignetHttp
    /// stays fatal.
    fn isUnavailable(self: *const Store, err: BackendError) bool {
        return switch (err) {
            error.SignetHttpFailed, error.SignetUnavailable => true,
            error.SignetHttp => if (self.client) |c| c.last_error.status >= 500 else false,
            else => false,
        };
    }

    /// Read a surface's bytes. Disabled or unrouted surfaces read the local
    /// file; signet surfaces go through the backend. A transport-class
    /// backend failure (unreachable, or a 5xx answer through a proxy)
    /// degrades to the local copy; refusal, integrity, and decrypt errors
    /// stay fail-closed.
    pub fn readSurface(self: *Store, alloc: Allocator, rel_path: []const u8) BackendError!?[]u8 {
        return self.readSurfaceInner(alloc, rel_path, true);
    }

    /// Read with no local fallback: a transport-class failure propagates.
    /// For write-path verification reads (collision checks), an unseen
    /// remote entry must fail the operation, not look absent.
    pub fn readSurfaceStrict(self: *Store, alloc: Allocator, rel_path: []const u8) BackendError!?[]u8 {
        return self.readSurfaceInner(alloc, rel_path, false);
    }

    fn readSurfaceInner(
        self: *Store,
        alloc: Allocator,
        rel_path: []const u8,
        allow_fallback: bool,
    ) BackendError!?[]u8 {
        if (self.activeBackend()) |b| {
            const route = try routePath(alloc, rel_path);
            switch (route) {
                .local => {},
                .signet => |key| {
                    defer alloc.free(key);
                    if (b.read(alloc, key)) |remote| {
                        return remote;
                    } else |err| {
                        if (!allow_fallback or !self.isUnavailable(err)) return err;
                        debug_trace.logf(
                            "signet",
                            "remote read unavailable rel={s} err={s}; serving local copy",
                            .{ rel_path, @errorName(err) },
                        );
                    }
                },
            }
        }
        const path = try std.fs.path.join(alloc, &.{ self.home, profile_paths.root_dir_name, rel_path });
        defer alloc.free(path);
        return localRead(alloc, path);
    }

    /// Batched read: results[i] answers rel_paths[i]. Local-routed paths
    /// keep the per-path file reads; signet-routed paths share one
    /// backend batch, which means one manifest fetch+verify. Caller owns
    /// the slice and each non-null element.
    pub fn readSurfacesBatch(
        self: *Store,
        alloc: Allocator,
        rel_paths: []const []const u8,
    ) BackendError![]?[]u8 {
        const results = try alloc.alloc(?[]u8, rel_paths.len);
        @memset(results, null);
        errdefer {
            for (results) |r| if (r) |b| alloc.free(b);
            alloc.free(results);
        }
        const backend = self.activeBackend() orelse {
            for (rel_paths, 0..) |rel_path, i| {
                const path = try std.fs.path.join(
                    alloc,
                    &.{ self.home, profile_paths.root_dir_name, rel_path },
                );
                defer alloc.free(path);
                results[i] = try localRead(alloc, path);
            }
            return results;
        };
        var remote_idx: std.ArrayList(usize) = .empty;
        defer remote_idx.deinit(alloc);
        var remote_keys: std.ArrayList([]const u8) = .empty;
        defer {
            for (remote_keys.items) |k| alloc.free(k);
            remote_keys.deinit(alloc);
        }
        for (rel_paths, 0..) |rel_path, i| {
            const route = try routePath(alloc, rel_path);
            switch (route) {
                .local => {
                    const path = try std.fs.path.join(
                        alloc,
                        &.{ self.home, profile_paths.root_dir_name, rel_path },
                    );
                    defer alloc.free(path);
                    results[i] = try localRead(alloc, path);
                },
                .signet => |key| {
                    try remote_keys.append(alloc, key);
                    try remote_idx.append(alloc, i);
                },
            }
        }
        if (remote_keys.items.len == 0) return results;
        const remote_results = backend.readBatch(alloc, remote_keys.items) catch |err| {
            if (!self.isUnavailable(err)) return err;
            debug_trace.logf(
                "signet",
                "remote batch read unavailable err={s}; serving local copies",
                .{@errorName(err)},
            );
            for (remote_idx.items) |i| {
                const path = try std.fs.path.join(
                    alloc,
                    &.{ self.home, profile_paths.root_dir_name, rel_paths[i] },
                );
                defer alloc.free(path);
                results[i] = try localRead(alloc, path);
            }
            return results;
        };
        // Move the elements into results; remote_results' slice is the
        // only thing left to free.
        defer alloc.free(remote_results);
        for (remote_idx.items, 0..) |i, j| results[i] = remote_results[j];
        return results;
    }

    /// Write a surface's bytes. Local backend uses the same
    /// mkdir-plus-atomic-write the stores use today.
    pub fn writeSurface(self: *Store, alloc: Allocator, rel_path: []const u8, bytes: []const u8) BackendError!void {
        if (self.activeBackend()) |b| {
            const route = try routePath(alloc, rel_path);
            switch (route) {
                .local => {},
                .signet => |key| {
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
                .signet => |key| {
                    defer alloc.free(key);
                    return b.delete(alloc, key);
                },
            }
        }
        const path = try std.fs.path.join(alloc, &.{ self.home, profile_paths.root_dir_name, rel_path });
        defer alloc.free(path);
        localDelete(path) catch return error.SignetUnavailable;
    }

    /// Batched surface write. Signet-routed paths go through one backend
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
                    .signet => |key| {
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
                    .signet => |key| try keys.append(alloc, key),
                    .local => {
                        const path = try std.fs.path.join(
                            alloc,
                            &.{ self.home, profile_paths.root_dir_name, rel },
                        );
                        defer alloc.free(path);
                        localDelete(path) catch return error.SignetUnavailable;
                    },
                }
            }
            if (keys.items.len > 0) try b.deleteBatch(alloc, keys.items);
            return;
        }
        for (rel_paths) |rel| {
            const path = try std.fs.path.join(alloc, &.{ self.home, profile_paths.root_dir_name, rel });
            defer alloc.free(path);
            localDelete(path) catch return error.SignetUnavailable;
        }
    }

    /// Scan assembled plaintext under `key` (a real file or surface
    /// name) the way the backend would before upload. Local mode scans
    /// nothing: the bytes never leave the filesystem.
    pub fn scanSurface(
        self: *Store,
        alloc: Allocator,
        key: []const u8,
        bytes: []const u8,
    ) BackendError!void {
        const b = self.activeBackend() orelse return;
        return b.scan(alloc, key, bytes);
    }

    /// List entry keys (signet) or profile-relative paths (local) under
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
/// the directory is a signet surface at all. Caller frees the result.
fn routePrefix(alloc: Allocator, rel_prefix: []const u8) Allocator.Error!?[]u8 {
    const trimmed = std.mem.trimEnd(u8, rel_prefix, "/");
    if (trimmed.len == 0 or !client_mod.isValidPathShape(trimmed)) return null;
    const routed = std.mem.eql(u8, trimmed, "sessions") or
        std.mem.eql(u8, trimmed, "grants") or
        std.mem.eql(u8, trimmed, "memory") or
        std.mem.startsWith(u8, trimmed, "sessions/") or
        std.mem.startsWith(u8, trimmed, "grants/") or
        std.mem.startsWith(u8, trimmed, "memory/");
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

// ─── Store-opening seam for the store wrappers ──────────────────────────

/// Open a signet-enabled Store for a home dir, heap-allocated for the
/// store wrappers that hold it behind an optional pointer. Returns null
/// when the backend is disabled; a misconfigured enabled state (missing
/// secrets, bad namespace) propagates rather than silently falling back
/// to local files. destroyOwned frees the store and its memory.
pub fn openEnabled(alloc: Allocator, home: []const u8) !?*Store {
    const store = try alloc.create(Store);
    errdefer alloc.destroy(store);
    store.* = try Store.open(alloc, home);
    if (!store.signetEnabled()) {
        store.deinit();
        alloc.destroy(store);
        return null;
    }
    return store;
}

/// Deinit and free a Store obtained from openEnabled.
pub fn destroyOwned(store: *Store) void {
    const alloc = store.alloc;
    store.deinit();
    alloc.destroy(store);
}

/// The persisted anti-rollback cursor for a signet namespace (SN-041).
const ManifestState = struct {
    seq: u64,
    /// sha256 hex of the last verified canonical manifest. Owned slice.
    canonical_sha256: []u8,
};

/// Load {seq, canonical_sha256} written by Client.persistManifestState.
/// Null when no cursor exists yet; a malformed file is fail-closed
/// (SignetStateCorrupt) rather than a silently reset seq floor.
fn loadManifestState(alloc: Allocator, path: []const u8) !?ManifestState {
    const bytes = blk: {
        var file = io_mod.openExistingRegularFile(std.Io.Dir.cwd(), path, .read_only) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return error.SignetStateCorrupt,
        };
        defer file.close(io_mod.getIo());
        break :blk io_mod.readFileToEnd(alloc, &file, 64 * 1024) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.SignetStateCorrupt,
        };
    };
    defer alloc.free(bytes);

    var parsed = std.json.parseFromSlice(std.json.Value, alloc, bytes, .{}) catch
        return error.SignetStateCorrupt;
    defer parsed.deinit();
    if (parsed.value != .object) return error.SignetStateCorrupt;
    const obj = parsed.value.object;
    const seq_v = obj.get("seq") orelse return error.SignetStateCorrupt;
    const hash_v = obj.get("canonical_sha256") orelse return error.SignetStateCorrupt;
    if (seq_v != .integer or seq_v.integer < 0) return error.SignetStateCorrupt;
    if (hash_v != .string or hash_v.string.len != 64) return error.SignetStateCorrupt;
    return .{
        .seq = @intCast(seq_v.integer),
        .canonical_sha256 = try alloc.dupe(u8, hash_v.string),
    };
}

/// Derive the home dir from a ~/.fx path ("<home>/.fx[/...]"). Returns
/// null when the path does not end at the profile root dir name.
pub fn homeFromFxPath(fx_path: []const u8) ?[]const u8 {
    const trimmed = std.mem.trimEnd(u8, fx_path, "/");
    if (!std.mem.endsWith(u8, trimmed, profile_paths.root_dir_name)) return null;
    const home = trimmed[0 .. trimmed.len - profile_paths.root_dir_name.len];
    return std.mem.trimEnd(u8, home, "/");
}

// ─── Test seam ──────────────────────────────────────────────────────────

/// In-memory backend shared by the signet unit tests. Counts each vtable
/// call so tests can pin batching behavior.
pub const MockBackend = struct {
    entries: std.StringHashMapUnmanaged([]u8) = .empty,
    reads: usize = 0,
    batch_reads: usize = 0,
    writes: usize = 0,
    deletes: usize = 0,
    fail_read_with: ?BackendError = null,

    pub fn deinit(self: *MockBackend, alloc: Allocator) void {
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            alloc.free(@constCast(kv.key_ptr.*));
            alloc.free(kv.value_ptr.*);
        }
        self.entries.deinit(alloc);
    }

    pub fn backend(self: *MockBackend) Backend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: Backend.VTable = .{
        .read = readImpl,
        .write = writeImpl,
        .delete = deleteImpl,
        .list = listImpl,
        .read_batch = readBatchImpl,
    };

    fn readImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) BackendError!?[]u8 {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        self.reads += 1;
        if (self.fail_read_with) |e| return e;
        const value = self.entries.get(key) orelse return null;
        return try alloc.dupe(u8, value);
    }

    fn readBatchImpl(ptr: *anyopaque, alloc: Allocator, keys: []const []const u8) BackendError![]?[]u8 {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        self.batch_reads += 1;
        if (self.fail_read_with) |e| return e;
        const results = try alloc.alloc(?[]u8, keys.len);
        @memset(results, null);
        errdefer {
            for (results) |r| if (r) |b| alloc.free(b);
            alloc.free(results);
        }
        for (keys, 0..) |key, i| {
            const value = self.entries.get(key) orelse continue;
            results[i] = try alloc.dupe(u8, value);
        }
        return results;
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
        errdefer {
            for (out.items) |s| alloc.free(s);
            out.deinit(alloc);
        }
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            if (std.mem.startsWith(u8, kv.key_ptr.*, prefix)) {
                const owned = try alloc.dupe(u8, kv.key_ptr.*);
                errdefer alloc.free(owned);
                try out.append(alloc, owned);
            }
        }
        return out.toOwnedSlice(alloc);
    }
};

// ─── Tests ──────────────────────────────────────────────────────────────

test "routePath maps the enumerated surfaces and nothing else" {
    const alloc = std.testing.allocator;

    const cases = [_]struct { path: []const u8, key: []const u8 }{
        .{ .path = "settings.json", .key = "config/settings.json" },
        .{ .path = "memories.json", .key = "memory/memories.json" },
        .{ .path = "history.jsonl", .key = "config/history.jsonl" },
        .{ .path = "mcp.json", .key = "config/mcp.json" },
        .{ .path = "sessions/abc/000001", .key = "sessions/abc/000001" },
        .{ .path = "grants/grant-1.json", .key = "grants/grant-1.json" },
        .{ .path = "memory/user/prefers-pnpm.md", .key = "memory/user/prefers-pnpm.md" },
    };
    for (cases) |case| {
        const route = try routePath(alloc, case.path);
        try std.testing.expect(route == .signet);
        try std.testing.expectEqualStrings(case.key, route.signet);
        alloc.free(route.signet);
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
        // Non-chunk sessions paths are not valid entry keys (SN-022).
        "sessions/abc/session.json",
        "sessions/abc/meta/index.json",
        "sessions/latest/pointer.json",
        "grants/../escape",
        "grants/bad segment/x",
        "grants/",
        "memory/../escape",
        "memory/bad segment/x",
        "settings.lock",
    };
    for (local_cases) |path| {
        const route = try routePath(alloc, path);
        switch (route) {
            .local => {},
            .signet => |key| {
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
    try std.testing.expect(!store.signetEnabled());

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

test "enabled store routes signet surfaces through the backend only" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmpHome(alloc, &tmp);
    defer alloc.free(home);

    var mock = MockBackend{};
    defer mock.deinit(alloc);

    var store = try Store.init(alloc, home, mock.backend());
    defer store.deinit();
    try std.testing.expect(store.signetEnabled());

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

    // Session chunk surfaces map under sessions/<id>/<seq> (SN-022).
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

    // Delete routes to the backend for signet surfaces.
    try store.deleteSurface(alloc, "memories.json");
    try std.testing.expectEqual(@as(usize, 1), mock.deletes);
    try std.testing.expect((try store.readSurface(alloc, "memories.json")) == null);

    // List on the backend sees signet keys under the prefix.
    const session_keys = try store.listSurface(alloc, "sessions/");
    defer {
        for (session_keys) |k| alloc.free(k);
        alloc.free(session_keys);
    }
    try std.testing.expectEqual(@as(usize, 1), session_keys.len);
    try std.testing.expectEqualStrings("sessions/s1/000001", session_keys[0]);
}

test "unavailable backend reads degrade to the local copy" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmpHome(alloc, &tmp);
    defer alloc.free(home);

    // A local copy exists (a local-mode run wrote it before signet was
    // enabled, or an earlier session mirrored it).
    var local = try Store.init(alloc, home, null);
    defer local.deinit();
    try local.writeSurface(alloc, "memories.json", "[\"m-local\"]\n");

    var mock = MockBackend{ .fail_read_with = error.SignetHttpFailed };
    defer mock.deinit(alloc);
    var store = try Store.init(alloc, home, mock.backend());
    defer store.deinit();

    // Transport failure: the remote is unreachable, the local copy serves.
    const read_back = (try store.readSurface(alloc, "memories.json")).?;
    defer alloc.free(read_back);
    try std.testing.expectEqualStrings("[\"m-local\"]\n", read_back);
    try std.testing.expectEqual(@as(usize, 1), mock.reads);

    // Batch reads degrade the same way.
    const surfaces = [_][]const u8{ "memories.json", "settings.json" };
    const results = try store.readSurfacesBatch(alloc, &surfaces);
    defer {
        for (results) |r| if (r) |b| alloc.free(b);
        alloc.free(results);
    }
    try std.testing.expectEqualStrings("[\"m-local\"]\n", results[0].?);
    try std.testing.expect(results[1] == null);
    try std.testing.expectEqual(@as(usize, 1), mock.batch_reads);

    // Integrity, refusal, and unclassified failures stay fail-closed. An
    // injected backend has no client status, so SignetHttp stays fatal here.
    mock.fail_read_with = error.SignetIntegrity;
    try std.testing.expectError(error.SignetIntegrity, store.readSurface(alloc, "memories.json"));
    mock.fail_read_with = error.SignetHttp;
    try std.testing.expectError(error.SignetHttp, store.readSurface(alloc, "memories.json"));
}

// ─── Wire-level tests through the scripted server ───────────────────────

const test_server = @import("test_server.zig");

fn wireClient(
    alloc: Allocator,
    server: *test_server.Server,
    id: *const identity.Identity,
) !client_mod.Client {
    return client_mod.Client.init(alloc, server.transport(), .{
        .url = "http://signet.test",
        .key_pair = id.key_pair,
        .did = id.did,
        .passphrase = "wire-test-passphrase",
    });
}

test "signet backend retries a stale base and still commits" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmpHome(alloc, &tmp);
    defer alloc.free(home);

    var server = test_server.Server.init(alloc);
    defer server.deinit();
    server.namespace_missing = true;
    server.stale_puts_left = 2;

    var id = try identity.identityFromSeed(alloc, [_]u8{9} ** 32);
    defer id.deinit(alloc);
    var client = try wireClient(alloc, &server, &id);
    defer client.deinit();

    var pb = SignetBackend{ .client = &client };
    var store = try Store.init(alloc, home, pb.backend());
    defer store.deinit();

    try store.writeSurface(alloc, "memories.json", "[\"m1\"]\n");

    // Two stale verdicts, then the retried push committed the delta and
    // the signed manifest.
    try std.testing.expect(server.puts >= 3);
    try std.testing.expect(server.entries.get("memory/memories.json") != null);
    try std.testing.expect(server.entries.get(client_mod.manifest_entry_key) != null);
}

test "signet backend exhausts bounded stale-base retries" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try tmpHome(alloc, &tmp);
    defer alloc.free(home);

    var server = test_server.Server.init(alloc);
    defer server.deinit();
    server.namespace_missing = true;
    // One 409 past the retry budget.
    server.stale_puts_left = SignetBackend.stale_base_max_attempts;

    var id = try identity.identityFromSeed(alloc, [_]u8{9} ** 32);
    defer id.deinit(alloc);
    var client = try wireClient(alloc, &server, &id);
    defer client.deinit();

    var pb = SignetBackend{ .client = &client };
    var store = try Store.init(alloc, home, pb.backend());
    defer store.deinit();

    try std.testing.expectError(
        error.SignetStaleBase,
        store.writeSurface(alloc, "memories.json", "[\"m1\"]\n"),
    );
    try std.testing.expect(server.entries.get("memory/memories.json") == null);
}
