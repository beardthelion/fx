//! In-process passport server and backend shims for the wire-level tests.
//! Only test builds pull this file in: every importer references it from
//! inside a test block.

const std = @import("std");
const client_mod = @import("client.zig");
const crypto = @import("crypto.zig");
const identity = @import("identity.zig");
const store_redirect = @import("store_redirect.zig");

const Allocator = std.mem.Allocator;

/// How the unsigned ?view=hashes response diverges from the server's real
/// entry map. The client must fail closed on every divergence.
pub const ViewTamper = enum { none, extra_key, drop_key, wrong_hash };

/// A minimal passport server speaking the wire contract: challenge/verify
/// auth, ?view=hashes, ?view=integrity, PUT commits, and per-entry GETs.
/// Entries are ciphertext blobs keyed by entry key; the manifest blob
/// rides under client_mod.manifest_entry_key like a real entry.
pub const Server = struct {
    alloc: Allocator,
    entries: std.StringHashMapUnmanaged([]u8) = .empty,
    /// Blob served at ?view=integrity; null means the entry is absent.
    integrity_blob: ?[]u8 = null,
    /// When true the namespace reads as absent (404 "empty" everywhere).
    namespace_missing: bool = false,
    tamper: ViewTamper = .none,
    /// Last /auth/verify body, retained for signature assertions.
    verify_body: ?[]u8 = null,
    /// PUTs answered 409 before the first success.
    stale_puts_left: u8 = 0,
    puts: usize = 0,
    last_put_body: ?[]u8 = null,

    pub fn init(alloc: Allocator) Server {
        return .{ .alloc = alloc };
    }

    pub fn deinit(self: *Server) void {
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            self.alloc.free(@constCast(kv.key_ptr.*));
            self.alloc.free(kv.value_ptr.*);
        }
        self.entries.deinit(self.alloc);
        if (self.integrity_blob) |b| self.alloc.free(b);
        if (self.verify_body) |b| self.alloc.free(b);
        if (self.last_put_body) |b| self.alloc.free(b);
    }

    pub fn transport(self: *Server) client_mod.Transport {
        return .{ .ptr = self, .request_fn = requestImpl };
    }

    /// Install a ciphertext blob under key; the server owns the copy.
    pub fn putEntry(self: *Server, key: []const u8, blob: []const u8) !void {
        const owned_key = try self.alloc.dupe(u8, key);
        errdefer self.alloc.free(owned_key);
        const owned_blob = try self.alloc.dupe(u8, blob);
        if (self.entries.fetchRemove(key)) |kv| {
            self.alloc.free(@constCast(kv.key));
            self.alloc.free(kv.value);
        }
        try self.entries.put(self.alloc, owned_key, owned_blob);
    }

    fn reply(alloc: Allocator, status: u16, body: []const u8) !client_mod.Response {
        return .{ .status = status, .body = try alloc.dupe(u8, body) };
    }

    fn jsonReply(alloc: Allocator, value: std.json.Value) !client_mod.Response {
        var out: std.Io.Writer.Allocating = .init(alloc);
        errdefer out.deinit();
        try std.json.Stringify.value(value, .{}, &out.writer);
        return .{ .status = 200, .body = try out.toOwnedSlice() };
    }

    fn requestImpl(
        ptr: *anyopaque,
        alloc: Allocator,
        req: client_mod.Request,
    ) anyerror!client_mod.Response {
        const self: *Server = @ptrCast(@alignCast(ptr));
        const url = req.url;

        if (std.mem.endsWith(u8, url, "/auth/challenge")) {
            return reply(alloc, 200, "{\"nonce\":\"test-nonce-1\"}");
        }
        if (std.mem.endsWith(u8, url, "/auth/verify")) {
            if (self.verify_body) |old| self.alloc.free(old);
            self.verify_body = try self.alloc.dupe(u8, req.body orelse "");
            return reply(alloc, 200, "{\"token\":\"tok-1\",\"expiresAt\":253402300799000}");
        }

        const query_start = std.mem.indexOfScalar(u8, url, '?');
        const path = url[0 .. query_start orelse url.len];
        const query = if (query_start) |i| url[i + 1 ..] else "";

        if (std.mem.eql(u8, query, "view=hashes")) return self.hashesReply(alloc);
        if (std.mem.eql(u8, query, "view=integrity")) return self.integrityReply(alloc);

        if (req.method == .PUT) return self.putReply(alloc, req);
        if (req.method == .GET) return self.getReply(alloc, path);
        return reply(alloc, 500, "{}");
    }

    fn hashesReply(self: *Server, alloc: Allocator) !client_mod.Response {
        if (self.namespace_missing) {
            return reply(alloc, 404, "{\"error\":{\"code\":\"empty\"}}");
        }
        var map: std.json.ObjectMap = .empty;
        defer map.deinit(alloc);
        var it = self.entries.iterator();
        // Hashes must outlive the map: jsonReply stringifies the map values
        // only after this loop finishes.
        var hashes: std.ArrayList([]u8) = .empty;
        defer {
            for (hashes.items) |hash| alloc.free(hash);
            hashes.deinit(alloc);
        }
        while (it.next()) |kv| {
            const hash = try crypto.ciphertextHash(alloc, kv.value_ptr.*);
            try hashes.append(alloc, hash);
            try map.put(alloc, kv.key_ptr.*, .{ .string = hash });
        }
        switch (self.tamper) {
            .none => {},
            .extra_key => try map.put(alloc, "memory/forged.md", .{ .string = "sha256:ff" }),
            .drop_key, .wrong_hash => {
                var vit = map.iterator();
                while (vit.next()) |kv| {
                    if (std.mem.eql(u8, kv.key_ptr.*, client_mod.manifest_entry_key)) continue;
                    if (self.tamper == .drop_key) {
                        _ = map.orderedRemove(kv.key_ptr.*);
                    } else {
                        kv.value_ptr.* = .{ .string = "sha256:0000" };
                    }
                    break;
                }
            },
        }
        return jsonReply(alloc, .{ .object = map });
    }

    fn integrityReply(self: *Server, alloc: Allocator) !client_mod.Response {
        if (self.namespace_missing) {
            return reply(alloc, 404, "{\"error\":{\"code\":\"empty\"}}");
        }
        const blob = self.integrity_blob orelse {
            return reply(alloc, 404, "{\"error\":{\"code\":\"entry_not_found\"}}");
        };
        const body = try std.fmt.allocPrint(alloc, "{{\"entry\":\"{s}\"}}", .{blob});
        defer alloc.free(body);
        return reply(alloc, 200, body);
    }

    /// Entry GET: /passport/<enc_ns>/<key...>. Test keys carry no
    /// percent-escaped characters, so the literal suffix is the key.
    fn getReply(self: *Server, alloc: Allocator, path: []const u8) !client_mod.Response {
        const rest = std.mem.indexOf(u8, path, "/passport/") orelse
            return reply(alloc, 404, "{\"error\":{\"code\":\"entry_not_found\"}}");
        const after_ns = std.mem.indexOfScalarPos(u8, path, rest + "/passport/".len, '/') orelse
            return reply(alloc, 404, "{\"error\":{\"code\":\"entry_not_found\"}}");
        const key = path[after_ns + 1 ..];
        const blob = self.entries.get(key) orelse
            return reply(alloc, 404, "{\"error\":{\"code\":\"entry_not_found\"}}");
        const hash = try crypto.ciphertextHash(alloc, blob);
        defer alloc.free(hash);
        const body = try std.fmt.allocPrint(
            alloc,
            "{{\"entry\":\"{s}\",\"hash\":\"{s}\"}}",
            .{ blob, hash },
        );
        defer alloc.free(body);
        return reply(alloc, 200, body);
    }

    /// PUT {base, entries, deletions?}: apply the delta the way the real
    /// store does, or answer 409 while stale_puts_left holds.
    fn putReply(self: *Server, alloc: Allocator, req: client_mod.Request) !client_mod.Response {
        if (self.last_put_body) |old| self.alloc.free(old);
        self.last_put_body = try self.alloc.dupe(u8, req.body orelse "");
        self.puts += 1;
        if (self.stale_puts_left > 0) {
            self.stale_puts_left -= 1;
            return reply(alloc, 409, "{\"error\":{\"code\":\"stale_base\"}}");
        }

        var parsed = try std.json.parseFromSlice(
            std.json.Value,
            alloc,
            req.body orelse "{}",
            .{},
        );
        defer parsed.deinit();
        if (parsed.value != .object) return reply(alloc, 400, "{}");
        const obj = parsed.value.object;

        if (obj.get("entries")) |entries_v| {
            if (entries_v == .object) {
                var it = entries_v.object.iterator();
                while (it.next()) |kv| {
                    if (kv.value_ptr.* != .string) continue;
                    try self.putEntry(kv.key_ptr.*, kv.value_ptr.string);
                }
            }
        }
        var deleted_json: std.json.Array = .init(alloc);
        defer deleted_json.deinit();
        if (obj.get("deletions")) |del_v| {
            if (del_v == .array) {
                for (del_v.array.items) |item| {
                    if (item != .string) continue;
                    if (self.entries.fetchRemove(item.string)) |kv| {
                        self.alloc.free(@constCast(kv.key));
                        self.alloc.free(kv.value);
                    }
                    try deleted_json.append(item);
                }
            }
        }
        var out_map: std.json.ObjectMap = .empty;
        defer out_map.deinit(alloc);
        try out_map.put(alloc, "skipped", .{ .array = .init(alloc) });
        try out_map.put(alloc, "deleted", .{ .array = deleted_json });
        // jsonReply stringifies before out_map's deferred deinit runs, so
        // the moved ArrayList is still valid inside the call.
        var out: std.Io.Writer.Allocating = .init(alloc);
        errdefer out.deinit();
        try std.json.Stringify.value(
            @as(std.json.Value, .{ .object = out_map }),
            .{},
            &out.writer,
        );
        return .{ .status = 200, .body = try out.toOwnedSlice() };
    }
};

/// The encrypted manifest blob a server would hold, built the same way
/// Client.signManifest frames it. `entry_hashes` are key -> "sha256:..."
/// ciphertext-hash pairs. Returns the blob plus the canonical manifest
/// bytes so tests can pin the anti-rollback hash.
pub const SignedManifest = struct {
    blob: []u8,
    canonical: []u8,
};

pub fn signedManifestBlob(
    alloc: Allocator,
    enc_key: *const [crypto.key_len]u8,
    signer: *const identity.Ed25519.KeyPair,
    signer_did: []const u8,
    genesis_did: []const u8,
    seq: u64,
    entry_hashes: []const client_mod.Entry,
) !SignedManifest {
    var entries_obj: std.json.ObjectMap = .empty;
    defer entries_obj.deinit(alloc);
    for (entry_hashes) |e| {
        try entries_obj.put(alloc, e.key, .{ .string = e.plaintext });
    }
    var manifest: std.json.ObjectMap = .empty;
    defer manifest.deinit(alloc);
    try manifest.put(alloc, "seq", .{ .integer = @intCast(seq) });
    try manifest.put(alloc, "specVersion", .{ .string = client_mod.spec_version });
    try manifest.put(alloc, "genesisDid", .{ .string = genesis_did });
    try manifest.put(alloc, "entries", .{ .object = entries_obj });
    const canonical = try identity.canonicalJson(alloc, .{ .object = manifest });
    errdefer alloc.free(canonical);
    const sig = try identity.signMessage(alloc, signer, canonical);
    defer alloc.free(sig);

    var signed: std.json.ObjectMap = .empty;
    defer signed.deinit(alloc);
    try signed.put(alloc, "manifest", .{ .object = manifest });
    try signed.put(alloc, "did", .{ .string = signer_did });
    try signed.put(alloc, "sig", .{ .string = sig });
    const plaintext = try identity.canonicalJson(alloc, .{ .object = signed });
    defer alloc.free(plaintext);
    const blob = try crypto.encryptEntry(
        alloc,
        enc_key,
        client_mod.manifest_entry_key,
        plaintext,
    );
    return .{ .blob = blob, .canonical = canonical };
}

/// A Backend wrapper that fails the first `stale_writes_left` writes with
/// error.PassportStaleBase and the first `fail_reads_left` reads with
/// error.PassportUnavailable before delegating to `inner`. Lets a test
/// drive every bounded read->merge->write retry loop through the real
/// Store surface calls.
pub const FlakyBackend = struct {
    inner: store_redirect.Backend,
    stale_writes_left: u8 = 0,
    fail_reads_left: u8 = 0,
    write_calls: usize = 0,
    read_calls: usize = 0,

    pub fn backend(self: *FlakyBackend) store_redirect.Backend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: store_redirect.Backend.VTable = .{
        .read = readImpl,
        .write = writeImpl,
        .delete = deleteImpl,
        .list = listImpl,
        // No batch fns: the Store falls back to per-entry calls, which the
        // interceptors see.
    };

    fn readImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) store_redirect.BackendError!?[]u8 {
        const self: *FlakyBackend = @ptrCast(@alignCast(ptr));
        self.read_calls += 1;
        if (self.fail_reads_left > 0) {
            self.fail_reads_left -= 1;
            return error.PassportUnavailable;
        }
        return self.inner.read(alloc, key);
    }

    fn writeImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8, bytes: []const u8) store_redirect.BackendError!void {
        const self: *FlakyBackend = @ptrCast(@alignCast(ptr));
        self.write_calls += 1;
        if (self.stale_writes_left > 0) {
            self.stale_writes_left -= 1;
            return error.PassportStaleBase;
        }
        return self.inner.write(alloc, key, bytes);
    }

    fn deleteImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) store_redirect.BackendError!void {
        const self: *FlakyBackend = @ptrCast(@alignCast(ptr));
        return self.inner.delete(alloc, key);
    }

    fn listImpl(ptr: *anyopaque, alloc: Allocator, prefix: []const u8) store_redirect.BackendError![][]u8 {
        const self: *FlakyBackend = @ptrCast(@alignCast(ptr));
        return self.inner.list(alloc, prefix);
    }
};
