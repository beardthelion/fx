//! Session mirroring between the local session log directory and the
//! passport store. The local directory remains the canonical record:
//! commits mirror best-effort into passport entries, and a missing local
//! directory is hydrated from the mirror when a session is opened by id.
//!
//! Remote layout conforms to the sessions key grammar (PS-020/PS-022):
//! every entry under a session is `sessions/<id>/<seq>` with a
//! zero-padded six-digit sequence.
//!   sessions/<id>/000000      mirror manifest (index)
//!   sessions/<id>/<seq>       content chunks; each mirrored file occupies
//!                             the contiguous seq range its index record names
//!
//! Locks, intent files (*.pending.json), and the latest/ cache are never
//! mirrored: they are process-local or recomputable state, not session
//! content. The index makes torn mirrors detectable: hydration reads the
//! index first and ignores any remote key it does not name, so a crash
//! between the mirror write and the mirror cleanup can leave residue but
//! never a corrupted local session.

const std = @import("std");
const io_mod = @import("../shared/io.zig");
const identity = @import("identity.zig");
const client_mod = @import("client.zig");
const store_redirect = @import("store_redirect.zig");
const session_layout = @import("../session/session_layout.zig");

const Allocator = std.mem.Allocator;

/// Plaintext bytes per chunk entry. Keeps each ciphertext entry well
/// under the spec's 1 MiB per-entry cap (PS-081).
pub const event_chunk_bytes: usize = 512 * 1024;

const seq_width = 6;
const max_meta_file_bytes: usize = 8 * 1024 * 1024;
const max_events_bytes: usize = 512 * 1024 * 1024;
const max_index_bytes: usize = 256 * 1024;
const max_mirrored_files: usize = 64;
const events_file = "events.jsonl";

/// The index entry always sits at seq 0.
const index_seq: u64 = 0;

/// Session-dir members mirrored into the passport. Everything else under
/// the session directory stays local.
fn isMirroredFile(name: []const u8) bool {
    if (std.mem.eql(u8, name, events_file)) return true;
    for ([_][]const u8{
        "session.json",
        "checkpoint.json",
        "display.json",
        "authority.json",
        "usage-v2.json",
    }) |w| {
        if (std.mem.eql(u8, name, w)) return true;
    }
    // commit.<hex>.json records; the pending intent file is transient.
    return std.mem.startsWith(u8, name, "commit.") and
        std.mem.endsWith(u8, name, ".json") and
        !std.mem.eql(u8, name, "commit.pending.json");
}

fn sessionPrefix(alloc: Allocator, session_id: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(alloc, "sessions/{s}", .{session_id});
}

/// `sessions/<id>/<seq>` with seq zero-padded to six digits (PS-022).
fn chunkRel(alloc: Allocator, session_id: []const u8, seq: u64) Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        alloc,
        "sessions/{s}/{d:0>6}",
        .{ session_id, seq },
    );
}

fn chunksFor(bytes: u64) u64 {
    return (bytes + event_chunk_bytes - 1) / event_chunk_bytes;
}

/// A session id can only mirror when its longest possible entry key fits
/// the 255-byte cap. Keys are `sessions/<id>/<seq>`; our seqs never grow
/// past seven digits, so sixteen bytes of framing suffice.
fn sessionIdRemoteable(session_id: []const u8) bool {
    return session_id.len + 16 <= 255;
}

fn isChunkSeqText(seg: []const u8) bool {
    if (seg.len < seq_width) return false;
    for (seg) |ch| {
        if (!std.ascii.isDigit(ch)) return false;
    }
    return true;
}

/// One mirrored file's position in the chunk space.
const FileRecord = struct {
    name: []const u8,
    first: u64,
    chunks: u64,
    bytes: u64,
    sha256: []const u8,
};

const MirrorIndex = struct {
    files: []const FileRecord,
};

fn encodeIndex(alloc: Allocator, index: MirrorIndex) ![]u8 {
    var w: std.Io.Writer.Allocating = .init(alloc);
    errdefer w.deinit();
    try w.writer.writeAll("{\"v\":2,\"files\":[");
    for (index.files, 0..) |f, i| {
        if (i > 0) try w.writer.writeByte(',');
        try w.writer.print(
            "{{\"name\":\"{s}\",\"first\":{d},\"chunks\":{d},\"bytes\":{d},\"sha256\":\"{s}\"}}",
            .{ f.name, f.first, f.chunks, f.bytes, f.sha256 },
        );
    }
    try w.writer.writeAll("]}");
    return w.toOwnedSlice();
}

/// Parsed index contents. File names and sha256 strings are owned copies:
/// the parsed JSON tree is released before callers use them.
const ParsedIndex = struct {
    files: []ParsedFile,

    const ParsedFile = struct {
        name: []u8,
        first: u64,
        chunks: u64,
        bytes: u64,
        sha256: []u8,
    };

    fn deinit(self: *ParsedIndex, alloc: Allocator) void {
        for (self.files) |f| {
            alloc.free(f.name);
            alloc.free(f.sha256);
        }
        alloc.free(self.files);
    }
};

fn parseIndex(alloc: Allocator, bytes: []const u8) !ParsedIndex {
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, bytes, .{});
    defer parsed.deinit();
    const root = parsed.value;
    if (root != .object) return error.PassportMirrorCorrupt;
    const v = root.object.get("v") orelse return error.PassportMirrorCorrupt;
    if (v != .integer or v.integer != 2) return error.PassportMirrorCorrupt;

    const files_v = root.object.get("files") orelse return error.PassportMirrorCorrupt;
    if (files_v != .array) return error.PassportMirrorCorrupt;
    if (files_v.array.items.len > max_mirrored_files) return error.PassportMirrorCorrupt;

    var files: std.ArrayList(ParsedIndex.ParsedFile) = .empty;
    errdefer {
        for (files.items) |f| {
            alloc.free(f.name);
            alloc.free(f.sha256);
        }
        files.deinit(alloc);
    }
    for (files_v.array.items) |item| {
        if (item != .object) return error.PassportMirrorCorrupt;
        const name_v = item.object.get("name") orelse return error.PassportMirrorCorrupt;
        const first_v = item.object.get("first") orelse return error.PassportMirrorCorrupt;
        const chunks_v = item.object.get("chunks") orelse return error.PassportMirrorCorrupt;
        const bytes_v = item.object.get("bytes") orelse return error.PassportMirrorCorrupt;
        const sha_v = item.object.get("sha256") orelse return error.PassportMirrorCorrupt;
        if (name_v != .string or !isMirroredFile(name_v.string))
            return error.PassportMirrorCorrupt;
        if (first_v != .integer or first_v.integer <= 0)
            return error.PassportMirrorCorrupt;
        if (chunks_v != .integer or chunks_v.integer < 0)
            return error.PassportMirrorCorrupt;
        if (bytes_v != .integer or bytes_v.integer < 0)
            return error.PassportMirrorCorrupt;
        if (sha_v != .string or sha_v.string.len != 64)
            return error.PassportMirrorCorrupt;
        const name = name_v.string;
        const file_bytes: u64 = @intCast(bytes_v.integer);
        const cap: u64 = if (std.mem.eql(u8, name, events_file))
            max_events_bytes
        else
            max_meta_file_bytes;
        if (file_bytes > cap) return error.PassportMirrorCorrupt;
        const file_chunks: u64 = @intCast(chunks_v.integer);
        if (file_chunks != chunksFor(file_bytes)) return error.PassportMirrorCorrupt;
        const first: u64 = @intCast(first_v.integer);
        if (first + file_chunks < first) return error.PassportMirrorCorrupt;
        try files.append(alloc, .{
            .name = try alloc.dupe(u8, name),
            .first = first,
            .chunks = file_chunks,
            .bytes = file_bytes,
            .sha256 = try alloc.dupe(u8, sha_v.string),
        });
    }
    // Chunk ranges must not overlap or collide with the index entry.
    for (files.items, 0..) |a, i| {
        for (files.items[i + 1 ..]) |b| {
            const a_end = a.first + a.chunks;
            const b_end = b.first + b.chunks;
            if (a.first < b_end and b.first < a_end)
                return error.PassportMirrorCorrupt;
            if (std.mem.eql(u8, a.name, b.name))
                return error.PassportMirrorCorrupt;
        }
    }
    return .{ .files = try files.toOwnedSlice(alloc) };
}

fn readBounded(
    alloc: Allocator,
    dir: *const io_mod.VerifiedDir,
    name: []const u8,
    max_bytes: usize,
) !?[]u8 {
    var file = dir.dir.openFile(io_mod.getIo(), name, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io_mod.getIo());
    const stat = try file.stat(io_mod.getIo());
    if (stat.kind != .file or stat.size > max_bytes) return error.PassportMirrorCorrupt;
    return try io_mod.readFileToEnd(alloc, &file, max_bytes);
}

/// Push the current contents of a local session directory into the
/// passport store. Callers treat failures as advisory: the local commit
/// already landed, so a mirror failure must not fail the write path.
pub fn mirrorSession(
    alloc: Allocator,
    store: *store_redirect.Store,
    session_dir: *const io_mod.VerifiedDir,
    session_id: []const u8,
) !void {
    try session_layout.validateSessionId(session_id);
    if (!sessionIdRemoteable(session_id)) return error.PassportUnavailable;
    const zio = io_mod.getIo();

    var rel_paths: std.ArrayList([]const u8) = .empty;
    defer {
        for (rel_paths.items) |p| alloc.free(p);
        rel_paths.deinit(alloc);
    }
    var values: std.ArrayList([]u8) = .empty;
    defer {
        for (values.items) |v| alloc.free(v);
        values.deinit(alloc);
    }

    // Gather the mirrored members, sorted by name so seq assignment is
    // deterministic. events.jsonl always participates, even when empty,
    // so hydration restores a complete session shape.
    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |n| alloc.free(n);
        names.deinit(alloc);
    }
    var it = session_dir.dir.iterate();
    while (it.next(zio) catch return error.PassportUnavailable) |entry| {
        if (entry.kind != .file) continue;
        const name = entry.name;
        if (!isMirroredFile(name)) continue;
        if (std.mem.eql(u8, name, events_file)) continue;
        try names.append(alloc, try alloc.dupe(u8, name));
    }
    try names.append(alloc, try alloc.dupe(u8, events_file));
    std.mem.sort([]u8, names.items, {}, struct {
        fn lessThan(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.lessThan);
    if (names.items.len > max_mirrored_files) return error.PassportMirrorCorrupt;

    var records: std.ArrayList(FileRecord) = .empty;
    defer {
        for (records.items) |r| alloc.free(@constCast(r.sha256));
        records.deinit(alloc);
    }
    var next_seq: u64 = 1;
    for (names.items) |name| {
        const cap: usize = if (std.mem.eql(u8, name, events_file))
            max_events_bytes
        else
            max_meta_file_bytes;
        const bytes = (try readBounded(alloc, session_dir, name, cap)) orelse
            try alloc.dupe(u8, "");
        defer alloc.free(bytes);
        const digest = try identity.sha256Hex(alloc, bytes);
        defer alloc.free(digest);
        const n_chunks = chunksFor(bytes.len);
        const sha_copy = try alloc.dupe(u8, digest);
        errdefer alloc.free(sha_copy);
        try records.append(alloc, .{
            .name = name,
            .first = next_seq,
            .chunks = n_chunks,
            .bytes = bytes.len,
            .sha256 = sha_copy,
        });
        var seq: u64 = 0;
        while (seq < n_chunks) : (seq += 1) {
            const start: usize = @intCast(seq * event_chunk_bytes);
            const end = @min(start + event_chunk_bytes, bytes.len);
            try rel_paths.append(alloc, try chunkRel(alloc, session_id, next_seq + seq));
            try values.append(alloc, try alloc.dupe(u8, bytes[start..end]));
        }
        next_seq += n_chunks;
    }

    const index_json = try encodeIndex(alloc, .{ .files = records.items });
    try rel_paths.append(alloc, try chunkRel(alloc, session_id, index_seq));
    try values.append(alloc, index_json);

    // Stale remote keys: chunk seqs outside the set this mirror writes.
    // Keys that do not match the chunk grammar are left alone: they were
    // not written by this mirror and may belong to another writer.
    const prefix = try sessionPrefix(alloc, session_id);
    defer alloc.free(prefix);
    const remote_keys = try store.listSurface(alloc, prefix);
    defer {
        for (remote_keys) |k| alloc.free(k);
        alloc.free(remote_keys);
    }
    const key_prefix = try std.fmt.allocPrint(alloc, "{s}/", .{prefix});
    defer alloc.free(key_prefix);

    var deletions: std.ArrayList([]u8) = .empty;
    defer deletions.deinit(alloc);
    for (remote_keys) |key| {
        if (!std.mem.startsWith(u8, key, key_prefix)) continue;
        const seg = key[key_prefix.len..];
        if (!isChunkSeqText(seg)) continue;
        const remote_seq = std.fmt.parseUnsigned(u64, seg, 10) catch continue;
        var expected = remote_seq == index_seq;
        if (!expected) {
            for (records.items) |r| {
                if (remote_seq >= r.first and remote_seq < r.first + r.chunks) {
                    expected = true;
                    break;
                }
            }
        }
        if (!expected) try deletions.append(alloc, key);
    }

    try store.writeSurfaces(alloc, rel_paths.items, values.items);
    if (deletions.items.len > 0) {
        try store.deleteSurfaces(alloc, deletions.items);
    }
}

/// Materialize a passport-mirrored session into the local sessions
/// directory. Returns false when no mirror exists. Any mirror that
/// parses but fails its own integrity statement is an error, never a
/// silent partial restore.
pub fn hydrateSession(
    alloc: Allocator,
    store: *store_redirect.Store,
    sessions_dir: *io_mod.VerifiedDir,
    session_id: []const u8,
) !bool {
    try session_layout.validateSessionId(session_id);
    if (!sessionIdRemoteable(session_id)) return false;

    const index_rel = try chunkRel(alloc, session_id, index_seq);
    defer alloc.free(index_rel);
    const index_bytes = (try store.readSurface(alloc, index_rel)) orelse return false;
    defer alloc.free(index_bytes);
    if (index_bytes.len > max_index_bytes) return error.PassportMirrorCorrupt;
    var index = try parseIndex(alloc, index_bytes);
    defer index.deinit(alloc);

    // Fetch every chunk before touching the filesystem so a torn mirror
    // cannot leave a half-materialized directory.
    const FileContent = struct {
        name: []u8,
        bytes: []u8,
    };
    var contents: std.ArrayList(FileContent) = .empty;
    defer {
        for (contents.items) |c| alloc.free(c.bytes);
        contents.deinit(alloc);
    }
    for (index.files) |f| {
        const buf = try alloc.alloc(u8, @intCast(f.bytes));
        errdefer alloc.free(buf);
        var written: usize = 0;
        var seq: u64 = 0;
        while (seq < f.chunks) : (seq += 1) {
            const rel = try chunkRel(alloc, session_id, f.first + seq);
            defer alloc.free(rel);
            const chunk = (try store.readSurface(alloc, rel)) orelse
                return error.PassportMirrorCorrupt;
            defer alloc.free(chunk);
            if (written + chunk.len > buf.len) return error.PassportMirrorCorrupt;
            @memcpy(buf[written .. written + chunk.len], chunk);
            written += chunk.len;
        }
        if (written != buf.len) return error.PassportMirrorCorrupt;
        const digest = try identity.sha256Hex(alloc, buf);
        defer alloc.free(digest);
        if (!std.mem.eql(u8, digest, f.sha256)) return error.PassportMirrorCorrupt;
        try contents.append(alloc, .{ .name = f.name, .bytes = buf });
    }

    var dir = try io_mod.openOrCreateVerifiedPrivateDir(sessions_dir, session_id);
    errdefer {
        dir.close();
        sessions_dir.dir.deleteTree(io_mod.getIo(), session_id) catch {};
    }
    for (contents.items) |c| {
        try io_mod.durableReplaceVerified(alloc, &dir, c.name, c.bytes);
    }
    dir.close();
    return true;
}

/// Delete every passport entry under `sessions/<id>/`. Absent is fine.
pub fn deleteSession(
    alloc: Allocator,
    store: *store_redirect.Store,
    session_id: []const u8,
) !void {
    try session_layout.validateSessionId(session_id);
    const prefix = try sessionPrefix(alloc, session_id);
    defer alloc.free(prefix);
    const keys = try store.listSurface(alloc, prefix);
    defer {
        for (keys) |k| alloc.free(k);
        alloc.free(keys);
    }
    if (keys.len == 0) return;
    try store.deleteSurfaces(alloc, keys);
}

// ─── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

fn testBackend() type {
    return struct {
        entries: std.StringHashMapUnmanaged([]u8) = .empty,

        fn deinit(self: *@This(), alloc: Allocator) void {
            var it = self.entries.iterator();
            while (it.next()) |kv| {
                alloc.free(@constCast(kv.key_ptr.*));
                alloc.free(kv.value_ptr.*);
            }
            self.entries.deinit(alloc);
        }

        fn backend(self: *@This()) store_redirect.Backend {
            return .{ .ptr = self, .vtable = &vtable };
        }

        const vtable: store_redirect.Backend.VTable = .{
            .read = readImpl,
            .write = writeImpl,
            .delete = deleteImpl,
            .list = listImpl,
        };

        fn readImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) store_redirect.BackendError!?[]u8 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const value = self.entries.get(key) orelse return null;
            return try alloc.dupe(u8, value);
        }

        fn writeImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8, bytes: []const u8) store_redirect.BackendError!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.entries.fetchRemove(key)) |kv| {
                alloc.free(@constCast(kv.key));
                alloc.free(kv.value);
            }
            try self.entries.put(alloc, try alloc.dupe(u8, key), try alloc.dupe(u8, bytes));
        }

        fn deleteImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) store_redirect.BackendError!void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.entries.fetchRemove(key)) |kv| {
                alloc.free(@constCast(kv.key));
                alloc.free(kv.value);
            }
        }

        fn listImpl(ptr: *anyopaque, alloc: Allocator, prefix: []const u8) store_redirect.BackendError![][]u8 {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            var out: std.ArrayList([]u8) = .empty;
            errdefer {
                for (out.items) |s| alloc.free(s);
                out.deinit(alloc);
            }
            var it = self.entries.iterator();
            while (it.next()) |kv| {
                if (std.mem.startsWith(u8, kv.key_ptr.*, prefix)) {
                    try out.append(alloc, try alloc.dupe(u8, kv.key_ptr.*));
                }
            }
            return out.toOwnedSlice(alloc);
        }
    };
}

test "mirror then hydrate reproduces the session directory" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    var mock = testBackend(){};
    defer mock.deinit(alloc);
    var store = try store_redirect.Store.init(alloc, home, mock.backend());
    defer store.deinit();

    // A local sessions/<id> directory with the mirrored file set. The
    // tmpDir handle is O_PATH and cannot fsync; reopen with iteration.
    var home_vd = io_mod.VerifiedDir{ .dir = try tmp.dir.openDir(
        std.testing.io,
        ".",
        .{ .iterate = true, .follow_symlinks = false },
    ) };
    defer home_vd.close();
    var sessions_vd = try io_mod.openOrCreateVerifiedPrivateDir(&home_vd, "sessions");
    defer sessions_vd.close();
    var session_vd = try io_mod.openOrCreateVerifiedPrivateDir(&sessions_vd, "sess001");
    defer session_vd.close();
    try io_mod.durableReplaceVerified(alloc, &session_vd, "session.json", "{\"id\":\"sess001\"}\n");
    try io_mod.durableReplaceVerified(alloc, &session_vd, "events.jsonl", "{\"e\":1}\n{\"e\":2}\n");
    try io_mod.durableReplaceVerified(alloc, &session_vd, "authority.json", "{\"a\":1}\n");
    // Non-mirrored members: locks and intent files stay out.
    try io_mod.durableReplaceVerified(alloc, &session_vd, "session.lock", "");
    try io_mod.durableReplaceVerified(alloc, &session_vd, "commit.pending.json", "{}");

    try mirrorSession(alloc, &store, &session_vd, "sess001");

    // Every remote key conforms to sessions/<id>/<seq> (PS-022).
    try testing.expect(mock.entries.get("sessions/sess001/000000") != null);
    try testing.expect(mock.entries.get("sessions/sess001/000001") != null);
    try testing.expect(mock.entries.get("sessions/sess001/000002") != null);
    try testing.expect(mock.entries.get("sessions/sess001/000003") != null);
    try testing.expect(mock.entries.get("sessions/sess001/000004") == null);
    var kit = mock.entries.iterator();
    while (kit.next()) |kv| {
        try testing.expect(client_mod.isValidEntryKey(kv.key_ptr.*));
    }

    // Hydrate into a fresh sessions root.
    var tmp2 = testing.tmpDir(.{});
    defer tmp2.cleanup();
    var home2_vd = io_mod.VerifiedDir{ .dir = try tmp2.dir.openDir(
        std.testing.io,
        ".",
        .{ .iterate = true, .follow_symlinks = false },
    ) };
    defer home2_vd.close();
    var sessions2_vd = try io_mod.openOrCreateVerifiedPrivateDir(&home2_vd, "sessions");
    defer sessions2_vd.close();

    try testing.expect(try hydrateSession(alloc, &store, &sessions2_vd, "sess001"));
    var restored = try io_mod.openOrCreateVerifiedPrivateDir(&sessions2_vd, "sess001");
    defer restored.close();
    const events = (try readBounded(alloc, &restored, "events.jsonl", max_events_bytes)).?;
    defer alloc.free(events);
    try testing.expectEqualStrings("{\"e\":1}\n{\"e\":2}\n", events);
    const meta = (try readBounded(alloc, &restored, "session.json", max_meta_file_bytes)).?;
    defer alloc.free(meta);
    try testing.expectEqualStrings("{\"id\":\"sess001\"}\n", meta);
}

test "hydrate returns false when no mirror exists" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    var mock = testBackend(){};
    defer mock.deinit(alloc);
    var store = try store_redirect.Store.init(alloc, home, mock.backend());
    defer store.deinit();

    var home_vd = io_mod.VerifiedDir{ .dir = try tmp.dir.openDir(
        std.testing.io,
        ".",
        .{ .iterate = true, .follow_symlinks = false },
    ) };
    defer home_vd.close();
    var sessions_vd = try io_mod.openOrCreateVerifiedPrivateDir(&home_vd, "sessions");
    defer sessions_vd.close();
    try testing.expect(!(try hydrateSession(alloc, &store, &sessions_vd, "missing01")));
}

test "hydrate rejects a torn mirror" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    var mock = testBackend(){};
    defer mock.deinit(alloc);
    var store = try store_redirect.Store.init(alloc, home, mock.backend());
    defer store.deinit();

    // The index names two chunks for a file; only one exists.
    const digest = try identity.sha256Hex(alloc, "abcabc");
    defer alloc.free(digest);
    const index = try std.fmt.allocPrint(
        alloc,
        "{{\"v\":2,\"files\":[{{\"name\":\"session.json\",\"first\":1,\"chunks\":2,\"bytes\":6,\"sha256\":\"{s}\"}}]}}",
        .{digest},
    );
    defer alloc.free(index);
    try mock.entries.put(alloc, try alloc.dupe(u8, "sessions/s1/000000"), try alloc.dupe(u8, index));
    try mock.entries.put(alloc, try alloc.dupe(u8, "sessions/s1/000001"), try alloc.dupe(u8, "abc"));

    var home_vd = io_mod.VerifiedDir{ .dir = try tmp.dir.openDir(
        std.testing.io,
        ".",
        .{ .iterate = true, .follow_symlinks = false },
    ) };
    defer home_vd.close();
    var sessions_vd = try io_mod.openOrCreateVerifiedPrivateDir(&home_vd, "sessions");
    defer sessions_vd.close();
    try testing.expectError(
        error.PassportMirrorCorrupt,
        hydrateSession(alloc, &store, &sessions_vd, "s1"),
    );
}

test "deleteSession removes every mirrored key" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    var mock = testBackend(){};
    defer mock.deinit(alloc);
    var store = try store_redirect.Store.init(alloc, home, mock.backend());
    defer store.deinit();

    try mock.entries.put(alloc, try alloc.dupe(u8, "sessions/d1/000000"), try alloc.dupe(u8, "{}"));
    try mock.entries.put(alloc, try alloc.dupe(u8, "sessions/d1/000001"), try alloc.dupe(u8, "x"));
    try mock.entries.put(alloc, try alloc.dupe(u8, "sessions/other/000000"), try alloc.dupe(u8, "{}"));

    try deleteSession(alloc, &store, "d1");
    try testing.expect(mock.entries.get("sessions/d1/000000") == null);
    try testing.expect(mock.entries.get("sessions/d1/000001") == null);
    try testing.expect(mock.entries.get("sessions/other/000000") != null);
}
