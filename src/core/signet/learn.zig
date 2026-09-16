//! Session-end learning capture for the signet backend (spec SN-120;
//! suite plan KTD8 / unit U7).
//!
//! The authoritative distillation lives in the signet-suite TypeScript
//! layer (src/learn/). This file is the fx trigger: when a writable
//! session ends, the learning candidates recorded in the session's
//! `learnings.jsonl` sidecar are rendered as `memory/<type>/<slug>.md`
//! entries and written through the Store seam. One JSON object per line:
//!
//!   {"type":"user|feedback|project|reference",
//!    "slug":"kebab-case",      // optional; derived from title when absent
//!    "title":"one-line summary",
//!    "body":"the learning"}
//!
//! The sidecar is harness-owned scratch state: absent or empty means the
//! session produced nothing worth learning and nothing is written.
//!
//! Entries carry `type:` and `provenance: learned:fx` frontmatter (SN-120)
//! and deliberately no timestamps or session ids: identical learned
//! content must render byte-identical plaintext so deterministic
//! encryption (SN-033) produces the same ciphertext hash and the manifest
//! dedupes a re-learned fact instead of duplicating it. The backend's own
//! SN-110 secret scan applies on write, identical to every other
//! redirected surface.

const std = @import("std");
const io_mod = @import("../shared/io.zig");
const client_mod = @import("client.zig");
const identity_mod = @import("identity.zig");
const store_redirect = @import("store_redirect.zig");

const Allocator = std.mem.Allocator;

const learnings_file = "learnings.jsonl";
const provenance = "learned:fx";

pub const max_learnings_bytes: usize = 256 * 1024;
const max_learnings: usize = 64;
const max_title_bytes: usize = 512;
const max_body_bytes: usize = 64 * 1024;
const max_slug_words: usize = 8;
const max_slug_bytes: usize = 48;

const learning_types = [_][]const u8{ "user", "feedback", "project", "reference" };

/// One candidate learning, pre-render. Field slices are borrowed.
pub const Learning = struct {
    type: []const u8,
    slug: []const u8 = "",
    title: []const u8,
    body: []const u8,
};

const Rendered = struct {
    key: []u8,
    content: []u8,

    fn deinit(self: *Rendered, alloc: Allocator) void {
        alloc.free(self.key);
        alloc.free(self.content);
    }
};

pub fn isLearningType(t: []const u8) bool {
    for (learning_types) |w| {
        if (std.mem.eql(u8, t, w)) return true;
    }
    return false;
}

/// Lowercase alnum words hyphen-joined, matching the suite's slugify.
/// Caller owns the result.
fn slugify(alloc: Allocator, title: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    var word_start: ?usize = null;
    var words: usize = 0;
    for (title, 0..) |raw, i| {
        if (std.ascii.isAlphanumeric(raw)) {
            if (word_start == null) word_start = i;
            continue;
        }
        const start = word_start orelse continue;
        if (words > 0) try out.append(alloc, '-');
        for (title[start..i]) |c| try out.append(alloc, std.ascii.toLower(c));
        words += 1;
        word_start = null;
        if (words >= max_slug_words or out.items.len >= max_slug_bytes) break;
    }
    if (word_start) |start| {
        if (words < max_slug_words and out.items.len < max_slug_bytes) {
            if (words > 0) try out.append(alloc, '-');
            for (title[start..]) |c| try out.append(alloc, std.ascii.toLower(c));
        }
    }
    while (out.items.len > max_slug_bytes) _ = out.pop();
    while (out.items.len > 0 and out.items[out.items.len - 1] == '-') _ = out.pop();
    return out.toOwnedSlice(alloc);
}

/// Collapse all whitespace runs (including newlines) to single spaces so a
/// title stays one YAML-safe line. Caller owns the result.
fn flattenWhitespace(alloc: Allocator, text: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    var pending_space = false;
    for (text) |ch| {
        if (std.ascii.isWhitespace(ch)) {
            if (out.items.len > 0) pending_space = true;
            continue;
        }
        if (pending_space) try out.append(alloc, ' ');
        pending_space = false;
        try out.append(alloc, ch);
    }
    return out.toOwnedSlice(alloc);
}

fn hex8(alloc: Allocator, bytes: []const u8) Allocator.Error![]u8 {
    const hex = try identity_mod.sha256Hex(alloc, bytes);
    defer alloc.free(hex);
    return alloc.dupe(u8, hex[0..8]);
}

/// Render a learning to its `memory/<type>/<slug>.md` key plus full entry
/// content, or null when the candidate is malformed. Caller owns the
/// result (Rendered.deinit).
fn render(alloc: Allocator, learning: Learning) Allocator.Error!?Rendered {
    if (!isLearningType(learning.type)) return null;
    if (learning.title.len == 0 or learning.title.len > max_title_bytes) return null;
    const body = std.mem.trim(u8, learning.body, " \t\r\n");
    if (body.len == 0 or body.len > max_body_bytes) return null;

    const slug = if (learning.slug.len > 0)
        try alloc.dupe(u8, learning.slug)
    else
        try slugify(alloc, learning.title);
    defer alloc.free(slug);

    const key = try std.fmt.allocPrint(alloc, "memory/{s}/{s}.md", .{ learning.type, slug });
    errdefer alloc.free(key);
    if (!client_mod.isValidEntryKey(key)) return null;

    const description = try flattenWhitespace(alloc, learning.title);
    defer alloc.free(description);

    const content = try std.fmt.allocPrint(
        alloc,
        "---\ntype: {s}\nprovenance: {s}\ndescription: {s}\n---\n\n{s}\n",
        .{ learning.type, provenance, description, body },
    );
    errdefer alloc.free(content);
    return .{ .key = key, .content = content };
}

pub fn readLearningsFile(
    alloc: Allocator,
    session_dir: *const io_mod.VerifiedDir,
) !?[]u8 {
    var file = session_dir.dir.openFile(io_mod.getIo(), learnings_file, .{
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
    if (stat.kind != .file or stat.size > max_learnings_bytes) {
        return error.SignetLearnCorrupt;
    }
    return try io_mod.readFileToEnd(alloc, &file, max_learnings_bytes);
}

/// Parse one learnings.jsonl line and render it. Returns null for anything
/// malformed — a bad line must not sink the rest of the session's
/// learnings. Caller owns the result (Rendered.deinit).
fn parseLine(alloc: Allocator, line: []const u8) Allocator.Error!?Rendered {
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, line, .{}) catch return null;
    defer parsed.deinit();
    const obj = parsed.value;
    if (obj != .object) return null;

    const type_v = obj.object.get("type") orelse return null;
    const title_v = obj.object.get("title") orelse return null;
    const body_v = obj.object.get("body") orelse return null;
    if (type_v != .string or title_v != .string or body_v != .string) return null;
    const slug: []const u8 = if (obj.object.get("slug")) |v|
        if (v == .string) v.string else ""
    else
        "";

    // The field slices borrow the parse tree; render() allocates its own
    // output before the tree is released.
    return try render(alloc, .{
        .type = type_v.string,
        .slug = slug,
        .title = title_v.string,
        .body = body_v.string,
    });
}

/// Write one learning immediately — the explicit-save trigger. Returns
/// false when the signet backend is disabled or the candidate is
/// malformed; both are clean no-ops, never partial writes.
pub fn saveLearning(
    alloc: Allocator,
    store: *store_redirect.Store,
    learning: Learning,
) !bool {
    if (!store.signetEnabled()) return false;
    var rendered = (try render(alloc, learning)) orelse return false;
    defer rendered.deinit(alloc);
    try store.writeSurface(alloc, rendered.key, rendered.content);
    return true;
}

/// The session-end trigger: read the session's learnings sidecar and land
/// every well-formed candidate under memory/. No-op when the backend is
/// disabled, the sidecar is absent, or nothing in it parses — a session
/// with nothing worth learning writes nothing.
pub fn captureSessionEnd(
    alloc: Allocator,
    store: *store_redirect.Store,
    session_dir: *const io_mod.VerifiedDir,
) !void {
    if (!store.signetEnabled()) return;
    const bytes = (try readLearningsFile(alloc, session_dir)) orelse return;
    defer alloc.free(bytes);

    // One manifest fetch+verify covers every per-line collision check
    // below; without it each candidate would re-fetch the manifest. A
    // list failure propagates: checking collisions against an empty set
    // we did not actually fetch would silently overwrite distinct
    // learnings that share a slug.
    var existing: std.StringHashMapUnmanaged(void) = .empty;
    defer existing.deinit(alloc);
    // `listed` must outlive `existing`: the map borrows its key slices.
    const listed = try store.listSurface(alloc, "memory/");
    defer {
        for (listed) |k| alloc.free(k);
        alloc.free(listed);
    }
    for (listed) |k| try existing.put(alloc, k, {});

    var keys: std.ArrayList([]u8) = .empty;
    defer {
        for (keys.items) |k| alloc.free(k);
        keys.deinit(alloc);
    }
    var values: std.ArrayList([]u8) = .empty;
    defer {
        for (values.items) |v| alloc.free(v);
        values.deinit(alloc);
    }
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(alloc);

    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw_line| {
        if (keys.items.len >= max_learnings) break;
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        var rendered = (try parseLine(alloc, line)) orelse continue;
        if (seen.contains(rendered.key)) {
            rendered.deinit(alloc);
            continue;
        }
        // Same slug, different content: disambiguate with a content hash
        // suffix so neither learning is lost.
        const with_suffix = collides(alloc, store, rendered, &existing) catch |err| {
            rendered.deinit(alloc);
            return err;
        };
        if (with_suffix) |ws| {
            rendered.deinit(alloc);
            rendered = ws;
        }
        // keys/values own the rendered buffers; seen borrows key slices
        // that outlive it (its deinit runs first).
        try keys.append(alloc, rendered.key);
        try values.append(alloc, rendered.content);
        try seen.put(alloc, rendered.key, {});
    }

    if (keys.items.len == 0) return;
    try store.writeSurfaces(alloc, keys.items, values.items);
}

/// If a remote entry already exists at `rendered.key` with different
/// content, re-render under a hash-suffixed slug. Returns null when there
/// is no collision or the existing entry holds the same bytes. `existing`
/// is the memory/ key set fetched once by the caller. A read failure
/// propagates: an unverifiable collision must not silently overwrite the
/// entry already at the slug.
fn collides(
    alloc: Allocator,
    store: *store_redirect.Store,
    rendered: Rendered,
    existing: *const std.StringHashMapUnmanaged(void),
) !?Rendered {
    if (!existing.contains(rendered.key)) return null;
    const prior = (try store.readSurface(alloc, rendered.key)) orelse return null;
    defer alloc.free(prior);
    if (std.mem.eql(u8, prior, rendered.content)) return null;
    const suffix = try hex8(alloc, rendered.content);
    defer alloc.free(suffix);
    const stem = rendered.key[0 .. rendered.key.len - ".md".len];
    const key = try std.fmt.allocPrint(alloc, "{s}-{s}.md", .{ stem, suffix });
    errdefer alloc.free(key);
    if (!client_mod.isValidEntryKey(key)) {
        alloc.free(key);
        return null;
    }
    return .{ .key = key, .content = try alloc.dupe(u8, rendered.content) };
}

// ─── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

const MockBackend = store_redirect.MockBackend;
const test_server = @import("test_server.zig");

fn sessionDir(alloc: Allocator, tmp: *testing.TmpDir) !io_mod.VerifiedDir {
    _ = alloc;
    var home_vd = io_mod.VerifiedDir{ .dir = try tmp.dir.openDir(
        testing.io,
        ".",
        .{ .iterate = true, .follow_symlinks = false },
    ) };
    defer home_vd.close();
    var sessions_vd = try io_mod.openOrCreateVerifiedPrivateDir(&home_vd, "sessions");
    defer sessions_vd.close();
    return io_mod.openOrCreateVerifiedPrivateDir(&sessions_vd, "sess001");
}

test "session-end capture writes typed memory entries through the store seam" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    var mock = MockBackend{};
    defer mock.deinit(alloc);
    var store = try store_redirect.Store.init(alloc, home, mock.backend());
    defer store.deinit();

    var session_vd = try sessionDir(alloc, &tmp);
    defer session_vd.close();
    try io_mod.durableReplaceVerified(alloc, &session_vd, learnings_file,
        \\{"type":"user","slug":"prefers-pnpm","title":"I prefer pnpm over npm.","body":"I prefer pnpm over npm for all package management."}
        \\{"type":"project","title":"We decided to store agent state in the signet.","body":"We decided to store agent state in the signet, not in vendor clouds."}
        \\{"type":"bogus","title":"not a type","body":"rejected"}
        \\not json at all
        \\
    );

    try captureSessionEnd(alloc, &store, &session_vd);

    const pref = mock.entries.get("memory/user/prefers-pnpm.md").?;
    try testing.expect(std.mem.find(u8, pref, "type: user") != null);
    try testing.expect(std.mem.find(u8, pref, "provenance: learned:fx") != null);
    try testing.expect(std.mem.find(u8, pref, "pnpm") != null);

    const decided = mock.entries.get("memory/project/we-decided-to-store-agent-state-in-the.md").?;
    try testing.expect(std.mem.find(u8, decided, "type: project") != null);

    // Malformed and mistyped lines never land.
    var it = mock.entries.iterator();
    var count: usize = 0;
    while (it.next()) |kv| {
        try testing.expect(client_mod.isValidEntryKey(kv.key_ptr.*));
        count += 1;
    }
    try testing.expectEqual(@as(usize, 2), count);
}

test "capture is a no-op when the signet backend is disabled" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    var store = try store_redirect.Store.init(alloc, home, null);
    defer store.deinit();
    try testing.expect(!store.signetEnabled());

    var session_vd = try sessionDir(alloc, &tmp);
    defer session_vd.close();
    try io_mod.durableReplaceVerified(alloc, &session_vd, learnings_file,
        \\{"type":"user","slug":"prefers-pnpm","title":"I prefer pnpm.","body":"I prefer pnpm."}
        \\
    );

    try captureSessionEnd(alloc, &store, &session_vd);

    // Nothing landed anywhere: no remote write, and no local ~/.fx/memory.
    const memory_dir = try std.fs.path.join(alloc, &.{ home, ".fx", "memory" });
    defer alloc.free(memory_dir);
    try testing.expectError(
        error.FileNotFound,
        std.Io.Dir.openDirAbsolute(testing.io, memory_dir, .{}),
    );
}

test "absent or empty sidecar writes nothing" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    var mock = MockBackend{};
    defer mock.deinit(alloc);
    var store = try store_redirect.Store.init(alloc, home, mock.backend());
    defer store.deinit();

    var session_vd = try sessionDir(alloc, &tmp);
    defer session_vd.close();

    // No sidecar at all.
    try captureSessionEnd(alloc, &store, &session_vd);
    try testing.expectEqual(@as(usize, 0), mock.entries.count());

    // An empty sidecar.
    try io_mod.durableReplaceVerified(alloc, &session_vd, learnings_file, "\n\n");
    try captureSessionEnd(alloc, &store, &session_vd);
    try testing.expectEqual(@as(usize, 0), mock.entries.count());
}

test "collides propagates a read failure instead of overwriting the entry" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    // A remote entry already holds the slug the learning renders to, with
    // different content: capture must read it back to disambiguate.
    var mock = MockBackend{};
    defer mock.deinit(alloc);
    {
        const k = try alloc.dupe(u8, "memory/user/prefers-pnpm.md");
        errdefer alloc.free(k);
        const v = try alloc.dupe(u8, "prior contents");
        try mock.entries.put(alloc, k, v);
    }
    var flaky = test_server.FlakyBackend{
        .inner = mock.backend(),
        .fail_reads_left = 1,
    };
    var store = try store_redirect.Store.init(alloc, home, flaky.backend());
    defer store.deinit();

    var session_vd = try sessionDir(alloc, &tmp);
    defer session_vd.close();
    try io_mod.durableReplaceVerified(alloc, &session_vd, learnings_file,
        \\{"type":"user","slug":"prefers-pnpm","title":"I prefer pnpm.","body":"I prefer pnpm."}
        \\
    );

    try testing.expectError(
        error.SignetUnavailable,
        captureSessionEnd(alloc, &store, &session_vd),
    );
    // The prior entry is untouched.
    try testing.expectEqualStrings(
        "prior contents",
        mock.entries.get("memory/user/prefers-pnpm.md").?,
    );
}

test "explicit saveLearning lands one entry and no-ops when disabled" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    var mock = MockBackend{};
    defer mock.deinit(alloc);
    var store = try store_redirect.Store.init(alloc, home, mock.backend());
    defer store.deinit();

    try testing.expect(try saveLearning(alloc, &store, .{
        .type = "feedback",
        .title = "The root cause was a stale manifest seq.",
        .body = "Fixed by re-reading the manifest before push.",
    }));
    const entry = mock.entries.get("memory/feedback/the-root-cause-was-a-stale-manifest-seq.md").?;
    try testing.expect(std.mem.find(u8, entry, "type: feedback") != null);
    try testing.expect(std.mem.find(u8, entry, "provenance: learned:fx") != null);

    // An invalid type is refused, not written under a wrong path.
    try testing.expect(!(try saveLearning(alloc, &store, .{
        .type = "evil",
        .title = "x",
        .body = "y",
    })));

    var disabled = try store_redirect.Store.init(alloc, home, null);
    defer disabled.deinit();
    try testing.expect(!(try saveLearning(alloc, &disabled, .{
        .type = "user",
        .title = "x",
        .body = "y",
    })));
}
