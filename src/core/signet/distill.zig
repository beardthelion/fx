//! Session-end learning emission for the signet backend (spec SN-120;
//! suite plan KTD8 / unit U7).
//!
//! Ports the suite's deterministic distiller (src/learn/distill.ts) so a
//! finished session can emit learning candidates without a model call.
//! Candidates are appended to the session's learnings.jsonl sidecar;
//! learn.captureSessionEnd still owns rendering, collision handling, the
//! SN-110 secret scan, and the durable write. Emission stays scratch
//! state: a session with nothing worth learning writes nothing.

const std = @import("std");
const io_mod = @import("../shared/io.zig");
const types = @import("../shared/types.zig");
const learn = @import("learn.zig");

const Allocator = std.mem.Allocator;

const learnings_file = "learnings.jsonl";

const min_candidate_chars = 24;
const max_candidate_chars = 2000;
const max_title_chars = 100;
const max_emit_learnings = 16;

fn isWordChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

/// Regex `\b` semantics: a word/non-word transition at position i.
fn boundaryAt(text: []const u8, i: usize) bool {
    const before = i > 0 and isWordChar(text[i - 1]);
    const after = i < text.len and isWordChar(text[i]);
    return before != after;
}

/// `\bphrase\b` over whitespace-normalized lowercase text.
fn hasPhrase(text: []const u8, phrase: []const u8) bool {
    var from: usize = 0;
    while (std.mem.findPos(u8, text, from, phrase)) |pos| {
        if (boundaryAt(text, pos) and boundaryAt(text, pos + phrase.len)) return true;
        from = pos + 1;
    }
    return false;
}

/// `\bfirst\s+second\b`: on normalized text `\s+` is a single space.
fn hasPhraseSeq(
    text: []const u8,
    firsts: []const []const u8,
    seconds: []const []const u8,
) bool {
    for (firsts) |first| {
        var from: usize = 0;
        while (std.mem.findPos(u8, text, from, first)) |pos| {
            defer from = pos + 1;
            if (!boundaryAt(text, pos)) continue;
            const mid = pos + first.len;
            if (mid >= text.len or text[mid] != ' ') continue;
            const start = mid + 1;
            for (seconds) |second| {
                if (start + second.len > text.len) continue;
                if (!std.mem.eql(u8, text[start .. start + second.len], second)) continue;
                if (boundaryAt(text, start + second.len)) return true;
            }
        }
    }
    return false;
}

/// `\bprefix\w+\b`: a word starting with the given prefix.
fn hasWordPrefix(text: []const u8, prefix: []const u8) bool {
    var from: usize = 0;
    while (std.mem.findPos(u8, text, from, prefix)) |pos| {
        defer from = pos + 1;
        if (!boundaryAt(text, pos)) continue;
        const end = pos + prefix.len;
        if (end < text.len and isWordChar(text[end])) return true;
    }
    return false;
}

/// `\bneedle` with no trailing boundary requirement (URL prefixes).
fn hasBoundedStart(text: []const u8, needle: []const u8) bool {
    var from: usize = 0;
    while (std.mem.findPos(u8, text, from, needle)) |pos| {
        if (boundaryAt(text, pos)) return true;
        from = pos + 1;
    }
    return false;
}

const ref_words = [_][]const u8{
    "doc",    "docs",  "documentation", "runbook", "spec",
    "ticket", "issue", "pull request",  "pr",
};
const ref_connectors = [_][]const u8{ "at", "is at", "lives at", "for", "#" };

const user_subjects = [_][]const u8{ "i", "the user", "we" };
const user_verbs = [_][]const u8{
    "prefer", "prefers", "like",       "likes",
    "want",   "wants",   "always use", "usually use",
};
const please_verbs = [_][]const u8{ "use", "always", "never", "keep" };
const my_prefs = [_][]const u8{ "preference", "preferred" };

const feedback_phrases = [_][]const u8{
    "do not",       "don't",      "never",      "stop",
    "avoid",        "instead of", "corrected",  "the fix",
    "fix was",      "fixed by",   "root cause", "solved",
    "the solution", "workaround", "turns out",  "the problem was",
    "the bug was",
};

const project_phrases = [_][]const u8{
    "we decided", "decision",   "decided to", "chose",
    "chosen",     "going with", "agreed to",  "the plan is",
    "deadline",   "roadmap",    "convention", "renamed to",
};
const project_prefixes = [_][]const u8{ "migrat", "deprecat" };

/// Ordered rules, first match wins: reference, user, feedback, project.
/// `text` is whitespace-normalized and lowercased.
fn classify(text: []const u8) ?[]const u8 {
    if (hasBoundedStart(text, "http://") or hasBoundedStart(text, "https://")) {
        return "reference";
    }
    if (hasPhraseSeq(text, &ref_words, &ref_connectors)) return "reference";

    if (hasPhraseSeq(text, &user_subjects, &user_verbs)) return "user";
    if (hasPhraseSeq(text, &.{"please"}, &please_verbs)) return "user";
    if (hasPhraseSeq(text, &.{"my"}, &my_prefs)) return "user";

    for (feedback_phrases) |p| {
        if (hasPhrase(text, p)) return "feedback";
    }

    for (project_phrases) |p| {
        if (hasPhrase(text, p)) return "project";
    }
    for (project_prefixes) |p| {
        if (hasWordPrefix(text, p)) return "project";
    }
    return null;
}

const speaker_labels = [_][]const u8{
    "user", "human", "assistant", "agent", "system", "tool",
};

/// `^(?:user|human|assistant|agent|system|tool)\s*[:>]\s*`: returns the
/// index just past the label, or null when the line has none.
fn speakerEnd(s: []const u8) ?usize {
    var i: usize = 0;
    while (i < s.len and isWordChar(s[i])) i += 1;
    if (i == 0) return null;
    const word = s[0..i];
    var matched = false;
    for (speaker_labels) |label| {
        if (std.ascii.eqlIgnoreCase(word, label)) {
            matched = true;
            break;
        }
    }
    if (!matched) return null;
    var j = i;
    while (j < s.len and std.ascii.isWhitespace(s[j])) j += 1;
    if (j >= s.len or (s[j] != ':' and s[j] != '>')) return null;
    j += 1;
    while (j < s.len and std.ascii.isWhitespace(s[j])) j += 1;
    return j;
}

/// Strip transcript framing: speaker labels and markdown list markers.
fn stripFraming(line: []const u8) []const u8 {
    var s = line;
    if (speakerEnd(s)) |end| s = s[end..];
    if (s.len > 1 and (s[0] == '-' or s[0] == '*' or s[0] == '+') and
        std.ascii.isWhitespace(s[1]))
    {
        s = s[2..];
    }
    return std.mem.trim(u8, s, " \t");
}

/// Whitespace-collapse plus lowercase: the dedup identity, and the text
/// the rules run against. Caller owns the result.
fn normalize(alloc: Allocator, text: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    var pending_space = false;
    for (text) |c| {
        if (std.ascii.isWhitespace(c)) {
            if (out.items.len > 0) pending_space = true;
            continue;
        }
        if (pending_space) try out.append(alloc, ' ');
        pending_space = false;
        try out.append(alloc, std.ascii.toLower(c));
    }
    return out.toOwnedSlice(alloc);
}

/// The first sentence, or the line itself when it has no sentence break.
fn titleFor(alloc: Allocator, text: []const u8) Allocator.Error![]u8 {
    var end: usize = text.len;
    for (text, 0..) |c, i| {
        if ((c == '.' or c == '!' or c == '?') and
            (i + 1 == text.len or text[i + 1] == ' '))
        {
            end = i + 1;
            break;
        }
    }
    const title = text[0..end];
    if (title.len <= max_title_chars) return alloc.dupe(u8, title);
    return std.fmt.allocPrint(alloc, "{s}...", .{title[0..max_title_chars]});
}

/// Distill session text into typed learning candidates. All returned
/// memory belongs to `alloc`; using an arena is expected. Lines inside
/// fenced code blocks are skipped, and equal content (after whitespace
/// and case normalization) yields one candidate. Empty input or input
/// with no learnable signal returns an empty slice: callers must treat
/// that as "write nothing".
pub fn distillTexts(
    alloc: Allocator,
    texts: []const []const u8,
) Allocator.Error![]learn.Learning {
    var out: std.ArrayList(learn.Learning) = .empty;
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    var in_fence = false;

    for (texts) |text| {
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw_line| {
            const trimmed = std.mem.trim(u8, raw_line, " \t\r");
            if (std.mem.startsWith(u8, trimmed, "```")) {
                in_fence = !in_fence;
                continue;
            }
            if (in_fence) continue;
            const line = stripFraming(trimmed);
            if (line.len < min_candidate_chars or line.len > max_candidate_chars) continue;
            const norm = try normalize(alloc, line);
            const rule = classify(norm) orelse continue;
            if (seen.contains(norm)) continue;
            try seen.put(alloc, norm, {});
            try out.append(alloc, .{
                .type = rule,
                .title = try titleFor(alloc, line),
                .body = try std.fmt.allocPrint(alloc, "{s}\n", .{line}),
            });
            if (out.items.len >= max_emit_learnings) return out.items;
        }
    }
    return out.items;
}

/// Extract the learnable text of a session history: user prompts,
/// assistant replies, and compacted summaries. Tool output is skipped.
fn historyTexts(
    alloc: Allocator,
    history: []const types.HistoryTurn,
) Allocator.Error![]const []const u8 {
    var texts: std.ArrayList([]const u8) = .empty;
    for (history) |turn| {
        switch (turn) {
            .assistant => |t| {
                try texts.append(alloc, t.user.text);
                try texts.append(alloc, t.assistant);
            },
            .background_command => |t| {
                try texts.append(alloc, t.user.text);
                if (t.assistant) |a| try texts.append(alloc, a);
            },
            .interrupted => |t| try texts.append(alloc, t.user.text),
            .compacted_summary => |t| try texts.append(alloc, t.summary),
        }
    }
    return texts.items;
}

/// Collect the normalized body of every candidate already in the
/// sidecar so re-emission (resumed session, repeated teardown) does
/// not grow the file with duplicates.
fn existingBodies(
    alloc: Allocator,
    bytes: []const u8,
    seen: *std.StringHashMapUnmanaged(void),
) Allocator.Error!void {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        var parsed = std.json.parseFromSlice(std.json.Value, alloc, line, .{}) catch continue;
        defer parsed.deinit();
        if (parsed.value != .object) continue;
        const body_v = parsed.value.object.get("body") orelse continue;
        if (body_v != .string) continue;
        const norm = try normalize(alloc, body_v.string);
        try seen.put(alloc, norm, {});
    }
}

/// The session-end emission trigger: distill the session history and
/// append new candidates to the learnings.jsonl sidecar. Best-effort
/// scratch state — the durable write belongs to learn.captureSessionEnd,
/// which runs after this and consumes the sidecar. No candidates, or
/// only ones the sidecar already holds, writes nothing.
pub fn emitSessionLearnings(
    alloc: Allocator,
    session_dir: *io_mod.VerifiedDir,
    history: []const types.HistoryTurn,
) !void {
    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const candidates = try distillTexts(arena, try historyTexts(arena, history));
    if (candidates.len == 0) return;

    var seen: std.StringHashMapUnmanaged(void) = .empty;
    var existing: []const u8 = "";
    if (try learn.readLearningsFile(arena, session_dir)) |bytes| {
        existing = bytes;
        try existingBodies(arena, bytes, &seen);
    }

    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(arena, existing);
    // A hand-edited sidecar without a trailing newline must not let the
    // first appended candidate merge into its last line.
    if (existing.len > 0 and existing[existing.len - 1] != '\n') {
        try out.append(arena, '\n');
    }
    var added = false;
    for (candidates) |c| {
        const norm = try normalize(arena, c.body);
        if (seen.contains(norm)) continue;
        try seen.put(arena, norm, {});

        var line: std.Io.Writer.Allocating = .init(arena);
        try std.json.Stringify.value(
            .{ .type = c.type, .title = c.title, .body = c.body },
            .{},
            &line.writer,
        );
        try line.writer.writeByte('\n');
        const rendered = line.written();
        if (out.items.len + rendered.len > learn.max_learnings_bytes) break;
        try out.appendSlice(arena, rendered);
        added = true;
    }
    if (!added) return;
    try io_mod.durableReplaceVerified(alloc, session_dir, learnings_file, out.items);
}

// ─── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

fn distillOne(alloc: Allocator, text: []const u8) ![]learn.Learning {
    return distillTexts(alloc, &.{text});
}

test "distill classifies the four learning types" {
    const alloc = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const out = try distillTexts(arena, &.{
        "The runbook is at https://example.com/ops for the deploy pipeline.",
        "I prefer pnpm over npm for all package management in this repo.",
        "The root cause was a stale manifest seq on the second client.",
        "We decided to store agent state in the signet, not vendor clouds.",
        "just a plain line with nothing worth learning in it at all ok",
    });
    try testing.expectEqual(@as(usize, 4), out.len);
    try testing.expectEqualStrings("reference", out[0].type);
    try testing.expectEqualStrings("user", out[1].type);
    try testing.expectEqualStrings("feedback", out[2].type);
    try testing.expectEqualStrings("project", out[3].type);
}

test "distill strips speaker labels and list markers" {
    const alloc = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const out = try distillTexts(arena, &.{
        "user: I prefer tabs over spaces for indentation in this project.",
        "- We decided to rename the module to signet across the codebase.",
    });
    try testing.expectEqual(@as(usize, 2), out.len);
    try testing.expectEqualStrings("user", out[0].type);
    try testing.expectEqualStrings("project", out[1].type);
}

test "distill skips fenced code blocks and short lines" {
    const alloc = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const out = try distillOne(arena,
        \\```
        \\we decided this is code not a learning at all ever
        \\```
        \\short
        \\we decided the parser lives in core after all the discussion.
    );
    try testing.expectEqual(@as(usize, 1), out.len);
    try testing.expectEqualStrings("project", out[0].type);
}

test "distill dedupes normalized repeats and honors the candidate cap" {
    const alloc = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const duped = try distillTexts(arena, &.{
        "I prefer pnpm over npm for all package management in this repo.",
        "  i   prefer   pnpm over npm for all package management in this repo.",
    });
    try testing.expectEqual(@as(usize, 1), duped.len);

    var big: std.ArrayList(u8) = .empty;
    for (0..40) |i| {
        const line = try std.fmt.allocPrint(
            arena,
            "we decided on option number {d} for the rollout plan today.\n",
            .{i},
        );
        try big.appendSlice(arena, line);
    }
    const capped = try distillOne(arena, big.items);
    try testing.expectEqual(@as(usize, max_emit_learnings), capped.len);
}

test "distill rejects lines outside the candidate length bounds" {
    const alloc = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const short = try distillOne(arena, "i prefer pnpm");
    try testing.expectEqual(@as(usize, 0), short.len);

    var long_buf: std.ArrayList(u8) = .empty;
    try long_buf.appendSlice(arena, "i prefer ");
    for (0..max_candidate_chars) |_| try long_buf.append(arena, 'x');
    const long = try distillOne(arena, long_buf.items);
    try testing.expectEqual(@as(usize, 0), long.len);
}

test "emitSessionLearnings writes the sidecar and dedupes on rerun" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var home_vd = io_mod.VerifiedDir{ .dir = try tmp.dir.openDir(
        testing.io,
        ".",
        .{ .iterate = true, .follow_symlinks = false },
    ) };
    defer home_vd.close();
    var sessions_vd = try io_mod.openOrCreateVerifiedPrivateDir(&home_vd, "sessions");
    defer sessions_vd.close();
    var session_vd = try io_mod.openOrCreateVerifiedPrivateDir(&sessions_vd, "sess001");
    defer session_vd.close();

    const history = [_]types.HistoryTurn{
        .{ .assistant = .{
            .user = .{ .text = try alloc.dupe(u8, "I prefer pnpm over npm for all package management here.") },
            .assistant = try alloc.dupe(u8, "Got it. We decided pnpm is the package manager for this project."),
        } },
    };
    defer {
        for (history) |turn| switch (turn) {
            .assistant => |t| {
                alloc.free(t.user.text);
                alloc.free(t.assistant);
            },
            else => {},
        };
    }

    try emitSessionLearnings(alloc, &session_vd, &history);

    const first = (try learn.readLearningsFile(alloc, &session_vd)).?;
    defer alloc.free(first);
    try testing.expect(std.mem.find(u8, first, "\"type\":\"user\"") != null);
    try testing.expect(std.mem.find(u8, first, "\"type\":\"project\"") != null);
    const first_len = first.len;

    // A second emission over the same history appends nothing.
    try emitSessionLearnings(alloc, &session_vd, &history);
    const second = (try learn.readLearningsFile(alloc, &session_vd)).?;
    defer alloc.free(second);
    try testing.expectEqual(first_len, second.len);
}

test "emitSessionLearnings leaves no sidecar for an empty history" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();

    var home_vd = io_mod.VerifiedDir{ .dir = try tmp.dir.openDir(
        testing.io,
        ".",
        .{ .iterate = true, .follow_symlinks = false },
    ) };
    defer home_vd.close();
    var session_vd = try io_mod.openOrCreateVerifiedPrivateDir(&home_vd, "sess002");
    defer session_vd.close();

    try emitSessionLearnings(alloc, &session_vd, &.{});

    try testing.expectError(
        error.FileNotFound,
        session_vd.dir.openFile(testing.io, learnings_file, .{
            .mode = .read_only,
            .follow_symlinks = false,
            .resolve_beneath = true,
        }),
    );
}
