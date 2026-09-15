//! Client-side secret scanner — defense in depth (PS-110).
//!
//! A passport carries an agent's whole working state, and agents are
//! excellent at accidentally writing "the API key is sk-..." into a note.
//! Everything is encrypted before upload, but a synced secret is still a
//! synced secret. So every entry — session chunks included — is scanned
//! here, on the client, BEFORE encryption, and (by default) refused if it
//! looks like it carries a live credential.
//!
//! Ported from passport-suite src/client/secretscan.ts. Zig has no regex
//! engine, so each rule is a hand-written matcher with the same
//! block/pass semantics as the reference regexes (word boundaries, greedy
//! runs, and the trailing \b backtracking the reference engine performs).

const std = @import("std");

const Allocator = std.mem.Allocator;

pub const ScanMode = enum { block, warn, off };

pub const Finding = struct {
    /// Entry key the secret was found in.
    entry_key: []const u8,
    /// Short rule id, e.g. "aws-access-key-id".
    rule: []const u8,
    /// Human description.
    description: []const u8,
    /// 1-based line number.
    line: usize,
    /// The matched text, redacted to first/last few chars. Owned by the
    /// allocator passed to scanEntry/scanEntries.
    match: []u8,

    pub fn deinit(self: *Finding, alloc: Allocator) void {
        alloc.free(self.match);
    }
};

pub fn freeFindings(alloc: Allocator, findings: []Finding) void {
    for (findings) |*finding| finding.deinit(alloc);
    alloc.free(findings);
}

fn isWordChar(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '_';
}

/// \b at position `pos`: a transition between word and non-word/edge.
fn boundaryBefore(line: []const u8, pos: usize) bool {
    if (pos >= line.len) return false; // nothing to match
    if (!isWordChar(line[pos])) return false;
    return pos == 0 or !isWordChar(line[pos - 1]);
}

/// \b after the consumed run ending at `end` (exclusive). The last consumed
/// char and the following char must differ in word-ness, with a missing
/// neighbor counting as non-word.
fn boundaryAt(line: []const u8, end: usize) bool {
    if (end == 0) return false;
    const last_word = isWordChar(line[end - 1]);
    const next_word = end < line.len and isWordChar(line[end]);
    return last_word != next_word;
}

fn inSet(comptime set: []const u8, ch: u8) bool {
    return std.mem.findScalar(u8, set, ch) != null;
}

/// Length of the maximal run of `set` chars starting at `pos`.
fn runLen(line: []const u8, pos: usize, comptime set: []const u8) usize {
    var n: usize = 0;
    while (pos + n < line.len and inSet(set, line[pos + n])) n += 1;
    return n;
}

/// Regex `set{min,}\b` starting at `pos`: greedy run, then backtrack the
/// consumed length until the trailing \b holds (down to `min`). Returns the
/// match end (exclusive) or null.
fn runWithBoundary(line: []const u8, pos: usize, comptime set: []const u8, min: usize) ?usize {
    var len = runLen(line, pos, set);
    while (len >= min) : (len -= 1) {
        if (boundaryAt(line, pos + len)) return pos + len;
    }
    return null;
}

/// Regex `set{exact}\b` starting at `pos`. Returns the match end or null.
fn exactRunWithBoundary(
    line: []const u8,
    pos: usize,
    comptime set: []const u8,
    comptime exact: usize,
) ?usize {
    if (runLen(line, pos, set) < exact) return null;
    if (!boundaryAt(line, pos + exact)) return null;
    return pos + exact;
}

const Match = struct { start: usize, end: usize };

/// Find the first position where a `\b` + one of `prefixes` matches
/// (case-insensitive when `ci`), returning the position after the prefix.
fn matchAnyPrefix(
    line: []const u8,
    from: usize,
    prefixes: []const []const u8,
    ci: bool,
) ?struct { start: usize, end: usize } {
    var i = from;
    while (i < line.len) : (i += 1) {
        if (!boundaryBefore(line, i)) continue;
        for (prefixes) |prefix| {
            if (i + prefix.len > line.len) continue;
            const slice = line[i .. i + prefix.len];
            const hit = if (ci)
                std.ascii.eqlIgnoreCase(slice, prefix)
            else
                std.mem.eql(u8, slice, prefix);
            if (hit) return .{ .start = i, .end = i + prefix.len };
        }
    }
    return null;
}

/// Result of a rule match on one line: the reported text span and its
/// bounds. `match_start..match_end` is what gets redacted (the capture
/// group when the reference regex has one, else the whole match).
const RuleMatch = struct { start: usize, end: usize };

const RuleFn = *const fn (line: []const u8) ?RuleMatch;

const Rule = struct {
    id: []const u8,
    description: []const u8,
    match: RuleFn,
};

// ─── Rule matchers ──────────────────────────────────────────────────────

/// \b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b
fn matchAwsAccessKeyId(line: []const u8) ?RuleMatch {
    const prefixes = [_][]const u8{ "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA" };
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        if (!boundaryBefore(line, i)) continue;
        for (prefixes) |prefix| {
            if (i + prefix.len > line.len) continue;
            if (!std.mem.eql(u8, line[i .. i + prefix.len], prefix)) continue;
            const body_start = i + prefix.len;
            if (exactRunWithBoundary(line, body_start, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 16)) |end| {
                return .{ .start = i, .end = end };
            }
        }
    }
    return null;
}

/// \baws_?(?:secret_?)?access_?key[^\n]{0,20}['"=:\s]([A-Za-z0-9/+]{40})\b
/// (case-insensitive). The reported span is the 40-char capture group.
fn matchAwsSecretAccessKey(line: []const u8) ?RuleMatch {
    var i: usize = 0;
    while (i + 3 <= line.len) : (i += 1) {
        if (!boundaryBefore(line, i)) continue;
        if (!std.ascii.eqlIgnoreCase(line[i .. i + 3], "aws")) continue;
        var pos = i + 3;
        if (pos < line.len and line[pos] == '_') pos += 1;
        if (pos + 6 <= line.len and std.ascii.eqlIgnoreCase(line[pos .. pos + 6], "secret")) {
            pos += 6;
            if (pos < line.len and line[pos] == '_') pos += 1;
        }
        if (pos + 6 > line.len or !std.ascii.eqlIgnoreCase(line[pos .. pos + 6], "access")) continue;
        pos += 6;
        if (pos < line.len and line[pos] == '_') pos += 1;
        if (pos + 3 > line.len or !std.ascii.eqlIgnoreCase(line[pos .. pos + 3], "key")) continue;
        pos += 3;
        // [^\n]{0,20} is greedy: the reference engine tries the longest
        // window first and backtracks, so scan d descending.
        const remaining = line.len - pos;
        if (remaining == 0) continue;
        var d: usize = @min(20, remaining - 1);
        while (true) {
            const sep = line[pos + d];
            if (sep == '\'' or sep == '"' or sep == '=' or sep == ':' or
                std.ascii.isWhitespace(sep))
            {
                const group_start = pos + d + 1;
                if (exactRunWithBoundary(line, group_start, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+", 40)) |end| {
                    return .{ .start = group_start, .end = end };
                }
            }
            if (d == 0) break;
            d -= 1;
        }
    }
    return null;
}

/// \b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b
fn matchGithubToken(line: []const u8) ?RuleMatch {
    const prefixes = [_][]const u8{ "github_pat", "ghp", "gho", "ghu", "ghs", "ghr" };
    var i: usize = 0;
    while (i < line.len) : (i += 1) {
        if (!boundaryBefore(line, i)) continue;
        for (prefixes) |prefix| {
            if (i + prefix.len + 1 > line.len) continue;
            if (!std.mem.eql(u8, line[i .. i + prefix.len], prefix)) continue;
            if (line[i + prefix.len] != '_') continue;
            const body_start = i + prefix.len + 1;
            if (runWithBoundary(line, body_start, token_body_chars, 20)) |end| {
                return .{ .start = i, .end = end };
            }
        }
    }
    return null;
}

const token_body_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_";

/// \bxox[baprs]-[A-Za-z0-9-]{10,}\b
fn matchSlackToken(line: []const u8) ?RuleMatch {
    var i: usize = 0;
    while (i + 5 <= line.len) : (i += 1) {
        if (!boundaryBefore(line, i)) continue;
        if (!std.mem.eql(u8, line[i .. i + 3], "xox")) continue;
        if (!inSet("baprs", line[i + 3])) continue;
        if (line[i + 4] != '-') continue;
        if (runWithBoundary(line, i + 5, slack_body_chars, 10)) |end| {
            return .{ .start = i, .end = end };
        }
    }
    return null;
}

const slack_body_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-";

/// \bsk-ant-[A-Za-z0-9_-]{20,}\b (checked before the generic sk- shape so
/// both rules can report, matching the reference where each rule fires
/// independently).
fn matchAnthropicKey(line: []const u8) ?RuleMatch {
    return matchLiteralToken(line, "sk-ant-", token_dash_chars, 20);
}

/// \bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b
fn matchOpenaiKey(line: []const u8) ?RuleMatch {
    var i: usize = 0;
    while (i + 3 <= line.len) : (i += 1) {
        if (!boundaryBefore(line, i)) continue;
        if (!std.mem.eql(u8, line[i .. i + 3], "sk-")) continue;
        var body_start = i + 3;
        if (body_start + 5 <= line.len and
            std.mem.eql(u8, line[body_start .. body_start + 5], "proj-"))
        {
            body_start += 5;
        }
        if (runWithBoundary(line, body_start, token_dash_chars, 20)) |end| {
            return .{ .start = i, .end = end };
        }
    }
    return null;
}

const token_dash_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";

/// \bAIza[0-9A-Za-z_-]{35}\b
fn matchGoogleApiKey(line: []const u8) ?RuleMatch {
    var i: usize = 0;
    while (i + 4 <= line.len) : (i += 1) {
        if (!boundaryBefore(line, i)) continue;
        if (!std.mem.eql(u8, line[i .. i + 4], "AIza")) continue;
        if (exactRunWithBoundary(line, i + 4, token_dash_chars, 35)) |end| {
            return .{ .start = i, .end = end };
        }
    }
    return null;
}

/// \b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b
fn matchStripeKey(line: []const u8) ?RuleMatch {
    var i: usize = 0;
    while (i + 3 <= line.len) : (i += 1) {
        if (!boundaryBefore(line, i)) continue;
        const pair = line[i .. i + 2];
        if (!std.mem.eql(u8, pair, "sk") and !std.mem.eql(u8, pair, "rk")) continue;
        if (line[i + 2] != '_') continue;
        var pos = i + 3;
        if (pos + 4 <= line.len and std.mem.eql(u8, line[pos .. pos + 4], "live")) {
            pos += 4;
        } else if (pos + 4 <= line.len and std.mem.eql(u8, line[pos .. pos + 4], "test")) {
            pos += 4;
        } else continue;
        if (pos >= line.len or line[pos] != '_') continue;
        if (runWithBoundary(line, pos + 1, alnum_chars, 20)) |end| {
            return .{ .start = i, .end = end };
        }
    }
    return null;
}

const alnum_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

/// \bglpat-[A-Za-z0-9_-]{20,}\b
fn matchGitlabPat(line: []const u8) ?RuleMatch {
    return matchLiteralToken(line, "glpat-", token_dash_chars, 20);
}

/// \bnpm_[A-Za-z0-9]{36}\b
fn matchNpmToken(line: []const u8) ?RuleMatch {
    var i: usize = 0;
    while (i + 4 <= line.len) : (i += 1) {
        if (!boundaryBefore(line, i)) continue;
        if (!std.mem.eql(u8, line[i .. i + 4], "npm_")) continue;
        if (exactRunWithBoundary(line, i + 4, alnum_chars, 36)) |end| {
            return .{ .start = i, .end = end };
        }
    }
    return null;
}

fn matchLiteralToken(
    line: []const u8,
    comptime literal: []const u8,
    comptime set: []const u8,
    comptime min: usize,
) ?RuleMatch {
    var i: usize = 0;
    while (i + literal.len <= line.len) : (i += 1) {
        if (!boundaryBefore(line, i)) continue;
        if (!std.mem.eql(u8, line[i .. i + literal.len], literal)) continue;
        if (runWithBoundary(line, i + literal.len, set, min)) |end| {
            return .{ .start = i, .end = end };
        }
    }
    return null;
}

/// -----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----
fn matchPrivateKey(line: []const u8) ?RuleMatch {
    const begin = "-----BEGIN ";
    const trailer = "-----";
    var i: usize = 0;
    while (std.mem.findPos(u8, line, i, begin)) |pos| {
        var rest = pos + begin.len;
        const kinds = [_][]const u8{ "RSA ", "EC ", "OPENSSH ", "DSA ", "PGP ", "ENCRYPTED " };
        for (kinds) |kind| {
            if (rest + kind.len <= line.len and std.mem.eql(u8, line[rest .. rest + kind.len], kind)) {
                rest += kind.len;
                break;
            }
        }
        const key_marker = "PRIVATE KEY";
        if (rest + key_marker.len <= line.len and
            std.mem.eql(u8, line[rest .. rest + key_marker.len], key_marker))
        {
            rest += key_marker.len;
            const block = " BLOCK";
            if (rest + block.len <= line.len and std.mem.eql(u8, line[rest .. rest + block.len], block)) {
                rest += block.len;
            }
            if (rest + trailer.len <= line.len and
                std.mem.eql(u8, line[rest .. rest + trailer.len], trailer))
            {
                return .{ .start = pos, .end = rest + trailer.len };
            }
        }
        i = pos + 1;
    }
    return null;
}

/// \bBearer\s+[A-Za-z0-9._~+/=-]{20,}\b
fn matchBearerToken(line: []const u8) ?RuleMatch {
    var i: usize = 0;
    while (i + 6 <= line.len) : (i += 1) {
        if (!boundaryBefore(line, i)) continue;
        if (!std.mem.eql(u8, line[i .. i + 6], "Bearer")) continue;
        var pos = i + 6;
        if (pos >= line.len or !std.ascii.isWhitespace(line[pos])) continue;
        while (pos < line.len and std.ascii.isWhitespace(line[pos])) pos += 1;
        if (runWithBoundary(line, pos, bearer_chars, 20)) |end| {
            return .{ .start = i, .end = end };
        }
    }
    return null;
}

const bearer_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~+/=-";

/// \beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b
fn matchJwt(line: []const u8) ?RuleMatch {
    var i: usize = 0;
    while (i + 3 <= line.len) : (i += 1) {
        if (!boundaryBefore(line, i)) continue;
        if (!std.mem.eql(u8, line[i .. i + 3], "eyJ")) continue;
        var pos = i + 3;
        const run1 = runLen(line, pos, token_dash_chars);
        if (run1 < 10) continue;
        pos += run1;
        if (pos >= line.len or line[pos] != '.') continue;
        pos += 1;
        if (pos + 3 > line.len or !std.mem.eql(u8, line[pos .. pos + 3], "eyJ")) continue;
        pos += 3;
        const run2 = runLen(line, pos, token_dash_chars);
        if (run2 < 10) continue;
        pos += run2;
        if (pos >= line.len or line[pos] != '.') continue;
        pos += 1;
        if (runWithBoundary(line, pos, token_dash_chars, 10)) |end| {
            return .{ .start = i, .end = end };
        }
    }
    return null;
}

const assignment_keywords = [_][]const u8{
    "access_token", "access-token", "accesstoken",
    "api_key",      "api-key",      "apikey",
    "password",     "passwd",       "secret",
    "token",
};

/// Locate a secret-flavoured keyword with \b on both sides
/// (case-insensitive). Returns the position after the keyword.
fn matchAssignmentKeyword(line: []const u8, from: usize) ?struct { start: usize, end: usize } {
    var i = from;
    while (i < line.len) : (i += 1) {
        if (!boundaryBefore(line, i)) continue;
        for (assignment_keywords) |keyword| {
            if (i + keyword.len > line.len) continue;
            if (!std.ascii.eqlIgnoreCase(line[i .. i + keyword.len], keyword)) continue;
            // Trailing \b: keyword end must abut a non-word char or EOL.
            const end = i + keyword.len;
            if (end < line.len and isWordChar(line[end])) continue;
            return .{ .start = i, .end = end };
        }
    }
    return null;
}

/// \b(?:api[_-]?key|secret|passwd|password|token|access[_-]?token)\b
/// [^\n]{0,10}[=:]\s*['"][^'"\n]{8,}['"]  (case-insensitive)
fn matchGenericAssignmentQuoted(line: []const u8) ?RuleMatch {
    var from: usize = 0;
    while (matchAssignmentKeyword(line, from)) |kw| {
        // [^\n]{0,10} is greedy: the reference engine tries the longest
        // window first and backtracks, so scan d descending.
        const remaining = line.len - kw.end;
        if (remaining == 0) {
            from = kw.end;
            continue;
        }
        var d: usize = @min(10, remaining - 1);
        while (true) {
            const ch = line[kw.end + d];
            if (ch == '=' or ch == ':') {
                var pos = kw.end + d + 1;
                while (pos < line.len and std.ascii.isWhitespace(line[pos])) pos += 1;
                if (pos < line.len and (line[pos] == '\'' or line[pos] == '"')) {
                    const value_start = pos + 1;
                    var value_len: usize = 0;
                    while (value_start + value_len < line.len and
                        line[value_start + value_len] != '\'' and
                        line[value_start + value_len] != '"') value_len += 1;
                    if (value_len >= 8) {
                        const close = value_start + value_len;
                        if (close < line.len and
                            (line[close] == '\'' or line[close] == '"'))
                        {
                            return .{ .start = kw.start, .end = close + 1 };
                        }
                    }
                }
            }
            if (d == 0) break;
            d -= 1;
        }
        from = kw.end;
    }
    return null;
}

/// \b(?:api[_-]?key|secret|passwd|password|token|access[_-]?token)\b
/// \s*[=:]\s*([A-Za-z0-9+/=_-]{24,})\b  (case-insensitive)
/// The reported span is the captured value.
fn matchGenericAssignmentUnquoted(line: []const u8) ?RuleMatch {
    var from: usize = 0;
    while (matchAssignmentKeyword(line, from)) |kw| {
        var pos = kw.end;
        while (pos < line.len and std.ascii.isWhitespace(line[pos])) pos += 1;
        if (pos < line.len and (line[pos] == '=' or line[pos] == ':')) {
            pos += 1;
            while (pos < line.len and std.ascii.isWhitespace(line[pos])) pos += 1;
            if (runWithBoundary(line, pos, unquoted_value_chars, 24)) |end| {
                return .{ .start = pos, .end = end };
            }
        }
        from = kw.end;
    }
    return null;
}

const unquoted_value_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-";

const rules = [_]Rule{
    .{ .id = "aws-access-key-id", .description = "AWS access key id", .match = matchAwsAccessKeyId },
    .{ .id = "aws-secret-access-key", .description = "AWS secret access key", .match = matchAwsSecretAccessKey },
    .{ .id = "github-token", .description = "GitHub token", .match = matchGithubToken },
    .{ .id = "slack-token", .description = "Slack token", .match = matchSlackToken },
    .{ .id = "openai-key", .description = "OpenAI API key", .match = matchOpenaiKey },
    .{ .id = "anthropic-key", .description = "Anthropic API key", .match = matchAnthropicKey },
    .{ .id = "google-api-key", .description = "Google API key", .match = matchGoogleApiKey },
    .{ .id = "stripe-secret-key", .description = "Stripe secret key", .match = matchStripeKey },
    .{ .id = "gitlab-pat", .description = "GitLab personal access token", .match = matchGitlabPat },
    .{ .id = "npm-token", .description = "npm access token", .match = matchNpmToken },
    .{ .id = "private-key", .description = "PEM private key block", .match = matchPrivateKey },
    .{ .id = "bearer-token", .description = "Bearer token", .match = matchBearerToken },
    .{ .id = "jwt", .description = "JSON Web Token", .match = matchJwt },
    .{ .id = "generic-assignment", .description = "Hardcoded secret/password/token assignment (quoted)", .match = matchGenericAssignmentQuoted },
    .{ .id = "generic-assignment-unquoted", .description = "Hardcoded secret/password/token assignment (unquoted)", .match = matchGenericAssignmentUnquoted },
};

fn redact(alloc: Allocator, s: []const u8) Allocator.Error![]u8 {
    if (s.len <= 8) {
        const out = try alloc.alloc(u8, s.len);
        @memset(out, '*');
        return out;
    }
    return std.fmt.allocPrint(alloc, "{s}...{s}", .{ s[0..4], s[s.len - 4 ..] });
}

/// Scan a single entry's plaintext, returning any findings. The caller owns
/// the returned slice and each finding's `match` (see freeFindings).
pub fn scanEntry(alloc: Allocator, entry_key: []const u8, plaintext: []const u8) Allocator.Error![]Finding {
    var findings: std.ArrayList(Finding) = .empty;
    errdefer {
        for (findings.items) |*f| f.deinit(alloc);
        findings.deinit(alloc);
    }

    var line_no: usize = 1;
    var lines = std.mem.splitScalar(u8, plaintext, '\n');
    while (lines.next()) |line| : (line_no += 1) {
        for (rules) |rule| {
            if (rule.match(line)) |m| {
                try findings.append(alloc, .{
                    .entry_key = entry_key,
                    .rule = rule.id,
                    .description = rule.description,
                    .line = line_no,
                    .match = try redact(alloc, line[m.start..m.end]),
                });
            }
        }
    }
    return findings.toOwnedSlice(alloc);
}

pub const Entry = struct { key: []const u8, text: []const u8 };

/// Scan a whole set of entries (key -> plaintext), preserving order.
/// The caller owns the returned slice (see freeFindings).
pub fn scanEntries(alloc: Allocator, entries: []const Entry) Allocator.Error![]Finding {
    var all: std.ArrayList(Finding) = .empty;
    errdefer {
        for (all.items) |*f| f.deinit(alloc);
        all.deinit(alloc);
    }
    for (entries) |entry| {
        const found = try scanEntry(alloc, entry.key, entry.text);
        defer alloc.free(found); // finding structs move into `all`; matches stay owned
        try all.appendSlice(alloc, found);
    }
    return all.toOwnedSlice(alloc);
}

pub const EnforceError = error{SecretFound} || Allocator.Error;

/// Apply scan policy to entries about to be uploaded.
///   - off:   skip entirely.
///   - warn:  findings are appended to `findings` for the caller to log.
///   - block: appends findings and returns error.SecretFound.
pub fn enforce(
    alloc: Allocator,
    entries: []const Entry,
    mode: ScanMode,
    findings: *std.ArrayList(Finding),
) EnforceError!void {
    if (mode == .off) return;
    const found = try scanEntries(alloc, entries);
    defer alloc.free(found); // structs are copied into `findings`; container only
    try findings.appendSlice(alloc, found);
    if (found.len > 0 and mode == .block) return error.SecretFound;
}

// ─── Tests ──────────────────────────────────────────────────────────────

fn expectFinding(alloc: Allocator, entry_key: []const u8, text: []const u8, rule_id: []const u8) !void {
    const findings = try scanEntry(alloc, entry_key, text);
    defer freeFindings(alloc, findings);
    for (findings) |f| {
        if (std.mem.eql(u8, f.rule, rule_id)) return;
    }
    var names: std.ArrayList(u8) = .empty;
    defer names.deinit(alloc);
    for (findings) |f| {
        try names.appendSlice(alloc, f.rule);
        try names.append(alloc, ',');
    }
    std.debug.print("expected rule {s}, got findings: {s}\n", .{ rule_id, names.items });
    return error.TestExpectedFinding;
}

fn expectClean(alloc: Allocator, text: []const u8) !void {
    const findings = try scanEntry(alloc, "memory/test.md", text);
    defer freeFindings(alloc, findings);
    if (findings.len != 0) {
        std.debug.print("expected clean, got rule {s} at line {d}\n", .{
            findings[0].rule,
            findings[0].line,
        });
        return error.TestUnexpectedFinding;
    }
}

test "scanner blocks known token shapes" {
    const alloc = std.testing.allocator;

    try expectFinding(alloc, "memory/x", "key: AKIAIOSFODNN7EXAMPLE end", "aws-access-key-id");
    try expectFinding(alloc, "memory/x", "aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"", "aws-secret-access-key");
    try expectFinding(alloc, "memory/x", "tok ghp_abcdefghij0123456789AB end", "github-token");
    try expectFinding(alloc, "memory/x", "github_pat_11ABCDEFGHIJKLMNOPQRST_uvwxyz", "github-token");
    try expectFinding(alloc, "memory/x", "xoxb-1234567890-abcdefghijkl", "slack-token");
    try expectFinding(alloc, "memory/x", "sk-abcdefghij0123456789abcd", "openai-key");
    try expectFinding(alloc, "memory/x", "sk-proj-abcdefghij0123456789abcd", "openai-key");
    try expectFinding(alloc, "memory/x", "sk-ant-api03-abcdefghij0123456789", "anthropic-key");
    try expectFinding(alloc, "memory/x", "AIzaSyD4iE2xVSpkLLOXoyq2jwnufoD0EXAMPLE", "google-api-key");
    try expectFinding(alloc, "memory/x", "sk_live_abcdefghij0123456789", "stripe-secret-key");
    try expectFinding(alloc, "memory/x", "rk_test_abcdefghij0123456789", "stripe-secret-key");
    try expectFinding(alloc, "memory/x", "glpat-abcdefghij0123456789", "gitlab-pat");
    try expectFinding(alloc, "memory/x", "npm_abcdefghijklmnopqrstuvwxyz0123456789", "npm-token");
    try expectFinding(alloc, "memory/x", "-----BEGIN RSA PRIVATE KEY-----\nMII...", "private-key");
    try expectFinding(alloc, "memory/x", "-----BEGIN OPENSSH PRIVATE KEY BLOCK-----", "private-key");
    try expectFinding(alloc, "memory/x", "Authorization: Bearer abcdefghij0123456789.token", "bearer-token");
    try expectFinding(alloc, "memory/x", "eyJhbGciOiJIUzI1NiIs.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop", "jwt");
    try expectFinding(alloc, "memory/x", "password = \"hunter2-secret\"", "generic-assignment");
    try expectFinding(alloc, "memory/x", "API_KEY: \"abcdefgh12345678\"", "generic-assignment");
    try expectFinding(alloc, "memory/x", "token=abcdefghijklmnopqrstuvwxyz012345", "generic-assignment-unquoted");
}

test "scanner passes plausible non-secret lookalikes" {
    const alloc = std.testing.allocator;

    try expectClean(alloc, "theme = \"dark\"");
    try expectClean(alloc, "password = hunter2"); // too short, unquoted prose
    try expectClean(alloc, "Remember the spec.\nSecond line about keys and secrets.");
    try expectClean(alloc, "sk-short");
    try expectClean(alloc, "npm_tooshort123");
    try expectClean(alloc, "AKIATOOSHORT");
    try expectClean(alloc, "the skeleton key opens the door");
    try expectClean(alloc, "xox-123456789012345"); // missing class letter
    try expectClean(alloc, "Bearer short");
    try expectClean(alloc, "eyJabc.eyJdef.ghi"); // runs too short
    try expectClean(alloc, "passwords = \"alongvalue\""); // keyword boundary
}

test "enforce blocks, warns, and skips per mode" {
    const alloc = std.testing.allocator;
    const secret_entries = [_]Entry{
        .{ .key = "memory/x", .text = "token = \"supersecretvalue\"" },
    };
    const clean_entries = [_]Entry{
        .{ .key = "memory/y", .text = "all clear" },
    };

    var findings: std.ArrayList(Finding) = .empty;
    defer {
        for (findings.items) |*f| f.deinit(alloc);
        findings.deinit(alloc);
    }

    try std.testing.expectError(
        error.SecretFound,
        enforce(alloc, &secret_entries, .block, &findings),
    );
    try std.testing.expect(findings.items.len > 0);
    for (findings.items) |*f| f.deinit(alloc);
    findings.clearRetainingCapacity();

    try enforce(alloc, &secret_entries, .warn, &findings);
    try std.testing.expect(findings.items.len > 0);
    for (findings.items) |*f| f.deinit(alloc);
    findings.clearRetainingCapacity();

    try enforce(alloc, &secret_entries, .off, &findings);
    try std.testing.expect(findings.items.len == 0);

    try enforce(alloc, &clean_entries, .block, &findings);
    try std.testing.expect(findings.items.len == 0);
}
