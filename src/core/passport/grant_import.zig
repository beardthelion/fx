//! Pending-grant listing and the passport grant record path.
//!
//! Read path (PS-061): `listPending` lists `grants/` entries that map onto
//! fx's tool model and are still holder-decidable; `/permissions passport`
//! resolves one with `findPending`, applies it to the permission engine,
//! and journals the explicit decision with `recordDecision` so a grant is
//! never re-presented. Expired and unmapped grants never reach the holder
//! and produce no journal entry: no decision was made, so nothing is
//! decided permanently.
//!
//! Write path (PS-062): `recordToolGrant` is the only route that writes
//! `grants/` entries, and callers invoke it only for grants the holder
//! confirmed. Decided grants are applied straight to the engine rather
//! than through that path, so a confirmed decision never echoes back as a
//! new grant record.

const std = @import("std");
const grants = @import("grants.zig");
const io_mod = @import("../shared/io.zig");
const profile_paths = @import("../shared/profile_paths.zig");
const store_redirect = @import("store_redirect.zig");

const Allocator = std.mem.Allocator;

const journal_dir_name = "passport";
const journal_file_name = "grant-decisions.jsonl";
const max_journal_bytes: usize = 256 * 1024;

pub const Decision = enum {
    confirmed,
    denied,

    pub fn name(self: Decision) []const u8 {
        return switch (self) {
            .confirmed => "confirmed",
            .denied => "denied",
        };
    }
};

// ─── Decision journal ───────────────────────────────────────────────────
//
// ~/.fx/passport/grant-decisions.jsonl holds one
// {"id":"<grant-id>","decision":"confirmed|denied"} line per explicit
// holder decision. It is local on purpose: it records what this harness
// decided, which is not portable state.

pub const DecisionJournal = struct {
    decisions: std.StringHashMapUnmanaged(Decision) = .empty,

    pub fn deinit(self: *DecisionJournal, alloc: Allocator) void {
        var it = self.decisions.iterator();
        while (it.next()) |kv| alloc.free(@constCast(kv.key_ptr.*));
        self.decisions.deinit(alloc);
    }

    fn journalPath(alloc: Allocator, home: []const u8) ![]u8 {
        return std.fs.path.join(
            alloc,
            &.{ home, profile_paths.root_dir_name, journal_dir_name, journal_file_name },
        );
    }

    pub fn load(alloc: Allocator, home: []const u8) !DecisionJournal {
        var journal: DecisionJournal = .{};
        errdefer journal.deinit(alloc);

        const path = try journalPath(alloc, home);
        defer alloc.free(path);
        var file = io_mod.openExistingRegularFile(std.Io.Dir.cwd(), path, .read_only) catch |err| switch (err) {
            error.FileNotFound => return journal,
            else => return err,
        };
        defer file.close(io_mod.getIo());
        const bytes = try io_mod.readFileToEnd(alloc, &file, max_journal_bytes);
        defer alloc.free(bytes);

        var lines = std.mem.splitScalar(u8, bytes, '\n');
        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0) continue;
            var parsed = std.json.parseFromSlice(std.json.Value, alloc, trimmed, .{}) catch continue;
            defer parsed.deinit();
            if (parsed.value != .object) continue;
            const id_v = parsed.value.object.get("id") orelse continue;
            const decision_v = parsed.value.object.get("decision") orelse continue;
            if (id_v != .string or decision_v != .string) continue;
            const decision: Decision = if (std.mem.eql(u8, decision_v.string, "confirmed"))
                .confirmed
            else if (std.mem.eql(u8, decision_v.string, "denied"))
                .denied
            else
                continue;
            const decided_id = try alloc.dupe(u8, id_v.string);
            errdefer alloc.free(decided_id);
            try journal.decisions.put(alloc, decided_id, decision);
        }
        return journal;
    }

    pub fn decided(self: *const DecisionJournal, id: []const u8) ?Decision {
        return self.decisions.get(id);
    }

    /// Append a holder decision to the journal. Fails closed: a decision
    /// that cannot be persisted must not be treated as decided, or the
    /// grant would never be presented again.
    pub fn record(self: *DecisionJournal, alloc: Allocator, home: []const u8, id: []const u8, decision: Decision) !void {
        if (id.len == 0 or std.mem.indexOfAny(u8, id, "\"\\\r\n") != null) {
            return error.InvalidGrantId;
        }
        const dir_path = try std.fs.path.join(
            alloc,
            &.{ home, profile_paths.root_dir_name, journal_dir_name },
        );
        defer alloc.free(dir_path);
        try io_mod.makeDirRecursive(dir_path);
        const path = try journalPath(alloc, home);
        defer alloc.free(path);

        const line = try std.fmt.allocPrint(
            alloc,
            "{{\"id\":\"{s}\",\"decision\":\"{s}\"}}\n",
            .{ id, decision.name() },
        );
        defer alloc.free(line);

        var file = try std.Io.Dir.cwd().createFile(io_mod.getIo(), path, .{
            .read = true,
            .truncate = false,
            .permissions = std.Io.File.Permissions.fromMode(0o600),
        });
        defer file.close(io_mod.getIo());
        const end = try file.length(io_mod.getIo());
        try file.writePositionalAll(io_mod.getIo(), line, end);
        try file.sync(io_mod.getIo());

        const key = try alloc.dupe(u8, id);
        errdefer alloc.free(key);
        try self.decisions.put(alloc, key, decision);
    }
};

// ─── Pending-grant listing ──────────────────────────────────────────────

fn grantPresentable(grant: grants.Grant, now_ms: i64) bool {
    if (grants.mappedToolNames(grant.action).len == 0) return false;
    if (grants.isExpired(grant, now_ms)) return false;
    return true;
}

/// List undecided grants under `grants/` that this harness could honor:
/// parseable, a known action class, unexpired, and absent from the
/// decision journal. All grant fields live on `GrantDoc.grant`, backed by
/// `GrantDoc.backing`; free each element with GrantDoc.deinit.
pub fn listPending(
    alloc: Allocator,
    store: *store_redirect.Store,
    home: []const u8,
    now_ms: i64,
) ![]grants.GrantDoc {
    var journal = try DecisionJournal.load(alloc, home);
    defer journal.deinit(alloc);

    const keys = try store.listSurface(alloc, "grants");
    defer {
        for (keys) |k| alloc.free(k);
        alloc.free(keys);
    }

    // One manifest fetch+verify covers every grant read; per-entry reads
    // would re-fetch and re-verify the same manifest each time.
    const results = try store.readSurfacesBatch(alloc, keys);
    defer {
        for (results) |r| if (r) |b| alloc.free(b);
        alloc.free(results);
    }

    var out: std.ArrayList(grants.GrantDoc) = .empty;
    errdefer {
        for (out.items) |*g| g.deinit(alloc);
        out.deinit(alloc);
    }
    for (results) |bytes_opt| {
        const bytes = bytes_opt orelse continue;
        var doc = (try grants.parseGrantDoc(alloc, bytes)) orelse continue;
        errdefer doc.deinit(alloc);
        if (journal.decided(doc.grant.id) != null) {
            doc.deinit(alloc);
            continue;
        }
        if (!grantPresentable(doc.grant, now_ms)) {
            doc.deinit(alloc);
            continue;
        }
        try out.append(alloc, doc);
    }
    return out.toOwnedSlice(alloc);
}

/// Journal the holder's decision for a grant id without touching the
/// permission engine. Callers applying a confirmed grant do the engine
/// mutation themselves (under whatever lock guards it) and then record
/// the decision here.
pub fn recordDecision(alloc: Allocator, home: []const u8, id: []const u8, decision: Decision) !void {
    var journal = try DecisionJournal.load(alloc, home);
    defer journal.deinit(alloc);
    try journal.record(alloc, home, id, decision);
}

/// Find a pending grant by id. Borrows into `pending`; the returned
/// pointer is invalidated when the pending list is freed.
pub fn findPending(pending: []grants.GrantDoc, id: []const u8) ?*grants.GrantDoc {
    for (pending) |*g| {
        if (std.mem.eql(u8, g.grant.id, id)) return g;
    }
    return null;
}

// ─── Record path (PS-062) ───────────────────────────────────────────────

/// The action class an fx tool name reverse-maps to, if any. Tools with
/// no passport class produce no grant record.
pub fn actionClassForTool(tool_name: []const u8) ?grants.ActionClass {
    const tables = .{
        .{ grants.ActionClass.fs_read, &grants.fx_tool_names.fs_read },
        .{ grants.ActionClass.fs_write, &grants.fx_tool_names.fs_write },
        .{ grants.ActionClass.shell_exec, &grants.fx_tool_names.shell_exec },
        .{ grants.ActionClass.net_fetch, &grants.fx_tool_names.net_fetch },
        .{ grants.ActionClass.agent_spawn, &grants.fx_tool_names.agent_spawn },
    };
    inline for (tables) |table| {
        for (table[1]) |name| {
            if (std.mem.eql(u8, tool_name, name)) return table[0];
        }
    }
    return null;
}

/// Serialize "YYYY-MM-DDTHH:MM:SSZ" for an epoch-millis timestamp.
/// Negative (pre-1970) input is not representable in EpochSeconds and is
/// unreachable here: `ms` is a wall-clock timestamp.
pub fn formatIso8601Z(alloc: Allocator, ms: i64) ![]u8 {
    const epoch_secs: std.time.epoch.EpochSeconds = .{
        .secs = @intCast(@max(0, @divFloor(ms, 1000))),
    };
    const year_day = epoch_secs.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_secs = epoch_secs.getDaySeconds();
    return std.fmt.allocPrint(
        alloc,
        "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
        .{
            @as(u64, year_day.year),
            @as(u64, month_day.month.numeric()),
            @as(u64, month_day.day_index + 1),
            @as(u64, day_secs.getHoursIntoDay()),
            @as(u64, day_secs.getMinutesIntoHour()),
            @as(u64, day_secs.getSecondsIntoMinute()),
        },
    );
}

/// Record a holder-confirmed fx session grant into the passport. Tools
/// outside the passport action vocabulary produce no record. Returns the
/// grant id, or null when the tool has no action class.
pub fn recordToolGrant(
    alloc: Allocator,
    store: *store_redirect.Store,
    tool_name: []const u8,
    scope: []const u8,
    now_ms: i64,
) !?[]u8 {
    const class = actionClassForTool(tool_name) orelse return null;
    if (scope.len == 0 or scope.len > 4096) return error.InvalidGrantScope;

    var random_bytes: [8]u8 = undefined;
    io_mod.getIo().random(&random_bytes);
    const id = try std.fmt.allocPrint(
        alloc,
        "grant-{d}-{s}",
        .{ now_ms, std.fmt.bytesToHex(random_bytes, .lower) },
    );
    errdefer alloc.free(id);

    const granted_at = try formatIso8601Z(alloc, now_ms);
    defer alloc.free(granted_at);
    const granted_by = store.holderDid() orelse "fx";

    const record = try grants.buildGrantRecord(alloc, .{
        .id = id,
        .action = class.name(),
        .scope = scope,
        .granted_by = granted_by,
        .granted_at = granted_at,
    });
    defer alloc.free(record);

    const rel = try std.fmt.allocPrint(alloc, "grants/{s}.json", .{id});
    defer alloc.free(rel);
    try store.writeSurface(alloc, rel, record);
    return id;
}

// ─── Tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

const MockBackend = store_redirect.MockBackend;

fn putGrant(mock: *MockBackend, alloc: Allocator, id: []const u8, action: []const u8, scope: []const u8) !void {
    const record = try grants.buildGrantRecord(alloc, .{
        .id = id,
        .action = action,
        .scope = scope,
        .granted_by = "did:key:holder",
        .granted_at = "2026-01-01T00:00:00Z",
    });
    defer alloc.free(record);
    const key = try std.fmt.allocPrint(alloc, "grants/{s}.json", .{id});
    defer alloc.free(key);
    const owned_key = try alloc.dupe(u8, key);
    errdefer alloc.free(owned_key);
    const owned_record = try alloc.dupe(u8, record);
    errdefer alloc.free(owned_record);
    try mock.entries.put(alloc, owned_key, owned_record);
}

test "recordToolGrant writes a grants/ entry for mapped tools only" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    var mock = MockBackend{};
    defer mock.deinit(alloc);
    var store = try store_redirect.Store.init(alloc, home, mock.backend());
    defer store.deinit();

    const id = (try recordToolGrant(alloc, &store, "run_command", "make *", 1_700_000_000_000)).?;
    defer alloc.free(id);

    const key = try std.fmt.allocPrint(alloc, "grants/{s}.json", .{id});
    defer alloc.free(key);
    const record = mock.entries.get(key).?;
    var doc = (try grants.parseGrantDoc(alloc, record)).?;
    defer doc.deinit(alloc);
    try testing.expectEqualStrings("shell.exec", doc.grant.action);
    try testing.expectEqualStrings("make *", doc.grant.scope);
    try testing.expectEqualStrings("2023-11-14T22:13:20Z", doc.grant.granted_at);

    // Unmapped tool names produce no record.
    try testing.expect((try recordToolGrant(alloc, &store, "mcp_other_thing", "*", 0)) == null);
}

test "listPending hides decided and unmapped grants" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    var mock = MockBackend{};
    defer mock.deinit(alloc);
    var store = try store_redirect.Store.init(alloc, home, mock.backend());
    defer store.deinit();

    try putGrant(&mock, alloc, "g-one", "fs.read", "src/**");
    try putGrant(&mock, alloc, "g-two", "net.fetch", "*");

    const pending = try listPending(alloc, &store, home, 0);
    defer {
        for (pending) |*g| g.deinit(alloc);
        alloc.free(pending);
    }
    try testing.expectEqual(@as(usize, 2), pending.len);

    // Journal a decision; the grant stops being pending.
    var journal = try DecisionJournal.load(alloc, home);
    defer journal.deinit(alloc);
    try journal.record(alloc, home, "g-one", .denied);

    const pending2 = try listPending(alloc, &store, home, 0);
    defer {
        for (pending2) |*g| g.deinit(alloc);
        alloc.free(pending2);
    }
    try testing.expectEqual(@as(usize, 1), pending2.len);
    try testing.expectEqualStrings("g-two", pending2[0].grant.id);
}
