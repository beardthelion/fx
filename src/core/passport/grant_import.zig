//! Pending-grant import pipeline and the passport grant record path.
//!
//! Read path (PS-061): `importPending` lists `grants/` entries, maps each
//! onto fx's tool model, and requires an explicit holder decision through
//! a Confirmer. Confirmed grants land as ordinary session grants on the
//! permission engine; every explicit decision is journaled locally so a
//! grant is never re-presented. Expired and unmapped grants skip without
//! prompting and without a journal entry: no holder decision was made, so
//! nothing is decided permanently.
//!
//! Write path (PS-062): `recordToolGrant` is the only route that writes
//! `grants/` entries, and callers invoke it only for grants the holder
//! confirmed. Imported grants are applied straight to the engine rather
//! than through that path, so a confirmed import never echoes back as a
//! new grant record.

const std = @import("std");
const grants = @import("grants.zig");
const io_mod = @import("../shared/io.zig");
const permissions = @import("../permissions/permissions.zig");
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

/// A passport grant pending holder review. String fields borrow from
/// `doc.backing`, which owns them.
pub const PendingGrant = struct {
    id: []const u8,
    action: []const u8,
    scope: []const u8,
    granted_by: []const u8,
    doc: grants.GrantDoc,

    pub fn deinit(self: *PendingGrant, alloc: Allocator) void {
        self.doc.deinit(alloc);
    }
};

fn grantPresentable(grant: grants.Grant, now_ms: i64) bool {
    if (grants.mappedToolNames(grant.action).len == 0) return false;
    if (grants.isExpired(grant, now_ms)) return false;
    return true;
}

/// List undecided grants under `grants/` that this harness could honor:
/// parseable, a known action class, unexpired, and absent from the
/// decision journal.
pub fn listPending(
    alloc: Allocator,
    store: *store_redirect.Store,
    home: []const u8,
    now_ms: i64,
) ![]PendingGrant {
    var journal = try DecisionJournal.load(alloc, home);
    defer journal.deinit(alloc);

    const keys = try store.listSurface(alloc, "grants");
    defer {
        for (keys) |k| alloc.free(k);
        alloc.free(keys);
    }

    var out: std.ArrayList(PendingGrant) = .empty;
    errdefer {
        for (out.items) |*g| g.deinit(alloc);
        out.deinit(alloc);
    }
    for (keys) |key| {
        const bytes = (try store.readSurface(alloc, key)) orelse continue;
        defer alloc.free(bytes);
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
        try out.append(alloc, .{
            .id = doc.grant.id,
            .action = doc.grant.action,
            .scope = doc.grant.scope,
            .granted_by = doc.grant.granted_by,
            .doc = doc,
        });
    }
    return out.toOwnedSlice(alloc);
}

// ─── Import pipeline ────────────────────────────────────────────────────

pub const ImportReport = struct {
    /// Grants presented to the holder.
    presented: usize = 0,
    /// Confirmed and applied to the permission engine.
    confirmed: usize = 0,
    /// Explicitly declined by the holder.
    denied: usize = 0,
    /// Decided earlier, expired, unmapped, or unparseable.
    skipped: usize = 0,
};

/// Import every undecided grant under `grants/`. Each grant is mapped and
/// confirmed individually; confirmed grants become session-scoped
/// permission grants on `engine`. Holder decisions are journaled.
pub fn importPending(
    alloc: Allocator,
    store: *store_redirect.Store,
    confirmer: grants.Confirmer,
    engine: *permissions.PermissionEngine,
    home: []const u8,
    now_ms: i64,
) !ImportReport {
    var journal = try DecisionJournal.load(alloc, home);
    defer journal.deinit(alloc);

    const keys = try store.listSurface(alloc, "grants");
    defer {
        for (keys) |k| alloc.free(k);
        alloc.free(keys);
    }

    var report: ImportReport = .{};
    for (keys) |key| {
        const bytes = (try store.readSurface(alloc, key)) orelse continue;
        defer alloc.free(bytes);
        var doc = (try grants.parseGrantDoc(alloc, bytes)) orelse {
            report.skipped += 1;
            continue;
        };
        defer doc.deinit(alloc);
        if (journal.decided(doc.grant.id) != null or
            !grantPresentable(doc.grant, now_ms))
        {
            report.skipped += 1;
            continue;
        }

        report.presented += 1;
        const pattern = try alloc.dupe(u8, doc.grant.scope);
        defer alloc.free(pattern);
        const mapped: grants.MappedGrant = .{
            .grant = doc.grant,
            .tool_names = grants.mappedToolNames(doc.grant.action),
            .pattern = pattern,
        };
        if (!confirmer.confirm(alloc, mapped)) {
            try journal.record(alloc, home, doc.grant.id, .denied);
            report.denied += 1;
            continue;
        }
        for (mapped.tool_names) |tool_name| {
            try engine.allow(alloc, tool_name, mapped.pattern);
        }
        try journal.record(alloc, home, doc.grant.id, .confirmed);
        report.confirmed += 1;
    }
    return report;
}

pub const DecideResult = enum { applied, denied, not_pending };

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
pub fn findPending(pending: []PendingGrant, id: []const u8) ?*PendingGrant {
    for (pending) |*g| {
        if (std.mem.eql(u8, g.id, id)) return g;
    }
    return null;
}

/// Record the holder's decision for one pending grant (PS-061). A
/// confirmed grant is applied straight to `engine` and never re-recorded
/// under grants/. Returns .not_pending when no undecided grant has `id`.
/// Callers with a shared engine should resolve the grant with
/// listPending/findPending, mutate under their own lock, then
/// recordDecision — this helper is for contexts where `engine` needs no
/// external synchronization.
pub fn decideGrant(
    alloc: Allocator,
    store: *store_redirect.Store,
    engine: *permissions.PermissionEngine,
    home: []const u8,
    id: []const u8,
    approve: bool,
    now_ms: i64,
) !DecideResult {
    const pending = try listPending(alloc, store, home, now_ms);
    defer {
        for (pending) |*g| g.deinit(alloc);
        alloc.free(pending);
    }
    const g = findPending(pending, id) orelse return .not_pending;
    if (approve) {
        for (grants.mappedToolNames(g.action)) |tool_name| {
            try engine.allow(alloc, tool_name, g.scope);
        }
        try recordDecision(alloc, home, g.id, .confirmed);
        return .applied;
    }
    try recordDecision(alloc, home, g.id, .denied);
    return .denied;
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
pub fn formatIso8601Z(alloc: Allocator, ms: i64) ![]u8 {
    const days = @divFloor(ms, 86400_000);
    const rem = @mod(ms, 86400_000);
    const civil = civilFromDays(days);
    return std.fmt.allocPrint(
        alloc,
        "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z",
        .{
            @as(u64, @intCast(civil.year)),
            @as(u64, civil.month),
            @as(u64, civil.day),
            @as(u64, @intCast(@divFloor(rem, 3600_000))),
            @as(u64, @intCast(@divFloor(@mod(rem, 3600_000), 60_000))),
            @as(u64, @intCast(@divFloor(@mod(rem, 60_000), 1000))),
        },
    );
}

const Civil = struct { year: i64, month: u8, day: u8 };

/// Inverse of grants.zig's daysFromCivil (Howard Hinnant's algorithm).
fn civilFromDays(z: i64) Civil {
    const zz = z + 719468;
    const era = @divFloor(zz, 146097);
    const doe: u64 = @intCast(zz - era * 146097);
    const yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const y: i64 = @as(i64, @intCast(yoe)) + era * 400;
    const doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const mp = (5 * doy + 2) / 153;
    const d: u8 = @intCast(doy - (153 * mp + 2) / 5 + 1);
    const m: u8 = @intCast(if (mp < 10) mp + 3 else mp - 9);
    return .{ .year = if (m <= 2) y + 1 else y, .month = m, .day = d };
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
    const granted_by = if (store.client) |c| c.did else "fx";

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

const MockBackend = struct {
    entries: std.StringHashMapUnmanaged([]u8) = .empty,

    fn deinit(self: *MockBackend, alloc: Allocator) void {
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            alloc.free(@constCast(kv.key_ptr.*));
            alloc.free(kv.value_ptr.*);
        }
        self.entries.deinit(alloc);
    }

    fn backend(self: *MockBackend) store_redirect.Backend {
        return .{ .ptr = self, .vtable = &vtable };
    }

    const vtable: store_redirect.Backend.VTable = .{
        .read = readImpl,
        .write = writeImpl,
        .delete = deleteImpl,
        .list = listImpl,
    };

    fn readImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) store_redirect.BackendError!?[]u8 {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        const value = self.entries.get(key) orelse return null;
        return try alloc.dupe(u8, value);
    }

    fn writeImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8, bytes: []const u8) store_redirect.BackendError!void {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        if (self.entries.fetchRemove(key)) |kv| {
            alloc.free(@constCast(kv.key));
            alloc.free(kv.value);
        }
        try self.entries.put(alloc, try alloc.dupe(u8, key), try alloc.dupe(u8, bytes));
    }

    fn deleteImpl(ptr: *anyopaque, alloc: Allocator, key: []const u8) store_redirect.BackendError!void {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
        if (self.entries.fetchRemove(key)) |kv| {
            alloc.free(@constCast(kv.key));
            alloc.free(kv.value);
        }
    }

    fn listImpl(ptr: *anyopaque, alloc: Allocator, prefix: []const u8) store_redirect.BackendError![][]u8 {
        const self: *MockBackend = @ptrCast(@alignCast(ptr));
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

const TestConfirmer = struct {
    answer: bool = true,
    asked: usize = 0,
    only_id: ?[]const u8 = null,

    fn impl(ptr: *anyopaque, _: Allocator, grant: grants.MappedGrant) bool {
        const self: *TestConfirmer = @ptrCast(@alignCast(ptr));
        self.asked += 1;
        if (self.only_id) |id| return std.mem.eql(u8, grant.grant.id, id);
        return self.answer;
    }

    fn confirmer(self: *TestConfirmer) grants.Confirmer {
        return .{ .ptr = self, .confirm_fn = impl };
    }
};

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
    try mock.entries.put(alloc, try alloc.dupe(u8, key), try alloc.dupe(u8, record));
}

test "importPending applies only confirmed grants to the engine" {
    const alloc = testing.allocator;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    var mock = MockBackend{};
    defer mock.deinit(alloc);
    var store = try store_redirect.Store.init(alloc, home, mock.backend());
    defer store.deinit();

    try putGrant(&mock, alloc, "g-allow", "fs.read", "src/**");
    try putGrant(&mock, alloc, "g-deny", "shell.exec", "*");
    try putGrant(&mock, alloc, "g-foreign", "kernel.admin", "*");

    var engine: permissions.PermissionEngine = .{};
    defer engine.deinit(alloc);
    var confirmer = TestConfirmer{ .only_id = "g-allow" };

    const report = try importPending(alloc, &store, confirmer.confirmer(), &engine, home, 0);
    try testing.expectEqual(@as(usize, 2), report.presented);
    try testing.expectEqual(@as(usize, 1), report.confirmed);
    try testing.expectEqual(@as(usize, 1), report.denied);
    try testing.expectEqual(@as(usize, 1), report.skipped);
    try testing.expect(engine.isAllowed("read_file", "src/**"));
    try testing.expect(engine.isAllowed("list_files", "src/**"));
    try testing.expect(!engine.isAllowed("run_command", "*"));

    // A second import skips both decided grants without prompting.
    var again = TestConfirmer{};
    const report2 = try importPending(alloc, &store, again.confirmer(), &engine, home, 0);
    try testing.expectEqual(@as(usize, 0), report2.presented);
    try testing.expectEqual(@as(usize, 3), report2.skipped);
    try testing.expectEqual(@as(usize, 0), again.asked);
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
    try testing.expectEqualStrings("g-two", pending2[0].id);
}
