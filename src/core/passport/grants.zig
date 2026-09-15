//! Grant vocabulary (PS-060..062) and the mapping into fx's action model.
//!
//! A passport grant is `{id, action, scope, constraints, granted_by,
//! granted_at, expires_at?}` recorded under `grants/`. Grants are NEVER
//! silently honored across harness boundaries (PS-061): an incoming grant
//! is mapped onto fx's own tool/permission model and the holder must
//! confirm before it takes effect. There is no automatic grant-application
//! path: the holder decides through `/permissions passport`
//! (grant_import.zig), and the only write path for grant records is
//! `buildGrantRecord` (PS-062).

const std = @import("std");
const identity = @import("identity.zig");

const Allocator = std.mem.Allocator;

/// PS-060 action classes.
pub const ActionClass = enum {
    fs_read,
    fs_write,
    shell_exec,
    net_fetch,
    agent_spawn,

    pub fn name(self: ActionClass) []const u8 {
        return switch (self) {
            .fs_read => "fs.read",
            .fs_write => "fs.write",
            .shell_exec => "shell.exec",
            .net_fetch => "net.fetch",
            .agent_spawn => "agent.spawn",
        };
    }

    pub fn fromName(s: []const u8) ?ActionClass {
        inline for (@typeInfo(ActionClass).@"enum".fields) |field| {
            const class: ActionClass = @enumFromInt(field.value);
            if (std.mem.eql(u8, s, class.name())) return class;
        }
        return null;
    }
};

/// A grant document as stored under grants/ (PS-060). Slices borrow from
/// the parsed JSON or caller buffers.
pub const Grant = struct {
    id: []const u8,
    action: []const u8,
    scope: []const u8,
    constraints: []const u8 = "",
    granted_by: []const u8,
    granted_at: []const u8,
    expires_at: ?[]const u8 = null,
};

/// How a passport action class lands in fx's tool permission model. The
/// mapped names are the tool names fx's saved rules and session grants key
/// on (see src/core/permissions/permissions.zig).
pub const fx_tool_names = struct {
    pub const fs_read = [_][]const u8{ "read_file", "list_files" };
    pub const fs_write = [_][]const u8{ "write_file", "edit_file" };
    pub const shell_exec = [_][]const u8{ "run_command", "terminal" };
    pub const net_fetch = [_][]const u8{"web_fetch"};
    pub const agent_spawn = [_][]const u8{"subagent"};
};

/// The fx tool names a grant action maps onto. An unrecognized class maps
/// to nothing — foreign grants outside the defined vocabulary are never
/// honored at all.
pub fn mappedToolNames(action: []const u8) []const []const u8 {
    const class = ActionClass.fromName(action) orelse return &.{};
    return switch (class) {
        .fs_read => &fx_tool_names.fs_read,
        .fs_write => &fx_tool_names.fs_write,
        .shell_exec => &fx_tool_names.shell_exec,
        .net_fetch => &fx_tool_names.net_fetch,
        .agent_spawn => &fx_tool_names.agent_spawn,
    };
}

fn stringField(obj: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const v = obj.get(name) orelse return null;
    if (v != .string) return null;
    return v.string;
}

/// Parse a grants/ entry, duping every field so the result outlives the
/// caller's JSON buffer. All fields are owned by the returned grant's
/// `backing` allocation; call GrantDoc.deinit to free.
pub const GrantDoc = struct {
    grant: Grant,
    backing: []u8,

    pub fn deinit(self: *GrantDoc, alloc: Allocator) void {
        alloc.free(self.backing);
        self.* = undefined;
    }
};

pub fn parseGrantDoc(alloc: Allocator, json_bytes: []const u8) !?GrantDoc {
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, json_bytes, .{}) catch
        return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const obj = parsed.value.object;

    const id = stringField(obj, "id") orelse return null;
    const action = stringField(obj, "action") orelse return null;
    const scope = stringField(obj, "scope") orelse return null;
    const granted_by = stringField(obj, "granted_by") orelse return null;
    const granted_at = stringField(obj, "granted_at") orelse return null;
    const constraints = stringField(obj, "constraints") orelse "";
    const expires_at = stringField(obj, "expires_at");

    const total = id.len + action.len + scope.len + granted_by.len +
        granted_at.len + constraints.len + (if (expires_at) |e| e.len else 0);
    const backing = try alloc.alloc(u8, total);
    errdefer alloc.free(backing);

    var rest = backing;
    const copy = struct {
        fn f(dst: *[]u8, src: []const u8) []const u8 {
            @memcpy(dst.*[0..src.len], src);
            const out = dst.*[0..src.len];
            dst.* = dst.*[src.len..];
            return out;
        }
    }.f;

    return .{
        .grant = .{
            .id = copy(&rest, id),
            .action = copy(&rest, action),
            .scope = copy(&rest, scope),
            .constraints = copy(&rest, constraints),
            .granted_by = copy(&rest, granted_by),
            .granted_at = copy(&rest, granted_at),
            .expires_at = if (expires_at) |e| copy(&rest, e) else null,
        },
        .backing = backing,
    };
}

/// Serialize a holder-confirmed grant record for storage under grants/
/// (PS-062). Canonical JSON, no whitespace. The caller owns the slice.
pub fn buildGrantRecord(alloc: Allocator, grant: Grant) ![]u8 {
    var map: std.json.ObjectMap = .empty;
    defer map.deinit(alloc);
    try map.put(alloc, "id", .{ .string = grant.id });
    try map.put(alloc, "action", .{ .string = grant.action });
    try map.put(alloc, "scope", .{ .string = grant.scope });
    if (grant.constraints.len > 0) {
        try map.put(alloc, "constraints", .{ .string = grant.constraints });
    }
    try map.put(alloc, "granted_by", .{ .string = grant.granted_by });
    try map.put(alloc, "granted_at", .{ .string = grant.granted_at });
    if (grant.expires_at) |exp| {
        try map.put(alloc, "expires_at", .{ .string = exp });
    }
    return identity.canonicalJson(alloc, .{ .object = map });
}

/// Whether a grant is expired (or unmapped) at `now_ms`. An unparseable
/// expiry counts as expired: an unchecked expiry is never honored.
pub fn isExpired(grant: Grant, now_ms: i64) bool {
    const exp = grant.expires_at orelse return false;
    return isoExpired(exp, now_ms);
}

/// Conservative ISO-8601 expiry check: only a full YYYY-MM-DDTHH:MM:SSZ
/// shape is interpreted; anything else is treated as not-yet-checkable and
/// the grant is skipped rather than honored.
fn isoExpired(iso: []const u8, now_ms: i64) bool {
    const epoch_ms = parseIso8601Z(iso) orelse return true; // unparseable: skip
    return epoch_ms <= now_ms;
}

fn parseIso8601Z(iso: []const u8) ?i64 {
    // Minimal strict parser for "YYYY-MM-DDTHH:MM:SS(.sss)?Z".
    if (iso.len < 20) return null;
    if (iso[4] != '-' or iso[7] != '-' or iso[10] != 'T' or
        iso[13] != ':' or iso[16] != ':') return null;
    const year = std.fmt.parseInt(i64, iso[0..4], 10) catch return null;
    const month = std.fmt.parseInt(u8, iso[5..7], 10) catch return null;
    const day = std.fmt.parseInt(u8, iso[8..10], 10) catch return null;
    const hour = std.fmt.parseInt(u8, iso[11..13], 10) catch return null;
    const minute = std.fmt.parseInt(u8, iso[14..16], 10) catch return null;
    const second = std.fmt.parseInt(u8, iso[17..19], 10) catch return null;
    if (month < 1 or month > 12 or day < 1 or day > 31 or hour > 23 or
        minute > 59 or second > 59) return null;
    var idx: usize = 19;
    if (idx < iso.len and iso[idx] == '.') {
        idx += 1;
        while (idx < iso.len and std.ascii.isDigit(iso[idx])) idx += 1;
    }
    if (idx != iso.len - 1 or iso[idx] != 'Z') return null;

    return daysFromCivil(year, month, day) * 86400_000 +
        @as(i64, hour) * 3600_000 + @as(i64, minute) * 60_000 + @as(i64, second) * 1000;
}

/// Days since the unix epoch for a civil date (Howard Hinnant's algorithm).
fn daysFromCivil(y: i64, m: u8, d: u8) i64 {
    const yy = if (m <= 2) y - 1 else y;
    const era = @divFloor(yy, 400);
    const yoe = yy - era * 400;
    const mm: i64 = m;
    const doy = @divFloor(153 * (if (mm > 2) mm - 3 else mm + 9) + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

// ─── Tests ──────────────────────────────────────────────────────────────

test "grant actions map onto fx tool names" {
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "read_file", "list_files" },
        mappedToolNames("fs.read"),
    );
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "write_file", "edit_file" },
        mappedToolNames("fs.write"),
    );
    try std.testing.expectEqualSlices(
        []const u8,
        &.{ "run_command", "terminal" },
        mappedToolNames("shell.exec"),
    );
    try std.testing.expectEqualSlices(
        []const u8,
        &.{"web_fetch"},
        mappedToolNames("net.fetch"),
    );
    try std.testing.expectEqualSlices(
        []const u8,
        &.{"subagent"},
        mappedToolNames("agent.spawn"),
    );
    // Foreign classes map to nothing.
    try std.testing.expectEqual(@as(usize, 0), mappedToolNames("kernel.exec").len);
}

test "expired grants are never presentable" {
    const grant: Grant = .{
        .id = "g3",
        .action = "shell.exec",
        .scope = "make *",
        .granted_by = "holder",
        .granted_at = "2026-01-01T00:00:00Z",
        .expires_at = "2026-02-01T00:00:00Z",
    };
    const later_ms = parseIso8601Z("2026-03-01T00:00:00Z").?;
    try std.testing.expect(isExpired(grant, later_ms));
    try std.testing.expect(!isExpired(grant, 0));
    // An unparseable expiry counts as expired: an unchecked expiry is
    // never honored.
    const bad: Grant = .{
        .id = "g5",
        .action = "shell.exec",
        .scope = "*",
        .granted_by = "holder",
        .granted_at = "2026-01-01T00:00:00Z",
        .expires_at = "soon",
    };
    try std.testing.expect(isExpired(bad, 0));
}

test "grant records serialize canonically and parse back" {
    const alloc = std.testing.allocator;
    const grant: Grant = .{
        .id = "g1",
        .action = "fs.read",
        .scope = "src/**",
        .granted_by = "holder",
        .granted_at = "2026-01-01T00:00:00Z",
    };
    const record = try buildGrantRecord(alloc, grant);
    defer alloc.free(record);
    try std.testing.expectEqualStrings(
        "{\"action\":\"fs.read\",\"granted_at\":\"2026-01-01T00:00:00Z\",\"granted_by\":\"holder\",\"id\":\"g1\",\"scope\":\"src/**\"}",
        record,
    );

    var doc = (try parseGrantDoc(alloc, record)).?;
    defer doc.deinit(alloc);
    try std.testing.expectEqualStrings("g1", doc.grant.id);
    try std.testing.expectEqualStrings("fs.read", doc.grant.action);
    try std.testing.expectEqualStrings("src/**", doc.grant.scope);
    try std.testing.expect(doc.grant.expires_at == null);

    try std.testing.expect((try parseGrantDoc(alloc, "{\"id\":1}")) == null);
    try std.testing.expect((try parseGrantDoc(alloc, "not json")) == null);
}
