const std = @import("std");
const io_mod = @import("../../core/shared/io.zig");
const profile_paths = @import("../../core/shared/profile_paths.zig");
const signet_learn = @import("../../core/signet/learn.zig");
const store_redirect = @import("../../core/signet/store_redirect.zig");
const tool_args = @import("../../core/tooling/tool_args.zig");
const tool_dispatch = @import("../../core/tooling/tool_dispatch.zig");

const Allocator = std.mem.Allocator;
const max_memory_store_bytes: usize = 1024 * 1024;

const MemoryStoreError = error{
    OutOfMemory,
    MemoryStoreMalformed,
    MemoryStoreTooLarge,
    MemoryStoreUnreadable,
};

pub const Input = struct {
    action: []u8,
    fact: ?[]u8,
    learning_type: ?[]u8,
    title: ?[]u8,
    body: ?[]u8,
    slug: ?[]u8,

    pub fn deinit(self: *Input, alloc: Allocator) void {
        alloc.free(self.action);
        if (self.fact) |fact| alloc.free(fact);
        if (self.learning_type) |v| alloc.free(v);
        if (self.title) |v| alloc.free(v);
        if (self.body) |v| alloc.free(v);
        if (self.slug) |v| alloc.free(v);
        self.* = .{
            .action = &.{},
            .fact = null,
            .learning_type = null,
            .title = null,
            .body = null,
            .slug = null,
        };
    }
};

/// The fields a `learn` action carries; absent on other actions.
pub const LearnArgs = struct {
    learning_type: ?[]const u8 = null,
    title: ?[]const u8 = null,
    body: ?[]const u8 = null,
    slug: ?[]const u8 = null,
};

pub fn decode(ctx: tool_dispatch.DispatchContext, args_json: []const u8) tool_dispatch.DispatchError!tool_dispatch.DecodeResult {
    var parsed = std.json.parseFromSlice(std.json.Value, ctx.allocator, args_json, .{}) catch {
        return .{ .failure = try ctx.allocator.dupe(u8, "memory arguments must be valid JSON") };
    };
    defer parsed.deinit();

    if (parsed.value != .object) {
        return .{ .failure = try ctx.allocator.dupe(u8, "memory arguments must be an object") };
    }

    const action_value = parsed.value.object.get("action") orelse {
        return .{ .failure = try ctx.allocator.dupe(u8, "memory field \"action\" is required") };
    };
    if (action_value != .string) {
        return .{ .failure = try ctx.allocator.dupe(u8, "memory field \"action\" must be a string") };
    }

    const fact_value = parsed.value.object.get("fact");
    const fact: ?[]u8 = if (fact_value) |value|
        if (value == .string) try ctx.allocator.dupe(u8, value.string) else null
    else
        null;
    errdefer if (fact) |owned| ctx.allocator.free(owned);

    const learning_type = try dupeOptionalString(ctx.allocator, parsed.value.object.get("type"));
    errdefer if (learning_type) |owned| ctx.allocator.free(owned);
    const title = try dupeOptionalString(ctx.allocator, parsed.value.object.get("title"));
    errdefer if (title) |owned| ctx.allocator.free(owned);
    const body = try dupeOptionalString(ctx.allocator, parsed.value.object.get("body"));
    errdefer if (body) |owned| ctx.allocator.free(owned);
    const slug = try dupeOptionalString(ctx.allocator, parsed.value.object.get("slug"));
    errdefer if (slug) |owned| ctx.allocator.free(owned);

    const action = try ctx.allocator.dupe(u8, action_value.string);
    errdefer ctx.allocator.free(action);

    const input = try ctx.allocator.create(Input);
    errdefer ctx.allocator.destroy(input);
    input.* = .{
        .action = action,
        .fact = fact,
        .learning_type = learning_type,
        .title = title,
        .body = body,
        .slug = slug,
    };

    return .{ .input = .{ .ptr = input, .deinit_fn = inputDeinit } };
}

fn dupeOptionalString(alloc: Allocator, value: ?std.json.Value) Allocator.Error!?[]u8 {
    const v = value orelse return null;
    if (v != .string) return null;
    return try alloc.dupe(u8, v.string);
}

fn inputDeinit(ptr: *anyopaque, alloc: Allocator) void {
    const input: *Input = @ptrCast(@alignCast(ptr));
    input.deinit(alloc);
    alloc.destroy(input);
}

pub fn validate(ctx: tool_dispatch.DispatchContext, erased: tool_dispatch.ToolInput) tool_dispatch.DispatchError!?[]u8 {
    const input = erased.as(Input);
    if (!isSupportedAction(input.action)) {
        return try ctx.allocator.dupe(u8, "memory field \"action\" must be one of: save, list, clear, learn");
    }
    if (std.mem.eql(u8, input.action, "learn")) {
        if (input.learning_type == null or input.title == null or input.body == null) {
            return try ctx.allocator.dupe(u8, "memory action \"learn\" requires \"type\", \"title\", and \"body\"");
        }
        if (!signet_learn.isLearningType(input.learning_type.?)) {
            return try ctx.allocator.dupe(u8, "memory field \"type\" must be one of: user, feedback, project, reference");
        }
    }
    return null;
}

pub fn call(ctx: tool_dispatch.DispatchContext, erased: tool_dispatch.ToolInput) tool_dispatch.DispatchError!tool_dispatch.ToolResult {
    const input = erased.as(Input);
    const output = runMemory(ctx.allocator, input.action, input.fact, .{
        .learning_type = input.learning_type,
        .title = input.title,
        .body = input.body,
        .slug = input.slug,
    }, ctx.workspace_root) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.MemoryStoreMalformed => return .{ .failure = try ctx.allocator.dupe(
            u8,
            "memory store is malformed; ~/.fx/memories.json was not modified. Repair or remove the file, then retry",
        ) },
        error.MemoryStoreTooLarge => return .{ .failure = try ctx.allocator.dupe(
            u8,
            "memory store exceeds the 1 MiB limit; ~/.fx/memories.json was not modified. Reduce or remove the file, then retry",
        ) },
        error.MemoryStoreUnreadable => return .{ .failure = try ctx.allocator.dupe(
            u8,
            "memory store could not be read; ~/.fx/memories.json was not modified. Check the file type and permissions, then retry",
        ) },
        error.MemoryClearFailed => return .{ .failure = try ctx.allocator.dupe(
            u8,
            "memory clear failed: saved memories were not removed; ensure ~/.fx/memories.json is a removable file and retry",
        ) },
        else => return .{ .failure = try std.fmt.allocPrint(ctx.allocator, "memory failed: {s}", .{@errorName(err)}) },
    };
    return .{ .success = output };
}

pub fn execute(arena: Allocator, args_json: []const u8) ![]u8 {
    const args = try tool_args.parseToolArgsObject(arena, args_json);
    const action = try tool_args.requiredStringArg(args, "action");
    const fact = tool_args.optionalStringArg(args, "fact");
    return runMemory(arena, action, fact, .{
        .learning_type = tool_args.optionalStringArg(args, "type"),
        .title = tool_args.optionalStringArg(args, "title"),
        .body = tool_args.optionalStringArg(args, "body"),
        .slug = tool_args.optionalStringArg(args, "slug"),
    }, null);
}

const memories_surface = "memories.json";

fn runMemory(
    alloc: Allocator,
    action: []const u8,
    fact: ?[]const u8,
    learn_args: LearnArgs,
    workspace_root: ?[]const u8,
) ![]u8 {
    if (!isSupportedAction(action)) return error.UnsupportedMemoryAction;

    const home = io_mod.getenv("HOME") orelse return std.fmt.allocPrint(alloc, "memory unavailable: HOME not set", .{});
    const memories_path = try profile_paths.memoriesPath(alloc, home);
    defer alloc.free(memories_path);

    // When the signet backend is enabled the memories surface lives in
    // the encrypted store; when it is not, every call below takes the same
    // local file path as before. openEnabled returns null when disabled
    // and propagates a misconfigured enabled state rather than falling
    // back to local files.
    const store: ?*store_redirect.Store = store_redirect.openEnabled(alloc, home) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MemoryStoreUnreadable,
    };
    defer if (store) |ptr| store_redirect.destroyOwned(ptr);

    if (std.mem.eql(u8, action, "save")) {
        const fact_value = fact orelse return std.fmt.allocPrint(alloc, "no fact provided", .{});
        return saveWithRetry(alloc, store, memories_path, fact_value);
    }

    if (std.mem.eql(u8, action, "learn")) {
        const ltype = learn_args.learning_type orelse
            return std.fmt.allocPrint(alloc, "learn requires \"type\"", .{});
        const title = learn_args.title orelse
            return std.fmt.allocPrint(alloc, "learn requires \"title\"", .{});
        const body = learn_args.body orelse
            return std.fmt.allocPrint(alloc, "learn requires \"body\"", .{});
        const learning: signet_learn.Learning = .{
            .type = ltype,
            .slug = learn_args.slug orelse "",
            .title = title,
            .body = body,
        };
        if (store) |signet| {
            return learnWithRetry(alloc, signet, learning, workspace_root);
        }
        // No signet backend: degrade to a flat memory so the fact the
        // agent chose to keep still persists.
        const flat = try std.fmt.allocPrint(alloc, "{s}: {s}", .{ title, body });
        defer alloc.free(flat);
        return saveWithRetry(alloc, null, memories_path, flat);
    }

    if (std.mem.eql(u8, action, "list")) {
        var existing = try loadMemories(alloc, store, memories_path);
        defer freeMemories(alloc, &existing);

        if (existing.items.len == 0) return std.fmt.allocPrint(alloc, "No saved memories", .{});

        var out: std.Io.Writer.Allocating = .init(alloc);
        defer out.deinit();
        for (existing.items) |memory| {
            try out.writer.print("- {s}\n", .{memory});
        }
        return try out.toOwnedSlice();
    }

    if (std.mem.eql(u8, action, "clear")) {
        if (store) |signet| {
            signet.deleteSurface(alloc, memories_surface) catch return error.MemoryClearFailed;
        } else {
            std.Io.Dir.deleteFileAbsolute(io_mod.getIo(), memories_path) catch |err| switch (err) {
                error.FileNotFound => {},
                else => return error.MemoryClearFailed,
            };
        }
        return std.fmt.allocPrint(alloc, "memories cleared", .{});
    }

    return error.UnsupportedMemoryAction;
}

/// Read->merge->write retries on a stale-base verdict.
const stale_base_max_attempts: u8 = 3;

/// A stale-base verdict means the remote moved under the
/// load->merge->write cycle; retry the whole cycle, bounded, so a
/// concurrent save is not silently dropped.
fn saveWithRetry(
    alloc: Allocator,
    store: ?*store_redirect.Store,
    memories_path: []const u8,
    fact_value: []const u8,
) ![]u8 {
    var attempt: u8 = 0;
    while (true) {
        attempt += 1;
        return saveMemoriesOnce(alloc, store, memories_path, fact_value) catch |err| switch (err) {
            error.SignetStaleBase => {
                if (attempt >= stale_base_max_attempts) return err;
                continue;
            },
            else => |e| return e,
        };
    }
}

/// One load->dedup->append->write pass of the "save" action.
fn saveMemoriesOnce(
    alloc: Allocator,
    store: ?*store_redirect.Store,
    memories_path: []const u8,
    fact_value: []const u8,
) ![]u8 {
    var existing = try loadMemories(alloc, store, memories_path);
    defer freeMemories(alloc, &existing);

    for (existing.items) |memory| {
        if (std.mem.eql(u8, memory, fact_value)) return std.fmt.allocPrint(alloc, "remembered", .{});
    }

    {
        const fact_copy = try alloc.dupe(u8, fact_value);
        errdefer alloc.free(fact_copy);
        try existing.append(alloc, fact_copy);
    }
    try saveMemories(alloc, store, memories_path, existing.items);
    return std.fmt.allocPrint(alloc, "remembered", .{});
}

/// A `learn` action is an immediate durable write through the store
/// seam; retry on a stale-base verdict like the memory save path.
fn learnWithRetry(
    alloc: Allocator,
    store: *store_redirect.Store,
    learning: signet_learn.Learning,
    workspace_root: ?[]const u8,
) ![]u8 {
    var attempt: u8 = 0;
    while (true) {
        attempt += 1;
        const saved = signet_learn.saveLearning(alloc, store, learning, workspace_root) catch |err| switch (err) {
            error.SignetStaleBase => {
                if (attempt >= stale_base_max_attempts) return err;
                continue;
            },
            else => |e| return e,
        };
        if (!saved) {
            return std.fmt.allocPrint(
                alloc,
                "learning rejected: invalid type, title, or body",
                .{},
            );
        }
        return std.fmt.allocPrint(alloc, "learned", .{});
    }
}

fn isSupportedAction(action: []const u8) bool {
    return std.mem.eql(u8, action, "save") or
        std.mem.eql(u8, action, "list") or
        std.mem.eql(u8, action, "clear") or
        std.mem.eql(u8, action, "learn");
}

fn loadMemories(alloc: Allocator, store: ?*store_redirect.Store, path: []const u8) MemoryStoreError!std.ArrayList([]u8) {
    var list: std.ArrayList([]u8) = .empty;
    errdefer freeMemories(alloc, &list);

    var content: []u8 = undefined;
    if (store != null and store.?.signetEnabled()) {
        const remote = store.?.readSurface(alloc, memories_surface) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.MemoryStoreUnreadable,
        };
        content = remote orelse return list;
        if (content.len > max_memory_store_bytes) {
            alloc.free(content);
            return error.MemoryStoreTooLarge;
        }
    } else {
        var file = io_mod.openExistingRegularFile(std.Io.Dir.cwd(), path, .read_only) catch |err| switch (err) {
            error.FileNotFound => return list,
            else => return error.MemoryStoreUnreadable,
        };
        defer file.close(io_mod.getIo());
        content = io_mod.readFileToEnd(alloc, &file, max_memory_store_bytes) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => return error.MemoryStoreTooLarge,
            else => return error.MemoryStoreUnreadable,
        };
    }
    defer alloc.free(content);

    const parsed = std.json.parseFromSlice(std.json.Value, alloc, content, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.MemoryStoreMalformed,
    };
    defer parsed.deinit();

    if (parsed.value != .array) return error.MemoryStoreMalformed;
    for (parsed.value.array.items) |item| {
        if (item != .string) return error.MemoryStoreMalformed;
        const owned = try alloc.dupe(u8, item.string);
        list.append(alloc, owned) catch |err| {
            alloc.free(owned);
            return err;
        };
    }
    return list;
}

fn freeMemories(alloc: Allocator, list: *std.ArrayList([]u8)) void {
    for (list.items) |memory| alloc.free(memory);
    list.deinit(alloc);
}

fn saveMemories(alloc: Allocator, store: ?*store_redirect.Store, path: []const u8, memories: []const []u8) !void {
    var out: std.Io.Writer.Allocating = .init(alloc);
    defer out.deinit();
    try out.writer.writeByte('[');
    for (memories, 0..) |memory, index| {
        if (index > 0) try out.writer.writeByte(',');
        try out.writer.writeByte('\n');
        try out.writer.writeAll("  ");
        try std.json.Stringify.value(memory, .{}, &out.writer);
    }
    if (memories.len > 0) try out.writer.writeByte('\n');
    try out.writer.writeAll("]\n");
    const json = try out.toOwnedSlice();
    defer alloc.free(json);

    if (store != null and store.?.signetEnabled()) {
        return store.?.writeSurface(alloc, memories_surface, json);
    }

    const dir_path = std.fs.path.dirname(path) orelse return error.InvalidPath;
    std.Io.Dir.createDirAbsolute(io_mod.getIo(), dir_path, .default_dir) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
    try io_mod.writeFileAtomic(alloc, path, json);
}

pub fn readsOnly(erased: tool_dispatch.ToolInput) bool {
    return std.mem.eql(u8, erased.as(Input).action, "list");
}

pub fn presentation(args: std.json.ObjectMap) ?tool_dispatch.CallPresentation {
    const action = tool_args.optionalStringArg(args, "action") orelse return null;
    if (!std.mem.eql(u8, action, "list")) return null;
    return .{
        .activity_kind = .read,
        .action_label = "Listing",
        .completed_action_label = "Listed",
        .label_arg_kind = .none,
        .label_arg_default = "memories",
    };
}

pub fn isIrreversible(erased: tool_dispatch.ToolInput) bool {
    return std.mem.eql(u8, erased.as(Input).action, "clear");
}

fn expectDecodeFailure(args_json: []const u8, expected: []const u8) !void {
    const alloc = std.testing.allocator;
    const decoded = try decode(.{ .allocator = alloc }, args_json);
    switch (decoded) {
        .failure => |body| {
            defer alloc.free(body);
            try std.testing.expectEqualStrings(expected, body);
        },
        .input => |input| {
            defer input.deinit(alloc);
            try std.testing.expect(false);
        },
    }
}

fn expectMemoryOutput(args_json: []const u8, expected: []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const output = try execute(arena, args_json);
    try std.testing.expectEqualStrings(expected, output);
}

fn expectValidationFailure(args_json: []const u8, expected: []const u8) !void {
    const alloc = std.testing.allocator;
    const decoded = try decode(.{ .allocator = alloc }, args_json);
    switch (decoded) {
        .failure => |body| {
            defer alloc.free(body);
            try std.testing.expect(false);
        },
        .input => |input| {
            defer input.deinit(alloc);
            const reason = (try validate(.{ .allocator = alloc }, input)) orelse {
                try std.testing.expect(false);
                return;
            };
            defer alloc.free(reason);
            try std.testing.expectEqualStrings(expected, reason);
        },
    }
}

fn setTestHome(home: ?[]const u8) !void {
    const map = try std.heap.c_allocator.create(std.process.Environ.Map);
    map.* = std.process.Environ.Map.init(std.heap.c_allocator);
    if (home) |value| try map.put("HOME", value);
    io_mod.setEnvironMap(map);
}

test "memory owner rejects invalid JSON and action shape" {
    try expectDecodeFailure("{", "memory arguments must be valid JSON");
    try expectDecodeFailure("[]", "memory arguments must be an object");
    try expectDecodeFailure("{}", "memory field \"action\" is required");
    try expectDecodeFailure("{\"action\":1}", "memory field \"action\" must be a string");
}

test "memory owner rejects unsupported actions before execution" {
    try expectValidationFailure(
        "{\"action\":\"replace\",\"fact\":\"new value\"}",
        "memory field \"action\" must be one of: save, list, clear, learn",
    );

    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    try std.testing.expectError(
        error.UnsupportedMemoryAction,
        execute(arena_state.allocator(), "{\"action\":\"replace\"}"),
    );
}

test "memory learn validates required fields and type" {
    try expectValidationFailure(
        "{\"action\":\"learn\"}",
        "memory action \"learn\" requires \"type\", \"title\", and \"body\"",
    );
    try expectValidationFailure(
        "{\"action\":\"learn\",\"type\":\"user\",\"title\":\"x\"}",
        "memory action \"learn\" requires \"type\", \"title\", and \"body\"",
    );
    try expectValidationFailure(
        "{\"action\":\"learn\",\"type\":\"evil\",\"title\":\"x\",\"body\":\"y\"}",
        "memory field \"type\" must be one of: user, feedback, project, reference",
    );
}

test "memory learn without signet degrades to a flat memory" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io_mod.getIo(), "home");
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, "home");
    defer alloc.free(home);
    try setTestHome(home);
    defer setTestHome(null) catch {};

    try expectMemoryOutput(
        "{\"action\":\"learn\",\"type\":\"project\",\"title\":\"We chose pnpm\",\"body\":\"We decided pnpm for this repo.\"}",
        "remembered",
    );
    try expectMemoryOutput(
        "{\"action\":\"list\"}",
        "- We chose pnpm: We decided pnpm for this repo.\n",
    );
}

test "memory learn decodes the extra fields" {
    const alloc = std.testing.allocator;
    const decoded = try decode(
        .{ .allocator = alloc },
        "{\"action\":\"learn\",\"type\":\"feedback\",\"title\":\"t\",\"body\":\"b\",\"slug\":\"s\"}",
    );
    switch (decoded) {
        .failure => |body| {
            defer alloc.free(body);
            try std.testing.expect(false);
        },
        .input => |input| {
            defer input.deinit(alloc);
            const typed = input.as(Input);
            try std.testing.expectEqualStrings("learn", typed.action);
            try std.testing.expectEqualStrings("feedback", typed.learning_type.?);
            try std.testing.expectEqualStrings("t", typed.title.?);
            try std.testing.expectEqualStrings("b", typed.body.?);
            try std.testing.expectEqualStrings("s", typed.slug.?);
        },
    }
}

test "memory clear fails closed when state cannot be deleted" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io_mod.getIo(), "home/.fx/memories.json");
    {
        var survivor = try tmp.dir.createFile(
            io_mod.getIo(),
            "home/.fx/memories.json/must-survive.txt",
            .{},
        );
        survivor.close(io_mod.getIo());
    }

    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, "home");
    defer alloc.free(home);
    try setTestHome(home);
    defer setTestHome(null) catch {};

    var arena_state = std.heap.ArenaAllocator.init(alloc);
    defer arena_state.deinit();
    try std.testing.expectError(
        error.MemoryClearFailed,
        execute(arena_state.allocator(), "{\"action\":\"clear\"}"),
    );

    var survivor = try tmp.dir.openFile(
        io_mod.getIo(),
        "home/.fx/memories.json/must-survive.txt",
        .{},
    );
    survivor.close(io_mod.getIo());
}

test "memory corrupt store fails closed and preserves original bytes" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io_mod.getIo(), "home/.fx");
    const corrupt_store = "[\"recoverable prior memory\",\n";
    try tmp.dir.writeFile(io_mod.getIo(), .{
        .sub_path = "home/.fx/memories.json",
        .data = corrupt_store,
    });

    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, "home");
    defer alloc.free(home);
    try setTestHome(home);
    defer setTestHome(null) catch {};

    var list_arena_state = std.heap.ArenaAllocator.init(alloc);
    defer list_arena_state.deinit();
    try std.testing.expectError(
        error.MemoryStoreMalformed,
        execute(list_arena_state.allocator(), "{\"action\":\"list\"}"),
    );

    var save_arena_state = std.heap.ArenaAllocator.init(alloc);
    defer save_arena_state.deinit();
    try std.testing.expectError(
        error.MemoryStoreMalformed,
        execute(save_arena_state.allocator(), "{\"action\":\"save\",\"fact\":\"replacement\"}"),
    );

    var file = try tmp.dir.openFile(io_mod.getIo(), "home/.fx/memories.json", .{});
    defer file.close(io_mod.getIo());
    const after = try io_mod.readFileToEnd(alloc, &file, 4096);
    defer alloc.free(after);
    try std.testing.expectEqualStrings(corrupt_store, after);
}

test "memory loader distinguishes missing oversized and unreadable stores" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io_mod.getIo(), "home/.fx");

    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, "home");
    defer alloc.free(home);
    const memories_path = try profile_paths.memoriesPath(alloc, home);
    defer alloc.free(memories_path);

    var missing = try loadMemories(alloc, null, memories_path);
    defer freeMemories(alloc, &missing);
    try std.testing.expectEqual(@as(usize, 0), missing.items.len);

    {
        var file = try std.Io.Dir.createFileAbsolute(io_mod.getIo(), memories_path, .{});
        defer file.close(io_mod.getIo());
        try file.setLength(io_mod.getIo(), max_memory_store_bytes + 1);
    }
    try std.testing.expectError(
        error.MemoryStoreTooLarge,
        loadMemories(alloc, null, memories_path),
    );

    try std.Io.Dir.deleteFileAbsolute(io_mod.getIo(), memories_path);
    try std.Io.Dir.createDirAbsolute(io_mod.getIo(), memories_path, .default_dir);
    try std.testing.expectError(
        error.MemoryStoreUnreadable,
        loadMemories(alloc, null, memories_path),
    );
}

test "memory owner preserves active output behavior" {
    const alloc = std.testing.allocator;
    try setTestHome(null);
    defer setTestHome(null) catch {};
    try expectMemoryOutput("{\"action\":\"list\"}", "memory unavailable: HOME not set");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(io_mod.getIo(), "home");
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, "home");
    defer alloc.free(home);
    try setTestHome(home);

    try expectMemoryOutput("{\"action\":\"list\"}", "No saved memories");
    try expectMemoryOutput("{\"action\":\"save\"}", "no fact provided");
    try expectMemoryOutput("{\"action\":\"save\",\"fact\":\"likes Zig\"}", "remembered");
    try expectMemoryOutput("{\"action\":\"save\",\"fact\":\"likes Zig\"}", "remembered");
    try expectMemoryOutput("{\"action\":\"list\"}", "- likes Zig\n");

    const memories_path = try profile_paths.memoriesPath(alloc, home);
    defer alloc.free(memories_path);
    var file = try std.Io.Dir.openFileAbsolute(io_mod.getIo(), memories_path, .{});
    const content = blk: {
        defer file.close(io_mod.getIo());
        break :blk try io_mod.readFileToEnd(alloc, &file, 4096);
    };
    defer alloc.free(content);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, content, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.array.items.len);
    try std.testing.expectEqualStrings("likes Zig", parsed.value.array.items[0].string);

    try expectMemoryOutput("{\"action\":\"clear\"}", "memories cleared");
    try expectMemoryOutput("{\"action\":\"list\"}", "No saved memories");
}

const test_server = @import("../../core/signet/test_server.zig");

test "memory save retries a stale base and still lands the fact" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    var mock = store_redirect.MockBackend{};
    defer mock.deinit(alloc);
    var flaky = test_server.FlakyBackend{
        .inner = mock.backend(),
        .stale_writes_left = 1,
    };
    var store = try store_redirect.Store.init(alloc, home, flaky.backend());
    defer store.deinit();

    const out = try saveWithRetry(alloc, &store, "/unused/memories.json", "likes Zig");
    defer alloc.free(out);
    try std.testing.expectEqualStrings("remembered", out);
    try std.testing.expectEqual(@as(usize, 2), flaky.write_calls);

    const remote = mock.entries.get("memory/memories.json") orelse
        return error.TestExpectedRemoteMemories;
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, remote, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.array.items.len);
    try std.testing.expectEqualStrings("likes Zig", parsed.value.array.items[0].string);
}
