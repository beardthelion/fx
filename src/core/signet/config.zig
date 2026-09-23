//! Signet backend configuration: opt-in detection and FX_SIGNET_* env
//! custody.
//!
//! The backend is opt-in ONLY, resolved from exactly two sources:
//!   1. `~/.fx/settings.json` -> `"signet": {"enabled": true, "url": ...}`
//!   2. `FX_SIGNET_*` environment variables
//!
//! Committed project config (.fx.json) is never consulted: a checked-in
//! file must not be able to point a checkout at a shared state backend.
//!
//! FX_SIGNET_* variables can carry secrets (passphrase, seed). They are
//! captured at process start and then scrubbed from every environment
//! representation fx can pass to a spawned process, so tool and shell
//! children never inherit them.

const std = @import("std");
const builtin = @import("builtin");
const io_mod = @import("../shared/io.zig");
const profile_paths = @import("../shared/profile_paths.zig");
const secretscan = @import("secretscan.zig");

const Allocator = std.mem.Allocator;

extern "c" fn unsetenv(name: [*:0]const u8) c_int;
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;

pub const env_prefix = "FX_SIGNET_";
pub const env_enabled = "FX_SIGNET_ENABLED";
pub const env_url = "FX_SIGNET_URL";
pub const env_namespace = "FX_SIGNET_NAMESPACE";
pub const env_passphrase = "FX_SIGNET_PASSPHRASE";
pub const env_seed = "FX_SIGNET_SEED";
pub const env_scan = "FX_SIGNET_SCAN";

const custody_dir_name = "signet";
const passphrase_file_name = "passphrase";
const seed_file_name = "seed";

const max_settings_bytes: usize = 64 * 1024;
const max_secret_file_bytes: usize = 4 * 1024;

pub const Config = struct {
    /// Signet store base URL, e.g. http://localhost:8080.
    url: []u8,
    /// Explicit namespace override (normally derived from the genesis DID).
    namespace: ?[]u8 = null,
    /// Encryption passphrase; null when not yet resolvable.
    passphrase: ?[]u8 = null,
    /// Raw Ed25519 seed for the holder signing key, when provided.
    seed: ?[32]u8 = null,
    scan_mode: secretscan.ScanMode = .block,

    pub fn deinit(self: *Config, alloc: Allocator) void {
        alloc.free(self.url);
        if (self.namespace) |ns| alloc.free(ns);
        if (self.passphrase) |p| {
            secureFree(alloc, p);
        }
        self.* = undefined;
    }
};

fn secureFree(alloc: Allocator, bytes: []u8) void {
    // secureZero, not memset: the compiler may elide a dead store into a
    // buffer that is about to be freed.
    std.crypto.secureZero(u8, bytes);
    alloc.free(bytes);
}

// ─── Captured FX_SIGNET_* environment ─────────────────────────────────

var captured_mutex: std.Io.Mutex = .init;
var captured: ?std.StringHashMapUnmanaged([]const u8) = null;

/// The captured value of an FX_SIGNET_* variable. These are read before
/// scrubbing; after captureAndScrub runs they are unavailable from the
/// process environment by design.
pub fn capturedGet(key: []const u8) ?[]const u8 {
    captured_mutex.lockUncancelable(io_mod.getIo());
    defer captured_mutex.unlock(io_mod.getIo());
    const map = captured orelse return null;
    return map.get(key);
}

fn isSignetEnvKey(key: []const u8) bool {
    return std.mem.startsWith(u8, key, env_prefix);
}

/// Install the clone-time scrub hook so FX_SIGNET_* keys are dropped
/// from every child environment map, regardless of which environ
/// representation (raw envp, block, or host-installed map) a host set.
/// Idempotent.
pub fn installEnvScrub() void {
    io_mod.setEnvironScrubHook(isSignetEnvKey);
}

/// A signet env value, whether it was captured pre-scrub (raw envp
/// startup path) or is still readable from a host-installed environ map.
fn envValueFor(key: []const u8) ?[]const u8 {
    return capturedGet(key) orelse io_mod.getenv(key);
}

fn isSignetEnvEntry(entry: []const u8) bool {
    const eq = std.mem.findScalar(u8, entry, '=') orelse return false;
    return std.mem.startsWith(u8, entry[0..eq], env_prefix);
}

fn envKey(entry: []const u8) []const u8 {
    const eq = std.mem.findScalar(u8, entry, '=') orelse return entry;
    return entry[0..eq];
}

fn envValue(entry: []const u8) []const u8 {
    const eq = std.mem.findScalar(u8, entry, '=') orelse return "";
    return entry[eq + 1 ..];
}

fn unsetEnvPosix(key: []const u8) void {
    if (comptime !builtin.link_libc) return;
    if (key.len >= 256) return;
    var buf: [256]u8 = undefined;
    @memcpy(buf[0..key.len], key);
    buf[key.len] = 0;
    _ = unsetenv(buf[0..key.len :0]);
}

/// Capture every FX_SIGNET_* entry from `raw_env` without mutating it,
/// and install the clone-time scrub hook so child environments still drop
/// the secrets. Hosts embedding fx (napi) call this: the host's libc
/// environ is not ours to rewrite. Capture failure is fatal to the
/// caller — a secret we failed to keep must not silently fall back to
/// "disabled".
pub fn captureRawEnv(alloc: Allocator, raw_env: io_mod.RawEnviron) error{OutOfMemory}!void {
    installEnvScrub();
    captured_mutex.lockUncancelable(io_mod.getIo());
    defer captured_mutex.unlock(io_mod.getIo());

    var map: std.StringHashMapUnmanaged([]const u8) = captured orelse .empty;

    // raw_env may alias libc environ; nothing may mutate that array while
    // this loop walks it.
    var i: usize = 0;
    while (raw_env[i]) |entry_z| : (i += 1) {
        const entry = std.mem.sliceTo(entry_z, 0);
        if (!isSignetEnvEntry(entry)) continue;
        const key = try alloc.dupe(u8, envKey(entry));
        errdefer alloc.free(key);
        const value = try alloc.dupe(u8, envValue(entry));
        errdefer alloc.free(value);
        const gop = try map.getOrPut(alloc, key);
        if (gop.found_existing) {
            // Repeat capture of the same name (a second entry point calling
            // in): keep the stored key, refresh the value.
            alloc.free(key);
            alloc.free(gop.value_ptr.*);
        }
        gop.value_ptr.* = value;
    }
    captured = map;
}

/// Capture every FX_SIGNET_* entry from `raw_env`, then remove them in
/// place so downstream environ blocks (and therefore spawned children)
/// never see them. Call once, before io_mod.setRawEnviron, in the process
/// entry path. Only the owning process entry point may call this — it
/// rewrites the libc environ array.
pub fn captureAndScrubRaw(alloc: Allocator, raw_env: io_mod.MutRawEnviron) error{OutOfMemory}!void {
    try captureRawEnv(alloc, raw_env);

    captured_mutex.lockUncancelable(io_mod.getIo());
    defer captured_mutex.unlock(io_mod.getIo());

    // Pass 2: tell libc to drop its bookkeeping for each captured key. The
    // walk above is finished, so environ compaction is safe now. This is a
    // no-op on non-libc builds.
    if (captured) |map| {
        var it = map.iterator();
        while (it.next()) |kv| unsetEnvPosix(kv.key_ptr.*);
    }

    // Pass 3: compact the array in place. The envp pointer array is
    // process-writable memory (libc rewrites it on setenv), so this is
    // safe; it also covers the non-libc build where pass 2 did nothing.
    // raw_env arrives mutable (MutRawEnviron) so these stores are
    // visible to the caller — writing through a const-qualified pointer
    // would let the optimizer fold later reads back to the originals.
    var dst: usize = 0;
    var src: usize = 0;
    while (raw_env[src]) |entry_z| : (src += 1) {
        const entry = std.mem.sliceTo(entry_z, 0);
        if (isSignetEnvEntry(entry)) continue;
        raw_env[dst] = entry_z;
        dst += 1;
    }
    raw_env[dst] = null;
}

// ─── Config resolution ──────────────────────────────────────────────────

fn truthy(value: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, "1") or
        std.ascii.eqlIgnoreCase(value, "true") or
        std.ascii.eqlIgnoreCase(value, "yes") or
        std.ascii.eqlIgnoreCase(value, "on");
}

fn falsy(value: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, "0") or
        std.ascii.eqlIgnoreCase(value, "false") or
        std.ascii.eqlIgnoreCase(value, "no") or
        std.ascii.eqlIgnoreCase(value, "off");
}

fn readBoundedFile(alloc: Allocator, path: []const u8, max_bytes: usize) !?[]u8 {
    var file = io_mod.openExistingRegularFile(std.Io.Dir.cwd(), path, .read_only) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io_mod.getIo());
    return try io_mod.readFileToEnd(alloc, &file, max_bytes);
}

const SettingsSignet = struct {
    enabled: bool = false,
    url: ?[]u8 = null,
    namespace: ?[]u8 = null,
};

/// Read only the "signet" block out of ~/.fx/settings.json. This is a
/// minimal, read-only parse: the settings store itself is untouched, and a
/// missing, unreadable, or malformed file simply means "not configured".
/// Read errors must not surface here: the owning stores classify unsafe or
/// absent paths themselves, at their own stage, so a probe that reports
/// e.g. DurablePathUnsafe would reorder failure modes when the backend is
/// disabled.
fn readSettingsBlock(alloc: Allocator, home: []const u8) !?SettingsSignet {
    const path = try profile_paths.settingsPath(alloc, home);
    defer alloc.free(path);
    const bytes = readBoundedFile(alloc, path, max_settings_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    } orelse return null;
    defer alloc.free(bytes);

    var parsed = std.json.parseFromSlice(std.json.Value, alloc, bytes, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const block = parsed.value.object.get("signet") orelse return null;
    if (block != .object) return null;

    var out: SettingsSignet = .{};
    if (block.object.get("enabled")) |v| {
        if (v == .bool) out.enabled = v.bool;
    }
    if (block.object.get("url")) |v| {
        if (v == .string) out.url = try alloc.dupe(u8, v.string);
    }
    if (block.object.get("namespace")) |v| {
        if (v == .string) out.namespace = try alloc.dupe(u8, v.string);
    }
    return out;
}

/// Read a 0600 custody file under ~/.fx/signet/. Refuses group/other
/// access bits, per SN-101.
fn readCustodyFile(alloc: Allocator, home: []const u8, name: []const u8) !?[]u8 {
    const dir_path = try std.fs.path.join(alloc, &.{ home, profile_paths.root_dir_name, custody_dir_name });
    defer alloc.free(dir_path);
    const path = try std.fs.path.join(alloc, &.{ dir_path, name });
    defer alloc.free(path);

    var file = io_mod.openExistingRegularFile(std.Io.Dir.cwd(), path, .read_only) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer file.close(io_mod.getIo());
    const stat = try file.stat(io_mod.getIo());
    if ((stat.permissions.toMode() & 0o077) != 0) return error.CustodyFilePermissions;
    const bytes = try io_mod.readFileToEnd(alloc, &file, max_secret_file_bytes);
    const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
    const out = try alloc.dupe(u8, trimmed);
    alloc.free(bytes);
    return out;
}

fn parseSeedHex(text: []const u8) ?[32]u8 {
    var seed: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&seed, text) catch return null;
    return seed;
}

/// Resolve the effective signet config for a home dir. Returns null when
/// the backend is disabled. The caller owns the Config's slices; free with
/// Config.deinit.
pub fn resolve(alloc: Allocator, home: []const u8) !?Config {
    var enabled = false;
    var url: ?[]u8 = null;
    var namespace: ?[]u8 = null;
    errdefer {
        if (url) |u| alloc.free(u);
        if (namespace) |n| alloc.free(n);
    }

    if (try readSettingsBlock(alloc, home)) |block| {
        enabled = block.enabled;
        if (block.url) |u| url = u;
        if (block.namespace) |n| namespace = n;
    }

    // Environment wins over settings.json (fx's standard precedence), and
    // can also explicitly disable. An explicit FX_SIGNET_ENABLED=0 takes
    // precedence over everything else, including a URL that would
    // otherwise imply enablement.
    var explicit_disable = false;
    if (envValueFor(env_enabled)) |value| {
        if (truthy(value)) {
            enabled = true;
        } else if (falsy(value)) {
            enabled = false;
            explicit_disable = true;
        }
    }
    if (envValueFor(env_url)) |value| {
        if (value.len > 0) {
            if (url) |old| alloc.free(old);
            url = try alloc.dupe(u8, value);
            if (!explicit_disable) enabled = true;
        }
    }
    if (envValueFor(env_namespace)) |value| {
        if (value.len > 0) {
            if (namespace) |old| alloc.free(old);
            namespace = try alloc.dupe(u8, value);
        }
    }

    if (!enabled) {
        if (url) |u| alloc.free(u);
        if (namespace) |n| alloc.free(n);
        return null;
    }

    const final_url = url orelse return error.SignetUrlMissing;

    var config: Config = .{ .url = final_url, .namespace = namespace };

    if (envValueFor(env_scan)) |value| {
        if (std.ascii.eqlIgnoreCase(value, "warn")) {
            config.scan_mode = .warn;
        } else if (std.ascii.eqlIgnoreCase(value, "off")) {
            config.scan_mode = .off;
        }
    }

    if (envValueFor(env_passphrase)) |value| {
        config.passphrase = try alloc.dupe(u8, value);
    } else if (try readCustodyFile(alloc, home, passphrase_file_name)) |bytes| {
        config.passphrase = bytes;
    }

    if (envValueFor(env_seed)) |value| {
        config.seed = parseSeedHex(value);
    } else if (try readCustodyFile(alloc, home, seed_file_name)) |bytes| {
        defer secureFree(alloc, bytes);
        config.seed = parseSeedHex(bytes);
    }

    return config;
}

// ─── Tests ──────────────────────────────────────────────────────────────

test "captureAndScrubRaw captures then strips FX_SIGNET_* entries" {
    const alloc = std.testing.allocator;

    const entries = [_][:0]u8{
        try alloc.dupeZ(u8, "HOME=/home/test"),
        try alloc.dupeZ(u8, "FX_SIGNET_URL=http://localhost:9"),
        try alloc.dupeZ(u8, "FX_SIGNET_ENABLED=1"),
        try alloc.dupeZ(u8, "PATH=/bin"),
    };
    defer for (entries) |e| alloc.free(e);
    var env_buf: [5]?[*:0]const u8 = undefined;
    for (entries, 0..) |e, i| env_buf[i] = e.ptr;
    env_buf[entries.len] = null;
    const raw_env: io_mod.MutRawEnviron = @ptrCast(&env_buf);

    try captureAndScrubRaw(alloc, raw_env);
    defer {
        // Release captured entries so the test allocator stays clean.
        captured_mutex.lockUncancelable(std.testing.io);
        if (captured) |*map| {
            var it = map.iterator();
            while (it.next()) |kv| {
                alloc.free(@constCast(kv.key_ptr.*));
                alloc.free(@constCast(kv.value_ptr.*));
            }
            map.deinit(alloc);
            captured = null;
        }
        captured_mutex.unlock(std.testing.io);
    }

    try std.testing.expectEqualStrings("http://localhost:9", capturedGet(env_url).?);
    try std.testing.expectEqualStrings("1", capturedGet(env_enabled).?);

    var remaining: usize = 0;
    while (env_buf[remaining]) |entry_z| : (remaining += 1) {
        const entry = std.mem.sliceTo(entry_z, 0);
        try std.testing.expect(!std.mem.startsWith(u8, entry, env_prefix));
    }
    try std.testing.expectEqual(@as(usize, 2), remaining);
}

test "captureAndScrubRaw captures every adjacent FX_SIGNET_* var from the real environ" {
    if (comptime !builtin.link_libc) return error.SkipZigTest;
    const alloc = std.testing.allocator;

    // Production hands main's c_envp to captureAndScrubRaw, and c_envp
    // aliases libc environ — the array unsetenv mutates. A synthetic buffer
    // cannot see that, so this test installs real environ entries.
    const names = [_][:0]const u8{
        "FX_SIGNET_U7_ALPHA",
        "FX_SIGNET_U7_BETA",
        "FX_SIGNET_U7_GAMMA",
    };
    const values = [_][:0]const u8{ "u7-alpha", "u7-beta", "u7-gamma" };

    // Isolate the assertion set: drop any ambient FX_SIGNET_* vars.
    // Collect-then-remove — the same rule the fix follows, because environ
    // shifts under unsetenv while it is being walked.
    while (true) {
        var hit: ?[]const u8 = null;
        var scan: usize = 0;
        while (std.c.environ[scan]) |entry_z| : (scan += 1) {
            const entry = std.mem.sliceTo(entry_z, 0);
            if (isSignetEnvEntry(entry)) {
                hit = envKey(entry);
                break;
            }
        }
        unsetEnvPosix(hit orelse break);
    }

    for (names, values) |name, value| {
        try std.testing.expectEqual(@as(c_int, 0), setenv(name, value, 1));
    }
    defer for (names) |name| unsetEnvPosix(name);
    defer {
        // Release the entries this test captured so the test allocator
        // stays clean and no residue leaks into later tests.
        captured_mutex.lockUncancelable(std.testing.io);
        defer captured_mutex.unlock(std.testing.io);
        if (captured) |*map| {
            for (names) |name| {
                if (map.fetchRemove(name)) |kv| {
                    alloc.free(@constCast(kv.key));
                    alloc.free(kv.value);
                }
            }
            if (map.count() == 0) {
                map.deinit(alloc);
                captured = null;
            }
        }
    }

    const raw_env: io_mod.MutRawEnviron = @ptrCast(std.c.environ);
    try captureAndScrubRaw(alloc, raw_env);

    // All three must be captured, not just the first — a removal that
    // shifts the array mid-iteration would silently drop the neighbours.
    for (names, values) |name, value| {
        const got = capturedGet(name) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings(value, got);
    }
    // And none may survive in environ.
    var scan: usize = 0;
    while (std.c.environ[scan]) |entry_z| : (scan += 1) {
        try std.testing.expect(!isSignetEnvEntry(std.mem.sliceTo(entry_z, 0)));
    }
}

test "resolve is disabled without settings or env" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    try std.testing.expect((try resolve(alloc, home)) == null);
}

test "resolve reads the settings.json signet block only" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    try tmp.dir.createDir(std.testing.io, ".fx", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".fx/settings.json",
        .data = "{\"model\":\"x\",\"signet\":{\"enabled\":true,\"url\":\"http://localhost:8080\"}}",
    });

    var config = (try resolve(alloc, home)).?;
    defer config.deinit(alloc);
    try std.testing.expectEqualStrings("http://localhost:8080", config.url);
    try std.testing.expect(config.scan_mode == .block);
}

test "explicit FX_SIGNET_ENABLED=0 beats settings and URL enablement" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);

    try tmp.dir.createDir(std.testing.io, ".fx", .default_dir);
    try tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".fx/settings.json",
        .data = "{\"signet\":{\"enabled\":true,\"url\":\"http://localhost:8080\"}}",
    });

    // The captured env carries both the explicit disable and a URL that
    // would otherwise imply enablement.
    const entries = [_][:0]u8{
        try alloc.dupeZ(u8, "FX_SIGNET_ENABLED=0"),
        try alloc.dupeZ(u8, "FX_SIGNET_URL=http://localhost:9"),
    };
    defer for (entries) |e| alloc.free(e);
    var env_buf: [3]?[*:0]const u8 = undefined;
    for (entries, 0..) |e, i| env_buf[i] = e.ptr;
    env_buf[entries.len] = null;
    const raw_env: io_mod.RawEnviron = @ptrCast(&env_buf);

    try captureRawEnv(alloc, raw_env);
    defer {
        captured_mutex.lockUncancelable(std.testing.io);
        if (captured) |*map| {
            var it = map.iterator();
            while (it.next()) |kv| {
                alloc.free(@constCast(kv.key_ptr.*));
                alloc.free(@constCast(kv.value_ptr.*));
            }
            map.deinit(alloc);
            captured = null;
        }
        captured_mutex.unlock(std.testing.io);
    }

    // An explicit disable wins over both the settings block and the URL.
    try std.testing.expect((try resolve(alloc, home)) == null);
}
