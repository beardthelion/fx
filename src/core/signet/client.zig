//! Zero-knowledge signet store client (SPEC section 7).
//!
//! Wraps crypto, identity, and the HTTP contract so callers work in
//! plaintext and never touch ciphertext or the wire format. Encryption and
//! signing happen in-process; the passphrase and private key never leave
//! this machine. Everything the server can see stays inside the SN-034
//! metadata boundary.
//!
//! Wire protocol:
//!   POST /auth/challenge            -> {nonce, expiresAt}
//!   POST /auth/verify {did, nonce, sig, attestations?} -> {token, expiresAt}
//!   GET  /signet/<ns>             -> manifest view
//!   GET  /signet/<ns>?view=hashes -> {entryKey: sha256-hash}
//!   GET  /signet/<ns>?view=integrity -> the signed manifest blob
//!   GET  /signet/<ns>/<entryKey>  -> one ciphertext blob
//!   PUT  /signet/<ns>             -> {base, entries, deletions?}
//!
//! The transport is injectable so tests can stand up the wire contract
//! in-process without a socket.

const std = @import("std");
const io_mod = @import("../shared/io.zig");
const crypto = @import("crypto.zig");
const identity = @import("identity.zig");
const secretscan = @import("secretscan.zig");

const Allocator = std.mem.Allocator;

pub const spec_version = "signet-spec/0.1";

/// The entry carrying the signed integrity manifest (SN-040).
pub const manifest_entry_key = "identity/manifest.json";

const default_timeout_ms: i64 = 120_000;
const max_response_bytes: usize = 16 * 1024 * 1024;

// ─── Transport ──────────────────────────────────────────────────────────

pub const Header = std.http.Header;

pub const Request = struct {
    method: std.http.Method,
    url: []const u8,
    headers: []const Header = &.{},
    body: ?[]const u8 = null,
};

/// One answered request: the status line plus the body, already read.
/// `body` is allocated from the allocator handed to `request` and owned by
/// the caller.
pub const Response = struct {
    status: u16,
    body: []u8,

    pub fn ok(self: Response) bool {
        return self.status >= 200 and self.status < 300;
    }
};

pub const Transport = struct {
    ptr: *anyopaque,
    request_fn: *const fn (
        ptr: *anyopaque,
        alloc: Allocator,
        req: Request,
    ) anyerror!Response,

    pub fn request(self: Transport, alloc: Allocator, req: Request) anyerror!Response {
        return self.request_fn(self.ptr, alloc, req);
    }
};

/// Real HTTP transport over std.http.Client, following the bounded-read
/// pattern used elsewhere in fx (upgrade_helpers / mcp transports).
pub const HttpTransport = struct {
    client: std.http.Client,

    pub fn init(alloc: Allocator) HttpTransport {
        return .{ .client = .{ .allocator = alloc, .io = io_mod.getIo() } };
    }

    pub fn deinit(self: *HttpTransport) void {
        self.client.deinit();
    }

    pub fn transport(self: *HttpTransport) Transport {
        return .{ .ptr = self, .request_fn = requestImpl };
    }

    /// A hung store must not block a synchronous caller (the commit
    /// mirror runs on the write path), so every request races a deadline.
    /// When the deadline wins the request task is cancelled; cancellation
    /// reaches it at the next Io cancellation point. Io backends without
    /// task concurrency fail fast: an unbounded request against a hostile
    /// store is never allowed to run.
    fn requestImpl(ptr: *anyopaque, alloc: Allocator, req: Request) anyerror!Response {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        const zio = io_mod.getIo();
        const deadline = std.Io.Clock.Timestamp.fromNow(zio, .{
            .clock = .awake,
            .raw = .fromMilliseconds(default_timeout_ms),
        });

        const Event = union(enum) {
            response: anyerror!Response,
            deadline: anyerror!void,
        };
        const Ops = struct {
            fn runRequest(t: *HttpTransport, a: Allocator, r: Request) anyerror!Response {
                return t.requestInner(a, r);
            }
            fn waitDeadline(d: std.Io.Clock.Timestamp) anyerror!void {
                try d.wait(io_mod.getIo());
            }
            fn drain(a: Allocator, select: *std.Io.Select(Event)) void {
                // The losing task may still finish with an allocated
                // body; free it before dropping its event.
                while (select.cancel()) |item| switch (item) {
                    .response => |result| {
                        if (result) |res| a.free(res.body) else |_| {}
                    },
                    .deadline => {},
                };
            }
        };

        var buffer: [2]Event = undefined;
        var select: std.Io.Select(Event) = .init(zio, &buffer);
        select.concurrent(.deadline, Ops.waitDeadline, .{deadline}) catch {
            // No task concurrency on this backend: fail fast rather than
            // let a hostile store hold the request open without a bound.
            return error.SignetHttpFailed;
        };
        select.concurrent(.response, Ops.runRequest, .{ self, alloc, req }) catch {
            Ops.drain(alloc, &select);
            return error.SignetHttpFailed;
        };
        const event = select.await() catch {
            Ops.drain(alloc, &select);
            return error.SignetHttpFailed;
        };
        switch (event) {
            .response => |result| {
                Ops.drain(alloc, &select);
                return result;
            },
            .deadline => {
                Ops.drain(alloc, &select);
                return error.SignetHttpFailed;
            },
        }
    }

    fn requestInner(self: *HttpTransport, alloc: Allocator, req: Request) anyerror!Response {
        const uri = std.Uri.parse(req.url) catch return error.SignetHttpFailed;

        var http_req = self.client.request(req.method, uri, .{
            .redirect_behavior = .unhandled,
            .headers = .{
                .accept_encoding = .omit,
                .content_type = if (req.body != null)
                    .{ .override = "application/json" }
                else
                    .default,
            },
            .extra_headers = req.headers,
        }) catch return error.SignetHttpFailed;
        defer http_req.deinit();

        if (req.body) |body| {
            http_req.sendBodyComplete(@constCast(body)) catch return error.SignetHttpFailed;
        } else if (req.method.requestHasBody()) {
            // POST/PUT/PATCH always carry a body, even an empty one:
            // sendBodiless asserts the method is bodiless.
            var empty: [0]u8 = .{};
            http_req.sendBodyComplete(&empty) catch return error.SignetHttpFailed;
        } else {
            http_req.sendBodiless() catch return error.SignetHttpFailed;
        }

        var redirect_buf: [8192]u8 = undefined;
        var response = http_req.receiveHead(&redirect_buf) catch return error.SignetHttpFailed;
        if (response.head.status.class() == .redirect) return error.SignetHttpFailed;
        if (response.head.content_length) |len| {
            if (len > max_response_bytes) return error.SignetHttpFailed;
        }

        var out: std.Io.Writer.Allocating = .init(alloc);
        defer out.deinit();
        var transfer_buf: [4096]u8 = undefined;
        const reader = response.reader(&transfer_buf);
        var chunk: [4096]u8 = undefined;
        while (true) {
            const n = reader.readSliceShort(&chunk) catch return error.SignetHttpFailed;
            if (n == 0) break;
            if (n > max_response_bytes -| out.writer.buffered().len)
                return error.SignetHttpFailed;
            out.writer.writeAll(chunk[0..n]) catch return error.SignetHttpFailed;
        }
        return .{
            .status = @intFromEnum(response.head.status),
            .body = out.toOwnedSlice() catch return error.OutOfMemory,
        };
    }
};

// ─── Errors ─────────────────────────────────────────────────────────────

pub const Error = error{
    /// The store answered with a non-2xx status. `last_error` carries the
    /// server's own error code when it sent one.
    SignetHttp,
    /// The signed integrity manifest failed verification or rollback
    /// checks (SN-041). Fail closed.
    SignetIntegrity,
    /// A blob did not decrypt with this client's key or its hash did not
    /// match the verified manifest.
    SignetDecrypt,
    /// The server refused some entries of a push (SN-081: skipped, never a
    /// silent drop).
    SignetSkipped,
    /// The request body or response could not be understood.
    SignetProtocol,
    /// The store reports a stale `base` (409): nothing committed.
    SignetStaleBase,
    /// The persisted anti-rollback cursor could not be parsed (SN-041).
    /// Fail closed: an unreadable cursor must not reset the seq floor.
    SignetStateCorrupt,
    /// The anti-rollback cursor could not be persisted after a verified
    /// manifest adoption.
    SignetStatePersistFailed,
    /// A pushed entry carried a credential-shaped secret (SN-110).
    SecretFound,
    /// An entry key violated SN-020/021.
    InvalidEntryKey,
    /// The ciphertext payload was malformed (bad base64 or too short).
    CiphertextTooShort,
    UnsupportedCiphertextVersion,
    AuthenticationFailed,
    WeakParameters,
    OutputTooLong,
    OutOfMemory,
    SignetHttpFailed,
    IdentityElement,
    KeyMismatch,
    NonCanonical,
    WeakPublicKey,
};

/// Details of the last refused request, when the server sent them.
pub const ErrorDetail = struct {
    status: u16 = 0,
    code: []const u8 = "",

    pub fn deinit(self: *ErrorDetail, alloc: Allocator) void {
        if (self.code.len > 0) alloc.free(@constCast(self.code));
        self.* = .{};
    }
};

// ─── Result types ───────────────────────────────────────────────────────

pub const PushResult = struct {
    namespace: []const u8,
    /// The manifest seq this push published (unchanged on a no-op).
    seq: u64,
    uploaded: [][]u8,
    unchanged: [][]u8,
    deleted: [][]u8,

    pub fn deinit(self: *PushResult, alloc: Allocator) void {
        for (self.uploaded) |s| alloc.free(s);
        for (self.unchanged) |s| alloc.free(s);
        for (self.deleted) |s| alloc.free(s);
        alloc.free(self.uploaded);
        alloc.free(self.unchanged);
        alloc.free(self.deleted);
        self.* = undefined;
    }
};

pub const Entry = struct {
    key: []const u8,
    plaintext: []const u8,
};

pub const PullResult = struct {
    namespace: []const u8,
    seq: u64,
    /// Decrypted plaintext per entry key; slices owned by `arena`-style
    /// caller allocator.
    entries: []Entry,
};

// ─── Entry-key validation (SN-020/021) ──────────────────────────────────

const entry_sections = [_][]const u8{ "memory", "config", "sessions", "grants", "identity" };

pub fn isValidSegment(seg: []const u8) bool {
    if (seg.len == 0) return false;
    if (!std.ascii.isAlphanumeric(seg[0])) return false;
    for (seg) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '.' and ch != '_' and ch != '-')
            return false;
    }
    return true;
}

/// `sessions/<id>/<seq>` chunk suffix: six or more digits (SN-022).
pub fn isChunkSeq(seg: []const u8) bool {
    if (seg.len < 6) return false;
    for (seg) |ch| {
        if (!std.ascii.isDigit(ch)) return false;
    }
    return true;
}

/// The lexical shape every routed path must have: no traversal, no empty
/// or invalid segments. Shared with the redirect layer, which applies
/// this shape without the entry-section allowlist or the 255-byte cap.
pub fn isValidPathShape(path: []const u8) bool {
    if (path.len == 0) return false;
    if (path[0] == '/' or path[path.len - 1] == '/') return false;
    if (std.mem.find(u8, path, "..") != null) return false;
    if (std.mem.find(u8, path, "//") != null) return false;
    if (std.mem.findScalar(u8, path, '\\') != null) return false;
    if (std.mem.findScalar(u8, path, 0) != null) return false;
    var it = std.mem.splitScalar(u8, path, '/');
    while (it.next()) |seg| {
        if (!isValidSegment(seg)) return false;
    }
    return true;
}

pub fn isValidEntryKey(key: []const u8) bool {
    if (key.len > 255 or !isValidPathShape(key)) return false;
    var it = std.mem.splitScalar(u8, key, '/');
    const section = it.next() orelse return false;
    for (entry_sections) |s| {
        if (std.mem.eql(u8, section, s)) break;
    } else return false;
    if (std.mem.eql(u8, section, "sessions")) {
        // Session keys are exactly sessions/<id>/<seq>: a valid segment
        // id plus a six-or-more-digit chunk sequence (SN-022).
        const id_seg = it.next() orelse return false;
        const seq_seg = it.next() orelse return false;
        if (it.next() != null) return false;
        return isValidSegment(id_seg) and isChunkSeq(seq_seg);
    }
    // Every remaining segment is already shape-valid; the key needs at
    // least one segment past the section.
    return it.next() != null;
}

/// Percent-encode one path segment per RFC 3986 unreserved set.
fn urlEncodeSegment(alloc: Allocator, seg: []const u8) Allocator.Error![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const component: std.Uri.Component = .{ .raw = seg };
    component.formatEscaped(&out.writer) catch return error.OutOfMemory;
    return out.toOwnedSlice();
}

/// `sha256:` hex over the sorted `key\thash` lines — the PUT `base`.
pub fn manifestHash(alloc: Allocator, entry_hashes: []const Entry) Allocator.Error![]u8 {
    const sorted = try alloc.dupe(Entry, entry_hashes);
    defer alloc.free(sorted);
    std.mem.sort(Entry, sorted, {}, struct {
        fn lessThan(_: void, a: Entry, b: Entry) bool {
            return std.mem.lessThan(u8, a.key, b.key);
        }
    }.lessThan);
    var lines: std.Io.Writer.Allocating = .init(alloc);
    defer lines.deinit();
    for (sorted, 0..) |entry, i| {
        if (i > 0) lines.writer.writeByte('\n') catch return error.OutOfMemory;
        lines.writer.print("{s}\t{s}", .{ entry.key, entry.plaintext }) catch return error.OutOfMemory;
    }
    const digest = try identity.sha256Hex(alloc, lines.writer.buffered());
    defer alloc.free(digest);
    return std.fmt.allocPrint(alloc, "sha256:{s}", .{digest});
}

/// did.json payload — the same shape the reference client emits.
pub fn didDocument(alloc: Allocator, did: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        alloc,
        "{{\"did\":\"{s}\",\"method\":\"did:key\"}}\n",
        .{did},
    );
}

// ─── Client ─────────────────────────────────────────────────────────────

const VerifiedManifest = struct {
    seq: u64,
    /// Canonical JSON of the signed manifest body (SN-041 same-seq check).
    canonical: []u8,
    /// Decrypted manifest entry plaintext.
    plaintext: []u8,
    /// DID that signed the blob, verified cryptographically.
    signer_did: []u8,
    /// entryKey -> sha256 hash, as named by the verified manifest.
    entries: std.json.ObjectMap,

    fn deinit(self: *VerifiedManifest, alloc: Allocator) void {
        alloc.free(self.canonical);
        alloc.free(self.plaintext);
        alloc.free(self.signer_did);
        // entries' strings live in `plaintext`'s parse arena — we deep-duped
        // them into the map keys/values? No: see verifyManifestBlob, which
        // dupes each string with alloc.
        var it = self.entries.iterator();
        while (it.next()) |kv| {
            alloc.free(@constCast(kv.key_ptr.*));
            alloc.free(@constCast(kv.value_ptr.*.string));
        }
        self.entries.deinit(alloc);
        self.* = undefined;
    }
};

const Token = struct {
    value: []u8,
    expires_ms: i64,

    fn deinit(self: *Token, alloc: Allocator) void {
        alloc.free(self.value);
    }
};

pub const Client = struct {
    alloc: Allocator,
    transport: Transport,
    url: []const u8,
    key_pair: identity.Ed25519.KeyPair,
    did: []const u8,
    genesis_did: []const u8,
    attestations: []const identity.RotationAttestation,
    scan_mode: secretscan.ScanMode,
    enc_key: [crypto.key_len]u8,
    namespace: []u8,
    /// urlEncodeSegment(namespace), computed once at init.
    encoded_namespace: []u8,
    token: ?Token = null,
    last_seq: u64,
    /// sha256 hex of the last verified canonical manifest (SN-041). The
    /// hash is what persists across restarts, so the same-seq check
    /// compares hashes rather than retaining canonical bytes.
    last_manifest_hash: ?[]u8 = null,
    /// Where the anti-rollback cursor persists, when enabled.
    manifest_state_path: ?[]u8 = null,
    last_error: ErrorDetail = .{},
    /// Scan findings from the most recent push (warn mode, or a blocked
    /// push that reported SecretFound). Owned by the client.
    last_scan_findings: ?[]secretscan.Finding = null,

    pub const Options = struct {
        /// Base URL, e.g. http://localhost:8080 (no trailing slash needed).
        url: []const u8,
        /// Active signing key pair. Equals genesis until a rotation lands.
        key_pair: identity.Ed25519.KeyPair,
        /// DID of the active key.
        did: []const u8,
        /// The signet's immutable root DID. Defaults to `did`.
        genesis_did: ?[]const u8 = null,
        /// Explicit namespace override (SN-012): pins a namespace that
        /// differs from the genesis-DID-derived one (post-rotation
        /// holder). The entry key is derived against this namespace.
        /// Callers validate the shape before passing it in.
        namespace: ?[]const u8 = null,
        /// Rotation chain to present at /auth/verify (post-rotation auth).
        attestations: []const identity.RotationAttestation = &.{},
        /// Passphrase the entry key is derived from. Never sent.
        passphrase: []const u8,
        /// Secret-scan policy before encryption. Default block (SN-110).
        scan_mode: secretscan.ScanMode = .block,
        /// Last verified manifest seq (SN-041 anti-rollback).
        last_seq: u64 = 0,
        /// sha256 hex of the last verified canonical manifest, restored
        /// from persisted state so a restarted client still detects a
        /// same-seq manifest swap (SN-041).
        last_manifest_hash: ?[]const u8 = null,
        /// Where the anti-rollback cursor persists ({seq, canonical
        /// manifest hash}), e.g. ~/.fx/signet/manifest-state.json.
        /// Null disables persistence (tests, in-memory clients).
        manifest_state_path: ?[]const u8 = null,
    };

    pub fn init(alloc: Allocator, transport: Transport, opts: Options) !Client {
        const genesis_did = opts.genesis_did orelse opts.did;
        const namespace = if (opts.namespace) |ns|
            try alloc.dupe(u8, ns)
        else
            try identity.namespaceFor(alloc, genesis_did);
        errdefer alloc.free(namespace);
        const enc_key = try crypto.deriveKey(alloc, opts.passphrase, namespace);
        const encoded_namespace = try urlEncodeSegment(alloc, namespace);
        errdefer alloc.free(encoded_namespace);
        const last_manifest_hash: ?[]u8 = if (opts.last_manifest_hash) |hash|
            try alloc.dupe(u8, hash)
        else
            null;
        errdefer if (last_manifest_hash) |hash| alloc.free(hash);
        const manifest_state_path: ?[]u8 = if (opts.manifest_state_path) |path|
            try alloc.dupe(u8, path)
        else
            null;
        errdefer if (manifest_state_path) |path| alloc.free(path);
        var url = opts.url;
        if (url.len > 0 and url[url.len - 1] == '/') url = url[0 .. url.len - 1];
        return .{
            .alloc = alloc,
            .transport = transport,
            .url = url,
            .key_pair = opts.key_pair,
            .did = opts.did,
            .genesis_did = genesis_did,
            .attestations = opts.attestations,
            .scan_mode = opts.scan_mode,
            .enc_key = enc_key,
            .namespace = namespace,
            .encoded_namespace = encoded_namespace,
            .last_seq = opts.last_seq,
            .last_manifest_hash = last_manifest_hash,
            .manifest_state_path = manifest_state_path,
        };
    }

    pub fn deinit(self: *Client) void {
        if (self.token) |*t| t.deinit(self.alloc);
        if (self.last_manifest_hash) |h| self.alloc.free(h);
        if (self.manifest_state_path) |p| self.alloc.free(p);
        self.last_error.deinit(self.alloc);
        if (self.last_scan_findings) |f| secretscan.freeFindings(self.alloc, f);
        self.alloc.free(self.namespace);
        self.alloc.free(self.encoded_namespace);
        self.* = undefined;
    }

    pub fn manifestSeq(self: *const Client) u64 {
        return self.last_seq;
    }

    /// Scan findings left by the most recent push (warn mode, or a
    /// blocked push that reported SecretFound). Borrowed; invalidated by
    /// the next push or deinit.
    pub fn scanFindings(self: *const Client) ?[]const secretscan.Finding {
        return self.last_scan_findings;
    }

    // ─── Wire helpers ───────────────────────────────────────────────────

    fn setHttpError(self: *Client, res: Response) Error {
        self.last_error.deinit(self.alloc);
        self.last_error = .{ .status = res.status };
        // Extract the server's error code when it sent one.
        if (std.json.parseFromSlice(std.json.Value, self.alloc, res.body, .{})) |parsed| {
            defer parsed.deinit();
            if (parsed.value == .object) {
                if (parsed.value.object.get("error")) |err_obj| {
                    if (err_obj == .object) {
                        if (err_obj.object.get("code")) |code_v| {
                            if (code_v == .string) {
                                self.last_error.code = self.alloc.dupe(u8, code_v.string) catch &.{};
                            }
                        }
                    }
                }
            }
        } else |_| {}
        return error.SignetHttp;
    }

    fn rawRequest(
        self: *Client,
        method: std.http.Method,
        url: []const u8,
        headers: []const Header,
        body: ?[]const u8,
    ) Error!Response {
        return self.transport.request(self.alloc, .{
            .method = method,
            .url = url,
            .headers = headers,
            .body = body,
        }) catch |err| switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.SignetHttpFailed,
        };
    }

    fn endpointUrl(self: *Client, alloc: Allocator, suffix: []const u8) ![]u8 {
        return std.fmt.allocPrint(alloc, "{s}/signet/{s}{s}", .{ self.url, self.encoded_namespace, suffix });
    }

    fn entryUrl(self: *Client, alloc: Allocator, entry_key: []const u8) ![]u8 {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(alloc);
        try encoded.appendSlice(alloc, "/signet/");
        try encoded.appendSlice(alloc, self.encoded_namespace);
        var it = std.mem.splitScalar(u8, entry_key, '/');
        while (it.next()) |seg| {
            const encoded_seg = try urlEncodeSegment(alloc, seg);
            defer alloc.free(encoded_seg);
            try encoded.append(alloc, '/');
            try encoded.appendSlice(alloc, encoded_seg);
        }
        return std.fmt.allocPrint(alloc, "{s}{s}", .{ self.url, encoded.items });
    }

    /// Challenge/response auth (SN-090): fresh nonce signed by the active
    /// key, exchanged for a bearer. The rotation chain rides along whenever
    /// the active key is a successor (SN-052).
    fn authenticate(self: *Client) Error!void {
        const alloc = self.alloc;
        const challenge_url = try std.fmt.allocPrint(alloc, "{s}/auth/challenge", .{self.url});
        defer alloc.free(challenge_url);
        const challenge = try self.rawRequest(.POST, challenge_url, &.{}, null);
        defer alloc.free(challenge.body);
        if (!challenge.ok()) return self.setHttpError(challenge);

        var parsed = std.json.parseFromSlice(std.json.Value, alloc, challenge.body, .{}) catch
            return error.SignetProtocol;
        defer parsed.deinit();
        const nonce = blk: {
            if (parsed.value != .object) return error.SignetProtocol;
            const v = parsed.value.object.get("nonce") orelse return error.SignetProtocol;
            if (v != .string) return error.SignetProtocol;
            break :blk try alloc.dupe(u8, v.string);
        };
        defer alloc.free(nonce);

        // The signed preimage is domain-separated so a nonce can never be
        // replayed as some other document's signature (SN-090).
        const preimage = try std.fmt.allocPrint(alloc, "signet-auth:{s}", .{nonce});
        defer alloc.free(preimage);
        const sig = try identity.signMessage(alloc, &self.key_pair, preimage);
        defer alloc.free(sig);

        var body_map: std.json.ObjectMap = .empty;
        defer body_map.deinit(alloc);
        try body_map.put(alloc, "did", .{ .string = self.did });
        try body_map.put(alloc, "nonce", .{ .string = nonce });
        try body_map.put(alloc, "sig", .{ .string = sig });
        if (self.attestations.len > 0) {
            var arr = std.json.Array.init(alloc);
            defer {
                for (arr.items) |*v| {
                    if (v.* == .object) v.object.deinit(alloc);
                }
                arr.deinit();
            }
            for (self.attestations) |att| {
                var m: std.json.ObjectMap = .empty;
                errdefer m.deinit(alloc);
                try m.put(alloc, "genesisDid", .{ .string = att.genesis_did });
                try m.put(alloc, "newDid", .{ .string = att.new_did });
                try m.put(alloc, "seq", .{ .integer = @intCast(att.seq) });
                try m.put(alloc, "prevHash", .{ .string = att.prev_hash });
                try m.put(alloc, "sig", .{ .string = att.sig });
                try arr.append(.{ .object = m });
            }
            try body_map.put(alloc, "attestations", .{ .array = arr });
        }
        var body_out: std.Io.Writer.Allocating = .init(alloc);
        defer body_out.deinit();
        std.json.Stringify.value(
            @as(std.json.Value, .{ .object = body_map }),
            .{},
            &body_out.writer,
        ) catch return error.OutOfMemory;

        const verify_url = try std.fmt.allocPrint(alloc, "{s}/auth/verify", .{self.url});
        defer alloc.free(verify_url);
        const verified = try self.rawRequest(.POST, verify_url, &.{}, body_out.writer.buffered());
        defer alloc.free(verified.body);
        if (!verified.ok()) return self.setHttpError(verified);

        var verify_parsed = std.json.parseFromSlice(std.json.Value, alloc, verified.body, .{}) catch
            return error.SignetProtocol;
        defer verify_parsed.deinit();
        if (verify_parsed.value != .object) return error.SignetProtocol;
        const token_v = verify_parsed.value.object.get("token") orelse return error.SignetProtocol;
        if (token_v != .string) return error.SignetProtocol;
        const token_value = try alloc.dupe(u8, token_v.string);
        errdefer alloc.free(token_value);

        var expires_ms = io_mod.milliTimestamp() + 60_000;
        if (verify_parsed.value.object.get("expiresAt")) |exp_v| {
            if (exp_v == .string) {
                // ISO-8601 parse is overkill for the token TTL; fall back to
                // a 60s assumption when it is not a number.
            } else if (exp_v == .integer) {
                expires_ms = @intCast(exp_v.integer);
            }
        }

        if (self.token) |*t| t.deinit(alloc);
        self.token = .{ .value = token_value, .expires_ms = expires_ms };
    }

    /// An authenticated request: bearer attached, one re-auth + retry on
    /// 401 so an expired token mid-session is transparent.
    fn request(
        self: *Client,
        method: std.http.Method,
        url: []const u8,
        body: ?[]const u8,
        retried: bool,
    ) Error!Response {
        const alloc = self.alloc;
        if (self.token == null or self.token.?.expires_ms <= io_mod.milliTimestamp()) {
            try self.authenticate();
        }
        const auth_header = try std.fmt.allocPrint(alloc, "Bearer {s}", .{self.token.?.value});
        defer alloc.free(auth_header);
        const headers = [_]Header{.{ .name = "authorization", .value = auth_header }};
        const res = try self.rawRequest(method, url, &headers, body);
        if (res.status == 401 and !retried) {
            alloc.free(res.body);
            if (self.token) |*t| t.deinit(alloc);
            self.token = null;
            return self.request(method, url, body, true);
        }
        return res;
    }

    /// The ?view=hashes map, or null when the signet does not exist yet.
    /// Keys and values are owned by the caller (freed via freeHashMap).
    fn hashesView(self: *Client) Error!?std.json.ObjectMap {
        const alloc = self.alloc;
        const url = try self.endpointUrl(alloc, "?view=hashes");
        defer alloc.free(url);
        const res = try self.request(.GET, url, null, false);
        defer alloc.free(res.body);
        if (res.status == 404) {
            // Only the server's own "nothing here" is emptiness.
            const code_is_empty = blk: {
                var parsed = std.json.parseFromSlice(std.json.Value, alloc, res.body, .{}) catch
                    break :blk false;
                defer parsed.deinit();
                if (parsed.value != .object) break :blk false;
                const err_v = parsed.value.object.get("error") orelse break :blk false;
                if (err_v != .object) break :blk false;
                const code_v = err_v.object.get("code") orelse break :blk false;
                if (code_v != .string) break :blk false;
                break :blk std.mem.eql(u8, code_v.string, "empty");
            };
            if (!code_is_empty) return self.setHttpError(res);
            return null;
        }
        if (!res.ok()) return self.setHttpError(res);

        var parsed = std.json.parseFromSlice(std.json.Value, alloc, res.body, .{}) catch
            return error.SignetProtocol;
        defer parsed.deinit();
        if (parsed.value != .object) return error.SignetProtocol;

        var map: std.json.ObjectMap = .empty;
        errdefer freeHashMap(alloc, &map);
        var it = parsed.value.object.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.* != .string) return error.SignetProtocol;
            const owned_key = try alloc.dupe(u8, kv.key_ptr.*);
            errdefer alloc.free(owned_key);
            const owned_val = try alloc.dupe(u8, kv.value_ptr.string);
            errdefer alloc.free(owned_val);
            try map.put(alloc, owned_key, .{ .string = owned_val });
        }
        return map;
    }

    fn freeHashMap(alloc: Allocator, map: *std.json.ObjectMap) void {
        var it = map.iterator();
        while (it.next()) |kv| {
            alloc.free(@constCast(kv.key_ptr.*));
            alloc.free(@constCast(kv.value_ptr.*.string));
        }
        map.deinit(alloc);
    }

    const IntegrityView = union(enum) {
        ok: []u8,
        no_namespace,
        no_entry,
    };

    /// The ?view=integrity entry, or a status explaining its absence.
    fn integrityView(self: *Client) Error!IntegrityView {
        const alloc = self.alloc;
        const url = try self.endpointUrl(alloc, "?view=integrity");
        defer alloc.free(url);
        const res = try self.request(.GET, url, null, false);
        defer alloc.free(res.body);
        if (res.status == 404) {
            var parsed = std.json.parseFromSlice(std.json.Value, alloc, res.body, .{}) catch
                return self.setHttpError(res);
            defer parsed.deinit();
            if (parsed.value != .object) return self.setHttpError(res);
            const err_v = parsed.value.object.get("error") orelse return self.setHttpError(res);
            if (err_v != .object) return self.setHttpError(res);
            const code_v = err_v.object.get("code") orelse return self.setHttpError(res);
            if (code_v != .string) return self.setHttpError(res);
            if (std.mem.eql(u8, code_v.string, "empty")) return .no_namespace;
            if (std.mem.eql(u8, code_v.string, "entry_not_found")) return .no_entry;
            return self.setHttpError(res);
        }
        if (!res.ok()) return self.setHttpError(res);
        var parsed = std.json.parseFromSlice(std.json.Value, alloc, res.body, .{}) catch
            return error.SignetProtocol;
        defer parsed.deinit();
        if (parsed.value != .object) return error.SignetProtocol;
        const entry_v = parsed.value.object.get("entry") orelse return error.SignetProtocol;
        if (entry_v != .string) return error.SignetProtocol;
        return .{ .ok = try alloc.dupe(u8, entry_v.string) };
    }

    // ─── Integrity manifest (SN-040/041) ────────────────────────────────

    /// The DIDs allowed to have signed an integrity manifest: genesis, the
    /// active key, and every successor named by the rotation chain.
    /// The active key is always legal: its signature is still verified
    /// against the claimed DID's public key, so naming ourselves cannot be
    /// spoofed, and a post-rotation holder needs it to bootstrap the
    /// chain load before attestations are populated.
    fn isAuthorizedDid(self: *const Client, did: []const u8) bool {
        if (std.mem.eql(u8, did, self.genesis_did)) return true;
        if (std.mem.eql(u8, did, self.did)) return true;
        for (self.attestations) |att| {
            if (std.mem.eql(u8, att.new_did, did)) return true;
        }
        return false;
    }

    /// Decrypt, parse, and verify a signed manifest blob. Fail closed on
    /// every defect: bad signature, wrong signer, wrong genesis, or a seq
    /// that went backwards. `enforce_signer` checks the claimed DID
    /// against the authorized set; the rotation-chain bootstrap defers it
    /// (the signature is still verified) because the authorized set is
    /// what the chain itself establishes.
    fn verifyManifestBlob(self: *Client, blob: []const u8, enforce_signer: bool) Error!VerifiedManifest {
        const alloc = self.alloc;
        const plaintext = crypto.decryptEntry(alloc, &self.enc_key, manifest_entry_key, blob) catch
            return error.SignetDecrypt;
        errdefer alloc.free(plaintext);

        var parsed = std.json.parseFromSlice(std.json.Value, alloc, plaintext, .{}) catch
            return error.SignetIntegrity;
        defer parsed.deinit();
        if (parsed.value != .object) return error.SignetIntegrity;
        const obj = parsed.value.object;
        const manifest_v = obj.get("manifest") orelse return error.SignetIntegrity;
        const did_v = obj.get("did") orelse return error.SignetIntegrity;
        const sig_v = obj.get("sig") orelse return error.SignetIntegrity;
        if (manifest_v != .object or did_v != .string or sig_v != .string)
            return error.SignetIntegrity;
        const mobj = manifest_v.object;
        const seq_v = mobj.get("seq") orelse return error.SignetIntegrity;
        const genesis_v = mobj.get("genesisDid") orelse return error.SignetIntegrity;
        const entries_v = mobj.get("entries") orelse return error.SignetIntegrity;
        if (seq_v != .integer or seq_v.integer < 0) return error.SignetIntegrity;
        if (genesis_v != .string or entries_v != .object) return error.SignetIntegrity;

        if (!std.mem.eql(u8, genesis_v.string, self.genesis_did))
            return error.SignetIntegrity;
        if (enforce_signer and !self.isAuthorizedDid(did_v.string))
            return error.SignetIntegrity;

        const canonical = try identity.canonicalJson(alloc, manifest_v);
        errdefer alloc.free(canonical);
        if (!identity.verifyDidSignature(alloc, did_v.string, canonical, sig_v.string))
            return error.SignetIntegrity;

        const seq: u64 = @intCast(seq_v.integer);
        if (seq < self.last_seq) return error.SignetIntegrity;
        if (seq == self.last_seq and self.last_manifest_hash != null) {
            const incoming = try identity.sha256Hex(alloc, canonical);
            defer alloc.free(incoming);
            if (!std.mem.eql(u8, incoming, self.last_manifest_hash.?))
                return error.SignetIntegrity;
        }

        const signer_did = try alloc.dupe(u8, did_v.string);
        errdefer alloc.free(signer_did);

        var entries: std.json.ObjectMap = .empty;
        errdefer freeHashMap(alloc, &entries);
        var it = entries_v.object.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.* != .string) return error.SignetIntegrity;
            const owned_key = try alloc.dupe(u8, kv.key_ptr.*);
            errdefer alloc.free(owned_key);
            const owned_val = try alloc.dupe(u8, kv.value_ptr.string);
            errdefer alloc.free(owned_val);
            try entries.put(alloc, owned_key, .{ .string = owned_val });
        }

        return .{
            .seq = seq,
            .canonical = canonical,
            .plaintext = plaintext,
            .signer_did = signer_did,
            .entries = entries,
        };
    }

    /// Build + sign the next manifest over a projected entry-hash map. The
    /// manifest's own key is never listed.
    fn signManifest(
        self: *Client,
        entry_hashes: *const std.json.ObjectMap,
        seq: u64,
    ) Error!struct { plaintext: []u8, canonical: []u8 } {
        const alloc = self.alloc;

        var manifest: std.json.ObjectMap = .empty;
        defer manifest.deinit(alloc);
        try manifest.put(alloc, "seq", .{ .integer = @intCast(seq) });
        try manifest.put(alloc, "specVersion", .{ .string = spec_version });
        try manifest.put(alloc, "genesisDid", .{ .string = self.genesis_did });
        try manifest.put(alloc, "entries", .{ .object = entry_hashes.* });

        const canonical = try identity.canonicalJson(alloc, .{ .object = manifest });
        errdefer alloc.free(canonical);
        const sig = try identity.signMessage(alloc, &self.key_pair, canonical);
        defer alloc.free(sig);

        var signed: std.json.ObjectMap = .empty;
        defer signed.deinit(alloc);
        try signed.put(alloc, "manifest", .{ .object = manifest });
        try signed.put(alloc, "did", .{ .string = self.did });
        try signed.put(alloc, "sig", .{ .string = sig });
        const plaintext = try identity.canonicalJson(alloc, .{ .object = signed });
        return .{ .plaintext = plaintext, .canonical = canonical };
    }

    /// Fetch + verify the remote manifest. Null when the signet is empty.
    fn remoteManifest(self: *Client) Error!?VerifiedManifest {
        return self.remoteManifestMode(.enforce_signer);
    }

    const SignerMode = enum { enforce_signer, defer_signer };

    fn remoteManifestMode(self: *Client, mode: SignerMode) Error!?VerifiedManifest {
        const view = try self.integrityView();
        switch (view) {
            .no_namespace => return null,
            .no_entry => {
                // Entries exist but nothing signed them — a state this
                // client never produces. Fail closed rather than build on it.
                return error.SignetIntegrity;
            },
            .ok => |blob| {
                defer self.alloc.free(blob);
                return try self.verifyManifestBlob(blob, mode == .enforce_signer);
            },
        }
    }

    /// The remote manifest was cryptographically verified; adopt its seq
    /// and canonical hash as the local anti-rollback state and persist
    /// the cursor (SN-041). The write happens before the in-memory swap
    /// so a failed persist leaves the previous seq/hash fully intact and
    /// a mid-adoption error cannot blank the same-seq check.
    fn adoptManifest(self: *Client, verified: VerifiedManifest) Error!void {
        const alloc = self.alloc;
        const hash = try identity.sha256Hex(alloc, verified.canonical);
        errdefer alloc.free(hash);
        try self.persistManifestState(verified.seq, hash);
        self.last_seq = verified.seq;
        if (self.last_manifest_hash) |old| alloc.free(old);
        self.last_manifest_hash = hash;
    }

    /// Local counterpart of adoptManifest: adopt a manifest this client
    /// just signed and committed.
    fn adoptLocalManifest(self: *Client, seq: u64, canonical: []const u8) Error!void {
        const alloc = self.alloc;
        const hash = try identity.sha256Hex(alloc, canonical);
        errdefer alloc.free(hash);
        try self.persistManifestState(seq, hash);
        self.last_seq = seq;
        if (self.last_manifest_hash) |old| alloc.free(old);
        self.last_manifest_hash = hash;
    }

    /// A PUT `{base, entries, deletions?}` verdict: keys the store refused
    /// and deletions it confirmed. Slices are owned by the result.
    const CommitDeltaResult = struct {
        skipped: std.ArrayList([]u8) = .empty,
        deleted: std.ArrayList([]u8) = .empty,

        fn deinit(self: *CommitDeltaResult, alloc: Allocator) void {
            for (self.skipped.items) |s| alloc.free(s);
            self.skipped.deinit(alloc);
            for (self.deleted.items) |s| alloc.free(s);
            self.deleted.deinit(alloc);
        }

        fn containsSkipped(self: *const CommitDeltaResult, key: []const u8) bool {
            for (self.skipped.items) |s| {
                if (std.mem.eql(u8, s, key)) return true;
            }
            return false;
        }
    };

    /// PUT `{base, entries, deletions?}` against the namespace and return
    /// the server's verdict. `base_map` is the hash map the client
    /// believes the server currently holds; null means the namespace is
    /// expected to be empty.
    fn commitDelta(
        self: *Client,
        alloc: Allocator,
        base_map: ?*const std.json.ObjectMap,
        to_upload: *const std.json.ObjectMap,
        deletions: []const []const u8,
    ) Error!CommitDeltaResult {
        var body_map: std.json.ObjectMap = .empty;
        defer body_map.deinit(alloc);
        var base_str: ?[]u8 = null;
        defer if (base_str) |s| alloc.free(s);
        if (base_map) |map| {
            var hash_entries: std.ArrayList(Entry) = .empty;
            defer hash_entries.deinit(alloc);
            var hit = map.iterator();
            while (hit.next()) |kv| {
                try hash_entries.append(alloc, .{
                    .key = kv.key_ptr.*,
                    .plaintext = kv.value_ptr.string,
                });
            }
            base_str = try manifestHash(alloc, hash_entries.items);
            try body_map.put(alloc, "base", .{ .string = base_str.? });
        } else {
            try body_map.put(alloc, "base", .null);
        }
        var entries_arr: std.json.ObjectMap = .empty;
        defer entries_arr.deinit(alloc);
        var uit = to_upload.iterator();
        while (uit.next()) |kv| {
            try entries_arr.put(alloc, kv.key_ptr.*, kv.value_ptr.*);
        }
        try body_map.put(alloc, "entries", .{ .object = entries_arr });
        var del_arr: std.json.Array = .init(alloc);
        defer del_arr.deinit();
        if (deletions.len > 0) {
            for (deletions) |key| try del_arr.append(.{ .string = key });
            try body_map.put(alloc, "deletions", .{ .array = del_arr });
        }

        var body_out: std.Io.Writer.Allocating = .init(alloc);
        defer body_out.deinit();
        std.json.Stringify.value(
            @as(std.json.Value, .{ .object = body_map }),
            .{},
            &body_out.writer,
        ) catch return error.OutOfMemory;

        const url = try self.endpointUrl(alloc, "");
        defer alloc.free(url);
        const res = try self.request(.PUT, url, body_out.writer.buffered(), false);
        defer alloc.free(res.body);
        if (res.status == 409) return error.SignetStaleBase;
        if (!res.ok()) return self.setHttpError(res);

        var res_parsed = std.json.parseFromSlice(std.json.Value, alloc, res.body, .{}) catch
            return error.SignetProtocol;
        defer res_parsed.deinit();
        if (res_parsed.value != .object) return error.SignetProtocol;

        var result: CommitDeltaResult = .{};
        errdefer result.deinit(alloc);
        if (res_parsed.value.object.get("skipped")) |skipped_v| {
            if (skipped_v == .array) {
                for (skipped_v.array.items) |item| {
                    if (item != .string) continue;
                    const key_copy = try alloc.dupe(u8, item.string);
                    errdefer alloc.free(key_copy);
                    try result.skipped.append(alloc, key_copy);
                }
            }
        }
        if (res_parsed.value.object.get("deleted")) |del_v| {
            if (del_v == .array) {
                for (del_v.array.items) |item| {
                    if (item != .string) continue;
                    const key_copy = try alloc.dupe(u8, item.string);
                    errdefer alloc.free(key_copy);
                    try result.deleted.append(alloc, key_copy);
                }
            }
        }
        return result;
    }

    /// Persist the anti-rollback cursor {seq, canonical manifest hash}
    /// under the configured state path. No-op when persistence is off.
    /// Takes the candidate values explicitly so callers can persist
    /// before committing them to in-memory state.
    fn persistManifestState(self: *Client, seq: u64, hash: []const u8) Error!void {
        const path = self.manifest_state_path orelse return;
        const alloc = self.alloc;
        if (std.fs.path.dirname(path)) |dir| {
            io_mod.makeDirRecursive(dir) catch
                return error.SignetStatePersistFailed;
        }
        const body = try std.fmt.allocPrint(
            alloc,
            "{{\n  \"seq\": {d},\n  \"canonical_sha256\": \"{s}\"\n}}\n",
            .{ seq, hash },
        );
        defer alloc.free(body);
        io_mod.writeFileAtomic(alloc, path, body) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.SignetStatePersistFailed,
        };
    }

    /// Rebuild the rotation chain from `identity/rotations/<seq>.json`
    /// entries, verifying every attestation's linkage and predecessor
    /// signature (SN-051/052). The manifest's signer authorization is
    /// deferred until the chain is reconstructed: a manifest signed by an
    /// intermediate key is legitimate once the chain covers it.
    /// Returns the verified chain; the caller owns the slice and every
    /// field inside it.
    pub fn loadRotationChain(self: *Client, alloc: Allocator) Error![]identity.RotationAttestation {
        var remote_opt = try self.remoteManifestMode(.defer_signer);
        defer if (remote_opt) |*r| r.deinit(alloc);
        const remote = remote_opt orelse
            return try alloc.alloc(identity.RotationAttestation, 0);

        var chain: std.ArrayList(identity.RotationAttestation) = .empty;
        errdefer {
            for (chain.items) |*a| freeAttestation(alloc, a);
            chain.deinit(alloc);
        }
        var seq: u64 = 1;
        while (true) : (seq += 1) {
            const key = try std.fmt.allocPrint(alloc, "identity/rotations/{d}.json", .{seq});
            defer alloc.free(key);
            const expected = remote.entries.get(key) orelse break;
            if (expected != .string) return error.SignetIntegrity;
            const doc = try self.readVerifiedEntry(alloc, key, expected.string);
            defer alloc.free(doc);
            var att = try parseRotationAttestation(alloc, doc);
            errdefer freeAttestation(alloc, &att);
            if (att.seq != seq) return error.SignetIntegrity;
            if (!std.mem.eql(u8, att.genesis_did, self.genesis_did))
                return error.SignetIntegrity;
            const signer: []const u8 = if (seq == 1)
                self.genesis_did
            else
                chain.items[@intCast(seq - 2)].new_did;
            var owned_prev: ?[]u8 = null;
            defer if (owned_prev) |p| alloc.free(p);
            const expected_prev: []const u8 = if (seq == 1)
                identity.genesis_prev_hash
            else blk: {
                owned_prev = try identity.attestationHash(alloc, chain.items[@intCast(seq - 2)]);
                break :blk owned_prev.?;
            };
            if (!std.mem.eql(u8, att.prev_hash, expected_prev))
                return error.SignetIntegrity;
            if (!identity.verifyRotationAttestation(alloc, att, signer))
                return error.SignetIntegrity;
            try chain.append(alloc, att);
        }

        if (!self.signerAuthorizedWithChain(remote.signer_did, chain.items))
            return error.SignetIntegrity;
        try self.adoptManifest(remote);
        return try chain.toOwnedSlice(alloc);
    }

    /// Chain-aware signer check used while reconstructing the rotation
    /// chain at open time: genesis, the active key, or any chain
    /// successor may have signed the last manifest.
    fn signerAuthorizedWithChain(
        self: *const Client,
        did: []const u8,
        chain: []const identity.RotationAttestation,
    ) bool {
        if (std.mem.eql(u8, did, self.genesis_did)) return true;
        if (std.mem.eql(u8, did, self.did)) return true;
        for (chain) |att| {
            if (std.mem.eql(u8, att.new_did, did)) return true;
        }
        return false;
    }

    // ─── Public operations ──────────────────────────────────────────────

    /// Publish a new signet: identity/did.json plus the first signed
    /// integrity manifest. Refuses against a namespace that already holds
    /// a signet.
    pub fn initSignet(self: *Client) Error!PushResult {
        if (try self.hashesView() != null) return error.SignetProtocol;
        const doc = try didDocument(self.alloc, self.genesis_did);
        defer self.alloc.free(doc);
        const entries = [_]Entry{.{ .key = "identity/did.json", .plaintext = doc }};
        return self.push(&entries, &.{});
    }

    /// Encrypt + delta-push entries, then publish the next signed manifest.
    /// Plaintext is scanned for credential shapes BEFORE encryption
    /// (SN-110). `identity/manifest.json` is client-managed: a
    /// caller-supplied entry under that key is dropped.
    pub fn push(
        self: *Client,
        entries: []const Entry,
        deletions: []const []const u8,
    ) Error!PushResult {
        const alloc = self.alloc;

        // Strip the client-managed key before scanning/uploading.
        var user_entries: std.ArrayList(Entry) = .empty;
        defer user_entries.deinit(alloc);
        for (entries) |entry| {
            if (std.mem.eql(u8, entry.key, manifest_entry_key)) continue;
            if (!isValidEntryKey(entry.key)) return error.InvalidEntryKey;
            try user_entries.append(alloc, entry);
        }

        var user_deletions: std.ArrayList([]const u8) = .empty;
        defer user_deletions.deinit(alloc);
        for (deletions) |key| {
            if (std.mem.eql(u8, key, manifest_entry_key)) continue;
            try user_deletions.append(alloc, key);
        }

        // Secret scan before encryption (SN-110). Findings move to
        // last_scan_findings so a SecretFound error still reports them.
        if (self.last_scan_findings) |f| secretscan.freeFindings(alloc, f);
        self.last_scan_findings = null;
        var findings: std.ArrayList(secretscan.Finding) = .empty;
        var findings_owned = true;
        defer if (findings_owned) {
            for (findings.items) |*f| f.deinit(alloc);
            findings.deinit(alloc);
        };
        const scan_entries = try alloc.alloc(secretscan.Entry, user_entries.items.len);
        defer alloc.free(scan_entries);
        for (user_entries.items, 0..) |entry, i| {
            scan_entries[i] = .{ .key = entry.key, .text = entry.plaintext };
        }
        secretscan.enforce(alloc, scan_entries, self.scan_mode, &findings) catch |err| {
            // toOwnedSlice, not .items: capacity can exceed length, and a
            // size-tracking allocator needs the exact length back on
            // free. A failure here keeps findings owned so the defer
            // below still frees them.
            self.last_scan_findings = findings.toOwnedSlice(alloc) catch return err;
            findings_owned = false;
            return err;
        };
        self.last_scan_findings = try findings.toOwnedSlice(alloc);
        findings_owned = false;

        var hashes_opt = try self.hashesView();
        defer if (hashes_opt) |*h| freeHashMap(alloc, h);
        var remote_opt = try self.remoteManifest();
        defer if (remote_opt) |*r| r.deinit(alloc);
        if (remote_opt) |remote| try self.adoptManifest(remote);
        const base_seq: u64 = if (remote_opt) |r| r.seq else 0;

        // The unsigned ?view=hashes response is only the server's claim
        // about its own base state, never a source of keys for the signed
        // manifest. Require it to agree exactly with the verified
        // manifest's entries: a store reporting keys the holder never
        // signed, or hiding signed keys, is lying (fail closed).
        {
            var view_count: usize = 0;
            if (hashes_opt) |*view| {
                var vit = view.iterator();
                while (vit.next()) |kv| {
                    if (std.mem.eql(u8, kv.key_ptr.*, manifest_entry_key)) continue;
                    view_count += 1;
                    if (kv.value_ptr.* != .string) return error.SignetIntegrity;
                    const expected = if (remote_opt) |r|
                        r.entries.get(kv.key_ptr.*)
                    else
                        null;
                    if (expected == null or expected.? != .string or
                        !std.mem.eql(u8, expected.?.string, kv.value_ptr.string))
                        return error.SignetIntegrity;
                }
            }
            const verified_count = if (remote_opt) |r| r.entries.count() else 0;
            if (view_count != verified_count) return error.SignetIntegrity;
        }

        var to_upload: std.json.ObjectMap = .empty;
        defer freeHashMap(alloc, &to_upload);
        // Ciphertext hash per uploaded entry, needed to project the
        // server's post-delta map for the manifest commit's base.
        var uploaded_hashes: std.json.ObjectMap = .empty;
        defer freeHashMap(alloc, &uploaded_hashes);
        var uploaded: std.ArrayList([]u8) = .empty;
        defer uploaded.deinit(alloc);
        var unchanged: std.ArrayList([]u8) = .empty;
        defer unchanged.deinit(alloc);
        errdefer {
            for (uploaded.items) |s| alloc.free(s);
            for (unchanged.items) |s| alloc.free(s);
        }

        for (user_entries.items) |entry| {
            const blob = try crypto.encryptEntry(alloc, &self.enc_key, entry.key, entry.plaintext);
            defer alloc.free(blob);
            const hash = try crypto.ciphertextHash(alloc, blob);
            defer alloc.free(hash);

            var was_deleted = false;
            for (user_deletions.items) |key| {
                if (std.mem.eql(u8, key, entry.key)) {
                    was_deleted = true;
                    break;
                }
            }
            if (!was_deleted) {
                if (remote_opt) |r| {
                    if (r.entries.get(entry.key)) |existing| {
                        if (existing == .string and std.mem.eql(u8, existing.string, hash)) {
                            const key_copy = try alloc.dupe(u8, entry.key);
                            errdefer alloc.free(key_copy);
                            try unchanged.append(alloc, key_copy);
                            continue;
                        }
                    }
                }
            }

            {
                const owned_key = try alloc.dupe(u8, entry.key);
                errdefer alloc.free(owned_key);
                const owned_val = try alloc.dupe(u8, hash);
                errdefer alloc.free(owned_val);
                try uploaded_hashes.put(alloc, owned_key, .{ .string = owned_val });
            }
            {
                const owned_key = try alloc.dupe(u8, entry.key);
                errdefer alloc.free(owned_key);
                const owned_val = try alloc.dupe(u8, blob);
                errdefer alloc.free(owned_val);
                try to_upload.put(alloc, owned_key, .{ .string = owned_val });
            }
            {
                const key_copy = try alloc.dupe(u8, entry.key);
                errdefer alloc.free(key_copy);
                try uploaded.append(alloc, key_copy);
            }
        }

        var changed = uploaded.items.len > 0;
        if (!changed) {
            if (remote_opt) |r| {
                for (user_deletions.items) |key| {
                    if (r.entries.get(key) != null) {
                        changed = true;
                        break;
                    }
                }
            }
        }
        if (!changed) {
            return .{
                .namespace = self.namespace,
                .seq = base_seq,
                .uploaded = try uploaded.toOwnedSlice(alloc),
                .unchanged = try unchanged.toOwnedSlice(alloc),
                .deleted = try alloc.alloc([]u8, 0),
            };
        }

        // Phase 1: commit the entry/deletion delta without the manifest so
        // the server's per-entry verdict (skipped/deleted) is known before
        // anything is signed.
        var delta = try self.commitDelta(
            alloc,
            if (hashes_opt) |*h| h else null,
            &to_upload,
            user_deletions.items,
        );
        defer delta.deinit(alloc);

        // Project the server's post-delta map: its reported view minus
        // applied deletions, plus each entry it accepted. The manifest
        // commit's base is computed over this map, so a store that
        // rewrote state mid-push fails the base check.
        var post_map: std.json.ObjectMap = .empty;
        defer freeHashMap(alloc, &post_map);
        if (hashes_opt) |*view| {
            var vit = view.iterator();
            while (vit.next()) |kv| {
                const owned_key = try alloc.dupe(u8, kv.key_ptr.*);
                errdefer alloc.free(owned_key);
                const owned_val = try alloc.dupe(u8, kv.value_ptr.string);
                errdefer alloc.free(owned_val);
                try post_map.put(alloc, owned_key, .{ .string = owned_val });
            }
        }
        // Prefer the server's confirmed deletion list; an older store that
        // omits it applied the request's list.
        if (delta.deleted.items.len > 0) {
            for (delta.deleted.items) |key| {
                if (post_map.fetchOrderedRemove(key)) |kv| {
                    alloc.free(@constCast(kv.key));
                    alloc.free(@constCast(kv.value.string));
                }
            }
        } else {
            for (user_deletions.items) |key| {
                if (post_map.fetchOrderedRemove(key)) |kv| {
                    alloc.free(@constCast(kv.key));
                    alloc.free(@constCast(kv.value.string));
                }
            }
        }
        var uhit = uploaded_hashes.iterator();
        while (uhit.next()) |kv| {
            if (delta.containsSkipped(kv.key_ptr.*)) continue;
            const owned_key = try alloc.dupe(u8, kv.key_ptr.*);
            errdefer alloc.free(owned_key);
            const owned_val = try alloc.dupe(u8, kv.value_ptr.string);
            errdefer alloc.free(owned_val);
            try post_map.put(alloc, owned_key, .{ .string = owned_val });
        }

        // The signed manifest's entry map: verified remote entries plus
        // each accepted upload, minus applied deletions. It is derived
        // from the projection, so it can never name a skipped key or a
        // key only the unsigned view claimed.
        const seq = base_seq + 1;
        var next_hashes: std.json.ObjectMap = .empty;
        defer freeHashMap(alloc, &next_hashes);
        var mit = post_map.iterator();
        while (mit.next()) |kv| {
            if (std.mem.eql(u8, kv.key_ptr.*, manifest_entry_key)) continue;
            const owned_key = try alloc.dupe(u8, kv.key_ptr.*);
            errdefer alloc.free(owned_key);
            const owned_val = try alloc.dupe(u8, kv.value_ptr.string);
            errdefer alloc.free(owned_val);
            try next_hashes.put(alloc, owned_key, .{ .string = owned_val });
        }
        const signed_manifest = try self.signManifest(&next_hashes, seq);
        defer alloc.free(signed_manifest.plaintext);
        defer alloc.free(signed_manifest.canonical);

        const manifest_blob = try crypto.encryptEntry(
            alloc,
            &self.enc_key,
            manifest_entry_key,
            signed_manifest.plaintext,
        );
        defer alloc.free(manifest_blob);
        var manifest_map: std.json.ObjectMap = .empty;
        defer freeHashMap(alloc, &manifest_map);
        {
            const owned_key = try alloc.dupe(u8, manifest_entry_key);
            errdefer alloc.free(owned_key);
            const owned_val = try alloc.dupe(u8, manifest_blob);
            errdefer alloc.free(owned_val);
            try manifest_map.put(alloc, owned_key, .{ .string = owned_val });
        }

        // Phase 2: commit the signed manifest alone, based on the
        // post-delta map. A skipped manifest entry means the signed state
        // did not commit.
        var delta2 = try self.commitDelta(alloc, &post_map, &manifest_map, &.{});
        defer delta2.deinit(alloc);
        if (delta2.skipped.items.len > 0) return error.SignetSkipped;

        try self.adoptLocalManifest(seq, signed_manifest.canonical);

        {
            const key_copy = try alloc.dupe(u8, manifest_entry_key);
            errdefer alloc.free(key_copy);
            try uploaded.append(alloc, key_copy);
        }
        // Accepted uploads only: keys the store refused are removed from
        // the report.
        if (delta.skipped.items.len > 0) {
            var kept: std.ArrayList([]u8) = .empty;
            defer kept.deinit(alloc);
            for (uploaded.items) |key| {
                if (delta.containsSkipped(key)) {
                    alloc.free(key);
                    continue;
                }
                try kept.append(alloc, key);
            }
            uploaded.deinit(alloc);
            uploaded = kept;
            kept = .empty;
        }
        if (delta.skipped.items.len > 0) return error.SignetSkipped;

        return .{
            .namespace = self.namespace,
            .seq = seq,
            .uploaded = try uploaded.toOwnedSlice(alloc),
            .unchanged = try unchanged.toOwnedSlice(alloc),
            .deleted = try delta.deleted.toOwnedSlice(alloc),
        };
    }

    /// Pull + decrypt every entry named by the verified manifest (SN-041).
    /// Each blob's ciphertext hash is checked against the manifest before
    /// decryption — a blob the manifest does not name, or that fails GCM,
    /// is a hard error, never a silent skip.
    /// `result.entries` strings are allocated from `alloc` and owned by the
    /// caller.
    pub fn pull(self: *Client) Error!PullResult {
        const alloc = self.alloc;
        var remote_opt = try self.remoteManifest();
        defer if (remote_opt) |*r| r.deinit(alloc);
        const remote = remote_opt orelse {
            return .{
                .namespace = self.namespace,
                .seq = 0,
                .entries = try alloc.alloc(Entry, 0),
            };
        };
        try self.adoptManifest(remote);

        var entries: std.ArrayList(Entry) = .empty;
        errdefer {
            for (entries.items) |e| {
                alloc.free(@constCast(e.key));
                alloc.free(@constCast(e.plaintext));
            }
            entries.deinit(alloc);
        }

        var it = remote.entries.iterator();
        while (it.next()) |kv| {
            const entry_key = kv.key_ptr.*;
            const expected_hash = kv.value_ptr.string;
            const url = try self.entryUrl(alloc, entry_key);
            defer alloc.free(url);
            const res = try self.request(.GET, url, null, false);
            defer alloc.free(res.body);
            if (!res.ok()) return self.setHttpError(res);

            var parsed = std.json.parseFromSlice(std.json.Value, alloc, res.body, .{}) catch
                return error.SignetProtocol;
            defer parsed.deinit();
            if (parsed.value != .object) return error.SignetIntegrity;
            const entry_v = parsed.value.object.get("entry") orelse
                return error.SignetIntegrity;
            if (entry_v != .string) return error.SignetIntegrity;
            if (parsed.value.object.get("hash")) |hash_v| {
                if (hash_v != .string or !std.mem.eql(u8, hash_v.string, expected_hash))
                    return error.SignetIntegrity;
            }
            const actual_hash = try crypto.ciphertextHash(alloc, entry_v.string);
            defer alloc.free(actual_hash);
            if (!std.mem.eql(u8, actual_hash, expected_hash))
                return error.SignetIntegrity;

            const text = crypto.decryptEntry(alloc, &self.enc_key, entry_key, entry_v.string) catch
                return error.SignetDecrypt;
            errdefer alloc.free(text);
            const key_copy = try alloc.dupe(u8, entry_key);
            errdefer alloc.free(key_copy);
            try entries.append(alloc, .{
                .key = key_copy,
                .plaintext = text,
            });
        }
        // The manifest itself is signet state too.
        {
            const key_copy = try alloc.dupe(u8, manifest_entry_key);
            errdefer alloc.free(key_copy);
            const text_copy = try alloc.dupe(u8, remote.plaintext);
            errdefer alloc.free(text_copy);
            try entries.append(alloc, .{
                .key = key_copy,
                .plaintext = text_copy,
            });
        }

        return .{
            .namespace = self.namespace,
            .seq = remote.seq,
            .entries = try entries.toOwnedSlice(alloc),
        };
    }

    /// The ?view=hashes map as an entry list. Empty when the signet does
    /// not exist yet.
    /// Caller owns the returned slice and its strings.
    pub fn hashes(self: *Client) Error![]Entry {
        const alloc = self.alloc;
        var map_opt = try self.hashesView();
        defer if (map_opt) |*m| freeHashMap(alloc, m);
        const map = map_opt orelse return alloc.alloc(Entry, 0);
        var out: std.ArrayList(Entry) = .empty;
        errdefer {
            for (out.items) |e| {
                alloc.free(@constCast(e.key));
                alloc.free(@constCast(e.plaintext));
            }
            out.deinit(alloc);
        }
        var it = map.iterator();
        while (it.next()) |kv| {
            const key_copy = try alloc.dupe(u8, kv.key_ptr.*);
            errdefer alloc.free(key_copy);
            const val_copy = try alloc.dupe(u8, kv.value_ptr.string);
            errdefer alloc.free(val_copy);
            try out.append(alloc, .{
                .key = key_copy,
                .plaintext = val_copy,
            });
        }
        return out.toOwnedSlice(alloc);
    }

    /// Fetch, hash-check, and decrypt one entry the verified manifest
    /// already names. Shared by readEntry and readEntries.
    fn readVerifiedEntry(
        self: *Client,
        alloc: Allocator,
        entry_key: []const u8,
        expected_hash: []const u8,
    ) Error![]u8 {
        const url = try self.entryUrl(alloc, entry_key);
        defer alloc.free(url);
        const res = try self.request(.GET, url, null, false);
        defer alloc.free(res.body);
        if (!res.ok()) return self.setHttpError(res);
        var parsed = std.json.parseFromSlice(std.json.Value, alloc, res.body, .{}) catch
            return error.SignetProtocol;
        defer parsed.deinit();
        if (parsed.value != .object) return error.SignetIntegrity;
        const entry_v = parsed.value.object.get("entry") orelse return error.SignetIntegrity;
        if (entry_v != .string) return error.SignetIntegrity;
        if (parsed.value.object.get("hash")) |hash_v| {
            if (hash_v != .string or !std.mem.eql(u8, hash_v.string, expected_hash))
                return error.SignetIntegrity;
        }
        const actual_hash = try crypto.ciphertextHash(alloc, entry_v.string);
        defer alloc.free(actual_hash);
        if (!std.mem.eql(u8, actual_hash, expected_hash)) return error.SignetIntegrity;
        return crypto.decryptEntry(alloc, &self.enc_key, entry_key, entry_v.string) catch
            error.SignetDecrypt;
    }

    /// Read and decrypt one entry, verified against the signed manifest
    /// (SN-041). Returns null when the signet does not exist or the
    /// manifest does not name the key.
    pub fn readEntry(self: *Client, entry_key: []const u8) Error!?[]u8 {
        const alloc = self.alloc;
        var remote_opt = try self.remoteManifest();
        defer if (remote_opt) |*r| r.deinit(alloc);
        const remote = remote_opt orelse return null;
        try self.adoptManifest(remote);
        const expected = remote.entries.get(entry_key) orelse return null;
        return try self.readVerifiedEntry(alloc, entry_key, expected.string);
    }

    /// Read several entries under one manifest fetch+verify instead of
    /// one per entry. results[i] answers entry_keys[i]: null when the
    /// signet does not exist or the manifest does not name the key,
    /// the same contract as readEntry. Caller owns the slice and each
    /// non-null element.
    pub fn readEntries(self: *Client, alloc: Allocator, entry_keys: []const []const u8) Error![]?[]u8 {
        const results = try alloc.alloc(?[]u8, entry_keys.len);
        @memset(results, null);
        errdefer {
            for (results) |r| if (r) |b| alloc.free(b);
            alloc.free(results);
        }
        var remote_opt = try self.remoteManifest();
        defer if (remote_opt) |*r| r.deinit(self.alloc);
        const remote = remote_opt orelse return results;
        try self.adoptManifest(remote);
        for (entry_keys, 0..) |entry_key, i| {
            const expected = remote.entries.get(entry_key) orelse continue;
            results[i] = try self.readVerifiedEntry(alloc, entry_key, expected.string);
        }
        return results;
    }

    /// Rotate the signing key (SN-050/051): sign the attestation with the
    /// CURRENT key and record it under identity/rotations/<seq>.json.
    /// The caller owns the returned attestation's sig.
    pub fn rotate(
        self: *Client,
        successor_seed: [identity.Ed25519.KeyPair.seed_length]u8,
    ) Error!identity.RotationAttestation {
        const alloc = self.alloc;
        var successor = try identity.identityFromSeed(alloc, successor_seed);
        defer successor.deinit(alloc);

        const seq: u64 = @intCast(self.attestations.len + 1);
        var prev_hash_buf: []u8 = undefined;
        const prev_hash: []const u8 = if (seq == 1)
            identity.genesis_prev_hash
        else blk: {
            prev_hash_buf = try identity.attestationHash(
                alloc,
                self.attestations[self.attestations.len - 1],
            );
            break :blk prev_hash_buf;
        };
        defer if (seq > 1) alloc.free(prev_hash_buf);

        // The attestation outlives `successor`, so dupe the did it names.
        const new_did = try alloc.dupe(u8, successor.did);
        errdefer alloc.free(new_did);
        const attestation = try identity.buildRotationAttestation(
            alloc,
            self.genesis_did,
            &self.key_pair,
            new_did,
            seq,
            prev_hash,
        );
        errdefer alloc.free(attestation.sig);

        const canonical = try identity.canonicalAttestation(alloc, attestation);
        defer alloc.free(canonical);
        const stored = try std.fmt.allocPrint(alloc, "{s}\n", .{canonical});
        defer alloc.free(stored);
        const key = try std.fmt.allocPrint(alloc, "identity/rotations/{d}.json", .{seq});
        defer alloc.free(key);
        const entries = [_]Entry{.{ .key = key, .plaintext = stored }};
        var result = try self.push(&entries, &.{});
        result.deinit(alloc);
        return attestation;
    }
};

/// Free a RotationAttestation whose fields were allocated by `alloc`
/// (the parseRotationAttestation shape, not the borrowed-fields shape
/// produced by buildRotationAttestation).
fn freeAttestation(alloc: Allocator, att: *identity.RotationAttestation) void {
    alloc.free(@constCast(att.genesis_did));
    alloc.free(@constCast(att.new_did));
    alloc.free(@constCast(att.prev_hash));
    alloc.free(@constCast(att.sig));
}

/// Parse a stored `identity/rotations/<seq>.json` document
/// ({genesisDid, newDid, seq, prevHash, sig}) into an owned
/// RotationAttestation. The stored form may carry a trailing newline.
fn parseRotationAttestation(
    alloc: Allocator,
    doc: []const u8,
) error{ OutOfMemory, SignetIntegrity }!identity.RotationAttestation {
    const trimmed = std.mem.trimEnd(u8, doc, " \t\r\n");
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, trimmed, .{}) catch
        return error.SignetIntegrity;
    defer parsed.deinit();
    if (parsed.value != .object) return error.SignetIntegrity;
    const obj = parsed.value.object;
    const genesis_v = obj.get("genesisDid") orelse return error.SignetIntegrity;
    const new_v = obj.get("newDid") orelse return error.SignetIntegrity;
    const seq_v = obj.get("seq") orelse return error.SignetIntegrity;
    const prev_v = obj.get("prevHash") orelse return error.SignetIntegrity;
    const sig_v = obj.get("sig") orelse return error.SignetIntegrity;
    if (genesis_v != .string or new_v != .string or prev_v != .string or
        sig_v != .string or seq_v != .integer or seq_v.integer < 0)
        return error.SignetIntegrity;
    var att: identity.RotationAttestation = .{
        .genesis_did = try alloc.dupe(u8, genesis_v.string),
        .new_did = try alloc.dupe(u8, new_v.string),
        .seq = @intCast(seq_v.integer),
        .prev_hash = try alloc.dupe(u8, prev_v.string),
        .sig = try alloc.dupe(u8, sig_v.string),
    };
    errdefer freeAttestation(alloc, &att);
    return att;
}

// ─── Tests ──────────────────────────────────────────────────────────────

test "entry key validation enforces SN-020/021" {
    try std.testing.expect(isValidEntryKey("memory/MEMORY.md"));
    try std.testing.expect(isValidEntryKey("sessions/demo/000001"));
    try std.testing.expect(isValidEntryKey("config/settings.json"));
    try std.testing.expect(!isValidEntryKey("memory/../etc/passwd"));
    try std.testing.expect(!isValidEntryKey("memory//double"));
    try std.testing.expect(!isValidEntryKey("/memory/x"));
    try std.testing.expect(!isValidEntryKey("memory/x/"));
    try std.testing.expect(!isValidEntryKey("memory\\x"));
    try std.testing.expect(!isValidEntryKey("bogus/x"));
    try std.testing.expect(!isValidEntryKey("memory"));
    try std.testing.expect(!isValidEntryKey("memory/-leading"));
    try std.testing.expect(!isValidEntryKey("memory/.hidden-ok")); // '.' first char invalid
    // SN-022: sessions keys are exactly sessions/<id>/<6+digit seq>.
    try std.testing.expect(!isValidEntryKey("sessions/demo/1"));
    try std.testing.expect(!isValidEntryKey("sessions/demo/session.json"));
    try std.testing.expect(!isValidEntryKey("sessions/demo/meta/index.json"));
    try std.testing.expect(!isValidEntryKey("sessions/demo"));
    try std.testing.expect(isValidEntryKey("sessions/demo/000000"));
    try std.testing.expect(isValidEntryKey("sessions/demo/1234567"));
}

test "urlEncodeSegment leaves entry-key characters and encodes colons" {
    const alloc = std.testing.allocator;
    const encoded = try urlEncodeSegment(alloc, "signet:did_key_z6Mk");
    defer alloc.free(encoded);
    try std.testing.expectEqualStrings("signet%3Adid_key_z6Mk", encoded);
    const plain = try urlEncodeSegment(alloc, "settings.json");
    defer alloc.free(plain);
    try std.testing.expectEqualStrings("settings.json", plain);
}

test "manifestHash sorts key/hash lines" {
    const alloc = std.testing.allocator;
    const entries = [_]Entry{
        .{ .key = "b/two", .plaintext = "sha256:bb" },
        .{ .key = "a/one", .plaintext = "sha256:aa" },
    };
    const hash = try manifestHash(alloc, &entries);
    defer alloc.free(hash);
    const expected = try identity.sha256Hex(alloc, "a/one\tsha256:aa\nb/two\tsha256:bb");
    defer alloc.free(expected);
    try std.testing.expectEqualStrings(expected, hash[7..]);
}

test "HttpTransport frames an empty body for bodied methods" {
    // POST carries a body slot even when empty; routing it through the
    // bodiless send path trips std.http.Client's method assertion. This
    // loopback server records what the transport actually put on the wire.
    const alloc = std.testing.allocator;
    const io = io_mod.getIo();

    var address = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    const Probe = struct {
        head: [8192]u8 = undefined,
        head_len: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This(), l: *std.Io.net.Server) void {
            const zio = io_mod.getIo();
            var stream = l.accept(zio) catch |e| {
                self.err = e;
                return;
            };
            defer stream.close(zio);
            var buf: [4096]u8 = undefined;
            var r = stream.reader(zio, &buf);
            while (true) {
                r.interface.fillMore() catch |e| {
                    self.err = e;
                    return;
                };
                const buffered = r.interface.buffered();
                if (std.mem.indexOf(u8, buffered, "\r\n\r\n")) |idx| {
                    const head = buffered[0 .. idx + 4];
                    @memcpy(self.head[0..head.len], head);
                    self.head_len = head.len;
                    break;
                }
                if (buffered.len >= self.head.len - 4) {
                    self.err = error.HeadTooLarge;
                    return;
                }
            }
            var wbuf: [256]u8 = undefined;
            var w = stream.writer(zio, &wbuf);
            w.interface.writeAll(
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
            ) catch |e| {
                self.err = e;
                return;
            };
            w.interface.flush() catch |e| {
                self.err = e;
            };
        }
    };

    var probe: Probe = .{};
    const thread = try std.Thread.spawn(.{}, Probe.run, .{ &probe, &listener });

    var transport = HttpTransport.init(alloc);
    defer transport.deinit();
    const url = try std.fmt.allocPrint(alloc, "http://127.0.0.1:{d}/auth/challenge", .{port});
    defer alloc.free(url);
    const res = try transport.transport().request(alloc, .{
        .method = .POST,
        .url = url,
    });
    defer alloc.free(res.body);

    thread.join();
    try std.testing.expectEqual(@as(?anyerror, null), probe.err);
    try std.testing.expectEqual(@as(u16, 200), res.status);
    try std.testing.expectEqualStrings("{}", res.body);

    const head = probe.head[0..probe.head_len];
    try std.testing.expect(std.mem.startsWith(u8, head, "POST /auth/challenge HTTP/1.1\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, head, "content-length: 0") != null);
}

// ─── Wire-level tests through the scripted server ───────────────────────

const test_server = @import("test_server.zig");

const test_seed = [_]u8{9} ** 32;
const test_passphrase = "wire-test-passphrase";

/// Identity + scripted server + client, wired so `client.transport` points
/// at the fixture's own (address-stable) server.
const WireFixture = struct {
    id: identity.Identity = undefined,
    server: test_server.Server = undefined,
    client: Client = undefined,

    fn init(self: *WireFixture, alloc: Allocator) !void {
        self.id = try identity.identityFromSeed(alloc, test_seed);
        self.server = test_server.Server.init(alloc);
        self.client = try Client.init(alloc, self.server.transport(), .{
            .url = "http://signet.test",
            .key_pair = self.id.key_pair,
            .did = self.id.did,
            .passphrase = test_passphrase,
        });
    }

    fn deinit(self: *WireFixture, alloc: Allocator) void {
        self.client.deinit();
        self.server.deinit();
        self.id.deinit(alloc);
    }

    fn encKey(self: *const WireFixture, alloc: Allocator) ![crypto.key_len]u8 {
        return crypto.deriveKey(alloc, test_passphrase, self.client.namespace);
    }

    /// Seed one ciphertext entry plus the signed seq-1 manifest naming it.
    /// The manifest blob registers both at ?view=integrity and under the
    /// manifest entry key, matching a real store's state.
    fn seedSignedEntry(
        self: *WireFixture,
        alloc: Allocator,
        key: []const u8,
        plaintext: []const u8,
    ) !void {
        const enc_key = try self.encKey(alloc);
        const blob = try crypto.encryptEntry(alloc, &enc_key, key, plaintext);
        defer alloc.free(blob);
        try self.server.putEntry(key, blob);
        const hash = try crypto.ciphertextHash(alloc, blob);
        defer alloc.free(hash);
        const entry_hashes = [_]Entry{.{ .key = key, .plaintext = hash }};
        const manifest = try test_server.signedManifestBlob(
            alloc,
            &enc_key,
            &self.id.key_pair,
            self.id.did,
            self.id.did,
            1,
            &entry_hashes,
        );
        defer alloc.free(manifest.canonical);
        defer alloc.free(manifest.blob);
        try self.server.putEntry(manifest_entry_key, manifest.blob);
        if (self.server.integrity_blob) |old| alloc.free(old);
        self.server.integrity_blob = try alloc.dupe(u8, manifest.blob);
    }
};

test "auth signs the domain-separated nonce preimage" {
    const alloc = std.testing.allocator;
    var f: WireFixture = .{};
    try f.init(alloc);
    defer f.deinit(alloc);

    try f.client.authenticate();

    const body = f.server.verify_body orelse return error.TestExpectedVerifyBody;
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value == .object);
    const obj = parsed.value.object;
    const nonce = obj.get("nonce").?.string;
    const sig = obj.get("sig").?.string;
    try std.testing.expectEqualStrings("test-nonce-1", nonce);

    const preimage = try std.fmt.allocPrint(alloc, "signet-auth:{s}", .{nonce});
    defer alloc.free(preimage);
    // The signature verifies against the domain-separated preimage and
    // never against the bare nonce.
    try std.testing.expect(identity.verifyDidSignature(alloc, f.id.did, preimage, sig));
    try std.testing.expect(!identity.verifyDidSignature(alloc, f.id.did, nonce, sig));
}

test "push signs only verified entries plus accepted uploads" {
    const alloc = std.testing.allocator;
    var f: WireFixture = .{};
    try f.init(alloc);
    defer f.deinit(alloc);
    try f.seedSignedEntry(alloc, "memory/old.md", "old contents");

    const upload = [_]Entry{.{ .key = "memory/new.md", .plaintext = "new contents" }};
    const deletions = [_][]const u8{"memory/old.md"};
    var result = try f.client.push(&upload, &deletions);
    defer result.deinit(alloc);

    try std.testing.expectEqual(@as(u64, 2), result.seq);
    try std.testing.expectEqual(@as(usize, 2), result.uploaded.len);
    try std.testing.expectEqual(@as(usize, 1), result.deleted.len);
    try std.testing.expectEqualStrings("memory/old.md", result.deleted[0]);

    // The server's committed manifest names only the accepted upload: the
    // deleted key is gone and no view-only key leaked in.
    const committed = f.server.entries.get(manifest_entry_key) orelse
        return error.TestExpectedManifest;
    const enc_key = try f.encKey(alloc);
    const plaintext = try crypto.decryptEntry(alloc, &enc_key, manifest_entry_key, committed);
    defer alloc.free(plaintext);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, plaintext, .{});
    defer parsed.deinit();
    const signed_entries = parsed.value.object.get("manifest").?.object.get("entries").?.object;
    try std.testing.expectEqual(@as(usize, 1), signed_entries.count());
    try std.testing.expect(signed_entries.get("memory/new.md") != null);
    try std.testing.expect(f.server.entries.get("memory/new.md") != null);
    try std.testing.expect(f.server.entries.get("memory/old.md") == null);
}

test "push fails closed when the hashes view diverges from the verified manifest" {
    const alloc = std.testing.allocator;
    const upload = [_]Entry{.{ .key = "memory/new.md", .plaintext = "new contents" }};

    for ([_]test_server.ViewTamper{ .extra_key, .drop_key, .wrong_hash }) |tamper| {
        var f: WireFixture = .{};
        try f.init(alloc);
        defer f.deinit(alloc);
        try f.seedSignedEntry(alloc, "memory/old.md", "old contents");
        f.server.tamper = tamper;
        try std.testing.expectError(
            error.SignetIntegrity,
            f.client.push(&upload, &.{}),
        );
    }
}

test "manifest seq floor and same-seq hash check fail closed" {
    const alloc = std.testing.allocator;

    // Rollback: a remote seq below the client's floor is rejected.
    {
        var f: WireFixture = .{};
        try f.init(alloc);
        defer f.deinit(alloc);
        try f.seedSignedEntry(alloc, "memory/a.md", "a");
        f.client.last_seq = 5;
        try std.testing.expectError(error.SignetIntegrity, f.client.pull());
    }

    // Same seq, different canonical manifest: rejected by the hash check.
    {
        var f: WireFixture = .{};
        try f.init(alloc);
        defer f.deinit(alloc);
        try f.seedSignedEntry(alloc, "memory/a.md", "a");

        // Record what the client verified, then swap the remote manifest
        // for a different document at the same seq.
        try std.testing.expect(f.client.last_manifest_hash == null);
        const pull_result = try f.client.pull();
        defer {
            for (pull_result.entries) |e| {
                alloc.free(@constCast(e.key));
                alloc.free(@constCast(e.plaintext));
            }
            alloc.free(pull_result.entries);
        }
        try std.testing.expect(f.client.last_manifest_hash != null);

        const enc_key = try f.encKey(alloc);
        const swapped = try test_server.signedManifestBlob(
            alloc,
            &enc_key,
            &f.id.key_pair,
            f.id.did,
            f.id.did,
            1,
            &.{},
        );
        defer alloc.free(swapped.canonical);
        defer alloc.free(swapped.blob);
        if (f.server.integrity_blob) |old| alloc.free(old);
        f.server.integrity_blob = try alloc.dupe(u8, swapped.blob);

        try std.testing.expectError(error.SignetIntegrity, f.client.pull());
    }
}

test "manifest-state cursor persists and reloads across clients" {
    const alloc = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const home = try io_mod.dirRealpathAlloc(alloc, tmp.dir, ".");
    defer alloc.free(home);
    const state_path = try std.fs.path.join(
        alloc,
        &.{ home, "signet", "manifest-state.json" },
    );
    defer alloc.free(state_path);

    var f: WireFixture = .{};
    try f.init(alloc);
    defer f.deinit(alloc);
    f.server.namespace_missing = true;
    f.client.manifest_state_path = try alloc.dupe(u8, state_path);

    const upload = [_]Entry{.{ .key = "memory/x.md", .plaintext = "x" }};
    var result = try f.client.push(&upload, &.{});
    defer result.deinit(alloc);
    try std.testing.expectEqual(@as(u64, 1), result.seq);

    // The cursor file holds the committed seq and canonical hash.
    var file = try tmp.dir.openFile(
        std.testing.io,
        "signet/manifest-state.json",
        .{},
    );
    const body = try io_mod.readFileToEnd(alloc, &file, 4096);
    file.close(std.testing.io);
    defer alloc.free(body);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqual(@as(i64, 1), obj.get("seq").?.integer);
    try std.testing.expectEqualStrings(
        f.client.last_manifest_hash.?,
        obj.get("canonical_sha256").?.string,
    );

    // A restarted client restores the floor from the file and accepts the
    // same verified manifest.
    const committed = f.server.entries.get(manifest_entry_key).?;
    if (f.server.integrity_blob) |old| alloc.free(old);
    f.server.integrity_blob = try alloc.dupe(u8, committed);
    f.server.namespace_missing = false;

    var client2 = try Client.init(alloc, f.server.transport(), .{
        .url = "http://signet.test",
        .key_pair = f.id.key_pair,
        .did = f.id.did,
        .passphrase = test_passphrase,
        .last_seq = 1,
        .last_manifest_hash = obj.get("canonical_sha256").?.string,
    });
    defer client2.deinit();
    const pull_result = try client2.pull();
    defer {
        for (pull_result.entries) |e| {
            alloc.free(@constCast(e.key));
            alloc.free(@constCast(e.plaintext));
        }
        alloc.free(pull_result.entries);
    }
    try std.testing.expectEqual(@as(u64, 1), pull_result.seq);

    // A same-seq swap still fails closed for the restarted client.
    const enc_key = try f.encKey(alloc);
    const swapped = try test_server.signedManifestBlob(
        alloc,
        &enc_key,
        &f.id.key_pair,
        f.id.did,
        f.id.did,
        1,
        &.{},
    );
    defer alloc.free(swapped.canonical);
    defer alloc.free(swapped.blob);
    alloc.free(f.server.integrity_blob.?);
    f.server.integrity_blob = try alloc.dupe(u8, swapped.blob);
    try std.testing.expectError(error.SignetIntegrity, client2.pull());
}
