//! Holder identity: did:key encoding, Ed25519 signing, canonical JSON, and
//! rotation attestations (PS-001, PS-010/011, PS-050..053).
//!
//! A passport is rooted at exactly one genesis DID (PS-010): a `did:key`
//! Ed25519 identity created at init. The private key is one of the two
//! secrets that govern the passport (PS-100); it lives client-side only.
//! What crosses the wire is the DID itself (public), Ed25519 signatures
//! over server nonces and canonical-JSON documents, and rotation
//! attestations.
//!
//! The DID encoding (PS-001) is `did:key:z` + base58btc(0xed01 || pubkey).
//! base58btc is implemented locally and matches the reference encoder in
//! passport-suite (src/client/identity.ts) byte for byte, so the shared
//! vectors in spec/vectors/{identity,rotation}.json reproduce exactly.
//!
//! Signatures are over canonical JSON: object keys sorted at every level,
//! no whitespace.

const std = @import("std");
const io_mod = @import("../shared/io.zig");

const Allocator = std.mem.Allocator;
pub const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

// ─── base58btc (did:key multibase) ──────────────────────────────────────

const b58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// base58btc encode with the multibase 'z' prefix (PS-001).
/// The caller owns the returned slice.
pub fn base58btc(alloc: Allocator, bytes: []const u8) Allocator.Error![]u8 {
    var digits: std.ArrayList(u8) = .empty;
    defer digits.deinit(alloc);
    try digits.append(alloc, 0);
    for (bytes) |b| {
        var carry: u32 = b;
        for (digits.items) |*digit| {
            carry += @as(u32, digit.*) << 8;
            digit.* = @intCast(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            try digits.append(alloc, @intCast(carry % 58));
            carry /= 58;
        }
    }
    var zeros: usize = 0;
    while (zeros < bytes.len and bytes[zeros] == 0) zeros += 1;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    try out.append(alloc, 'z');
    try out.appendNTimes(alloc, '1', zeros);
    var i = digits.items.len;
    while (i > 0) {
        i -= 1;
        try out.append(alloc, b58_alphabet[digits.items[i]]);
    }
    return out.toOwnedSlice(alloc);
}

/// base58btc decode (no multibase prefix). Null on a bad character.
/// The caller owns the returned slice.
pub fn base58btcDecode(alloc: Allocator, s: []const u8) Allocator.Error!?[]u8 {
    var digits: std.ArrayList(u8) = .empty;
    defer digits.deinit(alloc);
    try digits.append(alloc, 0);
    for (s) |ch| {
        const v = std.mem.findScalar(u8, b58_alphabet, ch) orelse return null;
        var carry: u32 = @intCast(v);
        for (digits.items) |*digit| {
            carry += @as(u32, digit.*) * 58;
            digit.* = @intCast(carry & 0xff);
            carry >>= 8;
        }
        while (carry > 0) {
            try digits.append(alloc, @intCast(carry & 0xff));
            carry >>= 8;
        }
    }
    var zeros: usize = 0;
    while (zeros < s.len and s[zeros] == '1') zeros += 1;

    const out = try alloc.alloc(u8, zeros + digits.items.len);
    @memset(out[0..zeros], 0);
    for (digits.items, 0..) |_, i| {
        out[zeros + i] = digits.items[digits.items.len - 1 - i];
    }
    return out;
}

// ─── Ed25519 identities ─────────────────────────────────────────────────

const ed25519_multicodec = [2]u8{ 0xed, 0x01 };

pub const Identity = struct {
    /// did:key form: `did:key:z` + base58btc(0xed01 || pubkey).
    did: []u8,
    /// The signing key pair; the secret half never leaves custody.
    key_pair: Ed25519.KeyPair,
    /// The raw 32-byte seed (custody/export encoding input).
    seed: [Ed25519.KeyPair.seed_length]u8,

    pub fn deinit(self: *Identity, alloc: Allocator) void {
        alloc.free(self.did);
        self.* = undefined;
    }

    /// Raw 32-byte public key — what the DID carries.
    pub fn publicKeyRaw(self: *const Identity) [Ed25519.PublicKey.encoded_length]u8 {
        return self.key_pair.public_key.toBytes();
    }
};

fn didFromPublicKey(
    alloc: Allocator,
    public_key: *const Ed25519.PublicKey,
) Allocator.Error![]u8 {
    var multicodec: [2 + Ed25519.PublicKey.encoded_length]u8 = undefined;
    multicodec[0..2].* = ed25519_multicodec;
    multicodec[2..].* = public_key.toBytes();
    const encoded = try base58btc(alloc, &multicodec);
    defer alloc.free(encoded);
    return std.fmt.allocPrint(alloc, "did:key:{s}", .{encoded});
}

/// Rebuild an identity from a raw 32-byte Ed25519 seed. Deterministic — the
/// path spec vectors and custody restore use to pin identities.
pub fn identityFromSeed(alloc: Allocator, seed: [Ed25519.KeyPair.seed_length]u8) !Identity {
    const key_pair = try Ed25519.KeyPair.generateDeterministic(seed);
    const did = try didFromPublicKey(alloc, &key_pair.public_key);
    return .{ .did = did, .key_pair = key_pair, .seed = seed };
}

/// Generate a fresh Ed25519 identity — the genesis key of a new passport.
pub fn generateIdentity(alloc: Allocator) !Identity {
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    while (true) {
        io_mod.getIo().random(&seed);
        return identityFromSeed(alloc, seed) catch |err| switch (err) {
            error.IdentityElement => continue,
            else => return err,
        };
    }
}

/// Extract the Ed25519 public key a did:key carries. Returns null for
/// anything that is not exactly `did:key:z<base58btc(0xed01 || pubkey)>`.
pub fn publicKeyFromDid(alloc: Allocator, did: []const u8) !?Ed25519.PublicKey {
    const prefix = "did:key:z";
    if (!std.mem.startsWith(u8, did, prefix)) return null;
    const encoded = did[prefix.len..];
    if (encoded.len == 0) return null;
    // Characters must come from the base58btc alphabet.
    for (encoded) |ch| {
        if (std.mem.findScalar(u8, b58_alphabet, ch) == null) return null;
    }
    const bytes = (try base58btcDecode(alloc, encoded)) orelse return null;
    defer alloc.free(bytes);
    if (bytes.len != 34) return null;
    if (bytes[0] != ed25519_multicodec[0] or bytes[1] != ed25519_multicodec[1]) return null;
    const key = Ed25519.PublicKey.fromBytes(bytes[2..34].*) catch return null;
    return key;
}

// ─── Canonical JSON + signatures ────────────────────────────────────────

/// Deterministic JSON: object keys sorted at every level, no whitespace.
/// Matches JSON.stringify leaf encoding for the value shapes passports
/// carry (strings, integers, booleans, null, arrays, objects).
/// The caller owns the returned slice.
pub fn canonicalJson(alloc: Allocator, value: std.json.Value) Allocator.Error![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    writeCanonical(alloc, &out.writer, value) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // An Allocating writer cannot fail to write; collapse the
        // unreachable sink error so callers see only allocation failure.
        else => return error.OutOfMemory,
    };
    return out.toOwnedSlice();
}

fn writeCanonical(
    alloc: Allocator,
    writer: *std.Io.Writer,
    value: std.json.Value,
) (Allocator.Error || std.Io.Writer.Error)!void {
    switch (value) {
        .null => try writer.writeAll("null"),
        .bool => |b| try writer.writeAll(if (b) "true" else "false"),
        .integer => |i| try writer.print("{d}", .{i}),
        .float => |f| try writer.print("{d}", .{f}),
        .number_string => |s| try writer.writeAll(s),
        .string => |s| try writeJsonString(writer, s),
        .array => |items| {
            try writer.writeByte('[');
            for (items.items, 0..) |item, i| {
                if (i > 0) try writer.writeByte(',');
                try writeCanonical(alloc, writer, item);
            }
            try writer.writeByte(']');
        },
        .object => |map| {
            const keys = try alloc.alloc([]const u8, map.count());
            defer alloc.free(keys);
            var it = map.iterator();
            var n: usize = 0;
            while (it.next()) |kv| : (n += 1) keys[n] = kv.key_ptr.*;
            std.mem.sort([]const u8, keys, {}, struct {
                fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                    return std.mem.lessThan(u8, a, b);
                }
            }.lessThan);

            try writer.writeByte('{');
            for (keys, 0..) |key, i| {
                if (i > 0) try writer.writeByte(',');
                try writeJsonString(writer, key);
                try writer.writeByte(':');
                try writeCanonical(alloc, writer, map.get(key).?);
            }
            try writer.writeByte('}');
        },
    }
}

/// JSON.stringify-compatible string encoding: escapes ", \, and control
/// characters below 0x20 (short escapes where they exist, \u00xx otherwise).
fn writeJsonString(writer: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try std.json.Stringify.encodeJsonString(s, .{}, writer);
}

/// Ed25519-sign a message (raw bytes), base64 result.
/// The caller owns the returned slice.
pub fn signMessage(
    alloc: Allocator,
    key_pair: *const Ed25519.KeyPair,
    message: []const u8,
) ![]u8 {
    const signature = try key_pair.sign(message, null);
    const sig_bytes = signature.toBytes();
    const out = try alloc.alloc(u8, std.base64.standard.Encoder.calcSize(sig_bytes.len));
    _ = std.base64.standard.Encoder.encode(out, &sig_bytes);
    return out;
}

/// Verify a base64 Ed25519 signature over `message` against a did:key.
pub fn verifyDidSignature(
    alloc: Allocator,
    did: []const u8,
    message: []const u8,
    sig_b64: []const u8,
) bool {
    const public_key = (publicKeyFromDid(alloc, did) catch return false) orelse return false;

    const sig_len = std.base64.standard.Decoder.calcSizeForSlice(sig_b64) catch return false;
    if (sig_len != Ed25519.Signature.encoded_length) return false;
    var sig_bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
    std.base64.standard.Decoder.decode(&sig_bytes, sig_b64) catch return false;
    // Reject non-canonical base64 (mirrors the reference round-trip check).
    var reencoded_buf: [std.base64.standard.Encoder.calcSize(Ed25519.Signature.encoded_length)]u8 = undefined;
    const reencoded = std.base64.standard.Encoder.encode(&reencoded_buf, &sig_bytes);
    if (!std.mem.eql(
        u8,
        std.mem.trimEnd(u8, reencoded, "="),
        std.mem.trimEnd(u8, sig_b64, "="),
    )) return false;

    const signature = Ed25519.Signature.fromBytes(sig_bytes);
    signature.verify(message, public_key) catch return false;
    return true;
}

// ─── Namespaces (PS-011) ────────────────────────────────────────────────

/// `did:key:z6Mk...` -> `did_key_z6Mk...` — the injective namespace encoding.
/// The caller owns the returned slice.
pub fn encodeDid(alloc: Allocator, did: []const u8) Allocator.Error![]u8 {
    const out = try alloc.dupe(u8, did);
    std.mem.replaceScalar(u8, out, ':', '_');
    return out;
}

/// The namespace a genesis DID owns: `passport:<encoded did>` (PS-011).
/// The caller owns the returned slice.
pub fn namespaceFor(alloc: Allocator, did: []const u8) Allocator.Error![]u8 {
    const encoded = try encodeDid(alloc, did);
    defer alloc.free(encoded);
    return std.fmt.allocPrint(alloc, "passport:{s}", .{encoded});
}

/// Inverse of namespaceFor: recover the genesis DID a `passport:` namespace
/// pins (PS-012). The caller owns the returned slice; null when the
/// namespace does not decode back to a well-formed did:key identity.
pub fn didFromNamespace(alloc: Allocator, namespace: []const u8) Allocator.Error!?[]u8 {
    const prefix = "passport:";
    if (!std.mem.startsWith(u8, namespace, prefix)) return null;
    const did = try alloc.dupe(u8, namespace[prefix.len..]);
    std.mem.replaceScalar(u8, did, '_', ':');
    if ((try publicKeyFromDid(alloc, did)) == null) {
        alloc.free(did);
        return null;
    }
    return did;
}

/// PS-012: encoded namespaces must match this shape before storage access.
pub fn isValidNamespace(namespace: []const u8) bool {
    const prefix = "passport:did_";
    if (!std.mem.startsWith(u8, namespace, prefix)) return false;
    const rest = namespace[prefix.len..];
    const sep = std.mem.findScalar(u8, rest, '_') orelse return false;
    const method = rest[0..sep];
    if (method.len == 0) return false;
    for (method) |ch| {
        if (!std.ascii.isLower(ch)) return false;
    }
    const suffix = rest[sep + 1 ..];
    if (suffix.len == 0 or suffix.len > 240) return false;
    for (suffix) |ch| {
        if (!std.ascii.isAlphanumeric(ch) and ch != '.' and ch != '_' and ch != '-') return false;
    }
    return true;
}

// ─── Rotation attestations (PS-050/051) ─────────────────────────────────

/// prevHash of the first attestation in a chain (PS-051).
pub const genesis_prev_hash = "0" ** 64;

pub const RotationAttestation = struct {
    genesis_did: []const u8,
    new_did: []const u8,
    seq: u64,
    prev_hash: []const u8,
    sig: []const u8,
};

/// sha256 hex of a string — the attestation hash linkage.
/// The caller owns the returned slice.
pub fn sha256Hex(alloc: Allocator, s: []const u8) Allocator.Error![]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(s, &digest, .{});
    return std.fmt.allocPrint(alloc, "{x}", .{digest});
}

fn attestationBodyValue(
    alloc: Allocator,
    genesis_did: []const u8,
    new_did: []const u8,
    seq: u64,
    prev_hash: []const u8,
) Allocator.Error!std.json.Value {
    var map: std.json.ObjectMap = .empty;
    try map.put(alloc, "genesisDid", .{ .string = genesis_did });
    try map.put(alloc, "newDid", .{ .string = new_did });
    try map.put(alloc, "seq", .{ .integer = @intCast(seq) });
    try map.put(alloc, "prevHash", .{ .string = prev_hash });
    return .{ .object = map };
}

/// Canonical JSON of the unsigned attestation body {genesisDid, newDid,
/// seq, prevHash} — the exact bytes the predecessor key signs (PS-051).
/// The caller owns the returned slice.
pub fn canonicalAttestationBody(
    alloc: Allocator,
    genesis_did: []const u8,
    new_did: []const u8,
    seq: u64,
    prev_hash: []const u8,
) Allocator.Error![]u8 {
    var body = try attestationBodyValue(alloc, genesis_did, new_did, seq, prev_hash);
    defer body.object.deinit(alloc);
    return canonicalJson(alloc, body);
}

/// Canonical JSON of a full attestation document (with sig) — the input to
/// attestationHash and to rotation-entry storage.
/// The caller owns the returned slice.
pub fn canonicalAttestation(alloc: Allocator, att: RotationAttestation) Allocator.Error![]u8 {
    var map: std.json.ObjectMap = .empty;
    defer map.deinit(alloc);
    try map.put(alloc, "genesisDid", .{ .string = att.genesis_did });
    try map.put(alloc, "newDid", .{ .string = att.new_did });
    try map.put(alloc, "seq", .{ .integer = @intCast(att.seq) });
    try map.put(alloc, "prevHash", .{ .string = att.prev_hash });
    try map.put(alloc, "sig", .{ .string = att.sig });
    return canonicalJson(alloc, .{ .object = map });
}

/// sha256 hex of an attestation's canonical JSON — the next link's prevHash.
/// The caller owns the returned slice.
pub fn attestationHash(alloc: Allocator, att: RotationAttestation) Allocator.Error![]u8 {
    const canonical = try canonicalAttestation(alloc, att);
    defer alloc.free(canonical);
    return sha256Hex(alloc, canonical);
}

/// Build a rotation attestation (PS-051): the predecessor key signs the
/// canonical JSON of {genesisDid, newDid, seq, prevHash}. The successor's
/// own signature is not part of the document — control of the old key is
/// the whole authorization.
pub fn buildRotationAttestation(
    alloc: Allocator,
    genesis_did: []const u8,
    signer: *const Ed25519.KeyPair,
    new_did: []const u8,
    seq: u64,
    prev_hash: []const u8,
) !RotationAttestation {
    const body = try canonicalAttestationBody(alloc, genesis_did, new_did, seq, prev_hash);
    defer alloc.free(body);
    const sig = try signMessage(alloc, signer, body);
    return .{
        .genesis_did = genesis_did,
        .new_did = new_did,
        .seq = seq,
        .prev_hash = prev_hash,
        .sig = sig,
    };
}

/// Verify one attestation's structure and predecessor signature (PS-051):
/// the sig must be a valid Ed25519 signature, under `signer_did`, over the
/// canonical JSON of {genesisDid, newDid, seq, prevHash}. Chain ordering
/// (seq strictly increasing, prevHash linkage) is the caller's check.
pub fn verifyRotationAttestation(
    alloc: Allocator,
    att: RotationAttestation,
    signer_did: []const u8,
) bool {
    const body = canonicalAttestationBody(
        alloc,
        att.genesis_did,
        att.new_did,
        att.seq,
        att.prev_hash,
    ) catch return false;
    defer alloc.free(body);
    return verifyDidSignature(alloc, signer_did, body, att.sig);
}

// ─── Tests ──────────────────────────────────────────────────────────────

const identity_vectors = @embedFile("testdata/identity.json");
const rotation_vectors = @embedFile("testdata/rotation.json");

fn hexSeed(comptime hex: []const u8) [Ed25519.KeyPair.seed_length]u8 {
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&seed, hex) catch unreachable;
    return seed;
}

test "identityFromSeed reproduces the shared identity vector" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, identity_vectors, .{});
    defer parsed.deinit();

    const seed_hex = parsed.value.object.get("genesisSeedHex").?.string;
    const expected_did = parsed.value.object.get("genesisDid").?.string;
    const expected_pub = parsed.value.object.get("publicKeyHex").?.string;

    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, seed_hex);
    var identity = try identityFromSeed(alloc, seed);
    defer identity.deinit(alloc);

    try std.testing.expectEqualStrings(expected_did, identity.did);

    var expected_pub_bytes: [Ed25519.PublicKey.encoded_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected_pub_bytes, expected_pub);
    try std.testing.expectEqual(expected_pub_bytes, identity.publicKeyRaw());
}

test "signMessage reproduces the shared signature vector" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, identity_vectors, .{});
    defer parsed.deinit();

    const seed_hex = parsed.value.object.get("genesisSeedHex").?.string;
    const message = parsed.value.object.get("signMessage").?.string;
    const expected_sig = parsed.value.object.get("signature").?.string;
    const did = parsed.value.object.get("genesisDid").?.string;

    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, seed_hex);
    var identity = try identityFromSeed(alloc, seed);
    defer identity.deinit(alloc);

    const sig = try signMessage(alloc, &identity.key_pair, message);
    defer alloc.free(sig);
    try std.testing.expectEqualStrings(expected_sig, sig);

    try std.testing.expect(verifyDidSignature(alloc, did, message, sig));
    try std.testing.expect(!verifyDidSignature(alloc, did, "different message", sig));
    try std.testing.expect(!verifyDidSignature(alloc, did, message, "not-base64!!!"));
}

test "namespaceFor and encodeDid match the vector namespace" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, identity_vectors, .{});
    defer parsed.deinit();

    const did = parsed.value.object.get("genesisDid").?.string;
    const expected_ns = parsed.value.object.get("namespace").?.string;

    const ns = try namespaceFor(alloc, did);
    defer alloc.free(ns);
    try std.testing.expectEqualStrings(expected_ns, ns);
    try std.testing.expect(isValidNamespace(ns));
    try std.testing.expect(!isValidNamespace("passport:did:key:z6Mk"));
    try std.testing.expect(!isValidNamespace("other:did_key_z6Mk"));

    // Successor DID encodes to a different namespace (PS-053).
    const successor = parsed.value.object.get("successorDid").?.string;
    const successor_ns = try namespaceFor(alloc, successor);
    defer alloc.free(successor_ns);
    try std.testing.expect(!std.mem.eql(u8, ns, successor_ns));
}

test "base58btc round-trips and rejects bad characters" {
    const alloc = std.testing.allocator;
    const bytes = [_]u8{ 0x00, 0xed, 0x01, 0xde, 0xad, 0xbe, 0xef };
    const encoded = try base58btc(alloc, &bytes);
    defer alloc.free(encoded);
    try std.testing.expect(encoded[0] == 'z');
    try std.testing.expect(encoded[1] == '1'); // leading zero byte -> '1'

    const decoded = (try base58btcDecode(alloc, encoded[1..])).?;
    defer alloc.free(decoded);
    try std.testing.expectEqualSlices(u8, &bytes, decoded);

    try std.testing.expect((try base58btcDecode(alloc, "0OIl")) == null);
}

test "rotation attestation reproduces the shared rotation vector" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, rotation_vectors, .{});
    defer parsed.deinit();

    const expected = parsed.value.object.get("attestation").?.object;
    const genesis_did = expected.get("genesisDid").?.string;
    const new_did = expected.get("newDid").?.string;
    const expected_sig = expected.get("sig").?.string;
    const expected_hash = parsed.value.object.get("attestationHash").?.string;

    const id_parsed = try std.json.parseFromSlice(std.json.Value, alloc, identity_vectors, .{});
    defer id_parsed.deinit();
    const seed_hex = id_parsed.value.object.get("genesisSeedHex").?.string;
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    _ = try std.fmt.hexToBytes(&seed, seed_hex);
    var identity = try identityFromSeed(alloc, seed);
    defer identity.deinit(alloc);

    const att = try buildRotationAttestation(
        alloc,
        genesis_did,
        &identity.key_pair,
        new_did,
        1,
        genesis_prev_hash,
    );
    defer alloc.free(att.sig);

    try std.testing.expectEqualStrings(expected_sig, att.sig);

    const hash = try attestationHash(alloc, att);
    defer alloc.free(hash);
    try std.testing.expectEqualStrings(expected_hash, hash);

    try std.testing.expect(verifyRotationAttestation(alloc, att, genesis_did));
    // Signed by the wrong DID must not verify.
    try std.testing.expect(!verifyRotationAttestation(alloc, att, new_did));
}

test "canonicalJson sorts keys at every level without whitespace" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        alloc,
        "{\"b\":1,\"a\":{\"d\":null,\"c\":[true,\"x\"]},\"e\":\"hi\"}",
        .{},
    );
    defer parsed.deinit();
    const canonical = try canonicalJson(alloc, parsed.value);
    defer alloc.free(canonical);
    try std.testing.expectEqualStrings(
        "{\"a\":{\"c\":[true,\"x\"],\"d\":null},\"b\":1,\"e\":\"hi\"}",
        canonical,
    );
}

test "canonicalJson escapes strings the way JSON.stringify does" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        alloc,
        "{\"s\":\"a\\\"b\\\\c\\nd\\r\\t\\b\\f\\u0001e\"}",
        .{},
    );
    defer parsed.deinit();
    const canonical = try canonicalJson(alloc, parsed.value);
    defer alloc.free(canonical);
    try std.testing.expectEqualStrings(
        "{\"s\":\"a\\\"b\\\\c\\nd\\r\\t\\b\\f\\u0001e\"}",
        canonical,
    );
}

test "publicKeyFromDid round-trips a generated identity" {
    const alloc = std.testing.allocator;
    const seed: [Ed25519.KeyPair.seed_length]u8 = [_]u8{0x42} ** Ed25519.KeyPair.seed_length;
    var identity = try identityFromSeed(alloc, seed);
    defer identity.deinit(alloc);

    const public_key = (try publicKeyFromDid(alloc, identity.did)).?;
    try std.testing.expectEqual(identity.publicKeyRaw(), public_key.toBytes());

    try std.testing.expect((try publicKeyFromDid(alloc, "did:web:example.com")) == null);
    try std.testing.expect((try publicKeyFromDid(alloc, "did:key:z!!!")) == null);
    try std.testing.expect((try publicKeyFromDid(alloc, "did:key:z1")) == null);
}
