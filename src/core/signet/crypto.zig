//! Client-side end-to-end encryption for the AI Signet (SN-030..035).
//!
//! This module is the trust boundary made concrete: plaintext is encrypted
//! here, on the holder's machine, before anything crosses the wire. A
//! conformant store sees only ciphertext plus the bounded metadata of
//! SN-034.
//!
//! Crypto choices (matches src/client/crypto.ts in signet-suite, and
//! spec/vectors/crypto.json byte for byte):
//!   - Key derivation: scrypt(passphrase, salt = sha256("signet:" +
//!     namespace), 32, {N: 2^15, r: 8, p: 1}) (SN-031).
//!   - Cipher: AES-256-GCM with the entry key as AEAD AAD (SN-032).
//!   - Nonce: deterministic HMAC-SHA256(encKey, entryKey || 0x00 ||
//!     plaintext)[0:12] (SN-033). Random nonces MUST NOT be substituted.
//!
//! Wire/storage blob layout, then base64 (SN-030):
//!   [ 0x01 version ][ 12-byte nonce ][ 16-byte GCM tag ][ ciphertext ]

const std = @import("std");

const Allocator = std.mem.Allocator;
const Aes256Gcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const version_byte: u8 = 0x01;
pub const nonce_len = Aes256Gcm.nonce_length; // 12
pub const tag_len = Aes256Gcm.tag_length; // 16
pub const key_len = Aes256Gcm.key_length; // 32
pub const scrypt_params: std.crypto.pwhash.scrypt.Params = .{ .ln = 15, .r = 8, .p = 1 };
pub const salt_prefix = "signet:";

pub const Error = error{
    CiphertextTooShort,
    UnsupportedCiphertextVersion,
    AuthenticationFailed,
    OutOfMemory,
    WeakParameters,
    OutputTooLong,
};

/// Derive the 32-byte signet key from a passphrase + namespace (SN-031).
pub fn deriveKey(
    alloc: Allocator,
    passphrase: []const u8,
    namespace: []const u8,
) Error![key_len]u8 {
    var salt: [Sha256.digest_length]u8 = undefined;
    var hasher = Sha256.init(.{});
    hasher.update(salt_prefix);
    hasher.update(namespace);
    hasher.final(&salt);

    var key: [key_len]u8 = undefined;
    std.crypto.pwhash.scrypt.kdf(alloc, &key, passphrase, &salt, scrypt_params) catch |err| {
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.WeakParameters,
        };
    };
    return key;
}

/// HMAC-SHA256(key, entryKey || 0x00 || plaintext)[0:12] (SN-033).
fn deterministicNonce(
    key: *const [key_len]u8,
    entry_key: []const u8,
    plaintext: []const u8,
) [nonce_len]u8 {
    var mac = HmacSha256.init(key);
    mac.update(entry_key);
    mac.update(&[_]u8{0});
    mac.update(plaintext);
    var digest: [HmacSha256.mac_length]u8 = undefined;
    mac.final(&digest);
    var nonce: [nonce_len]u8 = undefined;
    @memcpy(&nonce, digest[0..nonce_len]);
    return nonce;
}

/// Encrypt one entry's plaintext -> base64 ciphertext blob (SN-030/032/033).
/// The caller owns the returned slice.
pub fn encryptEntry(
    alloc: Allocator,
    key: *const [key_len]u8,
    entry_key: []const u8,
    plaintext: []const u8,
) Error![]u8 {
    const nonce = deterministicNonce(key, entry_key, plaintext);

    const blob_len = 1 + nonce_len + tag_len + plaintext.len;
    const blob = try alloc.alloc(u8, blob_len);
    defer alloc.free(blob);

    blob[0] = version_byte;
    @memcpy(blob[1 .. 1 + nonce_len], &nonce);
    var tag: [tag_len]u8 = undefined;
    Aes256Gcm.encrypt(
        blob[1 + nonce_len + tag_len ..],
        &tag,
        plaintext,
        entry_key,
        nonce,
        key.*,
    );
    @memcpy(blob[1 + nonce_len .. 1 + nonce_len + tag_len], &tag);

    const encoded_len = std.base64.standard.Encoder.calcSize(blob.len);
    const out = try alloc.alloc(u8, encoded_len);
    errdefer alloc.free(out);
    _ = std.base64.standard.Encoder.encode(out, blob);
    return out;
}

/// Decrypt a base64 blob -> plaintext. Fails on tamper, wrong key, bad AAD.
/// The caller owns the returned slice.
pub fn decryptEntry(
    alloc: Allocator,
    key: *const [key_len]u8,
    entry_key: []const u8,
    b64: []const u8,
) Error![]u8 {
    const blob_len = std.base64.standard.Decoder.calcSizeForSlice(b64) catch
        return error.CiphertextTooShort;
    if (blob_len < 1 + nonce_len + tag_len) return error.CiphertextTooShort;
    const blob = try alloc.alloc(u8, blob_len);
    defer alloc.free(blob);
    std.base64.standard.Decoder.decode(blob, b64) catch return error.CiphertextTooShort;

    if (blob[0] != version_byte) return error.UnsupportedCiphertextVersion;
    const nonce: [nonce_len]u8 = blob[1 .. 1 + nonce_len].*;
    const tag: [tag_len]u8 = blob[1 + nonce_len .. 1 + nonce_len + tag_len].*;
    const ct = blob[1 + nonce_len + tag_len ..];

    const plaintext = try alloc.alloc(u8, ct.len);
    errdefer alloc.free(plaintext);
    Aes256Gcm.decrypt(plaintext, ct, tag, entry_key, nonce, key.*) catch
        return error.AuthenticationFailed;
    return plaintext;
}

/// `sha256:<hex>` of the base64-decoded blob; the hash the manifest records.
/// The caller owns the returned slice.
pub fn ciphertextHash(alloc: Allocator, b64: []const u8) Error![]u8 {
    const blob_len = std.base64.standard.Decoder.calcSizeForSlice(b64) catch
        return error.CiphertextTooShort;
    const blob = try alloc.alloc(u8, blob_len);
    defer alloc.free(blob);
    std.base64.standard.Decoder.decode(blob, b64) catch return error.CiphertextTooShort;

    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(blob, &digest, .{});
    return std.fmt.allocPrint(alloc, "sha256:{x}", .{digest});
}

const test_vectors = @embedFile("testdata/crypto.json");

test "deriveKey reproduces the shared crypto vector" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, test_vectors, .{});
    defer parsed.deinit();

    const passphrase = parsed.value.object.get("passphrase").?.string;
    const namespace = parsed.value.object.get("namespace").?.string;
    const key_hex = parsed.value.object.get("keyHex").?.string;

    var expected: [key_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, key_hex);

    const key = try deriveKey(alloc, passphrase, namespace);
    try std.testing.expectEqual(expected, key);
}

test "encryptEntry and decryptEntry reproduce every shared crypto vector" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, test_vectors, .{});
    defer parsed.deinit();

    const passphrase = parsed.value.object.get("passphrase").?.string;
    const namespace = parsed.value.object.get("namespace").?.string;
    const key = try deriveKey(alloc, passphrase, namespace);

    var it = parsed.value.object.get("entries").?.object.iterator();
    while (it.next()) |kv| {
        const entry_key = kv.key_ptr.*;
        const plaintext = kv.value_ptr.object.get("plaintext").?.string;
        const expected_blob = kv.value_ptr.object.get("blob").?.string;

        const blob = try encryptEntry(alloc, &key, entry_key, plaintext);
        defer alloc.free(blob);
        try std.testing.expectEqualStrings(expected_blob, blob);

        const decrypted = try decryptEntry(alloc, &key, entry_key, blob);
        defer alloc.free(decrypted);
        try std.testing.expectEqualStrings(plaintext, decrypted);
    }
}

test "decryptEntry rejects tampering, wrong keys, and bad AAD" {
    const alloc = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, test_vectors, .{});
    defer parsed.deinit();
    const passphrase = parsed.value.object.get("passphrase").?.string;
    const namespace = parsed.value.object.get("namespace").?.string;
    const key = try deriveKey(alloc, passphrase, namespace);

    const entry = parsed.value.object.get("entries").?.object.get("config/settings.json").?;
    const plaintext = entry.object.get("plaintext").?.string;
    const blob = try encryptEntry(alloc, &key, "config/settings.json", plaintext);
    defer alloc.free(blob);

    // Wrong entry key (AAD mismatch) must fail.
    try std.testing.expectError(
        error.AuthenticationFailed,
        decryptEntry(alloc, &key, "memory/MEMORY.md", blob),
    );

    // A different key must fail.
    const other_key = try deriveKey(alloc, "other passphrase", namespace);
    try std.testing.expectError(
        error.AuthenticationFailed,
        decryptEntry(alloc, &other_key, "config/settings.json", blob),
    );

    // Truncated blob must fail.
    try std.testing.expectError(
        error.CiphertextTooShort,
        decryptEntry(alloc, &key, "config/settings.json", blob[0..10]),
    );
}

test "ciphertextHash matches manifest vector hashes" {
    const alloc = std.testing.allocator;
    const crypto_parsed = try std.json.parseFromSlice(std.json.Value, alloc, test_vectors, .{});
    defer crypto_parsed.deinit();
    const manifest_parsed = try std.json.parseFromSlice(
        std.json.Value,
        alloc,
        @embedFile("testdata/manifest.json"),
        .{},
    );
    defer manifest_parsed.deinit();

    const manifest_entries = manifest_parsed.value.object
        .get("manifest").?.object.get("entries").?.object;
    var it = crypto_parsed.value.object.get("entries").?.object.iterator();
    while (it.next()) |kv| {
        const expected_hash = manifest_entries.get(kv.key_ptr.*).?.string;
        const hash = try ciphertextHash(alloc, kv.value_ptr.object.get("blob").?.string);
        defer alloc.free(hash);
        try std.testing.expectEqualStrings(expected_hash, hash);
    }
}
