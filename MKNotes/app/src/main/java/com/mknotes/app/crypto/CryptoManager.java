package com.mknotes.app.crypto;

import android.util.Base64;
import android.util.Log;

import com.goterl.lazysodium.LazySodiumAndroid;
import com.goterl.lazysodium.SodiumAndroid;
import com.goterl.lazysodium.interfaces.AEAD;
import com.goterl.lazysodium.interfaces.PwHash;
import com.sun.jna.NativeLong;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Core encryption engine -- Notesnook-equivalent architecture.
 *
 * Architecture:
 * - Argon2id key derivation (ops=3, mem=65536 KiB, ALG_ARGON2ID13)
 * - XChaCha20-Poly1305 IETF for authenticated encryption (24-byte nonce)
 * - 256-bit keys throughout
 * - JSON cipher format: {"alg":"xcha-argon2id13","ct":"base64","iv":"base64","salt":"base64","len":N}
 *
 * Backward compatibility:
 * - Detects old "ivHex:ciphertextHex" AES-GCM format for migration decryption
 * - Legacy PBKDF2 key derivation kept in separate methods for migration ONLY
 *
 * Memory safety:
 * - Key material is byte[], never String
 * - zeroFill() overwrites with 0x00
 */
public final class CryptoManager {

    private static final String TAG = "CryptoManager";

    // ======================== LAZYSODIUM SINGLETON ========================

    private static LazySodiumAndroid lazySodium;
    private static SodiumAndroid sodiumAndroid;

    /**
     * Initialize lazysodium. MUST be called once in Application.onCreate().
     */
    public static synchronized void init() {
        if (lazySodium == null) {
            sodiumAndroid = new SodiumAndroid();
            lazySodium = new LazySodiumAndroid(sodiumAndroid);
            Log.d(TAG, "Lazysodium initialized");
        }
    }

    public static LazySodiumAndroid getLazySodium() {
        if (lazySodium == null) {
            init();
        }
        return lazySodium;
    }

    public static SodiumAndroid getSodium() {
        if (sodiumAndroid == null) {
            init();
        }
        return sodiumAndroid;
    }

    // ======================== CONSTANTS ========================

    /** XChaCha20-Poly1305 nonce length: 24 bytes */
    public static final int XCHACHA_NONCE_LENGTH = 24;

    /** XChaCha20-Poly1305 auth tag overhead: 16 bytes */
    public static final int XCHACHA_TAG_LENGTH = 16;

    /** Key length: 256 bits = 32 bytes */
    public static final int KEY_LENGTH_BYTES = 32;

    /** Salt length for Argon2: 16 bytes */
    public static final int SALT_LENGTH = 16;

    /** Argon2id parameters matching Notesnook:
     *  ops=3 (time cost), mem=65536 KiB (64 MB), ALG_ARGON2ID13 */
    public static final int ARGON2_OPS_LIMIT = 3;
    public static final long ARGON2_MEM_LIMIT = 65536L * 1024L; // 64 MB in bytes
    public static final int ARGON2_ALG = PwHash.Alg.PWHASH_ALG_ARGON2ID13.getValue();

    /** Algorithm identifier for cipher format */
    public static final String ALG_IDENTIFIER = "xcha-argon2id13";

    /** FIXED iteration count for LEGACY PBKDF2 ONLY -- NEVER change. */
    public static final int FIXED_ITERATIONS = 120_000;
    public static final int LEGACY_ITERATIONS = 15_000;

    /** Old AES-GCM constants for migration backward compatibility */
    private static final int OLD_GCM_IV_LENGTH = 12;

    private static final SecureRandom sRandom = new SecureRandom();

    private CryptoManager() {
        // Static utility class
    }

    // ======================== SALT & KEY GENERATION ========================

    /**
     * Generate a cryptographically random 16-byte salt.
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        sRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Generate a cryptographically random 256-bit key (DEK/UEK/DBK).
     */
    public static byte[] generateDEK() {
        byte[] key = new byte[KEY_LENGTH_BYTES];
        sRandom.nextBytes(key);
        return key;
    }

    // ======================== KEY DERIVATION (ARGON2ID) ========================

    /**
     * Derive a 256-bit key from password + salt using Argon2id.
     * Parameters: ops=3, mem=65536 KiB (64 MB), ALG_ARGON2ID13.
     *
     * This is the PRIMARY key derivation for the new system.
     *
     * @param password user's master password
     * @param salt     16-byte salt
     * @return byte[32] derived key, or null on failure
     */
    public static byte[] deriveKeyArgon2(String password, byte[] salt) {
        if (password == null || password.length() == 0 || salt == null || salt.length == 0) {
            Log.e(TAG, "deriveKeyArgon2: invalid input");
            return null;
        }
        try {
            byte[] key = new byte[KEY_LENGTH_BYTES];
            byte[] pwBytes = password.getBytes(StandardCharsets.UTF_8);

            boolean success = getSodium().crypto_pwhash(
                    key, key.length,
                    pwBytes, pwBytes.length,
                    salt,
                    ARGON2_OPS_LIMIT,
                    new NativeLong(ARGON2_MEM_LIMIT),
                    ARGON2_ALG
            );

            if (success) {
                return key;
            } else {
                Log.e(TAG, "deriveKeyArgon2: crypto_pwhash returned false");
                return null;
            }
        } catch (Exception e) {
            Log.e(TAG, "deriveKeyArgon2 failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Alias for deriveKeyArgon2 -- used as the primary deriveMasterKey.
     */
    public static byte[] deriveMasterKey(String password, byte[] salt) {
        return deriveKeyArgon2(password, salt);
    }

    /**
     * Derive legacy key for PBKDF2 migration ONLY. Uses old 120,000 iterations.
     */
    public static byte[] deriveLegacyKey(String password, byte[] salt) {
        if (password == null || salt == null) return null;
        javax.crypto.spec.PBEKeySpec spec = null;
        try {
            spec = new javax.crypto.spec.PBEKeySpec(
                    password.toCharArray(), salt, FIXED_ITERATIONS, KEY_LENGTH_BYTES * 8);
            javax.crypto.SecretKeyFactory factory =
                    javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            return null;
        } finally {
            if (spec != null) spec.clearPassword();
        }
    }

    /**
     * Derive legacy key with old 15,000 iterations for v1 migration.
     */
    public static byte[] deriveLegacyKeyV1(String password, byte[] salt) {
        if (password == null || salt == null) return null;
        javax.crypto.spec.PBEKeySpec spec = null;
        try {
            spec = new javax.crypto.spec.PBEKeySpec(
                    password.toCharArray(), salt, LEGACY_ITERATIONS, KEY_LENGTH_BYTES * 8);
            javax.crypto.SecretKeyFactory factory =
                    javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            return factory.generateSecret(spec).getEncoded();
        } catch (Exception e) {
            return null;
        } finally {
            if (spec != null) spec.clearPassword();
        }
    }

    // ======================== XCHACHA20-POLY1305 ENCRYPTION ========================

    /**
     * Encrypt plaintext using XChaCha20-Poly1305.
     * Returns JSON cipher string: {"alg":"xcha-argon2id13","ct":"base64","iv":"base64","len":N}
     *
     * @param plaintext text to encrypt
     * @param key       byte[32] encryption key (UEK)
     * @return JSON cipher string, or "" for null/empty input, or null on failure
     */
    public static String encrypt(String plaintext, byte[] key) {
        if (plaintext == null || plaintext.length() == 0) {
            return "";
        }
        if (key == null || key.length != KEY_LENGTH_BYTES) {
            Log.e(TAG, "encrypt: invalid key");
            return null;
        }
        try {
            byte[] message = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] nonce = new byte[XCHACHA_NONCE_LENGTH];
            sRandom.nextBytes(nonce);

            // Output buffer: message + tag (16 bytes)
            byte[] ciphertext = new byte[message.length + XCHACHA_TAG_LENGTH];
            long[] ciphertextLen = new long[1];

            boolean success = getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
                    ciphertext, ciphertextLen,
                    message, message.length,
                    null, 0,  // no additional data
                    null,     // nsec (unused in IETF)
                    nonce,
                    key
            );

            if (!success) {
                Log.e(TAG, "encrypt: crypto_aead_xchacha20poly1305_ietf_encrypt failed");
                return null;
            }

            // Build JSON cipher format
            String ctB64 = Base64.encodeToString(ciphertext, 0, (int) ciphertextLen[0], Base64.NO_WRAP);
            String ivB64 = Base64.encodeToString(nonce, Base64.NO_WRAP);

            return "{\"alg\":\"" + ALG_IDENTIFIER + "\","
                    + "\"ct\":\"" + ctB64 + "\","
                    + "\"iv\":\"" + ivB64 + "\","
                    + "\"len\":" + message.length + "}";

        } catch (Exception e) {
            Log.e(TAG, "encrypt failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypt ciphertext. Auto-detects format:
     * - New JSON format: {"alg":"xcha-argon2id13",...}
     * - Old hex format: "ivHex:ciphertextHex" (AES-GCM, for migration)
     *
     * @param encryptedData encrypted string
     * @param key           byte[32] encryption key
     * @return decrypted plaintext, original data if not encrypted, null on decrypt failure
     */
    public static String decrypt(String encryptedData, byte[] key) {
        if (encryptedData == null || encryptedData.length() == 0) {
            return "";
        }
        if (key == null) {
            return null;
        }

        // Detect format
        String trimmed = encryptedData.trim();
        if (trimmed.startsWith("{\"alg\":\"")) {
            return decryptXChaCha(trimmed, key);
        } else if (isOldEncryptedFormat(trimmed)) {
            return decryptOldAesGcm(trimmed, key);
        } else {
            // Not encrypted, return as-is (plaintext legacy data)
            return encryptedData;
        }
    }

    /**
     * Decrypt XChaCha20-Poly1305 JSON cipher format.
     */
    private static String decryptXChaCha(String jsonCipher, byte[] key) {
        try {
            // Simple JSON parsing (no external library needed)
            String ctB64 = extractJsonValue(jsonCipher, "ct");
            String ivB64 = extractJsonValue(jsonCipher, "iv");

            if (ctB64 == null || ivB64 == null) {
                Log.e(TAG, "decryptXChaCha: missing ct or iv");
                return null;
            }

            byte[] ciphertext = Base64.decode(ctB64, Base64.NO_WRAP);
            byte[] nonce = Base64.decode(ivB64, Base64.NO_WRAP);

            if (nonce.length != XCHACHA_NONCE_LENGTH) {
                Log.e(TAG, "decryptXChaCha: invalid nonce length=" + nonce.length);
                return null;
            }

            // Output buffer: ciphertext - tag (16 bytes)
            byte[] plaintext = new byte[ciphertext.length - XCHACHA_TAG_LENGTH];
            long[] plaintextLen = new long[1];

            boolean success = getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plaintext, plaintextLen,
                    null,     // nsec (unused)
                    ciphertext, ciphertext.length,
                    null, 0,  // no additional data
                    nonce,
                    key
            );

            if (!success) {
                Log.w(TAG, "decryptXChaCha: decryption failed (wrong key or tampered)");
                return null;
            }

            return new String(plaintext, 0, (int) plaintextLen[0], StandardCharsets.UTF_8);

        } catch (Exception e) {
            Log.e(TAG, "decryptXChaCha failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypt old AES-256-GCM format (ivHex:ciphertextHex) for backward compatibility.
     */
    private static String decryptOldAesGcm(String encryptedData, byte[] key) {
        try {
            int colonIdx = encryptedData.indexOf(':');
            if (colonIdx <= 0) return encryptedData;

            String ivHex = encryptedData.substring(0, colonIdx);
            String cipherHex = encryptedData.substring(colonIdx + 1);

            byte[] iv = hexToBytes(ivHex);
            byte[] ciphertext = hexToBytes(cipherHex);

            javax.crypto.spec.SecretKeySpec keySpec =
                    new javax.crypto.spec.SecretKeySpec(key, "AES");
            javax.crypto.spec.GCMParameterSpec gcmSpec =
                    new javax.crypto.spec.GCMParameterSpec(128, iv);
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] plainBytes = cipher.doFinal(ciphertext);

            return new String(plainBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Decryption failed
            return null;
        }
    }

    /**
     * Safe decrypt with fallback marker for UI display.
     */
    public static final String DECRYPT_FAILED_MARKER = "[DECRYPTION_FAILED]";

    public static String decryptSafe(String encryptedData, byte[] key) {
        if (encryptedData == null || encryptedData.length() == 0) {
            return "";
        }
        if (key == null) {
            if (isEncrypted(encryptedData)) {
                return DECRYPT_FAILED_MARKER;
            }
            return encryptedData;
        }
        String result = decrypt(encryptedData, key);
        if (result == null) {
            return DECRYPT_FAILED_MARKER;
        }
        return result;
    }

    // ======================== DEK WRAPPING (XChaCha20-Poly1305) ========================

    /**
     * Encrypt DEK/UEK with a wrapping key using XChaCha20-Poly1305.
     * Returns a VaultBundle with Base64-encoded ct, iv (nonce).
     *
     * @param dek       byte[32] data encryption key to wrap
     * @param wrapKey   byte[32] wrapping key (DB key or master key)
     * @return VaultBundle with Base64 encoded fields, or null on failure
     */
    public static VaultBundle encryptDEK(byte[] dek, byte[] wrapKey) {
        if (dek == null || wrapKey == null) {
            Log.e(TAG, "encryptDEK: null input");
            return null;
        }
        try {
            byte[] nonce = new byte[XCHACHA_NONCE_LENGTH];
            sRandom.nextBytes(nonce);

            byte[] ciphertext = new byte[dek.length + XCHACHA_TAG_LENGTH];
            long[] ciphertextLen = new long[1];

            boolean success = getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
                    ciphertext, ciphertextLen,
                    dek, dek.length,
                    null, 0,
                    null,
                    nonce,
                    wrapKey
            );

            if (!success) {
                Log.e(TAG, "encryptDEK: encryption failed");
                return null;
            }

            VaultBundle bundle = new VaultBundle();
            bundle.encryptedDEK = Base64.encodeToString(ciphertext, 0, (int) ciphertextLen[0], Base64.NO_WRAP);
            bundle.iv = Base64.encodeToString(nonce, Base64.NO_WRAP);
            bundle.tag = ""; // Tag is embedded in ciphertext for XChaCha20-Poly1305
            return bundle;

        } catch (Exception e) {
            Log.e(TAG, "encryptDEK failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypt DEK/UEK with a wrapping key using XChaCha20-Poly1305.
     *
     * @param encryptedDEKBase64 Base64-encoded ciphertext (with embedded tag)
     * @param ivBase64           Base64-encoded nonce (24 bytes)
     * @param tagBase64          unused for XChaCha20 (tag is embedded), kept for API compat
     * @param wrapKey            byte[32] wrapping key
     * @return byte[32] DEK on success, null on failure
     */
    public static byte[] decryptDEK(String encryptedDEKBase64, String ivBase64,
                                     String tagBase64, byte[] wrapKey) {
        if (encryptedDEKBase64 == null || ivBase64 == null || wrapKey == null) {
            Log.e(TAG, "decryptDEK: null input");
            return null;
        }
        try {
            byte[] ciphertext = Base64.decode(encryptedDEKBase64, Base64.NO_WRAP);
            byte[] nonce = Base64.decode(ivBase64, Base64.NO_WRAP);

            if (nonce.length != XCHACHA_NONCE_LENGTH) {
                // Try old AES-GCM format (12-byte IV)
                if (nonce.length == OLD_GCM_IV_LENGTH) {
                    return decryptDEKOldAesGcm(encryptedDEKBase64, ivBase64, tagBase64, wrapKey);
                }
                Log.e(TAG, "decryptDEK: invalid nonce length=" + nonce.length);
                return null;
            }

            byte[] plaintext = new byte[ciphertext.length - XCHACHA_TAG_LENGTH];
            long[] plaintextLen = new long[1];

            boolean success = getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plaintext, plaintextLen,
                    null,
                    ciphertext, ciphertext.length,
                    null, 0,
                    nonce,
                    wrapKey
            );

            if (!success) {
                Log.w(TAG, "decryptDEK: decryption failed -- wrong key or tampered");
                return null;
            }

            if (plaintextLen[0] != KEY_LENGTH_BYTES) {
                Log.e(TAG, "decryptDEK: unexpected DEK length=" + plaintextLen[0]);
                return null;
            }

            byte[] result = new byte[KEY_LENGTH_BYTES];
            System.arraycopy(plaintext, 0, result, 0, KEY_LENGTH_BYTES);
            zeroFill(plaintext);
            return result;

        } catch (Exception e) {
            Log.e(TAG, "decryptDEK failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypt DEK using OLD AES-256-GCM format (for migration from old vault).
     */
    private static byte[] decryptDEKOldAesGcm(String encDEKB64, String ivB64,
                                                String tagB64, byte[] masterKey) {
        try {
            byte[] ciphertext = Base64.decode(encDEKB64, Base64.NO_WRAP);
            byte[] iv = Base64.decode(ivB64, Base64.NO_WRAP);
            byte[] tag = tagB64 != null && tagB64.length() > 0
                    ? Base64.decode(tagB64, Base64.NO_WRAP)
                    : new byte[0];

            // Reassemble ciphertext + tag for Java GCM
            byte[] combined;
            if (tag.length > 0) {
                combined = new byte[ciphertext.length + tag.length];
                System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
                System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);
            } else {
                combined = ciphertext;
            }

            javax.crypto.spec.SecretKeySpec keySpec =
                    new javax.crypto.spec.SecretKeySpec(masterKey, "AES");
            javax.crypto.spec.GCMParameterSpec gcmSpec =
                    new javax.crypto.spec.GCMParameterSpec(128, iv);
            javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            return cipher.doFinal(combined);
        } catch (Exception e) {
            Log.e(TAG, "decryptDEKOldAesGcm failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypt data using a legacy key (old CryptoUtils single-layer system).
     * Same AES-256-GCM format (ivHex:ciphertextHex).
     */
    public static String decryptWithLegacyKey(String encryptedData, byte[] legacyKey) {
        return decryptOldAesGcm(encryptedData, legacyKey);
    }

    // ======================== RAW BYTE ENCRYPTION ========================

    /**
     * Encrypt raw bytes using XChaCha20-Poly1305.
     *
     * @param data plaintext bytes
     * @param key  byte[32] encryption key
     * @return EncryptedBlob with ciphertext and nonce, or null on failure
     */
    public static EncryptedBlob encryptBytes(byte[] data, byte[] key) {
        if (data == null || key == null) return null;
        try {
            byte[] nonce = new byte[XCHACHA_NONCE_LENGTH];
            sRandom.nextBytes(nonce);

            byte[] ciphertext = new byte[data.length + XCHACHA_TAG_LENGTH];
            long[] ciphertextLen = new long[1];

            boolean success = getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
                    ciphertext, ciphertextLen,
                    data, data.length,
                    null, 0,
                    null,
                    nonce,
                    key
            );

            if (!success) return null;

            EncryptedBlob blob = new EncryptedBlob();
            blob.ciphertext = Arrays.copyOf(ciphertext, (int) ciphertextLen[0]);
            blob.nonce = nonce;
            return blob;

        } catch (Exception e) {
            Log.e(TAG, "encryptBytes failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypt raw bytes using XChaCha20-Poly1305.
     *
     * @param ciphertext encrypted bytes (including tag)
     * @param nonce      24-byte nonce
     * @param key        byte[32] encryption key
     * @return plaintext bytes, or null on failure
     */
    public static byte[] decryptBytes(byte[] ciphertext, byte[] nonce, byte[] key) {
        if (ciphertext == null || nonce == null || key == null) return null;
        try {
            byte[] plaintext = new byte[ciphertext.length - XCHACHA_TAG_LENGTH];
            long[] plaintextLen = new long[1];

            boolean success = getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plaintext, plaintextLen,
                    null,
                    ciphertext, ciphertext.length,
                    null, 0,
                    nonce,
                    key
            );

            if (!success) return null;
            return Arrays.copyOf(plaintext, (int) plaintextLen[0]);

        } catch (Exception e) {
            Log.e(TAG, "decryptBytes failed: " + e.getMessage());
            return null;
        }
    }

    // ======================== FORMAT DETECTION ========================

    /**
     * Check if a string looks like encrypted data.
     * Supports both new JSON format and old hex format.
     */
    public static boolean isEncrypted(String data) {
        if (data == null || data.length() == 0) {
            return false;
        }
        String trimmed = data.trim();
        // New JSON format
        if (trimmed.startsWith("{\"alg\":\"")) {
            return true;
        }
        // Old hex format
        return isOldEncryptedFormat(trimmed);
    }

    /**
     * Check if data is in old AES-GCM hex format (ivHex:ciphertextHex).
     */
    private static boolean isOldEncryptedFormat(String data) {
        if (data == null || data.length() == 0) return false;
        int colonIdx = data.indexOf(':');
        if (colonIdx != OLD_GCM_IV_LENGTH * 2) return false;
        String ivPart = data.substring(0, colonIdx);
        for (int i = 0; i < ivPart.length(); i++) {
            char c = ivPart.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return true;
    }

    // ======================== MEMORY SAFETY ========================

    /**
     * Zero-fill a byte array to prevent key material from lingering in memory.
     */
    public static void zeroFill(byte[] data) {
        if (data != null) {
            Arrays.fill(data, (byte) 0);
        }
    }

    // ======================== JSON UTILITY ========================

    /**
     * Extract a string value from a simple JSON object.
     * Handles: {"key":"value", ...}
     */
    static String extractJsonValue(String json, String key) {
        String searchKey = "\"" + key + "\":\"";
        int start = json.indexOf(searchKey);
        if (start < 0) return null;
        start += searchKey.length();
        int end = json.indexOf("\"", start);
        if (end < 0) return null;
        return json.substring(start, end);
    }

    /**
     * Extract an integer value from a simple JSON object.
     * Handles: {"key":123, ...}
     */
    static int extractJsonInt(String json, String key) {
        String searchKey = "\"" + key + "\":";
        int start = json.indexOf(searchKey);
        if (start < 0) return -1;
        start += searchKey.length();
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)))) {
            end++;
        }
        try {
            return Integer.parseInt(json.substring(start, end));
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    // ======================== HEX UTILITY ========================

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) sb.append('0');
            sb.append(hex);
        }
        return sb.toString();
    }

    public static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() == 0) return new byte[0];
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // ======================== DATA CLASSES ========================

    /**
     * Holds the result of DEK encryption for vault storage.
     */
    public static class VaultBundle {
        public String encryptedDEK; // Base64 ciphertext (with embedded Poly1305 tag)
        public String iv;           // Base64 nonce (24 bytes)
        public String tag;          // Empty for XChaCha20 (tag is embedded), kept for API compat
    }

    /**
     * Holds encrypted raw bytes with nonce.
     */
    public static class EncryptedBlob {
        public byte[] ciphertext;
        public byte[] nonce;
    }
}
