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

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Core encryption engine -- v4 architecture.
 *
 * v4 CHANGE: DB Key ko vault unlock chain se completely remove kiya.
 * Ab DEK directly password-derived key se wrap/unwrap hota hai.
 *
 * Primitives (via lazysodium-android / libsodium):
 * - KDF: Argon2id (crypto_pwhash, ALG_ARGON2ID13, opsLimit=3, memLimit=67108864)
 * - Data encryption: XChaCha20-Poly1305 IETF (24-byte nonce, 16-byte tag)
 * - DEK wrapping: XChaCha20-Poly1305 (derivedKey wraps DEK)
 * - Streaming file encryption: crypto_secretstream_xchacha20poly1305
 *
 * Storage format for field encryption:
 * "xcha:{base64_nonce}:{base64_ciphertext}"
 *
 * Old format detection (migration):
 * "ivHex:ciphertextHex" where ivHex is 24 hex chars (12 bytes AES-GCM)
 *
 * Memory safety: key material is byte[], zeroed via zeroFill().
 *
 * LEGACY SUPPORT: Old PBKDF2/AES-GCM methods kept for migration only.
 */
public final class CryptoManager {

    private static final String TAG = "CryptoManager";

    // ============ Lazysodium singleton ============
    private static LazySodiumAndroid lazySodium;
    private static SodiumAndroid sodiumAndroid;

    /** Prefix for new XChaCha20-Poly1305 encrypted data. */
    public static final String XCHA_PREFIX = "xcha:";

    /** XChaCha20-Poly1305 constants */
    private static final int XCHACHA_NONCE_BYTES = 24;
    private static final int XCHACHA_TAG_BYTES   = 16; // Poly1305 auth tag appended
    private static final int KEY_LENGTH_BYTES     = 32;

    /** Argon2id KDF constants (matching Notesnook) */
    private static final int  ARGON2_SALT_BYTES = 16;
    private static final int  ARGON2_OPS_LIMIT  = 3;          // crypto_pwhash_OPSLIMIT_MODERATE
    private static final long ARGON2_MEM_LIMIT  = 67108864L;  // 64 MiB = crypto_pwhash_MEMLIMIT_MODERATE
    private static final int  ARGON2_ALG        = 2;           // crypto_pwhash_ALG_ARGON2ID13

    /** Old PBKDF2 constants -- ONLY for legacy migration. */
    public static final int FIXED_ITERATIONS  = 120_000;
    public static final int LEGACY_ITERATIONS = 15_000;
    private static final int GCM_IV_LENGTH       = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    private static final SecureRandom sRandom = new SecureRandom();

    public static final String DECRYPT_FAILED_MARKER = "[DECRYPTION_FAILED]";

    private CryptoManager() {}

    // ======================== INITIALIZATION ========================

    /**
     * Initialize lazysodium. MUST be called from Application.onCreate().
     */
    public static synchronized void init() {
        if (lazySodium == null) {
            sodiumAndroid = new SodiumAndroid();
            lazySodium    = new LazySodiumAndroid(sodiumAndroid);
            Log.d(TAG, "Lazysodium initialized (libsodium loaded)");
        }
    }

    public static LazySodiumAndroid getLazySodium() {
        if (lazySodium == null) {
            throw new IllegalStateException("CryptoManager.init() not called");
        }
        return lazySodium;
    }

    public static SodiumAndroid getSodium() {
        if (sodiumAndroid == null) {
            throw new IllegalStateException("CryptoManager.init() not called");
        }
        return sodiumAndroid;
    }

    // ======================== SALT & DEK GENERATION ========================

    public static byte[] generateSalt() {
        byte[] salt = new byte[ARGON2_SALT_BYTES];
        sRandom.nextBytes(salt);
        return salt;
    }

    public static byte[] generateDEK() {
        byte[] dek = new byte[KEY_LENGTH_BYTES];
        sRandom.nextBytes(dek);
        return dek;
    }

    // ======================== ARGON2ID KEY DERIVATION ========================

    /**
     * Derive a 256-bit key from password + salt using Argon2id.
     * Matches Notesnook: ALG_ARGON2ID13, opsLimit=3, memLimit=64MiB.
     *
     * DETERMINISTIC: Same password + same salt = same derived key ALWAYS.
     * Ye property clear data recovery ke liye critical hai.
     *
     * @param password user's master password
     * @param salt     16-byte salt
     * @return byte[32] derived key, or null on failure
     */
    public static byte[] deriveKeyArgon2id(String password, byte[] salt) {
        if (password == null || password.length() == 0 || salt == null || salt.length == 0) {
            Log.e(TAG, "deriveKeyArgon2id: invalid input");
            return null;
        }
        try {
            byte[] key = new byte[KEY_LENGTH_BYTES];
            byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

            int pwhashResult = getSodium().crypto_pwhash(
                    key, key.length,
                    passwordBytes, passwordBytes.length,
                    salt,
                    ARGON2_OPS_LIMIT,
                    new NativeLong(ARGON2_MEM_LIMIT),
                    ARGON2_ALG);

            if (pwhashResult != 0) {
                Log.e(TAG, "deriveKeyArgon2id: crypto_pwhash failed");
                return null;
            }
            return key;
        } catch (Exception e) {
            Log.e(TAG, "deriveKeyArgon2id failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Alias for deriveKeyArgon2id() -- kept for backward compatibility.
     * MigrationManager calls this method name.
     *
     * @param password user's master password
     * @param salt     16-byte salt
     * @return byte[32] derived key, or null on failure
     */
    public static byte[] deriveKeyArgon2(String password, byte[] salt) {
        return deriveKeyArgon2id(password, salt);
    }

    // ======================== XChaCha20-Poly1305 ENCRYPTION ========================

    /**
     * Encrypt plaintext using XChaCha20-Poly1305 IETF.
     * Format: "xcha:{base64_nonce}:{base64_ciphertext_with_tag}"
     *
     * @param plaintext text to encrypt
     * @param key       byte[32] encryption key (DEK)
     * @return encrypted string in xcha format, "" for null/empty input, null on failure
     */
    public static String encrypt(String plaintext, byte[] key) {
        if (plaintext == null || plaintext.length() == 0) return "";
        if (key == null || key.length != KEY_LENGTH_BYTES) return null;
        try {
            byte[] nonce = new byte[XCHACHA_NONCE_BYTES];
            sRandom.nextBytes(nonce);

            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertext     = new byte[plaintextBytes.length + XCHACHA_TAG_BYTES];
            long[] ciphertextLen  = new long[1];

            int encResult = getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
                    ciphertext, ciphertextLen,
                    plaintextBytes, plaintextBytes.length,
                    null, 0,  // no additional data
                    null,     // nsec (unused)
                    nonce, key);

            if (encResult != 0) {
                Log.e(TAG, "encrypt: xchacha20poly1305 encrypt failed");
                return null;
            }

            String nonceB64 = Base64.encodeToString(nonce, Base64.NO_WRAP);
            // Use actual ciphertext length if available, otherwise full buffer
            int ctLen = ciphertextLen[0] > 0 ? (int) ciphertextLen[0] : ciphertext.length;
            byte[] actualCt = ctLen < ciphertext.length ? Arrays.copyOf(ciphertext, ctLen) : ciphertext;
            String ctB64 = Base64.encodeToString(actualCt, Base64.NO_WRAP);

            return XCHA_PREFIX + nonceB64 + ":" + ctB64;
        } catch (Exception e) {
            Log.e(TAG, "encrypt failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Encrypt raw bytes using XChaCha20-Poly1305 IETF.
     * Returns EncryptedBlob with nonce and ciphertext bytes.
     *
     * @param plainBytes raw bytes to encrypt
     * @param key        byte[32] encryption key
     * @return EncryptedBlob or null on failure
     */
    public static EncryptedBlob encryptBytes(byte[] plainBytes, byte[] key) {
        if (plainBytes == null || plainBytes.length == 0) return null;
        if (key == null || key.length != KEY_LENGTH_BYTES) return null;
        try {
            byte[] nonce = new byte[XCHACHA_NONCE_BYTES];
            sRandom.nextBytes(nonce);

            byte[] ciphertext = new byte[plainBytes.length + XCHACHA_TAG_BYTES];
            long[] ctLen      = new long[1];

            int encResult = getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
                    ciphertext, ctLen,
                    plainBytes, plainBytes.length,
                    null, 0, null, nonce, key);

            if (encResult != 0) {
                Log.e(TAG, "encryptBytes: xchacha20poly1305 encrypt failed");
                return null;
            }

            int actualLen = ctLen[0] > 0 ? (int) ctLen[0] : ciphertext.length;
            byte[] actualCt = actualLen < ciphertext.length
                    ? Arrays.copyOf(ciphertext, actualLen) : ciphertext;

            EncryptedBlob blob = new EncryptedBlob();
            blob.nonce      = nonce;
            blob.ciphertext = actualCt;
            return blob;
        } catch (Exception e) {
            Log.e(TAG, "encryptBytes failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypt raw bytes using XChaCha20-Poly1305 IETF.
     *
     * @param ciphertext ciphertext bytes (includes Poly1305 tag)
     * @param nonce      24-byte nonce
     * @param key        byte[32] decryption key
     * @return decrypted bytes, or null on failure (wrong key / tampered)
     */
    public static byte[] decryptBytes(byte[] ciphertext, byte[] nonce, byte[] key) {
        if (ciphertext == null || nonce == null || key == null) return null;
        if (nonce.length != XCHACHA_NONCE_BYTES || key.length != KEY_LENGTH_BYTES) return null;
        if (ciphertext.length <= XCHACHA_TAG_BYTES) return null;
        try {
            byte[] plaintext    = new byte[ciphertext.length - XCHACHA_TAG_BYTES];
            long[] plaintextLen = new long[1];

            int decResult = getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plaintext, plaintextLen,
                    null,  // nsec (unused)
                    ciphertext, ciphertext.length,
                    null, 0, // no additional data
                    nonce, key);

            if (decResult != 0) {
                Log.w(TAG, "decryptBytes: authentication failed (wrong key or tampered)");
                return null;
            }

            int ptLen = plaintextLen[0] > 0 ? (int) plaintextLen[0] : plaintext.length;
            return ptLen < plaintext.length ? Arrays.copyOf(plaintext, ptLen) : plaintext;
        } catch (Exception e) {
            Log.e(TAG, "decryptBytes failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypt data encrypted with XChaCha20-Poly1305.
     * Supports both new "xcha:" format and old "ivHex:ciphertextHex" format.
     *
     * @param encryptedData the encrypted string
     * @param key           byte[32] decryption key (DEK)
     * @return decrypted plaintext, original if not encrypted, null on decrypt failure
     */
    public static String decrypt(String encryptedData, byte[] key) {
        if (encryptedData == null || encryptedData.length() == 0) return "";
        if (key == null) return null;

        // New format: "xcha:{nonce_b64}:{ciphertext_b64}"
        if (encryptedData.startsWith(XCHA_PREFIX)) {
            return decryptXChaCha(encryptedData, key);
        }

        // Old format: "ivHex:ciphertextHex" (AES-256-GCM, 12-byte IV = 24 hex chars)
        if (isOldEncrypted(encryptedData)) {
            return decryptOldAesGcm(encryptedData, key);
        }

        // Not encrypted -- return as-is (plaintext data)
        return encryptedData;
    }

    /**
     * Decrypt XChaCha20-Poly1305 format.
     */
    private static String decryptXChaCha(String encryptedData, byte[] key) {
        try {
            // Remove "xcha:" prefix, split nonce:ciphertext
            String payload  = encryptedData.substring(XCHA_PREFIX.length());
            int    colonIdx = payload.indexOf(':');
            if (colonIdx <= 0) return null;

            byte[] nonce      = Base64.decode(payload.substring(0, colonIdx), Base64.NO_WRAP);
            byte[] ciphertext = Base64.decode(payload.substring(colonIdx + 1), Base64.NO_WRAP);

            if (nonce.length != XCHACHA_NONCE_BYTES) {
                Log.e(TAG, "decryptXChaCha: invalid nonce length=" + nonce.length);
                return null;
            }

            byte[] plaintext    = new byte[ciphertext.length - XCHACHA_TAG_BYTES];
            long[] plaintextLen = new long[1];

            int decResult = getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plaintext, plaintextLen,
                    null, // nsec (unused)
                    ciphertext, ciphertext.length,
                    null, 0, // no additional data
                    nonce, key);

            if (decResult != 0) {
                Log.w(TAG, "decryptXChaCha: authentication failed (wrong key or tampered)");
                return null;
            }

            int ptLen = plaintextLen[0] > 0 ? (int) plaintextLen[0] : plaintext.length;
            return new String(plaintext, 0, ptLen, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Log.e(TAG, "decryptXChaCha failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Safe decrypt with fallback marker for UI display.
     */
    public static String decryptSafe(String encryptedData, byte[] dek) {
        if (encryptedData == null || encryptedData.length() == 0) return "";
        if (dek == null) {
            if (isEncrypted(encryptedData)) return DECRYPT_FAILED_MARKER;
            return encryptedData;
        }
        String result = decrypt(encryptedData, dek);
        if (result == null) return DECRYPT_FAILED_MARKER;
        return result;
    }

    // ======================== DEK WRAPPING WITH DERIVED KEY (v4 NEW) ========================

    /**
     * v4 NEW: Encrypt DEK with password-derived key using XChaCha20-Poly1305.
     * Ye method vault creation aur password change me use hota hai.
     *
     * Flow: derivedKey (from Argon2id) wraps random DEK
     *
     * @param dek         byte[32] random Data Encryption Key
     * @param derivedKey  byte[32] key derived from password via Argon2id
     * @return VaultBundle with base64 nonce and ciphertext, or null on failure
     */
    public static VaultBundle encryptDEKWithDerivedKey(byte[] dek, byte[] derivedKey) {
        if (dek == null || derivedKey == null) return null;
        if (dek.length != KEY_LENGTH_BYTES || derivedKey.length != KEY_LENGTH_BYTES) return null;
        try {
            byte[] nonce = new byte[XCHACHA_NONCE_BYTES];
            sRandom.nextBytes(nonce);

            byte[] ciphertext = new byte[dek.length + XCHACHA_TAG_BYTES];
            long[] ctLen      = new long[1];

            int encResult = getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
                    ciphertext, ctLen,
                    dek, dek.length,
                    null, 0, null, nonce, derivedKey);

            if (encResult != 0) {
                Log.e(TAG, "encryptDEKWithDerivedKey: XChaCha20 encrypt failed");
                return null;
            }

            VaultBundle bundle = new VaultBundle();
            bundle.encryptedDEK = Base64.encodeToString(ciphertext, Base64.NO_WRAP);
            bundle.iv           = Base64.encodeToString(nonce, Base64.NO_WRAP);
            bundle.tag          = "xchacha20poly1305"; // v4 format marker
            return bundle;
        } catch (Exception e) {
            Log.e(TAG, "encryptDEKWithDerivedKey failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * v4 NEW: Decrypt DEK using password-derived key.
     * Ye method vault unlock aur password change me use hota hai.
     *
     * Flow: derivedKey (from Argon2id) unwraps encryptedDEK -> returns random DEK
     *
     * Agar decrypt fail ho -> password galat hai.
     *
     * @param encryptedDEKBase64 base64 encoded ciphertext
     * @param ivBase64           base64 encoded nonce
     * @param derivedKey         byte[32] key derived from password via Argon2id
     * @return byte[32] DEK, or null if wrong password / tampered
     */
    public static byte[] decryptDEKWithDerivedKey(String encryptedDEKBase64, String ivBase64,
                                                   byte[] derivedKey) {
        if (encryptedDEKBase64 == null || ivBase64 == null || derivedKey == null) return null;
        if (derivedKey.length != KEY_LENGTH_BYTES) return null;
        try {
            byte[] nonce      = Base64.decode(ivBase64, Base64.NO_WRAP);
            byte[] ciphertext = Base64.decode(encryptedDEKBase64, Base64.NO_WRAP);

            if (nonce.length != XCHACHA_NONCE_BYTES) {
                Log.e(TAG, "decryptDEKWithDerivedKey: invalid nonce length=" + nonce.length);
                return null;
            }

            byte[] plaintext    = new byte[ciphertext.length - XCHACHA_TAG_BYTES];
            long[] plaintextLen = new long[1];

            int decResult = getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plaintext, plaintextLen,
                    null, ciphertext, ciphertext.length,
                    null, 0, nonce, derivedKey);

            if (decResult != 0) {
                Log.w(TAG, "decryptDEKWithDerivedKey: auth failed -- wrong password");
                return null;
            }

            if (plaintext.length != KEY_LENGTH_BYTES) {
                Log.e(TAG, "decryptDEKWithDerivedKey: unexpected DEK length=" + plaintext.length);
                zeroFill(plaintext);
                return null;
            }
            return plaintext;
        } catch (Exception e) {
            Log.e(TAG, "decryptDEKWithDerivedKey failed: " + e.getMessage());
            return null;
        }
    }

    // ======================== DEK WRAPPING (OLD - for backward compat) ========================

    /**
     * OLD: Encrypt DEK with DB key using XChaCha20-Poly1305.
     * DEPRECATED in v4 -- kept only for migration support.
     * New code should use encryptDEKWithDerivedKey() instead.
     */
    public static VaultBundle encryptDEK(byte[] dek, byte[] wrappingKey) {
        if (dek == null || wrappingKey == null) return null;
        try {
            byte[] nonce = new byte[XCHACHA_NONCE_BYTES];
            sRandom.nextBytes(nonce);

            byte[] ciphertext = new byte[dek.length + XCHACHA_TAG_BYTES];
            long[] ctLen      = new long[1];

            int encResult = getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
                    ciphertext, ctLen,
                    dek, dek.length,
                    null, 0, null, nonce, wrappingKey);

            if (encResult != 0) return null;

            VaultBundle bundle = new VaultBundle();
            bundle.encryptedDEK = Base64.encodeToString(ciphertext, Base64.NO_WRAP);
            bundle.iv           = Base64.encodeToString(nonce, Base64.NO_WRAP);
            bundle.tag          = "xchacha20poly1305";
            return bundle;
        } catch (Exception e) {
            Log.e(TAG, "encryptDEK failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * OLD: Decrypt DEK using XChaCha20-Poly1305.
     * Also supports old AES-256-GCM format (separate ciphertext + tag).
     * DEPRECATED in v4 -- kept only for migration support.
     */
    public static byte[] decryptDEK(String encryptedDEKBase64, String ivBase64,
                                     String tagBase64, byte[] wrappingKey) {
        if (encryptedDEKBase64 == null || ivBase64 == null || wrappingKey == null) return null;

        // New format: tag == "xchacha20poly1305", iv = nonce, encryptedDEK = ciphertext_with_tag
        if ("xchacha20poly1305".equals(tagBase64)) {
            return decryptDEKXChaCha(encryptedDEKBase64, ivBase64, wrappingKey);
        }

        // Old format: AES-256-GCM (separate ciphertext and tag)
        return decryptDEKOldAesGcm(encryptedDEKBase64, ivBase64, tagBase64, wrappingKey);
    }

    private static byte[] decryptDEKXChaCha(String encDEKB64, String nonceB64, byte[] key) {
        try {
            byte[] nonce      = Base64.decode(nonceB64, Base64.NO_WRAP);
            byte[] ciphertext = Base64.decode(encDEKB64, Base64.NO_WRAP);

            byte[] plaintext = new byte[ciphertext.length - XCHACHA_TAG_BYTES];
            long[] ptLen     = new long[1];

            int decResult = getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plaintext, ptLen,
                    null, ciphertext, ciphertext.length,
                    null, 0, nonce, key);

            if (decResult != 0) {
                Log.w(TAG, "decryptDEKXChaCha: auth failed -- wrong key");
                return null;
            }
            if (plaintext.length != KEY_LENGTH_BYTES) {
                Log.e(TAG, "decryptDEKXChaCha: unexpected DEK length=" + plaintext.length);
                zeroFill(plaintext);
                return null;
            }
            return plaintext;
        } catch (Exception e) {
            Log.e(TAG, "decryptDEKXChaCha failed: " + e.getMessage());
            return null;
        }
    }

    // ======================== LEGACY AES-GCM (migration only) ========================

    /**
     * Old AES-256-GCM DEK decryption. Used during migration from old vault format.
     */
    private static byte[] decryptDEKOldAesGcm(String encDEKB64, String ivB64,
                                               String tagB64, byte[] masterKey) {
        try {
            byte[] ciphertext = Base64.decode(encDEKB64, Base64.NO_WRAP);
            byte[] iv         = Base64.decode(ivB64, Base64.NO_WRAP);
            byte[] tag        = Base64.decode(tagB64, Base64.NO_WRAP);

            if (iv.length != GCM_IV_LENGTH) return null;

            byte[] ciphertextWithTag = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, ciphertextWithTag, 0, ciphertext.length);
            System.arraycopy(tag, 0, ciphertextWithTag, ciphertext.length, tag.length);

            SecretKeySpec  keySpec = new SecretKeySpec(masterKey, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] dek = cipher.doFinal(ciphertextWithTag);

            if (dek.length != KEY_LENGTH_BYTES) {
                zeroFill(dek);
                return null;
            }
            return dek;
        } catch (javax.crypto.AEADBadTagException e) {
            Log.w(TAG, "decryptDEKOldAesGcm: wrong password");
            return null;
        } catch (Exception e) {
            Log.e(TAG, "decryptDEKOldAesGcm failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypt old AES-256-GCM "ivHex:ciphertextHex" format.
     */
    private static String decryptOldAesGcm(String encryptedData, byte[] key) {
        try {
            int colonIdx = encryptedData.indexOf(':');
            if (colonIdx <= 0) return encryptedData;

            String ivHex     = encryptedData.substring(0, colonIdx);
            String cipherHex = encryptedData.substring(colonIdx + 1);

            if (ivHex.length() != GCM_IV_LENGTH * 2) return encryptedData;

            byte[] iv         = hexToBytes(ivHex);
            byte[] ciphertext = hexToBytes(cipherHex);

            SecretKeySpec  keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] plainBytes = cipher.doFinal(ciphertext);
            return new String(plainBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Derive legacy PBKDF2 master key. Only used by MigrationManager.
     */
    public static byte[] deriveMasterKey(String password, byte[] salt) {
        if (password == null || salt == null) return null;
        try {
            javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                    password.toCharArray(), salt, FIXED_ITERATIONS, 256);
            javax.crypto.SecretKeyFactory factory =
                    javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] key = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return key;
        } catch (Exception e) {
            return null;
        }
    }

    public static byte[] deriveLegacyKey(String password, byte[] salt) {
        if (password == null || salt == null) return null;
        try {
            javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                    password.toCharArray(), salt, LEGACY_ITERATIONS, 256);
            javax.crypto.SecretKeyFactory factory =
                    javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] key = factory.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return key;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Legacy decrypt with old CryptoManager key (for migration).
     */
    public static String decryptWithLegacyKey(String encryptedData, byte[] legacyKey) {
        return decryptOldAesGcm(encryptedData, legacyKey);
    }

    // ======================== DETECTION ========================

    /**
     * Check if data is encrypted (either new xcha or old AES-GCM format).
     */
    public static boolean isEncrypted(String data) {
        if (data == null || data.length() == 0) return false;
        if (data.startsWith(XCHA_PREFIX)) return true;
        return isOldEncrypted(data);
    }

    /**
     * Check if data uses old "ivHex:ciphertextHex" AES-GCM format.
     */
    public static boolean isOldEncrypted(String data) {
        if (data == null || data.length() == 0) return false;
        int colonIdx = data.indexOf(':');
        if (colonIdx != GCM_IV_LENGTH * 2) return false;
        String ivPart = data.substring(0, colonIdx);
        for (int i = 0; i < ivPart.length(); i++) {
            char c = ivPart.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    // ======================== MEMORY SAFETY ========================

    public static void zeroFill(byte[] data) {
        if (data != null) Arrays.fill(data, (byte) 0);
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

    // ======================== JSON UTILITY ========================

    /**
     * Simple JSON value extractor for Firestore-like JSON strings.
     * Finds "key":"value" pattern and returns the value.
     *
     * @param json JSON string
     * @param key  key to search for
     * @return value string, or null if not found
     */
    public static String extractJsonValue(String json, String key) {
        if (json == null || key == null) return null;
        String searchKey = "\"" + key + "\"";
        int keyIdx = json.indexOf(searchKey);
        if (keyIdx < 0) return null;

        int colonIdx = json.indexOf(':', keyIdx + searchKey.length());
        if (colonIdx < 0) return null;

        // Skip whitespace after colon
        int valueStart = colonIdx + 1;
        while (valueStart < json.length() && json.charAt(valueStart) == ' ') {
            valueStart++;
        }
        if (valueStart >= json.length()) return null;

        if (json.charAt(valueStart) == '"') {
            // String value
            int valueEnd = json.indexOf('"', valueStart + 1);
            if (valueEnd < 0) return null;
            return json.substring(valueStart + 1, valueEnd);
        } else {
            // Numeric or boolean value
            int valueEnd = valueStart;
            while (valueEnd < json.length()
                    && json.charAt(valueEnd) != ','
                    && json.charAt(valueEnd) != '}'
                    && json.charAt(valueEnd) != ' ') {
                valueEnd++;
            }
            return json.substring(valueStart, valueEnd).trim();
        }
    }

    // ======================== DATA CLASSES ========================

    /** Result of encryptBytes() */
    public static class EncryptedBlob {
        public byte[] nonce;
        public byte[] ciphertext;
    }

    /** Vault metadata bundle for Firestore storage */
    public static class VaultBundle {
        public String encryptedDEK;
        public String iv;
        public String tag;
    }
}
