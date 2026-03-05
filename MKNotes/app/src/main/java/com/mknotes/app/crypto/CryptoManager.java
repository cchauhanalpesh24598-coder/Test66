package com.mknotes.app.crypto;

import android.util.Base64;
import android.util.Log;

import com.goterl.lazysodium.LazySodiumAndroid;
import com.goterl.lazysodium.SodiumAndroid;
import com.sun.jna.NativeLong;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Core encryption engine -- FIXED Architecture (v4).
 *
 * KEY CHANGE: DB Key (Keystore-bound) is NO LONGER in the vault unlock chain.
 * DEK is now wrapped directly with password-derived key (Argon2id).
 * This makes vault recovery device-independent.
 *
 * Primitives (via lazysodium-android / libsodium):
 * - KDF: Argon2id (crypto_pwhash, ALG_ARGON2ID13, opsLimit=3, memLimit=67108864)
 * - DEK wrapping: XChaCha20-Poly1305 (derivedKey wraps DEK)
 * - Data encryption: XChaCha20-Poly1305 IETF (24-byte nonce, 16-byte tag)
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
    private static final long ARGON2_MEM_LIMIT  = 67108864L;  // 64 MiB
    private static final int  ARGON2_ALG        = 2;          // crypto_pwhash_ALG_ARGON2ID13

    /** Old PBKDF2 constants -- ONLY for legacy migration. */
    public static final int FIXED_ITERATIONS  = 120_000;
    public static final int LEGACY_ITERATIONS = 15_000;
    private static final int GCM_IV_LENGTH       = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;

    private static final SecureRandom sRandom = new SecureRandom();

    public static final String DECRYPT_FAILED_MARKER = "[DECRYPTION_FAILED]";

    private CryptoManager() {}

    // ======================== INITIALIZATION ========================

    public static synchronized void init() {
        if (lazySodium == null) {
            sodiumAndroid = new SodiumAndroid();
            lazySodium    = new LazySodiumAndroid(sodiumAndroid);
            Log.d(TAG, "Lazysodium initialized (libsodium loaded)");
        }
    }

    public static LazySodiumAndroid getLazySodium() {
        if (lazySodium == null) throw new IllegalStateException("CryptoManager.init() not called");
        return lazySodium;
    }

    public static SodiumAndroid getSodium() {
        if (sodiumAndroid == null) throw new IllegalStateException("CryptoManager.init() not called");
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
     * DETERMINISTIC: same password + same salt = same derivedKey.
     * This is the foundation of device-independent vault recovery.
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
            byte[] key           = new byte[KEY_LENGTH_BYTES];
            byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

            boolean success = getSodium().crypto_pwhash(
                    key, key.length,
                    passwordBytes, passwordBytes.length,
                    salt,
                    ARGON2_OPS_LIMIT,
                    new NativeLong(ARGON2_MEM_LIMIT),
                    ARGON2_ALG);

            if (!success) {
                Log.e(TAG, "deriveKeyArgon2id: crypto_pwhash failed");
                return null;
            }
            return key;
        } catch (Exception e) {
            Log.e(TAG, "deriveKeyArgon2id failed: " + e.getMessage());
            return null;
        }
    }

    // ======================== XChaCha20-Poly1305 NOTE ENCRYPTION ========================

    /**
     * Encrypt plaintext using XChaCha20-Poly1305 IETF.
     * Format: "xcha:{base64_nonce}:{base64_ciphertext_with_tag}"
     * Used for note field encryption with the DEK.
     */
    public static String encrypt(String plaintext, byte[] key) {
        if (plaintext == null || plaintext.length() == 0) return "";
        if (key == null || key.length != KEY_LENGTH_BYTES) return null;
        try {
            byte[] nonce = new byte[XCHACHA_NONCE_BYTES];
            sRandom.nextBytes(nonce);

            byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
            byte[] ciphertext     = new byte[plaintextBytes.length + XCHACHA_TAG_BYTES];
            int[]  ciphertextLen  = new int[1];

            boolean success = getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
                    ciphertext, ciphertextLen,
                    plaintextBytes, plaintextBytes.length,
                    null, 0,   // no additional data
                    null,      // nsec (unused)
                    nonce, key);

            if (!success) {
                Log.e(TAG, "encrypt: xchacha20poly1305 encrypt failed");
                return null;
            }

            String nonceB64 = Base64.encodeToString(nonce, Base64.NO_WRAP);
            int    ctLen    = ciphertextLen[0] > 0 ? ciphertextLen[0] : ciphertext.length;
            byte[] actualCt = ctLen < ciphertext.length ? Arrays.copyOf(ciphertext, ctLen) : ciphertext;
            String ctB64    = Base64.encodeToString(actualCt, Base64.NO_WRAP);

            return XCHA_PREFIX + nonceB64 + ":" + ctB64;
        } catch (Exception e) {
            Log.e(TAG, "encrypt failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Decrypt data encrypted with XChaCha20-Poly1305.
     * Supports both new "xcha:" format and old "ivHex:ciphertextHex" format.
     */
    public static String decrypt(String encryptedData, byte[] key) {
        if (encryptedData == null || encryptedData.length() == 0) return "";
        if (key == null) return null;

        if (encryptedData.startsWith(XCHA_PREFIX)) {
            return decryptXChaCha(encryptedData, key);
        }

        if (isOldEncrypted(encryptedData)) {
            return decryptOldAesGcm(encryptedData, key);
        }

        // Not encrypted -- return as-is
        return encryptedData;
    }

    private static String decryptXChaCha(String encryptedData, byte[] key) {
        try {
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
            int[]  plaintextLen = new int[1];

            boolean success = getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plaintext, plaintextLen,
                    null,
                    ciphertext, ciphertext.length,
                    null, 0,
                    nonce, key);

            if (!success) {
                Log.w(TAG, "decryptXChaCha: authentication failed (wrong key or tampered)");
                return null;
            }

            int ptLen = plaintextLen[0] > 0 ? plaintextLen[0] : plaintext.length;
            return new String(plaintext, 0, ptLen, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Log.e(TAG, "decryptXChaCha failed: " + e.getMessage());
            return null;
        }
    }

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

    // ======================== DEK WRAPPING WITH DERIVED KEY (NEW v4) ========================

    /**
     * NEW v4: Encrypt DEK with password-derived key using XChaCha20-Poly1305.
     * This replaces the old DB Key wrapping. The derivedKey comes from
     * Argon2id(password, salt) which is deterministic and device-independent.
     *
     * @param dek        byte[32] random Data Encryption Key
     * @param derivedKey byte[32] from Argon2id(password, salt)
     * @return VaultBundle with base64 nonce and ciphertext, or null on failure
     */
    public static VaultBundle encryptDEKWithDerivedKey(byte[] dek, byte[] derivedKey) {
        if (dek == null || derivedKey == null) return null;
        try {
            byte[] nonce = new byte[XCHACHA_NONCE_BYTES];
            sRandom.nextBytes(nonce);

            byte[] ciphertext = new byte[dek.length + XCHACHA_TAG_BYTES];
            int[]  ctLen      = new int[1];

            boolean success = getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
                    ciphertext, ctLen,
                    dek, dek.length,
                    null, 0, null, nonce, derivedKey);

            if (!success) {
                Log.e(TAG, "encryptDEKWithDerivedKey: encrypt failed");
                return null;
            }

            VaultBundle bundle = new VaultBundle();
            bundle.encryptedDEK = Base64.encodeToString(ciphertext, Base64.NO_WRAP);
            bundle.iv           = Base64.encodeToString(nonce, Base64.NO_WRAP);
            bundle.tag          = "xchacha20poly1305"; // Algorithm marker
            return bundle;
        } catch (Exception e) {
            Log.e(TAG, "encryptDEKWithDerivedKey failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * NEW v4: Decrypt DEK using password-derived key (XChaCha20-Poly1305).
     * If decrypt fails, password is wrong (auth tag mismatch).
     *
     * @param encryptedDEKBase64 Base64-encoded encrypted DEK
     * @param ivBase64           Base64-encoded 24-byte nonce
     * @param derivedKey         byte[32] from Argon2id(password, salt)
     * @return byte[32] DEK, or null if password wrong / tampered
     */
    public static byte[] decryptDEKWithDerivedKey(String encryptedDEKBase64,
                                                   String ivBase64,
                                                   byte[] derivedKey) {
        if (encryptedDEKBase64 == null || ivBase64 == null || derivedKey == null) return null;
        try {
            byte[] nonce      = Base64.decode(ivBase64, Base64.NO_WRAP);
            byte[] ciphertext = Base64.decode(encryptedDEKBase64, Base64.NO_WRAP);

            if (nonce.length != XCHACHA_NONCE_BYTES) {
                Log.e(TAG, "decryptDEKWithDerivedKey: invalid nonce length=" + nonce.length);
                return null;
            }

            byte[] plaintext = new byte[ciphertext.length - XCHACHA_TAG_BYTES];
            int[]  ptLen     = new int[1];

            boolean success = getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plaintext, ptLen,
                    null, ciphertext, ciphertext.length,
                    null, 0, nonce, derivedKey);

            if (!success) {
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

    // ======================== OLD DEK WRAPPING (LEGACY - kept for migration) ========================

    /**
     * OLD: Encrypt DEK with DB key using XChaCha20-Poly1305.
     * DEPRECATED: Only used during migration from old vault format.
     */
    public static VaultBundle encryptDEK(byte[] dek, byte[] wrappingKey) {
        if (dek == null || wrappingKey == null) return null;
        try {
            byte[] nonce      = new byte[XCHACHA_NONCE_BYTES];
            sRandom.nextBytes(nonce);
            byte[] ciphertext = new byte[dek.length + XCHACHA_TAG_BYTES];
            int[]  ctLen      = new int[1];

            boolean success = getSodium().crypto_aead_xchacha20poly1305_ietf_encrypt(
                    ciphertext, ctLen,
                    dek, dek.length,
                    null, 0, null, nonce, wrappingKey);

            if (!success) return null;

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
     * OLD: Decrypt DEK using XChaCha20-Poly1305 or AES-256-GCM.
     * DEPRECATED: Only used for migration path from old vault format.
     */
    public static byte[] decryptDEK(String encryptedDEKBase64, String ivBase64,
                                     String tagBase64, byte[] wrappingKey) {
        if (encryptedDEKBase64 == null || ivBase64 == null || wrappingKey == null) return null;

        if ("xchacha20poly1305".equals(tagBase64)) {
            return decryptDEKXChaCha(encryptedDEKBase64, ivBase64, wrappingKey);
        }

        return decryptDEKOldAesGcm(encryptedDEKBase64, ivBase64, tagBase64, wrappingKey);
    }

    private static byte[] decryptDEKXChaCha(String encDEKB64, String nonceB64, byte[] key) {
        try {
            byte[] nonce      = Base64.decode(nonceB64, Base64.NO_WRAP);
            byte[] ciphertext = Base64.decode(encDEKB64, Base64.NO_WRAP);

            byte[] plaintext = new byte[ciphertext.length - XCHACHA_TAG_BYTES];
            int[]  ptLen     = new int[1];

            boolean success = getSodium().crypto_aead_xchacha20poly1305_ietf_decrypt(
                    plaintext, ptLen,
                    null, ciphertext, ciphertext.length,
                    null, 0, nonce, key);

            if (!success) {
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

    private static String decryptOldAesGcm(String encryptedData, byte[] key) {
        try {
            int    colonIdx  = encryptedData.indexOf(':');
            if (colonIdx <= 0) return encryptedData;
            String ivHex     = encryptedData.substring(0, colonIdx);
            String cipherHex = encryptedData.substring(colonIdx + 1);
            if (ivHex.length() != GCM_IV_LENGTH * 2) return encryptedData;

            byte[] iv         = hexToBytes(ivHex);
            byte[] ciphertext = hexToBytes(cipherHex);

            SecretKeySpec    keySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
            byte[] plainBytes = cipher.doFinal(ciphertext);
            return new String(plainBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

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

    public static String decryptWithLegacyKey(String encryptedData, byte[] legacyKey) {
        return decryptOldAesGcm(encryptedData, legacyKey);
    }

    // ======================== DETECTION ========================

    public static boolean isEncrypted(String data) {
        if (data == null || data.length() == 0) return false;
        if (data.startsWith(XCHA_PREFIX)) return true;
        return isOldEncrypted(data);
    }

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
        int    len  = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // ======================== VAULT BUNDLE ========================

    public static class VaultBundle {
        public String encryptedDEK;
        public String iv;
        public String tag;
    }
}
