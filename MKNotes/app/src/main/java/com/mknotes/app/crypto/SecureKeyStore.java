package com.mknotes.app.crypto;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Android Keystore wrapper for hardware-backed key protection.
 *
 * v4 ROLE CHANGE:
 * ===============
 * PURANA (v3): Keystore wrap karta tha DB Key ko, jo vault unlock chain me use hota tha.
 *              Agar Keystore delete ho jaye (clear data) -> DB Key lost -> vault unrecoverable.
 *
 * NAYA (v4):   Keystore SIRF optional session DEK cache ke liye use hota hai.
 *              Vault unlock chain me Keystore ka koi role NAHI hai.
 *              Agar Keystore delete ho jaye -> koi problem nahi, user password se vault unlock hoga.
 *
 * Usage:
 * - wraps/unwraps the session DEK cache (for fast session resumption without Argon2id)
 * - wraps/unwraps the SQLCipher DB key (for database passphrase)
 * - Both are OPTIONAL -- vault security does NOT depend on Keystore anymore
 *
 * The Keystore key itself never leaves the secure hardware (TEE/StrongBox).
 */
public final class SecureKeyStore {

    private static final String TAG = "SecureKeyStore";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String TRANSFORMATION   = "AES/GCM/NoPadding";
    private static final int    GCM_TAG_BITS     = 128;

    /** Default alias for the DB key master wrapper (also used for session DEK cache). */
    public static final String ALIAS_DB_KEY_MASTER = "mknotes_db_key_master";

    private SecureKeyStore() {}

    /**
     * Generate a new AES-256-GCM key in Android Keystore if it doesn't already exist.
     *
     * @param alias Keystore alias
     * @return true if key exists or was created, false on failure
     */
    public static boolean generateOrGetKeystoreKey(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            if (ks.containsAlias(alias)) {
                return true;
            }

            KeyGenerator kg = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                    .build();
            kg.init(spec);
            kg.generateKey();
            Log.d(TAG, "Generated Keystore key: " + alias);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to generate Keystore key: " + e.getMessage());
            return false;
        }
    }

    /**
     * Wrap (encrypt) a plaintext key with the Keystore master key.
     *
     * v4: Used for OPTIONAL session DEK cache and SQLCipher DB key.
     * NOT used in vault unlock chain anymore.
     *
     * @param alias    Keystore alias
     * @param plainKey raw key bytes to protect (e.g. 32-byte DEK or DB key)
     * @return Base64 string "iv:ciphertext" or null on failure
     */
    public static String wrapKey(String alias, byte[] plainKey) {
        if (plainKey == null || plainKey.length == 0) return null;
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            SecretKey keystoreKey = (SecretKey) ks.getKey(alias, null);
            if (keystoreKey == null) {
                Log.e(TAG, "wrapKey: Keystore key not found: " + alias);
                return null;
            }

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, keystoreKey);
            byte[] iv        = cipher.getIV();
            byte[] encrypted = cipher.doFinal(plainKey);

            String ivB64 = Base64.encodeToString(iv, Base64.NO_WRAP);
            String ctB64 = Base64.encodeToString(encrypted, Base64.NO_WRAP);
            return ivB64 + ":" + ctB64;
        } catch (Exception e) {
            Log.e(TAG, "wrapKey failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Unwrap (decrypt) a wrapped key using the Keystore master key.
     *
     * v4: Used for OPTIONAL session DEK cache and SQLCipher DB key.
     * If this fails (e.g. after clear data), vault unlock still works via password.
     *
     * @param alias      Keystore alias
     * @param wrappedData Base64 "iv:ciphertext" string from wrapKey()
     * @return raw key bytes, or null on failure
     */
    public static byte[] unwrapKey(String alias, String wrappedData) {
        if (wrappedData == null || !wrappedData.contains(":")) return null;
        try {
            int    colonIdx = wrappedData.indexOf(':');
            byte[] iv       = Base64.decode(wrappedData.substring(0, colonIdx), Base64.NO_WRAP);
            byte[] encrypted = Base64.decode(wrappedData.substring(colonIdx + 1), Base64.NO_WRAP);

            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            SecretKey keystoreKey = (SecretKey) ks.getKey(alias, null);
            if (keystoreKey == null) {
                Log.e(TAG, "unwrapKey: Keystore key not found: " + alias);
                return null;
            }

            Cipher         cipher  = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, keystoreKey, gcmSpec);
            return cipher.doFinal(encrypted);
        } catch (android.security.keystore.KeyPermanentlyInvalidatedException e) {
            Log.e(TAG, "unwrapKey: Key permanently invalidated (biometric/lockscreen changed)");
            return null;
        } catch (Exception e) {
            Log.e(TAG, "unwrapKey failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Delete a Keystore key entry.
     *
     * @param alias Keystore alias to remove
     */
    public static void deleteKey(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            if (ks.containsAlias(alias)) {
                ks.deleteEntry(alias);
                Log.d(TAG, "Deleted Keystore key: " + alias);
            }
        } catch (Exception e) {
            Log.e(TAG, "deleteKey failed: " + e.getMessage());
        }
    }

    /**
     * Check if a Keystore key exists.
     */
    public static boolean hasKey(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            return ks.containsAlias(alias);
        } catch (Exception e) {
            return false;
        }
    }
}
