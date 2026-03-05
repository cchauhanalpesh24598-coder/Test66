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
 * v4 CHANGE: Keystore is now ONLY used for:
 * 1. SQLCipher DB key wrapping (local DB encryption)
 * 2. Optional DEK session caching (future enhancement)
 *
 * Keystore is NOT in the vault unlock chain.
 * If Keystore key is lost (clear data), a new DB key is generated
 * and the local SQLCipher DB is re-populated from cloud sync.
 * The actual DEK (note encryption key) is recovered purely from
 * password + Firestore vault metadata.
 */
public final class SecureKeyStore {

    private static final String TAG = "SecureKeyStore";
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String TRANSFORMATION   = "AES/GCM/NoPadding";
    private static final int    GCM_TAG_BITS     = 128;

    /** Default alias for the DB key master wrapper (SQLCipher only). */
    public static final String ALIAS_DB_KEY_MASTER = "mknotes_db_key_master";

    /** Optional alias for session DEK cache (future use). */
    public static final String ALIAS_SESSION_DEK_CACHE = "mknotes_session_dek";

    private SecureKeyStore() {}

    /**
     * Generate a new AES-256-GCM key in Android Keystore if it doesn't already exist.
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
     * Used for SQLCipher DB key protection only (not vault DEK).
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
     * Returns null if Keystore key was invalidated (e.g., after clear data).
     */
    public static byte[] unwrapKey(String alias, String wrappedData) {
        if (wrappedData == null || !wrappedData.contains(":")) return null;
        try {
            int    colonIdx  = wrappedData.indexOf(':');
            byte[] iv        = Base64.decode(wrappedData.substring(0, colonIdx), Base64.NO_WRAP);
            byte[] encrypted = Base64.decode(wrappedData.substring(colonIdx + 1), Base64.NO_WRAP);

            KeyStore ks = KeyStore.getInstance(ANDROID_KEYSTORE);
            ks.load(null);
            SecretKey keystoreKey = (SecretKey) ks.getKey(alias, null);
            if (keystoreKey == null) {
                Log.e(TAG, "unwrapKey: Keystore key not found: " + alias);
                return null;
            }

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, keystoreKey, gcmSpec);
            return cipher.doFinal(encrypted);
        } catch (android.security.keystore.KeyPermanentlyInvalidatedException e) {
            Log.e(TAG, "unwrapKey: Key permanently invalidated (clear data / biometric change)");
            return null;
        } catch (Exception e) {
            Log.e(TAG, "unwrapKey failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Delete a Keystore key entry.
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
