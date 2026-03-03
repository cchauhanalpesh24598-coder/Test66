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
 * Android Keystore wrapper for hardware-backed key storage.
 *
 * Provides AES-256-GCM key wrapping for the Database Key (DBK).
 * The Keystore master key never leaves the secure hardware (TEE/StrongBox).
 *
 * Usage:
 * - generateOrGetKeystoreKey(alias) - creates or retrieves AES-256-GCM key in Keystore
 * - wrapKey(alias, plainKey) - encrypts a 256-bit key with Keystore key
 * - unwrapKey(alias, wrappedData) - decrypts wrapped key using Keystore key
 * - deleteKey(alias) - removes Keystore entry
 */
public final class SecureKeyStore {

    private static final String TAG = "SecureKeyStore";
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_IV_LENGTH = 12;

    /** Alias for the master Keystore key that wraps the DB key. */
    public static final String ALIAS_DB_KEY_MASTER = "mknotes_db_key_master";

    private SecureKeyStore() {
        // Static utility class
    }

    /**
     * Generate a new AES-256-GCM key in Android Keystore, or get existing one.
     *
     * @param alias the Keystore alias
     * @return true if key exists or was created successfully
     */
    public static boolean generateOrGetKeystoreKey(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            if (keyStore.containsAlias(alias)) {
                Log.d(TAG, "Keystore key already exists: " + alias);
                return true;
            }

            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                    .build();

            KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER);
            keyGenerator.init(spec);
            keyGenerator.generateKey();

            Log.d(TAG, "Keystore key generated: " + alias);
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Failed to generate Keystore key: " + e.getMessage());
            return false;
        }
    }

    /**
     * Wrap (encrypt) a plaintext key using the Keystore master key.
     * Returns Base64-encoded string: "ivBase64:ciphertextBase64"
     *
     * @param alias    the Keystore alias
     * @param plainKey the raw key bytes to wrap (e.g., 32-byte DB key)
     * @return wrapped key string, or null on failure
     */
    public static String wrapKey(String alias, byte[] plainKey) {
        if (plainKey == null || plainKey.length == 0) {
            Log.e(TAG, "wrapKey: null or empty plainKey");
            return null;
        }
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            SecretKey keystoreKey = (SecretKey) keyStore.getKey(alias, null);
            if (keystoreKey == null) {
                Log.e(TAG, "wrapKey: Keystore key not found: " + alias);
                return null;
            }

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keystoreKey);

            byte[] iv = cipher.getIV();
            byte[] ciphertext = cipher.doFinal(plainKey);

            String ivB64 = Base64.encodeToString(iv, Base64.NO_WRAP);
            String ctB64 = Base64.encodeToString(ciphertext, Base64.NO_WRAP);

            return ivB64 + ":" + ctB64;

        } catch (Exception e) {
            Log.e(TAG, "wrapKey failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Unwrap (decrypt) a wrapped key using the Keystore master key.
     *
     * @param alias       the Keystore alias
     * @param wrappedData the wrapped key string ("ivBase64:ciphertextBase64")
     * @return raw key bytes, or null on failure
     */
    public static byte[] unwrapKey(String alias, String wrappedData) {
        if (wrappedData == null || wrappedData.length() == 0) {
            Log.e(TAG, "unwrapKey: null or empty wrappedData");
            return null;
        }
        try {
            int colonIdx = wrappedData.indexOf(':');
            if (colonIdx <= 0) {
                Log.e(TAG, "unwrapKey: invalid format (no colon)");
                return null;
            }

            String ivB64 = wrappedData.substring(0, colonIdx);
            String ctB64 = wrappedData.substring(colonIdx + 1);

            byte[] iv = Base64.decode(ivB64, Base64.NO_WRAP);
            byte[] ciphertext = Base64.decode(ctB64, Base64.NO_WRAP);

            if (iv.length != GCM_IV_LENGTH) {
                Log.e(TAG, "unwrapKey: invalid IV length=" + iv.length);
                return null;
            }

            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            SecretKey keystoreKey = (SecretKey) keyStore.getKey(alias, null);
            if (keystoreKey == null) {
                Log.e(TAG, "unwrapKey: Keystore key not found: " + alias);
                return null;
            }

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, keystoreKey, gcmSpec);

            return cipher.doFinal(ciphertext);

        } catch (android.security.keystore.KeyPermanentlyInvalidatedException e) {
            Log.e(TAG, "unwrapKey: Key permanently invalidated (device security changed)");
            return null;
        } catch (Exception e) {
            Log.e(TAG, "unwrapKey failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Delete a Keystore key entry.
     *
     * @param alias the Keystore alias to delete
     * @return true if deleted or didn't exist
     */
    public static boolean deleteKey(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);

            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
                Log.d(TAG, "Keystore key deleted: " + alias);
            }
            return true;

        } catch (Exception e) {
            Log.e(TAG, "deleteKey failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Check if a Keystore key exists.
     *
     * @param alias the Keystore alias to check
     * @return true if key exists
     */
    public static boolean keyExists(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
            keyStore.load(null);
            return keyStore.containsAlias(alias);
        } catch (Exception e) {
            Log.e(TAG, "keyExists check failed: " + e.getMessage());
            return false;
        }
    }
}
