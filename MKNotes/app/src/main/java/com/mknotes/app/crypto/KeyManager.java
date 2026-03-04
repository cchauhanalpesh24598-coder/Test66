package com.mknotes.app.crypto;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import com.google.firebase.firestore.DocumentReference;
import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.Source;

import com.mknotes.app.cloud.FirebaseAuthManager;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Singleton managing the key hierarchy (Notesnook-equivalent, FIXED).
 *
 * NEW Key Hierarchy (Clear-Data Resistant):
 *
 *   Layer 1: User Password
 *     -> (Argon2id KDF) -> Password Key (PK) - 256-bit
 *     -> PK encrypts RANDOM UEK via XChaCha20-Poly1305
 *     -> Stored as "encUEK_PK" + "iv_PK" in Firestore + local prefs
 *     -> THIS IS THE RECOVERY PATH (survives Clear Data)
 *
 *   Layer 2: Database Key (DBK) - 256-bit
 *     -> Random, generated once per device
 *     -> Wrapped with Android Keystore AES-256-GCM master key
 *     -> Stored as encrypted blob in SharedPreferences
 *     -> Used as: SQLCipher DB passphrase
 *     -> ALSO wraps UEK for fast local unlock (no Argon2 needed)
 *     -> Stored as "encUEK_DBK" + "iv_DBK" in local prefs only
 *
 *   Layer 3: Android Keystore hardware-backed AES key
 *     -> Never leaves secure hardware (TEE/StrongBox)
 *     -> Used ONLY to wrap/unwrap DB key
 *
 *   UEK (User Encryption Key) - 256-bit RANDOM
 *     -> Generated ONCE at vault creation (NEVER derived from password)
 *     -> This key encrypts/decrypts all note data
 *     -> Wrapped by BOTH PK (for recovery) and DBK (for fast unlock)
 *
 * Firestore document path: users/{uid}/crypto_metadata/vault
 * Fields: salt (Base64), encUEK_PK (Base64), iv_PK (Base64),
 *         algorithm ("xcha-argon2id13"), createdAt (long millis)
 *
 * RECOVERY AFTER CLEAR DATA:
 * 1. Login Firebase -> fetch vault from Firestore
 * 2. Vault has: salt, encUEK_PK, iv_PK
 * 3. User enters master password
 * 4. Derive PK from password + salt via Argon2id
 * 5. Decrypt UEK using PK -> SUCCESS (no DBK needed!)
 * 6. Generate NEW DBK, wrap with Keystore, store locally
 * 7. Re-wrap UEK with new DBK for local fast-unlock
 * 8. Notes decrypt normally with recovered UEK
 */
public class KeyManager {

    private static final String TAG = "KeyManager";

    // Local SharedPreferences keys
    private static final String PREFS_NAME = "mknotes_vault_v3";

    // Password-Key wrapped UEK (stored in Firestore + local prefs)
    private static final String KEY_SALT = "vault_salt_b64";
    private static final String KEY_ENC_UEK_PK = "enc_uek_pk_b64";        // UEK encrypted with Password Key
    private static final String KEY_IV_PK = "iv_pk_b64";                    // Nonce for PK wrapping

    // DBK-wrapped UEK (stored in local prefs ONLY)
    private static final String KEY_ENC_UEK_DBK = "user_key_cipher_b64";   // UEK encrypted with DBK (backward compat name)
    private static final String KEY_IV_DBK = "user_key_iv_b64";            // Nonce for DBK wrapping (backward compat name)

    // DB Key wrapped by Keystore
    private static final String KEY_WRAPPED_DB_KEY = "wrapped_db_key";

    // Metadata
    private static final String KEY_ALGORITHM = "vault_algorithm";
    private static final String KEY_CREATED_AT = "vault_created_at";
    private static final String KEY_VAULT_INITIALIZED = "vault_initialized";
    private static final String KEY_VAULT_UPLOADED = "vault_uploaded_to_firestore";
    private static final String KEY_HAS_PK_WRAPPING = "has_pk_wrapping";   // NEW: flag for PK wrapping

    // Old vault prefs name for migration detection
    private static final String OLD_PREFS_NAME = "mknotes_vault_v2";

    // Legacy key names (for reading old data during migration)
    private static final String LEGACY_KEY_USER_KEY_CIPHER = "user_key_cipher_b64";
    private static final String LEGACY_KEY_USER_KEY_IV = "user_key_iv_b64";

    public static final int CURRENT_VAULT_VERSION = 3;

    private static KeyManager sInstance;

    private final SharedPreferences prefs;
    private final SharedPreferences oldPrefs;
    private final Context appContext;

    /**
     * In-memory cached UEK (User Encryption Key). ONLY copy in memory.
     * Zeroed on lockVault().
     */
    private byte[] cachedUEK;

    /**
     * In-memory cached DB Key. Loaded from Keystore on app start.
     */
    private byte[] cachedDBKey;

    public static synchronized KeyManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new KeyManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private KeyManager(Context context) {
        this.appContext = context;
        this.prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        this.oldPrefs = context.getSharedPreferences(OLD_PREFS_NAME, Context.MODE_PRIVATE);
        this.cachedUEK = null;
        this.cachedDBKey = null;
    }

    // ======================== STATE CHECKS ========================

    /**
     * Check if vault metadata exists locally.
     * Supports both old format (only DBK wrapping) and new format (PK wrapping).
     */
    public boolean isVaultInitialized() {
        boolean hasBasicVault = prefs.getBoolean(KEY_VAULT_INITIALIZED, false)
                && prefs.getString(KEY_SALT, null) != null;

        if (!hasBasicVault) return false;

        // New format: has PK wrapping
        if (prefs.getString(KEY_ENC_UEK_PK, null) != null
                && prefs.getString(KEY_IV_PK, null) != null) {
            return true;
        }

        // Old format: only DBK wrapping (backward compat)
        if (prefs.getString(KEY_ENC_UEK_DBK, null) != null
                && prefs.getString(KEY_IV_DBK, null) != null
                && prefs.getString(KEY_WRAPPED_DB_KEY, null) != null) {
            return true;
        }

        return false;
    }

    /**
     * Check if vault has PK (password-key) wrapping -- the recovery-capable format.
     */
    public boolean hasPKWrapping() {
        return prefs.getString(KEY_ENC_UEK_PK, null) != null
                && prefs.getString(KEY_IV_PK, null) != null
                && prefs.getString(KEY_SALT, null) != null;
    }

    /**
     * Check if vault has DBK wrapping (device-local fast unlock).
     */
    public boolean hasDBKWrapping() {
        return prefs.getString(KEY_ENC_UEK_DBK, null) != null
                && prefs.getString(KEY_IV_DBK, null) != null
                && prefs.getString(KEY_WRAPPED_DB_KEY, null) != null;
    }

    /**
     * Check if vault is currently unlocked (UEK is in memory).
     */
    public boolean isVaultUnlocked() {
        return cachedUEK != null;
    }

    /**
     * Check if old vault (v2 PBKDF2/AES-GCM) exists for migration.
     */
    public boolean hasOldVault() {
        return oldPrefs.getBoolean("vault_initialized", false)
                && oldPrefs.getString("vault_salt_b64", null) != null
                && oldPrefs.getString("vault_enc_dek_b64", null) != null;
    }

    /**
     * Get vault version. Returns CURRENT_VAULT_VERSION if initialized.
     */
    public int getVaultVersion() {
        if (isVaultInitialized()) return CURRENT_VAULT_VERSION;
        if (hasOldVault()) return 2;
        return 0;
    }

    /**
     * Check if migration from old system is needed.
     */
    public boolean needsMigration() {
        return !isVaultInitialized() && hasOldVault();
    }

    /**
     * Check if vault has been confirmed uploaded to Firestore.
     */
    public boolean isVaultUploaded() {
        return prefs.getBoolean(KEY_VAULT_UPLOADED, false);
    }

    /**
     * Get iterations (legacy compat -- new system uses Argon2).
     */
    public int getIterations() {
        return 0; // Argon2 doesn't use simple iteration count
    }

    // ======================== DB KEY MANAGEMENT ========================

    /**
     * Initialize the Database Key (Layer 2).
     * Generates random 256-bit key, wraps with Android Keystore, stores wrapped blob.
     * Called once during first vault creation OR after Clear Data recovery.
     *
     * @return true if DB key was created or already exists
     */
    public boolean initializeDBKey() {
        // Check if already exists
        String wrappedDBKey = prefs.getString(KEY_WRAPPED_DB_KEY, null);
        if (wrappedDBKey != null && wrappedDBKey.length() > 0) {
            return true;
        }

        try {
            // Ensure Keystore master key exists
            if (!SecureKeyStore.generateOrGetKeystoreKey(SecureKeyStore.ALIAS_DB_KEY_MASTER)) {
                Log.e(TAG, "initializeDBKey: Keystore key generation failed");
                return false;
            }

            // Generate random 256-bit DB key
            byte[] dbKey = new byte[CryptoManager.KEY_LENGTH_BYTES];
            new SecureRandom().nextBytes(dbKey);

            // Wrap with Keystore
            String wrapped = SecureKeyStore.wrapKey(SecureKeyStore.ALIAS_DB_KEY_MASTER, dbKey);
            if (wrapped == null) {
                CryptoManager.zeroFill(dbKey);
                Log.e(TAG, "initializeDBKey: Keystore wrapping failed");
                return false;
            }

            // Store wrapped DB key
            prefs.edit().putString(KEY_WRAPPED_DB_KEY, wrapped).commit();

            // Cache in memory
            cachedDBKey = dbKey;

            Log.d(TAG, "DB key generated and wrapped successfully");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "initializeDBKey failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Load (unwrap) DB key from Keystore.
     * Called on app start to make DB key available.
     *
     * @return true if DB key is available in memory
     */
    public boolean loadDBKey() {
        if (cachedDBKey != null) return true;

        String wrappedDBKey = prefs.getString(KEY_WRAPPED_DB_KEY, null);
        if (wrappedDBKey == null || wrappedDBKey.length() == 0) {
            Log.w(TAG, "loadDBKey: no wrapped DB key found");
            return false;
        }

        byte[] dbKey = SecureKeyStore.unwrapKey(SecureKeyStore.ALIAS_DB_KEY_MASTER, wrappedDBKey);
        if (dbKey == null) {
            Log.e(TAG, "loadDBKey: Keystore unwrapping failed (device security changed?)");
            return false;
        }

        cachedDBKey = dbKey;
        Log.d(TAG, "DB key loaded from Keystore");
        return true;
    }

    /**
     * Get DB key (hex-encoded) for use as SQLCipher passphrase.
     * @return hex string or null if DB key not loaded
     */
    public String getDBKeyHex() {
        if (cachedDBKey == null) {
            loadDBKey();
        }
        if (cachedDBKey == null) return null;
        return CryptoManager.bytesToHex(cachedDBKey);
    }

    /**
     * Get raw DB key bytes for wrapping operations.
     */
    public byte[] getDBKey() {
        if (cachedDBKey == null) {
            loadDBKey();
        }
        if (cachedDBKey == null) return null;
        byte[] copy = new byte[cachedDBKey.length];
        System.arraycopy(cachedDBKey, 0, copy, 0, cachedDBKey.length);
        return copy;
    }

    // ======================== VAULT CREATION (NEW) ========================

    /**
     * First-time vault setup with Clear-Data-Resistant key hierarchy.
     *
     * 1. Generate RANDOM UEK (User Encryption Key) -- 256-bit
     * 2. Initialize DB key (generate + wrap with Keystore)
     * 3. Generate 16-byte random salt
     * 4. Derive PK (Password Key) from password via Argon2id
     * 5. Wrap UEK with PK via XChaCha20-Poly1305 --> encUEK_PK + iv_PK (RECOVERY PATH)
     * 6. Wrap UEK with DBK via XChaCha20-Poly1305 --> encUEK_DBK + iv_DBK (FAST LOCAL UNLOCK)
     * 7. Store vault metadata locally + upload to Firestore
     * 8. Cache UEK in memory
     *
     * @param password user's chosen master password
     * @param callback called on completion
     */
    public void initializeVault(final String password, final VaultCallback callback) {
        if (password == null || password.length() == 0) {
            Log.e(TAG, "[VAULT_CREATED] BLOCKED: empty password");
            if (callback != null) callback.onError("Password cannot be empty");
            return;
        }

        if (isVaultInitialized()) {
            Log.w(TAG, "[VAULT_CREATED] BLOCKED: vault already exists locally");
            if (callback != null) callback.onError("Vault already exists");
            return;
        }

        new Thread(new Runnable() {
            public void run() {
                byte[] uek = null;
                byte[] dbKey = null;
                byte[] pk = null;

                try {
                    // Step 1: Generate RANDOM UEK
                    uek = CryptoManager.generateDEK();
                    Log.d(TAG, "[VAULT_CREATED] Random UEK generated");

                    // Step 2: Initialize DB key
                    if (!initializeDBKey()) {
                        if (callback != null) callback.onError("DB key initialization failed");
                        return;
                    }

                    dbKey = getDBKey();
                    if (dbKey == null) {
                        if (callback != null) callback.onError("DB key not available");
                        return;
                    }

                    // Step 3: Generate salt
                    byte[] salt = CryptoManager.generateSalt();

                    // Step 4: Derive PK from password via Argon2id
                    pk = CryptoManager.deriveKeyArgon2(password, salt);
                    if (pk == null) {
                        Log.e(TAG, "[VAULT_CREATED] FAILED: Argon2id derivation returned null");
                        if (callback != null) callback.onError("Key derivation failed");
                        return;
                    }

                    // Step 5: Wrap UEK with PK (RECOVERY PATH - stored in Firestore)
                    CryptoManager.VaultBundle pkBundle = CryptoManager.encryptDEK(uek, pk);
                    CryptoManager.zeroFill(pk);
                    pk = null;

                    if (pkBundle == null) {
                        Log.e(TAG, "[VAULT_CREATED] FAILED: UEK-PK encryption failed");
                        if (callback != null) callback.onError("UEK-PK encryption failed");
                        return;
                    }

                    // Step 6: Wrap UEK with DBK (FAST LOCAL UNLOCK)
                    CryptoManager.VaultBundle dbkBundle = CryptoManager.encryptDEK(uek, dbKey);
                    CryptoManager.zeroFill(dbKey);
                    dbKey = null;

                    if (dbkBundle == null) {
                        Log.e(TAG, "[VAULT_CREATED] FAILED: UEK-DBK encryption failed");
                        if (callback != null) callback.onError("UEK-DBK encryption failed");
                        return;
                    }

                    final String saltB64 = Base64.encodeToString(salt, Base64.NO_WRAP);
                    final String encUEK_PK_B64 = pkBundle.encryptedDEK;
                    final String iv_PK_B64 = pkBundle.iv;
                    final String encUEK_DBK_B64 = dbkBundle.encryptedDEK;
                    final String iv_DBK_B64 = dbkBundle.iv;
                    final long createdAt = System.currentTimeMillis();

                    // Step 7: Store locally
                    prefs.edit()
                            .putString(KEY_SALT, saltB64)
                            .putString(KEY_ENC_UEK_PK, encUEK_PK_B64)
                            .putString(KEY_IV_PK, iv_PK_B64)
                            .putString(KEY_ENC_UEK_DBK, encUEK_DBK_B64)
                            .putString(KEY_IV_DBK, iv_DBK_B64)
                            .putString(KEY_ALGORITHM, CryptoManager.ALG_IDENTIFIER)
                            .putLong(KEY_CREATED_AT, createdAt)
                            .putBoolean(KEY_VAULT_INITIALIZED, true)
                            .putBoolean(KEY_VAULT_UPLOADED, false)
                            .putBoolean(KEY_HAS_PK_WRAPPING, true)
                            .commit();

                    // Step 8: Cache UEK in memory
                    cachedUEK = uek;
                    uek = null; // Prevent zeroFill in finally

                    Log.d(TAG, "[VAULT_CREATED] Vault stored locally, uploading to Firestore...");

                    // Upload to Firestore (PK-wrapped UEK + salt)
                    uploadVaultToFirestoreWithConfirmation(saltB64, encUEK_PK_B64,
                            iv_PK_B64, createdAt);

                    if (callback != null) callback.onSuccess();

                } catch (Exception e) {
                    Log.e(TAG, "[VAULT_CREATED] EXCEPTION: " + e.getMessage());
                    if (callback != null) callback.onError("Vault creation failed: " + e.getMessage());
                } finally {
                    CryptoManager.zeroFill(uek);
                    CryptoManager.zeroFill(dbKey);
                    CryptoManager.zeroFill(pk);
                }
            }
        }).start();
    }

    /**
     * Synchronous vault initialization for migration use.
     */
    public boolean initializeVaultSync(String password) {
        if (password == null || password.length() == 0) return false;
        if (isVaultInitialized()) return false;

        byte[] uek = null;
        byte[] dbKey = null;
        byte[] pk = null;

        try {
            // Generate RANDOM UEK
            uek = CryptoManager.generateDEK();

            if (!initializeDBKey()) return false;

            dbKey = getDBKey();
            if (dbKey == null) return false;

            byte[] salt = CryptoManager.generateSalt();
            pk = CryptoManager.deriveKeyArgon2(password, salt);
            if (pk == null) return false;

            // Wrap UEK with PK (recovery path)
            CryptoManager.VaultBundle pkBundle = CryptoManager.encryptDEK(uek, pk);
            CryptoManager.zeroFill(pk);
            pk = null;
            if (pkBundle == null) return false;

            // Wrap UEK with DBK (fast local unlock)
            CryptoManager.VaultBundle dbkBundle = CryptoManager.encryptDEK(uek, dbKey);
            CryptoManager.zeroFill(dbKey);
            dbKey = null;
            if (dbkBundle == null) return false;

            String saltB64 = Base64.encodeToString(salt, Base64.NO_WRAP);
            long createdAt = System.currentTimeMillis();

            prefs.edit()
                    .putString(KEY_SALT, saltB64)
                    .putString(KEY_ENC_UEK_PK, pkBundle.encryptedDEK)
                    .putString(KEY_IV_PK, pkBundle.iv)
                    .putString(KEY_ENC_UEK_DBK, dbkBundle.encryptedDEK)
                    .putString(KEY_IV_DBK, dbkBundle.iv)
                    .putString(KEY_ALGORITHM, CryptoManager.ALG_IDENTIFIER)
                    .putLong(KEY_CREATED_AT, createdAt)
                    .putBoolean(KEY_VAULT_INITIALIZED, true)
                    .putBoolean(KEY_VAULT_UPLOADED, false)
                    .putBoolean(KEY_HAS_PK_WRAPPING, true)
                    .commit();

            cachedUEK = uek;
            uek = null;

            uploadVaultToFirestoreWithConfirmation(saltB64, pkBundle.encryptedDEK,
                    pkBundle.iv, createdAt);

            return true;
        } catch (Exception e) {
            Log.e(TAG, "initializeVaultSync failed: " + e.getMessage());
            return false;
        } finally {
            CryptoManager.zeroFill(uek);
            CryptoManager.zeroFill(dbKey);
            CryptoManager.zeroFill(pk);
        }
    }

    // ======================== VAULT UNLOCK (NEW - DUAL PATH) ========================

    /**
     * Unlock vault with DUAL-PATH strategy:
     *
     * PATH A (Fast - Device Local):
     *   If DBK wrapping exists (wrapped_db_key + encUEK_DBK):
     *   1. Load DBK from Keystore
     *   2. Decrypt UEK from encUEK_DBK using DBK
     *   3. Verify by deriving PK from password, comparing with PK-decrypted UEK
     *
     * PATH B (Recovery - After Clear Data):
     *   If DBK wrapping MISSING but PK wrapping exists (encUEK_PK from Firestore):
     *   1. Derive PK from password + salt via Argon2id
     *   2. Decrypt UEK from encUEK_PK using PK
     *   3. If success: UEK recovered!
     *   4. Generate new DBK, re-wrap UEK with new DBK for future fast unlocks
     *
     * @param password user's master password
     * @return true if password correct and UEK cached
     */
    public boolean unlockVault(String password) {
        if (password == null || password.length() == 0) return false;
        if (!isVaultInitialized()) {
            Log.e(TAG, "[VAULT_UNLOCK_FAILED] vault not initialized");
            return false;
        }

        // Try PATH A first (fast local unlock via DBK)
        if (hasDBKWrapping()) {
            Log.d(TAG, "[VAULT_UNLOCK] Trying PATH A: DBK-based local unlock");
            boolean resultA = unlockViaDBK(password);
            if (resultA) {
                // Also upgrade to PK wrapping if not already done
                upgradeToPKWrappingIfNeeded(password);
                return true;
            }
            Log.w(TAG, "[VAULT_UNLOCK] PATH A failed, trying PATH B");
        }

        // PATH B: Recovery via PK (Password Key) wrapping
        if (hasPKWrapping()) {
            Log.d(TAG, "[VAULT_UNLOCK] Trying PATH B: PK-based recovery unlock");
            return unlockViaPK(password);
        }

        Log.e(TAG, "[VAULT_UNLOCK_FAILED] No valid unlock path available");
        return false;
    }

    /**
     * PATH A: Fast local unlock using DBK.
     */
    private boolean unlockViaDBK(String password) {
        byte[] derivedPK = null;
        byte[] dbKey = null;

        try {
            String encUEK_DBK_B64 = prefs.getString(KEY_ENC_UEK_DBK, null);
            String iv_DBK_B64 = prefs.getString(KEY_IV_DBK, null);
            String saltB64 = prefs.getString(KEY_SALT, null);

            if (encUEK_DBK_B64 == null || iv_DBK_B64 == null || saltB64 == null) {
                return false;
            }

            // Load DB key from Keystore
            if (!loadDBKey()) {
                Log.e(TAG, "[PATH_A] DB key not available");
                return false;
            }
            dbKey = getDBKey();

            // Decrypt UEK using DBK
            byte[] storedUEK = CryptoManager.decryptDEK(encUEK_DBK_B64, iv_DBK_B64, "", dbKey);
            CryptoManager.zeroFill(dbKey);
            dbKey = null;

            if (storedUEK == null) {
                Log.w(TAG, "[PATH_A] UEK-DBK decryption failed");
                return false;
            }

            // Now verify the password is correct
            // If we have PK wrapping, use that to verify
            if (hasPKWrapping()) {
                byte[] salt = Base64.decode(saltB64, Base64.NO_WRAP);
                derivedPK = CryptoManager.deriveKeyArgon2(password, salt);
                if (derivedPK == null) {
                    CryptoManager.zeroFill(storedUEK);
                    return false;
                }

                String encUEK_PK_B64 = prefs.getString(KEY_ENC_UEK_PK, null);
                String iv_PK_B64 = prefs.getString(KEY_IV_PK, null);

                byte[] pkDecryptedUEK = CryptoManager.decryptDEK(encUEK_PK_B64, iv_PK_B64, "", derivedPK);
                CryptoManager.zeroFill(derivedPK);
                derivedPK = null;

                if (pkDecryptedUEK == null) {
                    Log.w(TAG, "[PATH_A] Password verification via PK failed -- wrong password");
                    CryptoManager.zeroFill(storedUEK);
                    return false;
                }

                if (!constantTimeEquals(storedUEK, pkDecryptedUEK)) {
                    Log.w(TAG, "[PATH_A] UEK mismatch between DBK and PK paths -- data corruption?");
                    CryptoManager.zeroFill(storedUEK);
                    CryptoManager.zeroFill(pkDecryptedUEK);
                    return false;
                }
                CryptoManager.zeroFill(pkDecryptedUEK);
            } else {
                // LEGACY: Old format without PK wrapping -- use old verification
                // Derive key from password and compare with DBK-decrypted UEK
                byte[] salt = Base64.decode(saltB64, Base64.NO_WRAP);
                derivedPK = CryptoManager.deriveKeyArgon2(password, salt);
                if (derivedPK == null) {
                    CryptoManager.zeroFill(storedUEK);
                    return false;
                }

                // In the OLD system, UEK WAS the derived key (not random)
                // So comparing derived == stored was the verification
                if (!constantTimeEquals(derivedPK, storedUEK)) {
                    Log.w(TAG, "[PATH_A_LEGACY] derived key doesn't match stored UEK -- wrong password");
                    CryptoManager.zeroFill(derivedPK);
                    CryptoManager.zeroFill(storedUEK);
                    return false;
                }
                CryptoManager.zeroFill(derivedPK);
                derivedPK = null;
            }

            // Cache UEK
            cachedUEK = storedUEK;
            Log.d(TAG, "[PATH_A] Vault unlocked via DBK, UEK cached");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "[PATH_A] exception: " + e.getMessage());
            CryptoManager.zeroFill(derivedPK);
            return false;
        } finally {
            CryptoManager.zeroFill(dbKey);
        }
    }

    /**
     * PATH B: Recovery unlock using Password Key (PK).
     * Used after Clear Data when DBK is lost but Firestore has PK-wrapped UEK.
     */
    private boolean unlockViaPK(String password) {
        byte[] pk = null;
        byte[] dbKey = null;

        try {
            String saltB64 = prefs.getString(KEY_SALT, null);
            String encUEK_PK_B64 = prefs.getString(KEY_ENC_UEK_PK, null);
            String iv_PK_B64 = prefs.getString(KEY_IV_PK, null);

            if (saltB64 == null || encUEK_PK_B64 == null || iv_PK_B64 == null) {
                Log.e(TAG, "[PATH_B] Incomplete PK vault metadata");
                return false;
            }

            byte[] salt = Base64.decode(saltB64, Base64.NO_WRAP);

            Log.d(TAG, "[PATH_B] Deriving PK with Argon2id, salt_len=" + salt.length);

            // Step 1: Derive PK from password
            pk = CryptoManager.deriveKeyArgon2(password, salt);
            if (pk == null) {
                Log.e(TAG, "[PATH_B] Argon2id derivation returned null");
                return false;
            }

            // Step 2: Decrypt UEK using PK
            byte[] recoveredUEK = CryptoManager.decryptDEK(encUEK_PK_B64, iv_PK_B64, "", pk);
            CryptoManager.zeroFill(pk);
            pk = null;

            if (recoveredUEK == null) {
                Log.w(TAG, "[PATH_B] UEK-PK decryption failed -- wrong password");
                return false;
            }

            Log.d(TAG, "[PATH_B] UEK recovered from PK wrapping!");

            // Step 3: Generate new DBK for this device
            // First clear any stale DBK data
            prefs.edit().remove(KEY_WRAPPED_DB_KEY).commit();
            cachedDBKey = null;

            if (initializeDBKey()) {
                dbKey = getDBKey();
                if (dbKey != null) {
                    // Step 4: Re-wrap UEK with new DBK for future fast unlocks
                    CryptoManager.VaultBundle dbkBundle = CryptoManager.encryptDEK(recoveredUEK, dbKey);
                    CryptoManager.zeroFill(dbKey);
                    dbKey = null;

                    if (dbkBundle != null) {
                        prefs.edit()
                                .putString(KEY_ENC_UEK_DBK, dbkBundle.encryptedDEK)
                                .putString(KEY_IV_DBK, dbkBundle.iv)
                                .commit();
                        Log.d(TAG, "[PATH_B] UEK re-wrapped with new DBK for fast unlock");
                    }
                }
            }

            // Cache UEK
            cachedUEK = recoveredUEK;
            Log.d(TAG, "[PATH_B] Vault unlocked via PK recovery, UEK cached");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "[PATH_B] exception: " + e.getMessage());
            CryptoManager.zeroFill(pk);
            return false;
        } finally {
            CryptoManager.zeroFill(dbKey);
        }
    }

    /**
     * Upgrade existing vault to PK wrapping if not already done.
     * Called after successful PATH A unlock to add recovery capability.
     */
    private void upgradeToPKWrappingIfNeeded(final String password) {
        if (hasPKWrapping()) return;
        if (cachedUEK == null) return;

        Log.d(TAG, "[UPGRADE] Adding PK wrapping to vault...");

        new Thread(new Runnable() {
            public void run() {
                byte[] pk = null;
                try {
                    String saltB64 = prefs.getString(KEY_SALT, null);
                    if (saltB64 == null) return;

                    byte[] salt = Base64.decode(saltB64, Base64.NO_WRAP);
                    pk = CryptoManager.deriveKeyArgon2(password, salt);
                    if (pk == null) return;

                    byte[] uekCopy = getDEK();
                    if (uekCopy == null) return;

                    CryptoManager.VaultBundle pkBundle = CryptoManager.encryptDEK(uekCopy, pk);
                    CryptoManager.zeroFill(uekCopy);
                    CryptoManager.zeroFill(pk);
                    pk = null;

                    if (pkBundle == null) return;

                    prefs.edit()
                            .putString(KEY_ENC_UEK_PK, pkBundle.encryptedDEK)
                            .putString(KEY_IV_PK, pkBundle.iv)
                            .putBoolean(KEY_HAS_PK_WRAPPING, true)
                            .putBoolean(KEY_VAULT_UPLOADED, false)
                            .commit();

                    Log.d(TAG, "[UPGRADE] PK wrapping added, uploading to Firestore...");

                    // Upload the PK-wrapped vault to Firestore
                    long createdAt = prefs.getLong(KEY_CREATED_AT, System.currentTimeMillis());
                    uploadVaultToFirestoreWithConfirmation(saltB64, pkBundle.encryptedDEK,
                            pkBundle.iv, createdAt);

                } catch (Exception e) {
                    Log.e(TAG, "[UPGRADE] Failed: " + e.getMessage());
                    CryptoManager.zeroFill(pk);
                }
            }
        }).start();
    }

    // ======================== VAULT LOCK ========================

    /**
     * Lock vault: zero-fill UEK, nullify reference.
     * DB key stays loaded (needed for SQLCipher).
     */
    public void lockVault() {
        if (cachedUEK != null) {
            Arrays.fill(cachedUEK, (byte) 0);
            cachedUEK = null;
        }
        Log.d(TAG, "Vault locked, UEK zeroed");
    }

    // ======================== DEK ACCESS (UEK is the DEK) ========================

    /**
     * Get a COPY of the cached UEK. Caller must zero their copy when done.
     * Returns null if vault is locked.
     */
    public byte[] getDEK() {
        if (cachedUEK == null) return null;
        byte[] copy = new byte[cachedUEK.length];
        System.arraycopy(cachedUEK, 0, copy, 0, cachedUEK.length);
        return copy;
    }

    // ======================== FIRESTORE OPERATIONS ========================

    private DocumentReference getVaultDocRef(String uid) {
        return FirebaseFirestore.getInstance()
                .collection("users").document(uid)
                .collection("crypto_metadata").document("vault");
    }

    /**
     * Upload vault metadata to Firestore with upload confirmation tracking.
     * NOW uploads PK-wrapped UEK (recovery capable) instead of DBK-wrapped.
     */
    private void uploadVaultToFirestoreWithConfirmation(final String saltB64,
                                                         final String encUEK_PK_B64,
                                                         final String iv_PK_B64,
                                                         final long createdAt) {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
        if (!authManager.isLoggedIn()) {
            Log.w(TAG, "[VAULT_UPLOAD] Not logged in, will retry later");
            return;
        }
        String uid = authManager.getUid();
        if (uid == null) {
            Log.w(TAG, "[VAULT_UPLOAD] UID null, will retry later");
            return;
        }

        final DocumentReference docRef = getVaultDocRef(uid);

        Map<String, Object> data = new HashMap<>();
        data.put("salt", saltB64);
        data.put("encUEK_PK", encUEK_PK_B64);     // NEW: PK-wrapped UEK
        data.put("iv_PK", iv_PK_B64);               // NEW: PK nonce
        data.put("algorithm", CryptoManager.ALG_IDENTIFIER);
        data.put("createdAt", createdAt);
        data.put("vaultVersion", 4);                 // NEW: version marker

        // Keep old fields for backward compat detection
        data.put("userKeyCipher", encUEK_PK_B64);
        data.put("userKeyIV", iv_PK_B64);
        data.put("encryptedDEK", encUEK_PK_B64);
        data.put("iv", iv_PK_B64);
        data.put("tag", "");
        data.put("iterations", 0);

        docRef.set(data)
                .addOnSuccessListener(unused -> {
                    Log.d(TAG, "[VAULT_UPLOAD] SUCCESS: vault uploaded to Firestore");
                    prefs.edit().putBoolean(KEY_VAULT_UPLOADED, true).commit();
                })
                .addOnFailureListener(e -> {
                    Log.e(TAG, "[VAULT_UPLOAD] FAILED: " + e.getMessage());
                });
    }

    /**
     * Upload current local vault metadata to Firestore.
     */
    public void uploadVaultToFirestore() {
        if (!isVaultInitialized()) return;

        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
        if (!authManager.isLoggedIn()) return;
        String uid = authManager.getUid();
        if (uid == null) return;

        // Prefer PK wrapping for upload
        String saltB64 = prefs.getString(KEY_SALT, "");
        String encUEK_PK_B64 = prefs.getString(KEY_ENC_UEK_PK, "");
        String iv_PK_B64 = prefs.getString(KEY_IV_PK, "");

        // Fallback to old DBK wrapping names if PK not available
        if (encUEK_PK_B64.isEmpty()) {
            encUEK_PK_B64 = prefs.getString(KEY_ENC_UEK_DBK, "");
        }
        if (iv_PK_B64.isEmpty()) {
            iv_PK_B64 = prefs.getString(KEY_IV_DBK, "");
        }

        if (saltB64.isEmpty() || encUEK_PK_B64.isEmpty() || iv_PK_B64.isEmpty()) {
            Log.e(TAG, "uploadVaultToFirestore: incomplete local data");
            return;
        }

        long createdAt = prefs.getLong(KEY_CREATED_AT, System.currentTimeMillis());

        Map<String, Object> data = new HashMap<>();
        data.put("salt", saltB64);
        data.put("encUEK_PK", encUEK_PK_B64);
        data.put("iv_PK", iv_PK_B64);
        data.put("algorithm", CryptoManager.ALG_IDENTIFIER);
        data.put("createdAt", createdAt);
        data.put("vaultVersion", 4);
        data.put("userKeyCipher", encUEK_PK_B64);
        data.put("userKeyIV", iv_PK_B64);
        data.put("encryptedDEK", encUEK_PK_B64);
        data.put("iv", iv_PK_B64);
        data.put("tag", "");
        data.put("iterations", 0);

        getVaultDocRef(uid).set(data)
                .addOnSuccessListener(unused -> {
                    Log.d(TAG, "[VAULT_UPLOAD] Uploaded vault to Firestore");
                    prefs.edit().putBoolean(KEY_VAULT_UPLOADED, true).commit();
                })
                .addOnFailureListener(e ->
                        Log.e(TAG, "[VAULT_UPLOAD] Upload failed: " + e.getMessage()));
    }

    /**
     * Ensure vault metadata is uploaded to Firestore.
     * Call on every app start after successful unlock.
     */
    public void ensureVaultUploaded() {
        if (!isVaultInitialized()) return;
        if (isVaultUploaded()) return;
        Log.w(TAG, "[VAULT_UPLOAD_RETRY] Re-uploading vault...");
        uploadVaultToFirestore();
    }

    /**
     * Fetch vault from Firestore (3-state result).
     * NOW reads both new PK fields and old fields for backward compat.
     */
    public void fetchVaultFromFirestoreWithResult(final VaultFetchResultCallback callback) {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
        if (!authManager.isLoggedIn()) {
            if (callback != null) callback.onResult(VaultFetchResult.NETWORK_ERROR);
            return;
        }
        String uid = authManager.getUid();
        if (uid == null) {
            if (callback != null) callback.onResult(VaultFetchResult.NETWORK_ERROR);
            return;
        }

        final DocumentReference docRef = getVaultDocRef(uid);

        docRef.get(Source.SERVER)
                .addOnSuccessListener(doc -> {
                    if (processVaultDocument(doc)) {
                        if (callback != null) callback.onResult(VaultFetchResult.VAULT_FOUND);
                    } else {
                        if (callback != null) callback.onResult(VaultFetchResult.NO_VAULT_EXISTS);
                    }
                })
                .addOnFailureListener(e -> {
                    docRef.get(Source.CACHE)
                            .addOnSuccessListener(doc -> {
                                if (processVaultDocument(doc)) {
                                    if (callback != null) callback.onResult(VaultFetchResult.VAULT_FOUND);
                                } else {
                                    if (callback != null) callback.onResult(VaultFetchResult.NETWORK_ERROR);
                                }
                            })
                            .addOnFailureListener(e2 -> {
                                if (callback != null) callback.onResult(VaultFetchResult.NETWORK_ERROR);
                            });
                });
    }

    /**
     * Old 2-state API for backward compat.
     */
    public void fetchVaultFromFirestore(final VaultFetchCallback callback) {
        fetchVaultFromFirestoreWithResult(result -> {
            if (callback != null) {
                callback.onResult(result == VaultFetchResult.VAULT_FOUND);
            }
        });
    }

    /**
     * Process Firestore vault document and store locally.
     * Reads BOTH new PK fields and old fields.
     */
    private boolean processVaultDocument(DocumentSnapshot doc) {
        if (doc == null || !doc.exists()) return false;

        Map<String, Object> data = doc.getData();
        if (data == null) return false;

        String salt = getStr(data, "salt");
        String algorithm = getStr(data, "algorithm");

        // NEW v4 format fields
        String encUEK_PK = getStr(data, "encUEK_PK");
        String iv_PK = getStr(data, "iv_PK");

        // Fall back to old field names if new ones not present
        if (encUEK_PK.length() == 0) {
            encUEK_PK = getStr(data, "userKeyCipher");
        }
        if (encUEK_PK.length() == 0) {
            encUEK_PK = getStr(data, "encryptedDEK");
        }
        if (iv_PK.length() == 0) {
            iv_PK = getStr(data, "userKeyIV");
        }
        if (iv_PK.length() == 0) {
            iv_PK = getStr(data, "iv");
        }

        if (salt.length() > 0 && encUEK_PK.length() > 0 && iv_PK.length() > 0) {
            long createdAt = getLong(data, "createdAt");

            SharedPreferences.Editor editor = prefs.edit()
                    .putString(KEY_SALT, salt)
                    .putString(KEY_ENC_UEK_PK, encUEK_PK)
                    .putString(KEY_IV_PK, iv_PK)
                    .putString(KEY_ALGORITHM, algorithm.length() > 0 ? algorithm : CryptoManager.ALG_IDENTIFIER)
                    .putLong(KEY_CREATED_AT, createdAt)
                    .putBoolean(KEY_VAULT_INITIALIZED, true)
                    .putBoolean(KEY_VAULT_UPLOADED, true)
                    .putBoolean(KEY_HAS_PK_WRAPPING, true);

            // NOTE: We intentionally do NOT set encUEK_DBK or wrapped_db_key here
            // because after Clear Data, the old DBK is lost anyway.
            // The unlock flow (PATH B) will create a new DBK automatically.

            editor.commit();

            return true;
        }
        return false;
    }

    // ======================== CLOUD NOTES CHECK ========================

    public void checkCloudNotesExistWithResult(final VaultFetchResultCallback callback) {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
        if (!authManager.isLoggedIn()) {
            if (callback != null) callback.onResult(VaultFetchResult.NETWORK_ERROR);
            return;
        }
        String uid = authManager.getUid();
        if (uid == null) {
            if (callback != null) callback.onResult(VaultFetchResult.NETWORK_ERROR);
            return;
        }

        FirebaseFirestore.getInstance()
                .collection("users").document(uid)
                .collection("notes")
                .limit(1)
                .get(Source.SERVER)
                .addOnSuccessListener(querySnapshot -> {
                    boolean exists = querySnapshot != null && !querySnapshot.isEmpty();
                    if (exists) {
                        if (callback != null) callback.onResult(VaultFetchResult.VAULT_FOUND);
                    } else {
                        if (callback != null) callback.onResult(VaultFetchResult.NO_VAULT_EXISTS);
                    }
                })
                .addOnFailureListener(e -> {
                    FirebaseFirestore.getInstance()
                            .collection("users").document(uid)
                            .collection("notes")
                            .limit(1)
                            .get(Source.CACHE)
                            .addOnSuccessListener(querySnapshot -> {
                                boolean exists = querySnapshot != null && !querySnapshot.isEmpty();
                                if (exists) {
                                    if (callback != null) callback.onResult(VaultFetchResult.VAULT_FOUND);
                                } else {
                                    if (callback != null) callback.onResult(VaultFetchResult.NETWORK_ERROR);
                                }
                            })
                            .addOnFailureListener(e2 -> {
                                if (callback != null) callback.onResult(VaultFetchResult.NETWORK_ERROR);
                            });
                });
    }

    // ======================== PASSWORD CHANGE (SIMPLIFIED) ========================

    /**
     * Change master password.
     * Since UEK is RANDOM (not derived), only the PK wrapping changes.
     * Data stays encrypted with the same UEK -- NO re-encryption needed!
     *
     * Steps:
     * 1. Verify old password (derive old PK, decrypt encUEK_PK)
     * 2. Generate new salt, derive new PK
     * 3. Re-wrap UEK with new PK
     * 4. Also re-wrap UEK with existing DBK (new nonce)
     * 5. Update local storage + Firestore
     */
    public void changePassword(final String oldPassword, final String newPassword,
                                final VaultCallback callback) {
        if (oldPassword == null || newPassword == null) {
            if (callback != null) callback.onError("Passwords cannot be null");
            return;
        }
        if (!isVaultInitialized()) {
            if (callback != null) callback.onError("Vault not initialized");
            return;
        }
        if (cachedUEK == null) {
            if (callback != null) callback.onError("Vault is locked");
            return;
        }

        new Thread(() -> {
            byte[] oldPK = null;
            byte[] newPK = null;
            byte[] dbKey = null;

            try {
                String saltB64 = prefs.getString(KEY_SALT, null);
                if (saltB64 == null) {
                    if (callback != null) callback.onError("Vault metadata incomplete");
                    return;
                }

                byte[] oldSalt = Base64.decode(saltB64, Base64.NO_WRAP);

                // Step 1: Verify old password
                oldPK = CryptoManager.deriveKeyArgon2(oldPassword, oldSalt);
                if (oldPK == null) {
                    if (callback != null) callback.onError("Key derivation failed");
                    return;
                }

                // Verify by decrypting encUEK_PK with old PK
                String encUEK_PK_B64 = prefs.getString(KEY_ENC_UEK_PK, null);
                String iv_PK_B64 = prefs.getString(KEY_IV_PK, null);

                if (encUEK_PK_B64 != null && iv_PK_B64 != null) {
                    byte[] verifyUEK = CryptoManager.decryptDEK(encUEK_PK_B64, iv_PK_B64, "", oldPK);
                    if (verifyUEK == null) {
                        CryptoManager.zeroFill(oldPK);
                        if (callback != null) callback.onError("Old password incorrect");
                        return;
                    }
                    CryptoManager.zeroFill(verifyUEK);
                }

                CryptoManager.zeroFill(oldPK);
                oldPK = null;

                // Step 2: Generate new salt, derive new PK
                byte[] newSalt = CryptoManager.generateSalt();
                newPK = CryptoManager.deriveKeyArgon2(newPassword, newSalt);
                if (newPK == null) {
                    if (callback != null) callback.onError("New key derivation failed");
                    return;
                }

                // Step 3: Re-wrap UEK with new PK
                byte[] uekCopy = getDEK();
                if (uekCopy == null) {
                    CryptoManager.zeroFill(newPK);
                    if (callback != null) callback.onError("UEK not available");
                    return;
                }

                CryptoManager.VaultBundle newPKBundle = CryptoManager.encryptDEK(uekCopy, newPK);
                CryptoManager.zeroFill(newPK);
                newPK = null;

                if (newPKBundle == null) {
                    CryptoManager.zeroFill(uekCopy);
                    if (callback != null) callback.onError("UEK re-encryption failed");
                    return;
                }

                // Step 4: Re-wrap UEK with existing DBK (new nonce)
                String newSaltB64 = Base64.encodeToString(newSalt, Base64.NO_WRAP);
                long createdAt = prefs.getLong(KEY_CREATED_AT, System.currentTimeMillis());

                SharedPreferences.Editor editor = prefs.edit()
                        .putString(KEY_SALT, newSaltB64)
                        .putString(KEY_ENC_UEK_PK, newPKBundle.encryptedDEK)
                        .putString(KEY_IV_PK, newPKBundle.iv)
                        .putBoolean(KEY_VAULT_UPLOADED, false);

                dbKey = getDBKey();
                if (dbKey != null) {
                    CryptoManager.VaultBundle newDBKBundle = CryptoManager.encryptDEK(uekCopy, dbKey);
                    CryptoManager.zeroFill(dbKey);
                    dbKey = null;
                    if (newDBKBundle != null) {
                        editor.putString(KEY_ENC_UEK_DBK, newDBKBundle.encryptedDEK);
                        editor.putString(KEY_IV_DBK, newDBKBundle.iv);
                    }
                }

                CryptoManager.zeroFill(uekCopy);

                // Step 5: Save
                editor.commit();

                // Upload to Firestore
                uploadVaultToFirestoreWithConfirmation(newSaltB64, newPKBundle.encryptedDEK,
                        newPKBundle.iv, createdAt);

                Log.d(TAG, "Password changed successfully");
                if (callback != null) callback.onSuccess();

            } catch (Exception e) {
                Log.e(TAG, "Password change failed: " + e.getMessage());
                if (callback != null) callback.onError(e.getMessage());
            } finally {
                CryptoManager.zeroFill(oldPK);
                CryptoManager.zeroFill(newPK);
                CryptoManager.zeroFill(dbKey);
            }
        }).start();
    }

    // ======================== MIGRATION SUPPORT ========================

    /**
     * Store vault metadata locally after migration.
     */
    public void storeVaultLocally(String saltB64, String encUEK_PK_B64, String iv_PK_B64,
                                   String tagB64, long createdAt) {
        prefs.edit()
                .putString(KEY_SALT, saltB64)
                .putString(KEY_ENC_UEK_PK, encUEK_PK_B64)
                .putString(KEY_IV_PK, iv_PK_B64)
                .putString(KEY_ALGORITHM, CryptoManager.ALG_IDENTIFIER)
                .putLong(KEY_CREATED_AT, createdAt)
                .putBoolean(KEY_VAULT_INITIALIZED, true)
                .putBoolean(KEY_VAULT_UPLOADED, false)
                .putBoolean(KEY_HAS_PK_WRAPPING, true)
                .commit();
    }

    /**
     * Set cached UEK directly. Used by MigrationManager.
     */
    public void setCachedDEK(byte[] uek) {
        if (cachedUEK != null) Arrays.fill(cachedUEK, (byte) 0);
        cachedUEK = uek;
    }

    /**
     * Old vault access methods for migration.
     */
    public String getOldVaultSalt() {
        return oldPrefs.getString("vault_salt_b64", null);
    }

    public String getOldVaultEncDEK() {
        return oldPrefs.getString("vault_enc_dek_b64", null);
    }

    public String getOldVaultIV() {
        return oldPrefs.getString("vault_iv_b64", null);
    }

    public String getOldVaultTag() {
        return oldPrefs.getString("vault_tag_b64", null);
    }

    /**
     * Clear old vault prefs after successful migration.
     */
    public void clearOldVault() {
        oldPrefs.edit().clear().commit();
    }

    // ======================== LOCAL METADATA ACCESS ========================

    public String getSaltHex() {
        return prefs.getString(KEY_SALT, null);
    }

    public String getEncryptedDEK() {
        return prefs.getString(KEY_ENC_UEK_PK, null);
    }

    public String getVerifyTag() {
        return prefs.getString(KEY_IV_PK, null);
    }

    public String getLocalSalt() {
        return prefs.getString(KEY_SALT, null);
    }

    public String getLocalEncryptedDEK() {
        return prefs.getString(KEY_ENC_UEK_PK, null);
    }

    public String getLocalVerifyTag() {
        return prefs.getString(KEY_IV_PK, null);
    }

    public String getLocalIV() {
        return prefs.getString(KEY_IV_PK, null);
    }

    // ======================== BACKUP/RESTORE ========================

    public void restoreVaultFromBackup(String saltB64, String encDEKB64,
                                        String ivB64, String tagB64, int iterations) {
        prefs.edit()
                .putString(KEY_SALT, saltB64)
                .putString(KEY_ENC_UEK_PK, encDEKB64)
                .putString(KEY_IV_PK, ivB64)
                .putString(KEY_ALGORITHM, CryptoManager.ALG_IDENTIFIER)
                .putLong(KEY_CREATED_AT, System.currentTimeMillis())
                .putBoolean(KEY_VAULT_INITIALIZED, true)
                .putBoolean(KEY_VAULT_UPLOADED, false)
                .putBoolean(KEY_HAS_PK_WRAPPING, true)
                .commit();
    }

    // ======================== HELPERS ========================

    private String getStr(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof String) return (String) val;
        return "";
    }

    private int getInt(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof Number) return ((Number) val).intValue();
        return 0;
    }

    private long getLong(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val instanceof Number) return ((Number) val).longValue();
        return 0;
    }

    /**
     * Constant-time byte array comparison to prevent timing attacks.
     */
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null) return false;
        if (a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }

    // ======================== CALLBACKS ========================

    public enum VaultFetchResult {
        VAULT_FOUND,
        NO_VAULT_EXISTS,
        NETWORK_ERROR
    }

    public interface VaultFetchResultCallback {
        void onResult(VaultFetchResult result);
    }

    public interface VaultFetchCallback {
        void onResult(boolean vaultFound);
    }

    public interface VaultCallback {
        void onSuccess();
        void onError(String error);
    }
}
