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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Singleton managing the vault key lifecycle.
 *
 * ============== v4 ARCHITECTURE (BUG FIX) ==============
 *
 * PURANI ARCHITECTURE (BUGGY):
 * Layer 1: User Password -> Argon2id -> UEK (User Encryption Key)
 * Layer 2: UEK encrypted with DB Key (Keystore-wrapped) -> stored locally + Firestore
 * Layer 3: DB Key wrapped with Android Keystore AES -> stored in SharedPreferences
 * PROBLEM: Clear Data -> Keystore deleted -> DB Key lost -> UEK unrecoverable
 *
 * NAYI ARCHITECTURE (v4 FIX):
 * Layer 1: User Password + Salt -> Argon2id -> DerivedKey (DETERMINISTIC)
 * Layer 2: DerivedKey wraps random DEK via XChaCha20-Poly1305
 * Layer 3: DEK encrypts notes
 *
 * Firestore vault metadata:
 * { salt, encryptedDEK, iv, alg:"xchacha20poly1305", vaultVersion:4 }
 *
 * KEY PROPERTIES:
 * - Same password + same salt = same DerivedKey ALWAYS (deterministic)
 * - DerivedKey se encryptedDEK unwrap hota hai -> DEK milta hai
 * - Device independent recovery possible (Keystore NOT in unlock chain)
 * - Android Keystore sirf optional session DEK cache ke liye use hoga
 *
 * Clear Data Recovery Flow:
 * 1. User clears app data (Keystore + SharedPrefs deleted)
 * 2. User logs in again
 * 3. Vault metadata fetched from Firestore (salt, encryptedDEK, iv)
 * 4. User enters same password
 * 5. Argon2id(password, salt) -> same DerivedKey
 * 6. DerivedKey decrypts encryptedDEK -> DEK recovered
 * 7. Notes decrypt with DEK -> SUCCESS!
 */
public class KeyManager {

    private static final String TAG = "KeyManager";

    // SharedPreferences keys -- vault metadata
    private static final String PREFS_NAME             = "mknotes_vault_v3";
    private static final String KEY_SALT               = "vault_salt_b64";
    private static final String KEY_ENCRYPTED_DEK      = "vault_enc_dek_b64";
    private static final String KEY_IV                 = "vault_iv_b64";
    private static final String KEY_TAG                = "vault_tag_b64";
    private static final String KEY_ITERATIONS         = "vault_iterations";
    private static final String KEY_CREATED_AT         = "vault_created_at";
    private static final String KEY_VAULT_INITIALIZED  = "vault_initialized";
    private static final String KEY_VAULT_UPLOADED     = "vault_uploaded_to_firestore";
    private static final String KEY_VAULT_VERSION      = "vault_version";

    // DB Key -- stored wrapped by Android Keystore (OPTIONAL SESSION CACHE in v4)
    private static final String KEY_WRAPPED_DB_KEY     = "wrapped_db_key";
    private static final String KEY_DB_KEY_INITIALIZED = "db_key_initialized";

    // v4: Session DEK cache (Keystore-wrapped DEK for session resumption)
    private static final String KEY_SESSION_DEK_CACHE  = "session_dek_cache";

    // Migration tracking
    private static final String KEY_MIGRATION_V3_DONE  = "migration_v3_done";

    public static final int CURRENT_VAULT_VERSION = 4;

    private static KeyManager sInstance;
    private final SharedPreferences prefs;
    private final Context appContext;

    /** In-memory cached DEK (Data Encryption Key). Zeroed on lockVault(). */
    private byte[] cachedDEK;

    /** In-memory cached DB Key. Used for SQLCipher passphrase. */
    private byte[] cachedDBKey;

    public static synchronized KeyManager getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new KeyManager(context.getApplicationContext());
        }
        return sInstance;
    }

    private KeyManager(Context context) {
        this.appContext  = context;
        this.prefs       = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        this.cachedDEK   = null;
        this.cachedDBKey = null;
    }

    // ======================== STATE CHECKS ========================

    public boolean isVaultInitialized() {
        return prefs.getBoolean(KEY_VAULT_INITIALIZED, false)
                && prefs.getString(KEY_SALT, null) != null
                && prefs.getString(KEY_ENCRYPTED_DEK, null) != null
                && prefs.getString(KEY_IV, null) != null
                && prefs.getString(KEY_TAG, null) != null;
    }

    public boolean isVaultUnlocked() {
        return cachedDEK != null;
    }

    public boolean isDBKeyReady() {
        return cachedDBKey != null;
    }

    public int getIterations() {
        return prefs.getInt(KEY_ITERATIONS, CryptoManager.FIXED_ITERATIONS);
    }

    public int getVaultVersion() {
        return prefs.getInt(KEY_VAULT_VERSION, isVaultInitialized() ? CURRENT_VAULT_VERSION : 0);
    }

    public boolean needsMigration() {
        return !isVaultInitialized();
    }

    /**
     * Check if v2->v3 migration (to Argon2id + Keystore) has been completed.
     */
    public boolean needsV3Migration() {
        SharedPreferences oldPrefs = appContext.getSharedPreferences("mknotes_vault_v2", Context.MODE_PRIVATE);
        boolean hasOldVault = oldPrefs.getBoolean("vault_initialized", false);
        boolean v3Done      = prefs.getBoolean(KEY_MIGRATION_V3_DONE, false);
        return hasOldVault && !v3Done && !isVaultInitialized();
    }

    public boolean isVaultUploaded() {
        return prefs.getBoolean(KEY_VAULT_UPLOADED, false);
    }

    /**
     * v4: Check if old DB Key wrapping exists in SharedPreferences.
     * Used by MasterPasswordActivity to detect clear data scenario.
     */
    public boolean hasDBKWrapping() {
        return prefs.getBoolean(KEY_DB_KEY_INITIALIZED, false)
                && prefs.getString(KEY_WRAPPED_DB_KEY, null) != null;
    }

    /**
     * v4: Check if vault has password-derived key wrapping.
     * In v4 architecture, this is ALWAYS true when vault is initialized.
     */
    public boolean hasPKWrapping() {
        return isVaultInitialized();
    }

    // ======================== DB KEY MANAGEMENT ========================

    /**
     * Initialize the DB key: generate random 256-bit key, wrap with Keystore, store.
     * v4: DB Key is now ONLY used for SQLCipher passphrase, NOT for vault unlock.
     *
     * @return true if DB key is ready (already existed or newly created)
     */
    public boolean initializeDBKey() {
        if (prefs.getBoolean(KEY_DB_KEY_INITIALIZED, false)) {
            return unwrapAndCacheDBKey();
        }

        if (!SecureKeyStore.generateOrGetKeystoreKey(SecureKeyStore.ALIAS_DB_KEY_MASTER)) {
            Log.e(TAG, "Failed to create Keystore master key");
            return false;
        }

        byte[] dbKey = CryptoManager.generateDEK();

        String wrapped = SecureKeyStore.wrapKey(SecureKeyStore.ALIAS_DB_KEY_MASTER, dbKey);
        if (wrapped == null) {
            CryptoManager.zeroFill(dbKey);
            Log.e(TAG, "Failed to wrap DB key with Keystore");
            return false;
        }

        prefs.edit()
                .putString(KEY_WRAPPED_DB_KEY, wrapped)
                .putBoolean(KEY_DB_KEY_INITIALIZED, true)
                .commit();

        cachedDBKey = dbKey;
        Log.d(TAG, "DB key initialized and wrapped with Keystore");
        return true;
    }

    /**
     * Unwrap the DB key from Keystore-protected storage and cache it.
     */
    private boolean unwrapAndCacheDBKey() {
        if (cachedDBKey != null) return true;

        String wrapped = prefs.getString(KEY_WRAPPED_DB_KEY, null);
        if (wrapped == null) {
            Log.e(TAG, "No wrapped DB key found");
            return false;
        }

        byte[] dbKey = SecureKeyStore.unwrapKey(SecureKeyStore.ALIAS_DB_KEY_MASTER, wrapped);
        if (dbKey == null) {
            Log.e(TAG, "Failed to unwrap DB key (Keystore key invalidated?)");
            return false;
        }

        cachedDBKey = dbKey;
        return true;
    }

    /**
     * Get the SQLCipher passphrase (hex-encoded DB key).
     * Returns null if DB key is not ready.
     */
    public String getSQLCipherPassphrase() {
        if (cachedDBKey == null) {
            unwrapAndCacheDBKey();
        }
        if (cachedDBKey == null) return null;
        return CryptoManager.bytesToHex(cachedDBKey);
    }

    /**
     * Get a copy of the DB key.
     * v4: Only used for SQLCipher, NOT for vault unlock.
     */
    public byte[] getDBKey() {
        if (cachedDBKey == null) unwrapAndCacheDBKey();
        if (cachedDBKey == null) return null;
        byte[] copy = new byte[cachedDBKey.length];
        System.arraycopy(cachedDBKey, 0, copy, 0, cachedDBKey.length);
        return copy;
    }

    /**
     * Load DB key from Keystore-wrapped storage into memory cache.
     * Called by MigrationManager and NotesApplication when DB key
     * already exists but is not yet cached in memory.
     *
     * @return true if DB key loaded and cached successfully
     */
    public boolean loadDBKey() {
        return unwrapAndCacheDBKey();
    }

    /**
     * Get hex-encoded DB key string.
     * Used by MigrationManager for sqlcipher_export passphrase.
     *
     * @return hex string of DB key, or null if not available
     */
    public String getDBKeyHex() {
        if (cachedDBKey == null) {
            unwrapAndCacheDBKey();
        }
        if (cachedDBKey == null) return null;
        return CryptoManager.bytesToHex(cachedDBKey);
    }

    // ======================== VAULT CREATION (v4 REWRITTEN) ========================

    /**
     * v4: First-time vault setup with password-derived key architecture.
     *
     * Flow:
     * 1. Generate random salt (16 bytes)
     * 2. Derive key from password via Argon2id: derivedKey = Argon2id(password, salt)
     * 3. Generate random DEK (32 bytes)
     * 4. Encrypt DEK with derivedKey: encryptedDEK = XChaCha20(DEK, derivedKey)
     * 5. Store vault metadata locally + Firestore: { salt, encryptedDEK, iv, alg }
     * 6. Cache DEK in memory for immediate use
     * 7. Optionally initialize DB key for SQLCipher (independent of vault)
     *
     * DB Key is NOT used in the vault encryption chain anymore.
     */
    public void initializeVault(final String password, final VaultCallback callback) {
        if (password == null || password.length() == 0) {
            if (callback != null) callback.onError("Password cannot be empty");
            return;
        }
        if (isVaultInitialized()) {
            if (callback != null) callback.onError("Vault already exists");
            return;
        }

        new Thread(new Runnable() {
            public void run() {
                byte[] salt       = null;
                byte[] derivedKey = null;
                byte[] dek        = null;

                try {
                    // Step 1: Generate random salt
                    salt = CryptoManager.generateSalt();

                    // Step 2: Derive key from password via Argon2id
                    derivedKey = CryptoManager.deriveKeyArgon2id(password, salt);
                    if (derivedKey == null) {
                        if (callback != null) callback.onError("Argon2id key derivation failed");
                        return;
                    }

                    // Step 3: Generate random DEK
                    dek = CryptoManager.generateDEK();

                    // Step 4: Encrypt DEK with derivedKey (NOT with DB Key!)
                    CryptoManager.VaultBundle bundle = CryptoManager.encryptDEKWithDerivedKey(dek, derivedKey);

                    // Zero derivedKey immediately -- no longer needed
                    CryptoManager.zeroFill(derivedKey);
                    derivedKey = null;

                    if (bundle == null) {
                        if (callback != null) callback.onError("DEK encryption failed");
                        return;
                    }

                    String saltB64   = Base64.encodeToString(salt, Base64.NO_WRAP);
                    long   createdAt = System.currentTimeMillis();

                    // Step 5: Store vault metadata locally
                    prefs.edit()
                            .putString(KEY_SALT, saltB64)
                            .putString(KEY_ENCRYPTED_DEK, bundle.encryptedDEK)
                            .putString(KEY_IV, bundle.iv)
                            .putString(KEY_TAG, bundle.tag)
                            .putInt(KEY_ITERATIONS, 0)  // Argon2id marker
                            .putLong(KEY_CREATED_AT, createdAt)
                            .putBoolean(KEY_VAULT_INITIALIZED, true)
                            .putBoolean(KEY_VAULT_UPLOADED, false)
                            .putInt(KEY_VAULT_VERSION, CURRENT_VAULT_VERSION)
                            .commit();

                    // Step 6: Cache DEK in memory
                    cachedDEK = dek;
                    dek = null;  // Prevent zeroFill in finally

                    Log.d(TAG, "[VAULT_CREATED] v4 password-derived vault created");

                    // Step 7: Initialize DB key for SQLCipher (optional, independent)
                    initializeDBKey();

                    // Step 8: Upload to Firestore
                    uploadVaultToFirestoreWithConfirmation(saltB64, bundle.encryptedDEK,
                            bundle.iv, bundle.tag, createdAt);

                    if (callback != null) callback.onSuccess();

                } catch (Exception e) {
                    Log.e(TAG, "[VAULT_CREATED] EXCEPTION: " + e.getMessage());
                    if (callback != null) callback.onError("Vault creation failed: " + e.getMessage());
                } finally {
                    CryptoManager.zeroFill(salt);
                    CryptoManager.zeroFill(derivedKey);
                    if (dek != null) CryptoManager.zeroFill(dek);
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

        byte[] salt       = null;
        byte[] derivedKey = null;
        byte[] dek        = null;

        try {
            // Generate salt
            salt = CryptoManager.generateSalt();

            // Derive key from password
            derivedKey = CryptoManager.deriveKeyArgon2id(password, salt);
            if (derivedKey == null) return false;

            // Generate random DEK
            dek = CryptoManager.generateDEK();

            // Encrypt DEK with derivedKey (NOT DB Key)
            CryptoManager.VaultBundle bundle = CryptoManager.encryptDEKWithDerivedKey(dek, derivedKey);
            CryptoManager.zeroFill(derivedKey);
            derivedKey = null;

            if (bundle == null) return false;

            String saltB64   = Base64.encodeToString(salt, Base64.NO_WRAP);
            long   createdAt = System.currentTimeMillis();

            prefs.edit()
                    .putString(KEY_SALT, saltB64)
                    .putString(KEY_ENCRYPTED_DEK, bundle.encryptedDEK)
                    .putString(KEY_IV, bundle.iv)
                    .putString(KEY_TAG, bundle.tag)
                    .putInt(KEY_ITERATIONS, 0)
                    .putLong(KEY_CREATED_AT, createdAt)
                    .putBoolean(KEY_VAULT_INITIALIZED, true)
                    .putBoolean(KEY_VAULT_UPLOADED, false)
                    .putInt(KEY_VAULT_VERSION, CURRENT_VAULT_VERSION)
                    .commit();

            cachedDEK = dek;
            dek = null;

            // Initialize DB key for SQLCipher (independent)
            initializeDBKey();

            uploadVaultToFirestoreWithConfirmation(saltB64, bundle.encryptedDEK,
                    bundle.iv, bundle.tag, createdAt);
            return true;
        } catch (Exception e) {
            Log.e(TAG, "initializeVaultSync failed: " + e.getMessage());
            return false;
        } finally {
            CryptoManager.zeroFill(salt);
            CryptoManager.zeroFill(derivedKey);
            if (dek != null) CryptoManager.zeroFill(dek);
        }
    }

    // ======================== VAULT UNLOCK (v4 REWRITTEN) ========================

    /**
     * v4: Unlock vault using ONLY password-derived key.
     * DB Key is NOT used in unlock chain.
     *
     * Flow:
     * 1. Read vault metadata from SharedPreferences (salt, encryptedDEK, iv)
     * 2. Derive key: derivedKey = Argon2id(password, salt)
     * 3. Decrypt: DEK = XChaCha20_decrypt(encryptedDEK, derivedKey)
     * 4. If decrypt fails -> wrong password
     * 5. If decrypt succeeds -> cachedDEK = DEK, vault unlocked
     *
     * CLEAR DATA RECOVERY:
     * - SharedPreferences deleted? No problem -> vault metadata fetched from Firestore first
     * - Keystore deleted? No problem -> NOT used in unlock chain
     * - Same password + same salt = same derivedKey = DEK recovered!
     */
    public boolean unlockVault(String password) {
        if (password == null || password.length() == 0) return false;
        if (!isVaultInitialized()) {
            Log.e(TAG, "[VAULT_UNLOCK_FAILED] vault not initialized");
            return false;
        }

        byte[] derivedKey = null;
        try {
            // Step 1: Read vault metadata
            String saltB64   = prefs.getString(KEY_SALT, null);
            String encDEKB64 = prefs.getString(KEY_ENCRYPTED_DEK, null);
            String ivB64     = prefs.getString(KEY_IV, null);
            String tagB64    = prefs.getString(KEY_TAG, null);

            if (saltB64 == null || encDEKB64 == null || ivB64 == null || tagB64 == null) {
                Log.e(TAG, "[VAULT_UNLOCK_FAILED] incomplete vault metadata");
                return false;
            }

            byte[] salt = Base64.decode(saltB64, Base64.NO_WRAP);

            // Step 2: Derive key from password via Argon2id
            derivedKey = CryptoManager.deriveKeyArgon2id(password, salt);
            if (derivedKey == null) {
                Log.e(TAG, "[VAULT_UNLOCK_FAILED] Argon2id derivation failed");
                return false;
            }

            // Step 3: Try v4 path first -- decrypt DEK directly with derivedKey
            byte[] dek = CryptoManager.decryptDEKWithDerivedKey(encDEKB64, ivB64, derivedKey);

            if (dek != null) {
                // v4 path SUCCESS: DEK decrypted with password-derived key
                CryptoManager.zeroFill(derivedKey);
                derivedKey = null;

                cachedDEK = dek;
                Log.d(TAG, "[VAULT_UNLOCK_SUCCESS] v4 password-derived path");

                // Try to initialize DB key for SQLCipher (optional, non-blocking)
                try {
                    initializeDBKey();
                } catch (Exception e) {
                    Log.w(TAG, "DB key init failed (non-critical): " + e.getMessage());
                }

                // Cache DEK in Keystore for session resumption (optional)
                cacheSessionDEK(cachedDEK);

                return true;
            }

            // Step 4: v4 decrypt failed -- try v3 backward compat path
            // In v3, encryptedDEK contained UEK wrapped with DB Key.
            // We need DB Key to unwrap, then compare with derived UEK.
            Log.w(TAG, "[VAULT_UNLOCK] v4 path failed, trying v3 backward compat...");

            // Try v3 path: DB Key unwraps stored UEK, compare with derived UEK
            byte[] dbKey = getDBKey();
            if (dbKey != null) {
                byte[] storedUEK = CryptoManager.decryptDEK(encDEKB64, ivB64, tagB64, dbKey);
                CryptoManager.zeroFill(dbKey);

                if (storedUEK != null) {
                    // v3 format: stored value is UEK, compare with derived UEK
                    boolean match = java.security.MessageDigest.isEqual(derivedKey, storedUEK);

                    if (match) {
                        // v3 vault: UEK IS the encryption key
                        cachedDEK = storedUEK;
                        CryptoManager.zeroFill(derivedKey);
                        derivedKey = null;

                        Log.d(TAG, "[VAULT_UNLOCK_SUCCESS] v3 backward compat path");

                        // MIGRATE: Re-wrap using v4 architecture (password-derived key wraps DEK)
                        migrateVaultToV4(password, cachedDEK);

                        return true;
                    } else {
                        CryptoManager.zeroFill(storedUEK);
                    }
                }
            }

            // Step 5: Try v2 PBKDF2 fallback (very old vaults)
            Log.w(TAG, "[VAULT_UNLOCK] v3 path failed, trying PBKDF2 fallback...");
            byte[] masterKey = CryptoManager.deriveMasterKey(password, salt);
            if (masterKey != null) {
                byte[] storedDEK = CryptoManager.decryptDEK(encDEKB64, ivB64, tagB64, masterKey);
                CryptoManager.zeroFill(masterKey);
                if (storedDEK != null) {
                    cachedDEK = storedDEK;
                    CryptoManager.zeroFill(derivedKey);
                    derivedKey = null;

                    Log.d(TAG, "[VAULT_UNLOCK_SUCCESS] v2 PBKDF2 fallback path");

                    // MIGRATE: Re-wrap using v4 architecture
                    migrateVaultToV4(password, cachedDEK);

                    return true;
                }
            }

            // All paths failed -> wrong password
            CryptoManager.zeroFill(derivedKey);
            Log.w(TAG, "[VAULT_UNLOCK_FAILED] All paths failed -- wrong password");
            return false;

        } catch (Exception e) {
            Log.e(TAG, "[VAULT_UNLOCK_FAILED] exception: " + e.getMessage());
            CryptoManager.zeroFill(derivedKey);
            return false;
        }
    }

    /**
     * v4: Migrate an old vault to v4 architecture.
     * Re-wraps the DEK with password-derived key instead of DB Key.
     */
    private void migrateVaultToV4(String password, byte[] dek) {
        try {
            byte[] newSalt = CryptoManager.generateSalt();
            byte[] newDerivedKey = CryptoManager.deriveKeyArgon2id(password, newSalt);
            if (newDerivedKey == null) {
                Log.e(TAG, "[MIGRATE_V4] Argon2id derivation failed");
                return;
            }

            CryptoManager.VaultBundle bundle = CryptoManager.encryptDEKWithDerivedKey(dek, newDerivedKey);
            CryptoManager.zeroFill(newDerivedKey);

            if (bundle == null) {
                Log.e(TAG, "[MIGRATE_V4] DEK encryption failed");
                return;
            }

            String newSaltB64 = Base64.encodeToString(newSalt, Base64.NO_WRAP);
            long createdAt = prefs.getLong(KEY_CREATED_AT, System.currentTimeMillis());

            prefs.edit()
                    .putString(KEY_SALT, newSaltB64)
                    .putString(KEY_ENCRYPTED_DEK, bundle.encryptedDEK)
                    .putString(KEY_IV, bundle.iv)
                    .putString(KEY_TAG, bundle.tag)
                    .putInt(KEY_ITERATIONS, 0)
                    .putInt(KEY_VAULT_VERSION, CURRENT_VAULT_VERSION)
                    .putBoolean(KEY_VAULT_UPLOADED, false)
                    .commit();

            // Upload migrated vault to Firestore
            uploadVaultToFirestoreWithConfirmation(newSaltB64, bundle.encryptedDEK,
                    bundle.iv, bundle.tag, createdAt);

            Log.d(TAG, "[MIGRATE_V4] Vault successfully migrated to v4 architecture");
        } catch (Exception e) {
            Log.e(TAG, "[MIGRATE_V4] Migration failed: " + e.getMessage());
        }
    }

    // ======================== SESSION DEK CACHE (OPTIONAL) ========================

    /**
     * v4: Cache DEK in Keystore for session resumption.
     * This is OPTIONAL -- vault unlock still works without it.
     * Only used to avoid Argon2id re-derivation within same session.
     */
    private void cacheSessionDEK(byte[] dek) {
        try {
            if (!SecureKeyStore.generateOrGetKeystoreKey(SecureKeyStore.ALIAS_DB_KEY_MASTER)) {
                return;
            }
            String wrapped = SecureKeyStore.wrapKey(SecureKeyStore.ALIAS_DB_KEY_MASTER, dek);
            if (wrapped != null) {
                prefs.edit().putString(KEY_SESSION_DEK_CACHE, wrapped).commit();
                Log.d(TAG, "Session DEK cached in Keystore");
            }
        } catch (Exception e) {
            Log.w(TAG, "Session DEK cache failed (non-critical): " + e.getMessage());
        }
    }

    /**
     * v4: Try to restore DEK from Keystore session cache.
     * Returns true if DEK was restored, false otherwise.
     * On failure, user must enter password (which is the correct behavior).
     */
    public boolean tryRestoreSessionDEK() {
        if (cachedDEK != null) return true;

        String wrapped = prefs.getString(KEY_SESSION_DEK_CACHE, null);
        if (wrapped == null) return false;

        try {
            byte[] dek = SecureKeyStore.unwrapKey(SecureKeyStore.ALIAS_DB_KEY_MASTER, wrapped);
            if (dek != null && dek.length == 32) {
                cachedDEK = dek;
                Log.d(TAG, "Session DEK restored from Keystore cache");
                return true;
            }
        } catch (Exception e) {
            Log.w(TAG, "Session DEK restore failed: " + e.getMessage());
        }
        return false;
    }

    // ======================== VAULT LOCK ========================

    public void lockVault() {
        if (cachedDEK != null) {
            Arrays.fill(cachedDEK, (byte) 0);
            cachedDEK = null;
        }
        // Clear session DEK cache
        prefs.edit().remove(KEY_SESSION_DEK_CACHE).commit();
        Log.d(TAG, "Vault locked, DEK zeroed");
    }

    // ======================== DEK ACCESS ========================

    public byte[] getDEK() {
        if (cachedDEK == null) return null;
        byte[] copy = new byte[cachedDEK.length];
        System.arraycopy(cachedDEK, 0, copy, 0, cachedDEK.length);
        return copy;
    }

    // ======================== FIRESTORE OPERATIONS ========================

    private DocumentReference getVaultDocRef(String uid) {
        return FirebaseFirestore.getInstance()
                .collection("users").document(uid)
                .collection("crypto_metadata").document("vault");
    }

    private void uploadVaultToFirestoreWithConfirmation(final String saltB64,
            final String encDEKB64, final String ivB64, final String tagB64, final long createdAt) {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
        if (!authManager.isLoggedIn()) return;
        String uid = authManager.getUid();
        if (uid == null) return;

        Map<String, Object> data = new HashMap<>();
        data.put("salt", saltB64);
        data.put("encryptedDEK", encDEKB64);
        data.put("iv", ivB64);
        data.put("tag", tagB64);
        data.put("iterations", 0);  // Argon2id marker
        data.put("vaultVersion", CURRENT_VAULT_VERSION);
        data.put("createdAt", createdAt);

        getVaultDocRef(uid).set(data)
                .addOnSuccessListener(unused -> {
                    prefs.edit().putBoolean(KEY_VAULT_UPLOADED, true).commit();
                    Log.d(TAG, "[VAULT_UPLOAD] SUCCESS");
                })
                .addOnFailureListener(e ->
                        Log.e(TAG, "[VAULT_UPLOAD] FAILED: " + e.getMessage()));
    }

    public void uploadVaultToFirestore() {
        if (!isVaultInitialized()) return;

        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
        if (!authManager.isLoggedIn()) return;
        String uid = authManager.getUid();
        if (uid == null) return;

        String saltB64   = prefs.getString(KEY_SALT, "");
        String encDEKB64 = prefs.getString(KEY_ENCRYPTED_DEK, "");
        String ivB64     = prefs.getString(KEY_IV, "");
        String tagB64    = prefs.getString(KEY_TAG, "");
        long   createdAt = prefs.getLong(KEY_CREATED_AT, System.currentTimeMillis());

        if (saltB64.isEmpty() || encDEKB64.isEmpty() || ivB64.isEmpty() || tagB64.isEmpty()) return;

        Map<String, Object> data = new HashMap<>();
        data.put("salt", saltB64);
        data.put("encryptedDEK", encDEKB64);
        data.put("iv", ivB64);
        data.put("tag", tagB64);
        data.put("iterations", 0);
        data.put("vaultVersion", CURRENT_VAULT_VERSION);
        data.put("createdAt", createdAt);

        getVaultDocRef(uid).set(data)
                .addOnSuccessListener(unused -> {
                    prefs.edit().putBoolean(KEY_VAULT_UPLOADED, true).commit();
                })
                .addOnFailureListener(e ->
                        Log.e(TAG, "[VAULT_UPLOAD] Upload failed: " + e.getMessage()));
    }

    public void ensureVaultUploaded() {
        if (!isVaultInitialized()) return;
        if (isVaultUploaded()) return;
        uploadVaultToFirestore();
    }

    public void fetchVaultFromFirestoreWithResult(final VaultFetchResultCallback callback) {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
        if (!authManager.isLoggedIn() || authManager.getUid() == null) {
            if (callback != null) callback.onResult(VaultFetchResult.NETWORK_ERROR);
            return;
        }
        String uid = authManager.getUid();
        final DocumentReference docRef = getVaultDocRef(uid);

        docRef.get(Source.SERVER)
                .addOnSuccessListener(doc -> {
                    if (processVaultDocument(doc, null)) {
                        if (callback != null) callback.onResult(VaultFetchResult.VAULT_FOUND);
                    } else {
                        if (callback != null) callback.onResult(VaultFetchResult.NO_VAULT_EXISTS);
                    }
                })
                .addOnFailureListener(e -> {
                    docRef.get(Source.CACHE)
                            .addOnSuccessListener(doc -> {
                                if (processVaultDocument(doc, null)) {
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

    public void fetchVaultFromFirestore(final VaultFetchCallback callback) {
        fetchVaultFromFirestoreWithResult(result -> {
            if (callback != null) callback.onResult(result == VaultFetchResult.VAULT_FOUND);
        });
    }

    private boolean processVaultDocument(DocumentSnapshot doc, VaultFetchCallback callback) {
        if (doc == null || !doc.exists()) return false;
        Map<String, Object> data = doc.getData();
        if (data == null) return false;

        String salt        = getStr(data, "salt");
        String encDEK      = getStr(data, "encryptedDEK");
        String iv          = getStr(data, "iv");
        String tag         = getStr(data, "tag");
        int    iterations  = getInt(data, "iterations");
        long   createdAt   = getLong(data, "createdAt");
        int    vaultVersion = getInt(data, "vaultVersion");

        if (salt.length() > 0 && encDEK.length() > 0 && iv.length() > 0 && tag.length() > 0) {
            prefs.edit()
                    .putString(KEY_SALT, salt)
                    .putString(KEY_ENCRYPTED_DEK, encDEK)
                    .putString(KEY_IV, iv)
                    .putString(KEY_TAG, tag)
                    .putInt(KEY_ITERATIONS, iterations)
                    .putLong(KEY_CREATED_AT, createdAt)
                    .putBoolean(KEY_VAULT_INITIALIZED, true)
                    .putBoolean(KEY_VAULT_UPLOADED, true)
                    .putInt(KEY_VAULT_VERSION, vaultVersion > 0 ? vaultVersion : CURRENT_VAULT_VERSION)
                    .commit();
            return true;
        }
        return false;
    }

    public void checkCloudNotesExistWithResult(final VaultFetchResultCallback callback) {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(appContext);
        if (!authManager.isLoggedIn() || authManager.getUid() == null) {
            if (callback != null) callback.onResult(VaultFetchResult.NETWORK_ERROR);
            return;
        }
        String uid = authManager.getUid();

        FirebaseFirestore.getInstance()
                .collection("users").document(uid)
                .collection("notes").limit(1).get(Source.SERVER)
                .addOnSuccessListener(qs -> {
                    boolean exists = qs != null && !qs.isEmpty();
                    if (callback != null) callback.onResult(
                            exists ? VaultFetchResult.VAULT_FOUND : VaultFetchResult.NO_VAULT_EXISTS);
                })
                .addOnFailureListener(e -> {
                    FirebaseFirestore.getInstance()
                            .collection("users").document(uid)
                            .collection("notes").limit(1).get(Source.CACHE)
                            .addOnSuccessListener(qs -> {
                                boolean exists = qs != null && !qs.isEmpty();
                                if (callback != null) callback.onResult(
                                        exists ? VaultFetchResult.VAULT_FOUND : VaultFetchResult.NETWORK_ERROR);
                            })
                            .addOnFailureListener(e2 -> {
                                if (callback != null) callback.onResult(VaultFetchResult.NETWORK_ERROR);
                            });
                });
    }

    // ======================== PASSWORD CHANGE (v4 REWRITTEN) ========================

    /**
     * v4: Change master password.
     *
     * Flow:
     * 1. Derive oldDerivedKey = Argon2id(oldPassword, oldSalt)
     * 2. Decrypt encryptedDEK with oldDerivedKey -> get DEK
     * 3. If decrypt fails -> old password incorrect
     * 4. Generate newSalt
     * 5. Derive newDerivedKey = Argon2id(newPassword, newSalt)
     * 6. Encrypt DEK with newDerivedKey -> newEncryptedDEK
     * 7. Update local + Firestore
     *
     * Notes ko re-encrypt karne ki zarurat NAHI -- DEK same rehta hai!
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

        new Thread(new Runnable() {
            public void run() {
                byte[] oldDerivedKey = null;
                byte[] newDerivedKey = null;

                try {
                    // Step 1: Read current vault metadata
                    String saltB64   = prefs.getString(KEY_SALT, null);
                    String encDEKB64 = prefs.getString(KEY_ENCRYPTED_DEK, null);
                    String ivB64     = prefs.getString(KEY_IV, null);

                    if (saltB64 == null || encDEKB64 == null || ivB64 == null) {
                        if (callback != null) callback.onError("Vault metadata incomplete");
                        return;
                    }

                    byte[] oldSalt = Base64.decode(saltB64, Base64.NO_WRAP);

                    // Step 2: Derive old key
                    oldDerivedKey = CryptoManager.deriveKeyArgon2id(oldPassword, oldSalt);
                    if (oldDerivedKey == null) {
                        if (callback != null) callback.onError("Key derivation failed");
                        return;
                    }

                    // Step 3: Decrypt DEK with old derived key
                    byte[] dek = CryptoManager.decryptDEKWithDerivedKey(encDEKB64, ivB64, oldDerivedKey);
                    CryptoManager.zeroFill(oldDerivedKey);
                    oldDerivedKey = null;

                    if (dek == null) {
                        if (callback != null) callback.onError("Old password incorrect");
                        return;
                    }

                    // Step 4: Generate new salt
                    byte[] newSalt = CryptoManager.generateSalt();

                    // Step 5: Derive new key
                    newDerivedKey = CryptoManager.deriveKeyArgon2id(newPassword, newSalt);
                    if (newDerivedKey == null) {
                        CryptoManager.zeroFill(dek);
                        if (callback != null) callback.onError("New key derivation failed");
                        return;
                    }

                    // Step 6: Re-encrypt DEK with new derived key
                    CryptoManager.VaultBundle bundle = CryptoManager.encryptDEKWithDerivedKey(dek, newDerivedKey);
                    CryptoManager.zeroFill(newDerivedKey);
                    newDerivedKey = null;

                    if (bundle == null) {
                        CryptoManager.zeroFill(dek);
                        if (callback != null) callback.onError("DEK re-encryption failed");
                        return;
                    }

                    String newSaltB64 = Base64.encodeToString(newSalt, Base64.NO_WRAP);
                    long   createdAt  = prefs.getLong(KEY_CREATED_AT, System.currentTimeMillis());

                    // Step 7: Update local vault metadata
                    prefs.edit()
                            .putString(KEY_SALT, newSaltB64)
                            .putString(KEY_ENCRYPTED_DEK, bundle.encryptedDEK)
                            .putString(KEY_IV, bundle.iv)
                            .putString(KEY_TAG, bundle.tag)
                            .putInt(KEY_VAULT_VERSION, CURRENT_VAULT_VERSION)
                            .putBoolean(KEY_VAULT_UPLOADED, false)
                            .commit();

                    // Step 8: Upload to Firestore
                    uploadVaultToFirestoreWithConfirmation(newSaltB64, bundle.encryptedDEK,
                            bundle.iv, bundle.tag, createdAt);

                    // Update cached DEK (DEK itself doesn't change, just its wrapper)
                    if (cachedDEK != null) Arrays.fill(cachedDEK, (byte) 0);
                    cachedDEK = dek;

                    Log.d(TAG, "[PASSWORD_CHANGE] Success (v4 architecture)");
                    if (callback != null) callback.onSuccess();

                } catch (Exception e) {
                    Log.e(TAG, "Password change failed: " + e.getMessage());
                    CryptoManager.zeroFill(oldDerivedKey);
                    CryptoManager.zeroFill(newDerivedKey);
                    if (callback != null) callback.onError(e.getMessage());
                }
            }
        }).start();
    }

    // ======================== MIGRATION SUPPORT ========================

    public void storeVaultLocally(String saltB64, String encDEKB64, String ivB64,
                                   String tagB64, long createdAt) {
        prefs.edit()
                .putString(KEY_SALT, saltB64)
                .putString(KEY_ENCRYPTED_DEK, encDEKB64)
                .putString(KEY_IV, ivB64)
                .putString(KEY_TAG, tagB64)
                .putInt(KEY_ITERATIONS, 0)
                .putLong(KEY_CREATED_AT, createdAt)
                .putBoolean(KEY_VAULT_INITIALIZED, true)
                .putBoolean(KEY_VAULT_UPLOADED, false)
                .putInt(KEY_VAULT_VERSION, CURRENT_VAULT_VERSION)
                .commit();
    }

    public void setCachedDEK(byte[] dek) {
        if (cachedDEK != null) Arrays.fill(cachedDEK, (byte) 0);
        cachedDEK = dek;
    }

    public void markV3MigrationDone() {
        prefs.edit().putBoolean(KEY_MIGRATION_V3_DONE, true).commit();
    }

    // ======================== LOCAL METADATA ACCESS ========================

    public String getSaltHex()        { return prefs.getString(KEY_SALT, null); }
    public String getEncryptedDEK()   { return prefs.getString(KEY_ENCRYPTED_DEK, null); }
    public String getVerifyTag()      { return prefs.getString(KEY_TAG, null); }
    public String getLocalSalt()      { return prefs.getString(KEY_SALT, null); }
    public String getLocalEncryptedDEK() { return prefs.getString(KEY_ENCRYPTED_DEK, null); }
    public String getLocalVerifyTag() { return prefs.getString(KEY_TAG, null); }
    public String getLocalIV()        { return prefs.getString(KEY_IV, null); }

    public void restoreVaultFromBackup(String saltB64, String encDEKB64,
                                        String ivB64, String tagB64, int iterations) {
        prefs.edit()
                .putString(KEY_SALT, saltB64)
                .putString(KEY_ENCRYPTED_DEK, encDEKB64)
                .putString(KEY_IV, ivB64)
                .putString(KEY_TAG, tagB64)
                .putInt(KEY_ITERATIONS, iterations)
                .putLong(KEY_CREATED_AT, System.currentTimeMillis())
                .putBoolean(KEY_VAULT_INITIALIZED, true)
                .putBoolean(KEY_VAULT_UPLOADED, false)
                .putInt(KEY_VAULT_VERSION, CURRENT_VAULT_VERSION)
                .commit();
    }

    // ======================== HELPERS ========================

    private String getStr(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return val instanceof String ? (String) val : "";
    }
    private int getInt(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return val instanceof Number ? ((Number) val).intValue() : 0;
    }
    private long getLong(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return val instanceof Number ? ((Number) val).longValue() : 0;
    }

    // ======================== CALLBACKS ========================

    public enum VaultFetchResult { VAULT_FOUND, NO_VAULT_EXISTS, NETWORK_ERROR }

    public interface VaultFetchResultCallback { void onResult(VaultFetchResult result); }
    public interface VaultFetchCallback       { void onResult(boolean vaultFound); }
    public interface VaultCallback            { void onSuccess(); void onError(String error); }
}
