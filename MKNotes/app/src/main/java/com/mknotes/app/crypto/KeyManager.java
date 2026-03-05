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
 * Singleton managing the vault key lifecycle -- FIXED Architecture (v4).
 *
 * ============================================================
 * NEW ARCHITECTURE (Clear Data proof):
 * ============================================================
 *
 * Vault Creation:
 *   salt = random(16 bytes)
 *   derivedKey = Argon2id(password, salt)    <-- deterministic!
 *   dek = random(32 bytes)
 *   encryptedDEK = XChaCha20(dek, derivedKey)
 *   Store to Firestore: { salt, encryptedDEK, iv, vaultVersion=4 }
 *
 * Vault Unlock:
 *   Fetch { salt, encryptedDEK, iv } from Firestore (or local cache)
 *   derivedKey = Argon2id(password, salt)    <-- same password+salt = same key
 *   dek = XChaCha20_decrypt(encryptedDEK, derivedKey)
 *   If decrypt fails -> wrong password
 *   If decrypt succeeds -> cachedDEK = dek, vault unlocked
 *
 * KEY DIFFERENCE from old architecture:
 *   - DB Key (Android Keystore) is NOT in the unlock chain
 *   - encryptedDEK is wrapped by password-derived key, NOT by DB Key
 *   - Same password + same salt = same derivedKey on ANY device
 *   - Clear Data / reinstall -> vault recoverable via Firestore + password
 *
 * DB Key still exists for SQLCipher passphrase but is NOT used for
 * DEK wrapping. If DB Key is lost (clear data), a new one is generated
 * and SQLCipher DB is re-created from cloud sync.
 *
 * Keystore is optional session cache only.
 * ============================================================
 */
public class KeyManager {

    private static final String TAG = "KeyManager";

    // SharedPreferences keys -- vault metadata
    private static final String PREFS_NAME          = "mknotes_vault_v4";
    private static final String KEY_SALT            = "vault_salt_b64";
    private static final String KEY_ENCRYPTED_DEK   = "vault_enc_dek_b64";
    private static final String KEY_IV              = "vault_iv_b64";
    private static final String KEY_TAG             = "vault_tag_b64";
    private static final String KEY_ITERATIONS      = "vault_iterations";
    private static final String KEY_CREATED_AT      = "vault_created_at";
    private static final String KEY_VAULT_INITIALIZED = "vault_initialized";
    private static final String KEY_VAULT_UPLOADED   = "vault_uploaded_to_firestore";
    private static final String KEY_VAULT_VERSION    = "vault_version";

    // DB Key -- stored wrapped by Android Keystore (for SQLCipher only)
    private static final String KEY_WRAPPED_DB_KEY     = "wrapped_db_key";
    private static final String KEY_DB_KEY_INITIALIZED = "db_key_initialized";

    // Migration tracking
    private static final String KEY_MIGRATION_V3_DONE = "migration_v3_done";
    private static final String KEY_MIGRATION_V4_DONE = "migration_v4_done";

    public static final int CURRENT_VAULT_VERSION = 4;

    private static KeyManager sInstance;
    private final SharedPreferences prefs;
    private final Context appContext;

    /** In-memory cached DEK (Data Encryption Key). Zeroed on lockVault(). */
    private byte[] cachedDEK;

    /** In-memory cached DB Key. Used for SQLCipher passphrase only. */
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

        // Auto-migrate local prefs from v3 to v4 if needed
        migratePrefsV3ToV4();
    }

    /**
     * Migrate SharedPreferences from v3 prefs name to v4.
     * Only copies metadata; the actual vault re-wrapping happens on next unlock.
     */
    private void migratePrefsV3ToV4() {
        if (prefs.getBoolean(KEY_VAULT_INITIALIZED, false)) return; // Already v4

        SharedPreferences v3Prefs = appContext.getSharedPreferences("mknotes_vault_v3", Context.MODE_PRIVATE);
        if (!v3Prefs.getBoolean("vault_initialized", false)) return; // No v3 vault

        // Copy v3 metadata to v4 prefs (will be re-wrapped on next unlock)
        prefs.edit()
                .putString(KEY_SALT, v3Prefs.getString("vault_salt_b64", null))
                .putString(KEY_ENCRYPTED_DEK, v3Prefs.getString("vault_enc_dek_b64", null))
                .putString(KEY_IV, v3Prefs.getString("vault_iv_b64", null))
                .putString(KEY_TAG, v3Prefs.getString("vault_tag_b64", null))
                .putInt(KEY_ITERATIONS, v3Prefs.getInt("vault_iterations", 0))
                .putLong(KEY_CREATED_AT, v3Prefs.getLong("vault_created_at", System.currentTimeMillis()))
                .putBoolean(KEY_VAULT_INITIALIZED, true)
                .putBoolean(KEY_VAULT_UPLOADED, v3Prefs.getBoolean("vault_uploaded_to_firestore", false))
                .putInt(KEY_VAULT_VERSION, v3Prefs.getInt("vault_version", 3))
                // Copy DB key info too (for migration unlock)
                .putString(KEY_WRAPPED_DB_KEY, v3Prefs.getString("wrapped_db_key", null))
                .putBoolean(KEY_DB_KEY_INITIALIZED, v3Prefs.getBoolean("db_key_initialized", false))
                .commit();

        Log.d(TAG, "[MIGRATE_V3_TO_V4] Copied v3 vault metadata to v4 prefs");
    }

    // ======================== STATE CHECKS ========================

    public boolean isVaultInitialized() {
        return prefs.getBoolean(KEY_VAULT_INITIALIZED, false)
                && prefs.getString(KEY_SALT, null) != null
                && prefs.getString(KEY_ENCRYPTED_DEK, null) != null
                && prefs.getString(KEY_IV, null) != null;
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

    public boolean needsV3Migration() {
        SharedPreferences oldPrefs = appContext.getSharedPreferences("mknotes_vault_v2", Context.MODE_PRIVATE);
        boolean hasOldVault = oldPrefs.getBoolean("vault_initialized", false);
        boolean v3Done = prefs.getBoolean(KEY_MIGRATION_V3_DONE, false);
        return hasOldVault && !v3Done && !isVaultInitialized();
    }

    /**
     * Check if vault needs v4 migration (re-wrapping DEK with derived key).
     * True if vault version < 4 and vault is initialized.
     */
    public boolean needsV4Migration() {
        return isVaultInitialized()
                && getVaultVersion() < 4
                && !prefs.getBoolean(KEY_MIGRATION_V4_DONE, false);
    }

    public boolean isVaultUploaded() {
        return prefs.getBoolean(KEY_VAULT_UPLOADED, false);
    }

    /**
     * Check if old DB Key wrapping exists (v3 format).
     * Used by MasterPasswordActivity for UI messaging.
     */
    public boolean hasDBKWrapping() {
        return prefs.getBoolean(KEY_DB_KEY_INITIALIZED, false)
                && prefs.getString(KEY_WRAPPED_DB_KEY, null) != null;
    }

    /**
     * v4: Always true when vault is initialized, because v4 uses
     * password-derived key (PK) wrapping by default.
     */
    public boolean hasPKWrapping() {
        return isVaultInitialized();
    }

    // ======================== DB KEY MANAGEMENT (SQLCipher only) ========================

    /**
     * Initialize the DB key for SQLCipher. NOT used for DEK wrapping in v4.
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
        Log.d(TAG, "DB key initialized (SQLCipher only, not for DEK wrapping)");
        return true;
    }

    private boolean unwrapAndCacheDBKey() {
        if (cachedDBKey != null) return true;

        String wrapped = prefs.getString(KEY_WRAPPED_DB_KEY, null);
        if (wrapped == null) {
            Log.e(TAG, "No wrapped DB key found");
            return false;
        }

        byte[] dbKey = SecureKeyStore.unwrapKey(SecureKeyStore.ALIAS_DB_KEY_MASTER, wrapped);
        if (dbKey == null) {
            Log.e(TAG, "Failed to unwrap DB key (Keystore key lost after clear data?)");
            // This is OK in v4 -- DB key loss just means SQLCipher DB needs re-creation
            // The actual DEK (for note encryption) is recovered from password
            return false;
        }

        cachedDBKey = dbKey;
        return true;
    }

    public String getSQLCipherPassphrase() {
        if (cachedDBKey == null) unwrapAndCacheDBKey();
        if (cachedDBKey == null) {
            // DB key lost (clear data) -- generate a new one for fresh SQLCipher DB
            Log.w(TAG, "DB key lost, generating new DB key for SQLCipher");
            if (initializeDBKey()) {
                return CryptoManager.bytesToHex(cachedDBKey);
            }
            return null;
        }
        return CryptoManager.bytesToHex(cachedDBKey);
    }

    public byte[] getDBKey() {
        if (cachedDBKey == null) unwrapAndCacheDBKey();
        if (cachedDBKey == null) return null;
        byte[] copy = new byte[cachedDBKey.length];
        System.arraycopy(cachedDBKey, 0, copy, 0, cachedDBKey.length);
        return copy;
    }

    // ======================== VAULT CREATION (NEW v4) ========================

    /**
     * First-time vault setup with Argon2id + XChaCha20-Poly1305.
     * DB Key is NOT in the wrapping chain.
     *
     * Flow:
     * 1. Generate random salt (16 bytes)
     * 2. derivedKey = Argon2id(password, salt)
     * 3. dek = random(32 bytes)
     * 4. encryptedDEK = XChaCha20(dek, derivedKey)
     * 5. Store { salt, encryptedDEK, iv, vaultVersion=4 } to Firestore
     * 6. Cache DEK in memory
     *
     * Also initialize DB key for SQLCipher (separate from vault chain).
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
                    // Step 1: Initialize DB key for SQLCipher (separate concern)
                    initializeDBKey();

                    // Step 2: Generate salt
                    salt = CryptoManager.generateSalt();

                    // Step 3: Derive key from password (deterministic)
                    derivedKey = CryptoManager.deriveKeyArgon2id(password, salt);
                    if (derivedKey == null) {
                        if (callback != null) callback.onError("Argon2id key derivation failed");
                        return;
                    }

                    // Step 4: Generate random DEK
                    dek = CryptoManager.generateDEK();

                    // Step 5: Wrap DEK with derived key (NOT DB key!)
                    CryptoManager.VaultBundle bundle = CryptoManager.encryptDEKWithDerivedKey(dek, derivedKey);
                    CryptoManager.zeroFill(derivedKey);
                    derivedKey = null;

                    if (bundle == null) {
                        if (callback != null) callback.onError("DEK encryption failed");
                        return;
                    }

                    String saltB64   = Base64.encodeToString(salt, Base64.NO_WRAP);
                    long   createdAt = System.currentTimeMillis();

                    // Step 6: Store locally
                    prefs.edit()
                            .putString(KEY_SALT, saltB64)
                            .putString(KEY_ENCRYPTED_DEK, bundle.encryptedDEK)
                            .putString(KEY_IV, bundle.iv)
                            .putString(KEY_TAG, bundle.tag)
                            .putInt(KEY_ITERATIONS, 0) // Argon2id marker
                            .putLong(KEY_CREATED_AT, createdAt)
                            .putBoolean(KEY_VAULT_INITIALIZED, true)
                            .putBoolean(KEY_VAULT_UPLOADED, false)
                            .putInt(KEY_VAULT_VERSION, CURRENT_VAULT_VERSION)
                            .putBoolean(KEY_MIGRATION_V4_DONE, true)
                            .commit();

                    // Step 7: Cache DEK
                    cachedDEK = dek;
                    dek = null; // Prevent zeroFill in finally

                    Log.d(TAG, "[VAULT_CREATED_V4] Password-derived vault created (device-independent)");

                    // Step 8: Upload to Firestore
                    uploadVaultToFirestoreWithConfirmation(saltB64, bundle.encryptedDEK,
                            bundle.iv, bundle.tag, createdAt);

                    if (callback != null) callback.onSuccess();

                } catch (Exception e) {
                    Log.e(TAG, "[VAULT_CREATED_V4] EXCEPTION: " + e.getMessage());
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
            initializeDBKey();

            salt = CryptoManager.generateSalt();
            derivedKey = CryptoManager.deriveKeyArgon2id(password, salt);
            if (derivedKey == null) return false;

            dek = CryptoManager.generateDEK();

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
                    .putBoolean(KEY_MIGRATION_V4_DONE, true)
                    .commit();

            cachedDEK = dek;
            dek = null;

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

    // ======================== VAULT UNLOCK (NEW v4) ========================

    /**
     * Unlock vault: derive key from password, decrypt DEK.
     * DB Key is NOT needed. Fully device-independent.
     *
     * Flow:
     * 1. Get vault metadata (salt, encryptedDEK, iv)
     * 2. derivedKey = Argon2id(password, salt)
     * 3. dek = XChaCha20_decrypt(encryptedDEK, derivedKey)
     * 4. If decrypt fails -> wrong password
     * 5. If decrypt succeeds -> cachedDEK = dek
     *
     * For v3 vaults (migration): tries old DB Key path first, then
     * re-wraps DEK with derived key for v4 format.
     */
    public boolean unlockVault(String password) {
        if (password == null || password.length() == 0) return false;
        if (!isVaultInitialized()) {
            Log.e(TAG, "[VAULT_UNLOCK_FAILED] vault not initialized");
            return false;
        }

        try {
            String saltB64    = prefs.getString(KEY_SALT, null);
            String encDEKB64  = prefs.getString(KEY_ENCRYPTED_DEK, null);
            String ivB64      = prefs.getString(KEY_IV, null);
            String tagB64     = prefs.getString(KEY_TAG, null);

            if (saltB64 == null || encDEKB64 == null || ivB64 == null) {
                Log.e(TAG, "[VAULT_UNLOCK_FAILED] incomplete vault metadata");
                return false;
            }

            byte[] salt = Base64.decode(saltB64, Base64.NO_WRAP);

            // Derive key from password (deterministic)
            byte[] derivedKey = CryptoManager.deriveKeyArgon2id(password, salt);
            if (derivedKey == null) {
                Log.e(TAG, "[VAULT_UNLOCK_FAILED] Argon2id derivation failed");
                return false;
            }

            // ===== PATH A: v4 format -- DEK wrapped with derived key =====
            if (getVaultVersion() >= 4) {
                byte[] dek = CryptoManager.decryptDEKWithDerivedKey(encDEKB64, ivB64, derivedKey);
                CryptoManager.zeroFill(derivedKey);

                if (dek == null) {
                    Log.w(TAG, "[VAULT_UNLOCK_FAILED] Wrong password (v4 path)");
                    return false;
                }

                cachedDEK = dek;
                Log.d(TAG, "[VAULT_UNLOCK_SUCCESS] v4 path -- password-derived key");

                // Initialize DB key for SQLCipher (separate concern)
                initializeDBKey();
                return true;
            }

            // ===== PATH B: v3 format migration -- DEK wrapped with DB Key =====
            // Old v3 vault: encryptedDEK is wrapped with DB Key, and the "DEK"
            // stored in v3 was actually the UEK (= Argon2id derived key).
            // We need DB Key to unwrap it, then convert to v4 format.
            Log.d(TAG, "[VAULT_UNLOCK] v3 vault detected, attempting migration...");

            byte[] dek = null;

            // Try DB Key unwrap (only works if Keystore not lost)
            if (hasDBKWrapping()) {
                byte[] dbKey = getDBKey();
                if (dbKey != null) {
                    byte[] storedUEK = CryptoManager.decryptDEK(encDEKB64, ivB64, tagB64, dbKey);
                    CryptoManager.zeroFill(dbKey);

                    if (storedUEK != null) {
                        // v3: storedUEK should equal derivedKey (verify password)
                        boolean match = java.security.MessageDigest.isEqual(derivedKey, storedUEK);
                        if (match) {
                            // In v3, UEK was the encryption key for notes
                            dek = storedUEK;
                            Log.d(TAG, "[VAULT_UNLOCK] v3 DB Key path succeeded");
                        } else {
                            CryptoManager.zeroFill(storedUEK);
                            CryptoManager.zeroFill(derivedKey);
                            Log.w(TAG, "[VAULT_UNLOCK_FAILED] Wrong password (v3 UEK mismatch)");
                            return false;
                        }
                    }
                }
            }

            // Try PBKDF2 fallback for v2 vaults
            if (dek == null) {
                byte[] masterKey = CryptoManager.deriveMasterKey(password, salt);
                if (masterKey != null) {
                    dek = CryptoManager.decryptDEK(encDEKB64, ivB64, tagB64, masterKey);
                    CryptoManager.zeroFill(masterKey);
                }
            }

            if (dek == null) {
                CryptoManager.zeroFill(derivedKey);
                Log.w(TAG, "[VAULT_UNLOCK_FAILED] All paths exhausted");
                return false;
            }

            // SUCCESS: Cache DEK and migrate to v4 format
            cachedDEK = dek;

            // Migrate vault to v4: re-wrap DEK with password-derived key
            migrateVaultToV4(dek, derivedKey, salt);
            CryptoManager.zeroFill(derivedKey);

            // Initialize DB key for SQLCipher
            initializeDBKey();

            Log.d(TAG, "[VAULT_UNLOCK_SUCCESS] v3->v4 migration completed");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "[VAULT_UNLOCK_FAILED] exception: " + e.getMessage());
            return false;
        }
    }

    /**
     * Migrate vault from v3 (DB Key wrapped) to v4 (password-derived key wrapped).
     * Re-wraps the DEK with derivedKey and updates local + Firestore.
     */
    private void migrateVaultToV4(byte[] dek, byte[] derivedKey, byte[] salt) {
        try {
            CryptoManager.VaultBundle bundle = CryptoManager.encryptDEKWithDerivedKey(dek, derivedKey);
            if (bundle == null) {
                Log.e(TAG, "[MIGRATE_V4] Failed to re-wrap DEK");
                return;
            }

            String saltB64   = Base64.encodeToString(salt, Base64.NO_WRAP);
            long   createdAt = prefs.getLong(KEY_CREATED_AT, System.currentTimeMillis());

            prefs.edit()
                    .putString(KEY_ENCRYPTED_DEK, bundle.encryptedDEK)
                    .putString(KEY_IV, bundle.iv)
                    .putString(KEY_TAG, bundle.tag)
                    .putInt(KEY_VAULT_VERSION, CURRENT_VAULT_VERSION)
                    .putBoolean(KEY_MIGRATION_V4_DONE, true)
                    .putBoolean(KEY_VAULT_UPLOADED, false)
                    .commit();

            // Upload new v4 vault to Firestore
            uploadVaultToFirestoreWithConfirmation(saltB64, bundle.encryptedDEK,
                    bundle.iv, bundle.tag, createdAt);

            Log.d(TAG, "[MIGRATE_V4] Successfully migrated vault to v4 format");
        } catch (Exception e) {
            Log.e(TAG, "[MIGRATE_V4] Migration failed: " + e.getMessage());
        }
    }

    // ======================== VAULT LOCK ========================

    public void lockVault() {
        if (cachedDEK != null) {
            Arrays.fill(cachedDEK, (byte) 0);
            cachedDEK = null;
        }
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
        data.put("iterations", 0); // Argon2id marker
        data.put("vaultVersion", CURRENT_VAULT_VERSION);
        data.put("createdAt", createdAt);
        data.put("alg", "argon2id+xchacha20poly1305"); // v4 marker

        getVaultDocRef(uid).set(data)
                .addOnSuccessListener(unused -> {
                    prefs.edit().putBoolean(KEY_VAULT_UPLOADED, true).commit();
                    Log.d(TAG, "[VAULT_UPLOAD] SUCCESS (v4 format)");
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

        String saltB64    = prefs.getString(KEY_SALT, "");
        String encDEKB64  = prefs.getString(KEY_ENCRYPTED_DEK, "");
        String ivB64      = prefs.getString(KEY_IV, "");
        String tagB64     = prefs.getString(KEY_TAG, "");
        long   createdAt  = prefs.getLong(KEY_CREATED_AT, System.currentTimeMillis());

        if (saltB64.isEmpty() || encDEKB64.isEmpty() || ivB64.isEmpty()) return;

        Map<String, Object> data = new HashMap<>();
        data.put("salt", saltB64);
        data.put("encryptedDEK", encDEKB64);
        data.put("iv", ivB64);
        data.put("tag", tagB64);
        data.put("iterations", 0);
        data.put("vaultVersion", CURRENT_VAULT_VERSION);
        data.put("createdAt", createdAt);
        data.put("alg", "argon2id+xchacha20poly1305");

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

    public void fetchVaultFromFirestore(final VaultFetchCallback callback) {
        fetchVaultFromFirestoreWithResult(result -> {
            if (callback != null) callback.onResult(result == VaultFetchResult.VAULT_FOUND);
        });
    }

    private boolean processVaultDocument(DocumentSnapshot doc) {
        if (doc == null || !doc.exists()) return false;
        Map<String, Object> data = doc.getData();
        if (data == null) return false;

        String salt         = getStr(data, "salt");
        String encDEK       = getStr(data, "encryptedDEK");
        String iv           = getStr(data, "iv");
        String tag          = getStr(data, "tag");
        int    iterations   = getInt(data, "iterations");
        long   createdAt    = getLong(data, "createdAt");
        int    vaultVersion = getInt(data, "vaultVersion");

        if (salt.length() > 0 && encDEK.length() > 0 && iv.length() > 0) {
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

    // ======================== PASSWORD CHANGE (NEW v4) ========================

    /**
     * Change password: decrypt DEK with old derived key, re-wrap with new derived key.
     * Notes are NOT re-encrypted (DEK stays the same).
     *
     * Flow:
     * 1. oldDerivedKey = Argon2id(oldPassword, oldSalt)
     * 2. dek = decrypt(encryptedDEK, oldDerivedKey)
     * 3. newSalt = random(16 bytes)
     * 4. newDerivedKey = Argon2id(newPassword, newSalt)
     * 5. newEncryptedDEK = encrypt(dek, newDerivedKey)
     * 6. Update Firestore with new { salt, encryptedDEK, iv }
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
                    // Step 1: Get old salt and derive old key
                    String saltB64 = prefs.getString(KEY_SALT, null);
                    if (saltB64 == null) {
                        if (callback != null) callback.onError("Vault metadata incomplete");
                        return;
                    }
                    byte[] oldSalt = Base64.decode(saltB64, Base64.NO_WRAP);

                    oldDerivedKey = CryptoManager.deriveKeyArgon2id(oldPassword, oldSalt);
                    if (oldDerivedKey == null) {
                        if (callback != null) callback.onError("Key derivation failed");
                        return;
                    }

                    // Step 2: Decrypt DEK with old derived key
                    String encDEKB64 = prefs.getString(KEY_ENCRYPTED_DEK, null);
                    String ivB64     = prefs.getString(KEY_IV, null);

                    byte[] dek = CryptoManager.decryptDEKWithDerivedKey(encDEKB64, ivB64, oldDerivedKey);
                    CryptoManager.zeroFill(oldDerivedKey);
                    oldDerivedKey = null;

                    if (dek == null) {
                        if (callback != null) callback.onError("Old password incorrect");
                        return;
                    }

                    // Step 3: Generate new salt and derive new key
                    byte[] newSalt = CryptoManager.generateSalt();
                    newDerivedKey = CryptoManager.deriveKeyArgon2id(newPassword, newSalt);
                    if (newDerivedKey == null) {
                        CryptoManager.zeroFill(dek);
                        if (callback != null) callback.onError("New key derivation failed");
                        return;
                    }

                    // Step 4: Re-wrap DEK with new derived key
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

                    // Step 5: Update local
                    prefs.edit()
                            .putString(KEY_SALT, newSaltB64)
                            .putString(KEY_ENCRYPTED_DEK, bundle.encryptedDEK)
                            .putString(KEY_IV, bundle.iv)
                            .putString(KEY_TAG, bundle.tag)
                            .putBoolean(KEY_VAULT_UPLOADED, false)
                            .commit();

                    // Step 6: Upload to Firestore
                    uploadVaultToFirestoreWithConfirmation(newSaltB64, bundle.encryptedDEK,
                            bundle.iv, bundle.tag, createdAt);

                    // Update cached DEK (DEK itself didn't change)
                    if (cachedDEK != null) Arrays.fill(cachedDEK, (byte) 0);
                    cachedDEK = dek;

                    Log.d(TAG, "[PASSWORD_CHANGED] v4 format, DEK unchanged, wrapping updated");
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

    public void markV4MigrationDone() {
        prefs.edit().putBoolean(KEY_MIGRATION_V4_DONE, true).commit();
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
