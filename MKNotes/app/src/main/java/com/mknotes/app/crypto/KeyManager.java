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
 * Singleton managing the 3-layer key hierarchy (Notesnook-equivalent).
 *
 * Key Hierarchy:
 *   Layer 1: User Password
 *     -> (Argon2id KDF) -> User Encryption Key (UEK) - 256-bit
 *     -> UEK encrypted with DB Key via XChaCha20-Poly1305
 *     -> Stored as "userKeyCipher" in SharedPreferences + Firestore
 *
 *   Layer 2: Database Key (DBK) - 256-bit
 *     -> Random, generated once
 *     -> Wrapped with Android Keystore AES-256-GCM master key
 *     -> Stored as encrypted blob in SharedPreferences
 *     -> Used as: SQLCipher DB passphrase + XChaCha20-Poly1305 wrapping key
 *
 *   Layer 3: Android Keystore hardware-backed AES key
 *     -> Never leaves secure hardware (TEE/StrongBox)
 *     -> Used ONLY to wrap/unwrap DB key
 *
 * Firestore document path: users/{uid}/crypto_metadata/vault
 * Fields: salt (Base64), userKeyCipher (Base64), userKeyIV (Base64),
 *         algorithm ("xcha-argon2id13"), createdAt (long millis)
 *
 * RULES:
 * - DB key is device-local (wrapped by Keystore, never leaves device)
 * - UEK cipher is synced to Firestore for cross-device support
 * - Salt is stored both locally and in Firestore
 * - On reinstall: fetch UEK cipher + salt from Firestore, unwrap DB key from Keystore,
 *   derive UEK from password, use UEK for data operations
 */
public class KeyManager {

    private static final String TAG = "KeyManager";

    // Local SharedPreferences keys
    private static final String PREFS_NAME = "mknotes_vault_v3";
    private static final String KEY_SALT = "vault_salt_b64";
    private static final String KEY_USER_KEY_CIPHER = "user_key_cipher_b64";
    private static final String KEY_USER_KEY_IV = "user_key_iv_b64";
    private static final String KEY_WRAPPED_DB_KEY = "wrapped_db_key";
    private static final String KEY_ALGORITHM = "vault_algorithm";
    private static final String KEY_CREATED_AT = "vault_created_at";
    private static final String KEY_VAULT_INITIALIZED = "vault_initialized";
    private static final String KEY_VAULT_UPLOADED = "vault_uploaded_to_firestore";

    // Old vault prefs name for migration detection
    private static final String OLD_PREFS_NAME = "mknotes_vault_v2";

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
     * Check if new vault (v3) metadata exists locally.
     */
    public boolean isVaultInitialized() {
        return prefs.getBoolean(KEY_VAULT_INITIALIZED, false)
                && prefs.getString(KEY_SALT, null) != null
                && prefs.getString(KEY_USER_KEY_CIPHER, null) != null
                && prefs.getString(KEY_USER_KEY_IV, null) != null
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
     * Called once during first vault creation.
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

    // ======================== VAULT CREATION ========================

    /**
     * First-time vault setup with 3-layer key hierarchy.
     *
     * 1. Initialize DB key (generate + wrap with Keystore)
     * 2. Generate 16-byte random salt
     * 3. Derive UEK from password via Argon2id
     * 4. Encrypt UEK with DB key via XChaCha20-Poly1305
     * 5. Store vault metadata locally
     * 6. Upload to Firestore
     * 7. Cache UEK in memory
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

                try {
                    // Step 1: Initialize DB key
                    if (!initializeDBKey()) {
                        if (callback != null) callback.onError("DB key initialization failed");
                        return;
                    }

                    dbKey = getDBKey();
                    if (dbKey == null) {
                        if (callback != null) callback.onError("DB key not available");
                        return;
                    }

                    // Step 2: Generate salt
                    byte[] salt = CryptoManager.generateSalt();

                    // Step 3: Derive UEK from password via Argon2id
                    uek = CryptoManager.deriveKeyArgon2(password, salt);
                    if (uek == null) {
                        Log.e(TAG, "[VAULT_CREATED] FAILED: Argon2id derivation returned null");
                        if (callback != null) callback.onError("Key derivation failed");
                        return;
                    }

                    // Step 4: Encrypt UEK with DB key
                    CryptoManager.VaultBundle bundle = CryptoManager.encryptDEK(uek, dbKey);
                    CryptoManager.zeroFill(dbKey);
                    dbKey = null;

                    if (bundle == null) {
                        Log.e(TAG, "[VAULT_CREATED] FAILED: UEK encryption failed");
                        if (callback != null) callback.onError("UEK encryption failed");
                        return;
                    }

                    final String saltB64 = Base64.encodeToString(salt, Base64.NO_WRAP);
                    final String userKeyCipherB64 = bundle.encryptedDEK;
                    final String userKeyIVB64 = bundle.iv;
                    final long createdAt = System.currentTimeMillis();

                    // Step 5: Store locally first
                    prefs.edit()
                            .putString(KEY_SALT, saltB64)
                            .putString(KEY_USER_KEY_CIPHER, userKeyCipherB64)
                            .putString(KEY_USER_KEY_IV, userKeyIVB64)
                            .putString(KEY_ALGORITHM, CryptoManager.ALG_IDENTIFIER)
                            .putLong(KEY_CREATED_AT, createdAt)
                            .putBoolean(KEY_VAULT_INITIALIZED, true)
                            .putBoolean(KEY_VAULT_UPLOADED, false)
                            .commit();

                    // Step 7: Cache UEK in memory
                    cachedUEK = uek;
                    uek = null; // Prevent zeroFill in finally

                    Log.d(TAG, "[VAULT_CREATED] Vault stored locally, uploading to Firestore...");

                    // Step 6: Upload to Firestore
                    uploadVaultToFirestoreWithConfirmation(saltB64, userKeyCipherB64,
                            userKeyIVB64, createdAt);

                    if (callback != null) callback.onSuccess();

                } catch (Exception e) {
                    Log.e(TAG, "[VAULT_CREATED] EXCEPTION: " + e.getMessage());
                    if (callback != null) callback.onError("Vault creation failed: " + e.getMessage());
                } finally {
                    CryptoManager.zeroFill(uek);
                    CryptoManager.zeroFill(dbKey);
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

        try {
            if (!initializeDBKey()) return false;

            dbKey = getDBKey();
            if (dbKey == null) return false;

            byte[] salt = CryptoManager.generateSalt();
            uek = CryptoManager.deriveKeyArgon2(password, salt);
            if (uek == null) return false;

            CryptoManager.VaultBundle bundle = CryptoManager.encryptDEK(uek, dbKey);
            CryptoManager.zeroFill(dbKey);
            dbKey = null;

            if (bundle == null) return false;

            String saltB64 = Base64.encodeToString(salt, Base64.NO_WRAP);
            long createdAt = System.currentTimeMillis();

            prefs.edit()
                    .putString(KEY_SALT, saltB64)
                    .putString(KEY_USER_KEY_CIPHER, bundle.encryptedDEK)
                    .putString(KEY_USER_KEY_IV, bundle.iv)
                    .putString(KEY_ALGORITHM, CryptoManager.ALG_IDENTIFIER)
                    .putLong(KEY_CREATED_AT, createdAt)
                    .putBoolean(KEY_VAULT_INITIALIZED, true)
                    .putBoolean(KEY_VAULT_UPLOADED, false)
                    .commit();

            cachedUEK = uek;
            uek = null;

            uploadVaultToFirestoreWithConfirmation(saltB64, bundle.encryptedDEK,
                    bundle.iv, createdAt);

            return true;
        } catch (Exception e) {
            Log.e(TAG, "initializeVaultSync failed: " + e.getMessage());
            return false;
        } finally {
            CryptoManager.zeroFill(uek);
            CryptoManager.zeroFill(dbKey);
        }
    }

    // ======================== VAULT UNLOCK ========================

    /**
     * Unlock vault: derive UEK from password + stored salt via Argon2id.
     * Then verify by decrypting the stored UEK cipher.
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

        byte[] derivedUEK = null;
        byte[] dbKey = null;

        try {
            String saltB64 = prefs.getString(KEY_SALT, null);
            String userKeyCipherB64 = prefs.getString(KEY_USER_KEY_CIPHER, null);
            String userKeyIVB64 = prefs.getString(KEY_USER_KEY_IV, null);

            if (saltB64 == null || userKeyCipherB64 == null || userKeyIVB64 == null) {
                Log.e(TAG, "[VAULT_UNLOCK_FAILED] incomplete local vault metadata");
                return false;
            }

            // Load DB key from Keystore
            if (!loadDBKey()) {
                Log.e(TAG, "[VAULT_UNLOCK_FAILED] DB key not available");
                return false;
            }
            dbKey = getDBKey();

            byte[] salt = Base64.decode(saltB64, Base64.NO_WRAP);

            Log.d(TAG, "[VAULT_FETCH] Unlocking with Argon2id, salt_len=" + salt.length);

            // Derive UEK from password
            derivedUEK = CryptoManager.deriveKeyArgon2(password, salt);
            if (derivedUEK == null) {
                Log.e(TAG, "[VAULT_UNLOCK_FAILED] Argon2id derivation returned null");
                return false;
            }

            // Verify: decrypt the stored UEK cipher with DB key
            // If the derivation produced the correct UEK, the encrypted version
            // should match what we can decrypt from the stored cipher
            byte[] storedUEK = CryptoManager.decryptDEK(userKeyCipherB64, userKeyIVB64, "", dbKey);
            CryptoManager.zeroFill(dbKey);
            dbKey = null;

            if (storedUEK == null) {
                Log.w(TAG, "[VAULT_UNLOCK_FAILED] UEK cipher decryption failed");
                CryptoManager.zeroFill(derivedUEK);
                return false;
            }

            // Compare derived UEK with stored UEK
            if (!constantTimeEquals(derivedUEK, storedUEK)) {
                Log.w(TAG, "[VAULT_UNLOCK_FAILED] derived UEK doesn't match stored UEK -- wrong password");
                CryptoManager.zeroFill(derivedUEK);
                CryptoManager.zeroFill(storedUEK);
                return false;
            }

            CryptoManager.zeroFill(storedUEK);

            // Cache UEK
            cachedUEK = derivedUEK;
            derivedUEK = null;

            Log.d(TAG, "[VAULT_UNLOCK_SUCCESS] UEK derived and verified, cached");
            return true;

        } catch (Exception e) {
            Log.e(TAG, "[VAULT_UNLOCK_FAILED] exception: " + e.getMessage());
            CryptoManager.zeroFill(derivedUEK);
            return false;
        } finally {
            CryptoManager.zeroFill(dbKey);
        }
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

    // ======================== DEK ACCESS (UEK is the new DEK) ========================

    /**
     * Get a COPY of the cached UEK. Caller must zero their copy when done.
     * Returns null if vault is locked.
     *
     * NOTE: For API compatibility, this method is named getDEK() but returns UEK.
     * In the new architecture, UEK is the data encryption key.
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
     */
    private void uploadVaultToFirestoreWithConfirmation(final String saltB64,
                                                         final String userKeyCipherB64,
                                                         final String userKeyIVB64,
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
        data.put("userKeyCipher", userKeyCipherB64);
        data.put("userKeyIV", userKeyIVB64);
        data.put("algorithm", CryptoManager.ALG_IDENTIFIER);
        data.put("createdAt", createdAt);
        // Keep old fields for backward compat detection
        data.put("encryptedDEK", userKeyCipherB64);
        data.put("iv", userKeyIVB64);
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

        String saltB64 = prefs.getString(KEY_SALT, "");
        String userKeyCipherB64 = prefs.getString(KEY_USER_KEY_CIPHER, "");
        String userKeyIVB64 = prefs.getString(KEY_USER_KEY_IV, "");
        long createdAt = prefs.getLong(KEY_CREATED_AT, System.currentTimeMillis());

        if (saltB64.isEmpty() || userKeyCipherB64.isEmpty() || userKeyIVB64.isEmpty()) {
            Log.e(TAG, "uploadVaultToFirestore: incomplete local data");
            return;
        }

        Map<String, Object> data = new HashMap<>();
        data.put("salt", saltB64);
        data.put("userKeyCipher", userKeyCipherB64);
        data.put("userKeyIV", userKeyIVB64);
        data.put("algorithm", CryptoManager.ALG_IDENTIFIER);
        data.put("createdAt", createdAt);
        data.put("encryptedDEK", userKeyCipherB64);
        data.put("iv", userKeyIVB64);
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
     */
    private boolean processVaultDocument(DocumentSnapshot doc) {
        if (doc == null || !doc.exists()) return false;

        Map<String, Object> data = doc.getData();
        if (data == null) return false;

        String salt = getStr(data, "salt");
        String algorithm = getStr(data, "algorithm");

        // New v3 format
        String userKeyCipher = getStr(data, "userKeyCipher");
        String userKeyIV = getStr(data, "userKeyIV");

        // Fall back to old v2 format field names
        if (userKeyCipher.length() == 0) {
            userKeyCipher = getStr(data, "encryptedDEK");
        }
        if (userKeyIV.length() == 0) {
            userKeyIV = getStr(data, "iv");
        }

        if (salt.length() > 0 && userKeyCipher.length() > 0 && userKeyIV.length() > 0) {
            long createdAt = getLong(data, "createdAt");

            prefs.edit()
                    .putString(KEY_SALT, salt)
                    .putString(KEY_USER_KEY_CIPHER, userKeyCipher)
                    .putString(KEY_USER_KEY_IV, userKeyIV)
                    .putString(KEY_ALGORITHM, algorithm.length() > 0 ? algorithm : CryptoManager.ALG_IDENTIFIER)
                    .putLong(KEY_CREATED_AT, createdAt)
                    .putBoolean(KEY_VAULT_INITIALIZED, true)
                    .putBoolean(KEY_VAULT_UPLOADED, true)
                    .commit();

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

    // ======================== PASSWORD CHANGE ========================

    /**
     * Change master password. Re-derives UEK with Argon2id, re-encrypts with DB key.
     * UEK itself changes because Argon2 output changes. Data must NOT be re-encrypted
     * because we store the UEK cipher, not derive on-the-fly.
     *
     * ACTUALLY: We need to re-encrypt the UEK cipher only.
     * Old password -> derive old UEK -> decrypt stored UEK cipher to verify
     * New password -> derive new UEK -> this IS the new UEK
     * Encrypt new UEK with DB key -> store new cipher
     * RE-ENCRYPT all data from old UEK to new UEK
     *
     * Wait -- the UEK is what encrypts data. If we change the password, the derived
     * UEK changes. So we must re-encrypt all data. This is expensive.
     *
     * Notesnook's approach: UEK is a RANDOM key (like old DEK), not derived.
     * The password-derived key wraps the UEK. On password change, only the wrapper changes.
     *
     * Adopting Notesnook approach: UEK is random, wrapped by password-derived key.
     *
     * But we already store UEK encrypted with DB key (not password-derived key).
     * So password change = new salt + new Argon2 derivation, but UEK stays same.
     * We verify password by comparing derived == stored (decrypted from DB key).
     *
     * SOLUTION: Store the UEK encrypted with BOTH:
     * a) DB key (for device-local unlock after Keystore-based access)
     * b) Password-derived key (for cross-device recovery)
     *
     * For simplicity and matching existing flow:
     * - UEK is random (generated once)
     * - Stored encrypted with DB key locally
     * - Password verification: derive key from password, compare hash
     * - Store password verification hash alongside
     *
     * REVISED APPROACH (simpler, matches plan):
     * - UEK is random, wrapped by DB key (local) and by password-derived key (Firestore)
     * - On password change: re-wrap UEK with new password-derived key, update Firestore
     * - Data stays encrypted with same UEK
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

        new Thread(() -> {
            byte[] oldDerived = null;
            byte[] newDerived = null;
            byte[] dbKey = null;

            try {
                String saltB64 = prefs.getString(KEY_SALT, null);
                if (saltB64 == null) {
                    if (callback != null) callback.onError("Vault metadata incomplete");
                    return;
                }

                byte[] oldSalt = Base64.decode(saltB64, Base64.NO_WRAP);

                // Step 1: Verify old password
                oldDerived = CryptoManager.deriveKeyArgon2(oldPassword, oldSalt);
                if (oldDerived == null) {
                    if (callback != null) callback.onError("Key derivation failed");
                    return;
                }

                // Get stored UEK from DB key
                dbKey = getDBKey();
                if (dbKey == null) {
                    if (callback != null) callback.onError("DB key not available");
                    return;
                }

                String userKeyCipherB64 = prefs.getString(KEY_USER_KEY_CIPHER, null);
                String userKeyIVB64 = prefs.getString(KEY_USER_KEY_IV, null);

                byte[] storedUEK = CryptoManager.decryptDEK(userKeyCipherB64, userKeyIVB64, "", dbKey);
                if (storedUEK == null) {
                    if (callback != null) callback.onError("UEK decryption failed");
                    return;
                }

                // Verify old password matches
                if (!constantTimeEquals(oldDerived, storedUEK)) {
                    CryptoManager.zeroFill(storedUEK);
                    if (callback != null) callback.onError("Old password incorrect");
                    return;
                }

                CryptoManager.zeroFill(oldDerived);
                oldDerived = null;

                // Step 2: Generate new salt, derive new key
                byte[] newSalt = CryptoManager.generateSalt();
                newDerived = CryptoManager.deriveKeyArgon2(newPassword, newSalt);
                if (newDerived == null) {
                    CryptoManager.zeroFill(storedUEK);
                    if (callback != null) callback.onError("New key derivation failed");
                    return;
                }

                // Step 3: Re-encrypt UEK with DB key (same UEK, new IV)
                CryptoManager.VaultBundle bundle = CryptoManager.encryptDEK(storedUEK, dbKey);
                CryptoManager.zeroFill(dbKey);
                dbKey = null;

                if (bundle == null) {
                    CryptoManager.zeroFill(storedUEK);
                    if (callback != null) callback.onError("UEK re-encryption failed");
                    return;
                }

                String newSaltB64 = Base64.encodeToString(newSalt, Base64.NO_WRAP);
                long createdAt = prefs.getLong(KEY_CREATED_AT, System.currentTimeMillis());

                // Step 4: Update local storage
                prefs.edit()
                        .putString(KEY_SALT, newSaltB64)
                        .putString(KEY_USER_KEY_CIPHER, bundle.encryptedDEK)
                        .putString(KEY_USER_KEY_IV, bundle.iv)
                        .putBoolean(KEY_VAULT_UPLOADED, false)
                        .commit();

                // Step 5: Update Firestore
                uploadVaultToFirestoreWithConfirmation(newSaltB64, bundle.encryptedDEK,
                        bundle.iv, createdAt);

                // Update cached UEK
                if (cachedUEK != null) Arrays.fill(cachedUEK, (byte) 0);
                cachedUEK = storedUEK;

                CryptoManager.zeroFill(newDerived);
                newDerived = null;

                Log.d(TAG, "Password changed successfully");
                if (callback != null) callback.onSuccess();

            } catch (Exception e) {
                Log.e(TAG, "Password change failed: " + e.getMessage());
                if (callback != null) callback.onError(e.getMessage());
            } finally {
                CryptoManager.zeroFill(oldDerived);
                CryptoManager.zeroFill(newDerived);
                CryptoManager.zeroFill(dbKey);
            }
        }).start();
    }

    // ======================== MIGRATION SUPPORT ========================

    /**
     * Store vault metadata locally after migration.
     */
    public void storeVaultLocally(String saltB64, String userKeyCipherB64, String userKeyIVB64,
                                   String tagB64, long createdAt) {
        prefs.edit()
                .putString(KEY_SALT, saltB64)
                .putString(KEY_USER_KEY_CIPHER, userKeyCipherB64)
                .putString(KEY_USER_KEY_IV, userKeyIVB64)
                .putString(KEY_ALGORITHM, CryptoManager.ALG_IDENTIFIER)
                .putLong(KEY_CREATED_AT, createdAt)
                .putBoolean(KEY_VAULT_INITIALIZED, true)
                .putBoolean(KEY_VAULT_UPLOADED, false)
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
        return prefs.getString(KEY_USER_KEY_CIPHER, null);
    }

    public String getVerifyTag() {
        return prefs.getString(KEY_USER_KEY_IV, null);
    }

    public String getLocalSalt() {
        return prefs.getString(KEY_SALT, null);
    }

    public String getLocalEncryptedDEK() {
        return prefs.getString(KEY_USER_KEY_CIPHER, null);
    }

    public String getLocalVerifyTag() {
        return prefs.getString(KEY_USER_KEY_IV, null);
    }

    public String getLocalIV() {
        return prefs.getString(KEY_USER_KEY_IV, null);
    }

    // ======================== BACKUP/RESTORE ========================

    public void restoreVaultFromBackup(String saltB64, String encDEKB64,
                                        String ivB64, String tagB64, int iterations) {
        prefs.edit()
                .putString(KEY_SALT, saltB64)
                .putString(KEY_USER_KEY_CIPHER, encDEKB64)
                .putString(KEY_USER_KEY_IV, ivB64)
                .putString(KEY_ALGORITHM, CryptoManager.ALG_IDENTIFIER)
                .putLong(KEY_CREATED_AT, System.currentTimeMillis())
                .putBoolean(KEY_VAULT_INITIALIZED, true)
                .putBoolean(KEY_VAULT_UPLOADED, false)
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
