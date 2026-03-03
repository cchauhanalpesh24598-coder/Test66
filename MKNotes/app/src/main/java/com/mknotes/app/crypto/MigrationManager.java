package com.mknotes.app.crypto;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;

import net.sqlcipher.database.SQLiteDatabase;
import android.util.Base64;
import android.util.Log;

import com.google.firebase.firestore.DocumentSnapshot;
import com.google.firebase.firestore.FirebaseFirestore;
import com.google.firebase.firestore.QueryDocumentSnapshot;
import com.google.firebase.firestore.QuerySnapshot;
import com.google.firebase.firestore.SetOptions;
import com.google.firebase.firestore.WriteBatch;

import com.mknotes.app.cloud.FirebaseAuthManager;
import com.mknotes.app.db.NotesDatabaseHelper;
import com.mknotes.app.util.CryptoUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Handles migration from old PBKDF2/AES-GCM encryption to new
 * Argon2id/XChaCha20-Poly1305 + SQLCipher + Android Keystore system.
 *
 * Migration steps:
 * 1. Create full SQLite .db backup
 * 2. Derive old master key from password + old salt via PBKDF2 (old CryptoUtils)
 * 3. Ensure DB key exists (generate + wrap with Keystore if needed)
 * 4. Derive new UEK from password via Argon2id
 * 5. In SQLite transaction: decrypt all fields with old key, re-encrypt with new UEK
 *    Also encrypt previously-plaintext fields (images_data, files_data, audios_data, etc.)
 * 6. Encrypt UEK with DB key via XChaCha20-Poly1305
 * 7. Store new vault metadata in SharedPreferences + Firestore
 * 8. Encrypt all attachment files with streaming XChaCha20-Poly1305
 * 9. Delete backup ONLY after full success
 *
 * On failure: restore SQLite from backup, old data fully preserved.
 */
public class MigrationManager {

    private static final String TAG = "MigrationManager";
    private static final String DB_NAME = "mknotes.db";
    private static final String BACKUP_SUFFIX = ".pre_migration.bak";

    /**
     * Perform full migration from old single-layer to new 3-layer key system.
     *
     * @param context      Application context
     * @param password     User's master password
     * @param oldSalt      Old PBKDF2 salt
     * @param oldIterations Old PBKDF2 iteration count
     * @return true if migration succeeded
     */
    public static boolean migrate(Context context, String password, byte[] oldSalt, int oldIterations) {
        if (password == null || oldSalt == null) {
            Log.e(TAG, "Migration failed: null password or salt");
            return false;
        }

        File dbFile = context.getDatabasePath(DB_NAME);
        File backupFile = new File(dbFile.getParentFile(), DB_NAME + BACKUP_SUFFIX);

        byte[] oldMasterKey = null;
        byte[] newUEK = null;
        byte[] dbKey = null;

        try {
            // Step 1: Create SQLite backup
            if (!createDatabaseBackup(dbFile, backupFile)) {
                Log.e(TAG, "Migration failed: backup creation failed");
                return false;
            }

            // Step 2: Derive old master key using PBKDF2 (legacy CryptoUtils)
            oldMasterKey = CryptoUtils.deriveKey(password, oldSalt);
            if (oldMasterKey == null) {
                restoreBackup(dbFile, backupFile);
                return false;
            }

            // Step 3: Ensure DB key exists (initialize if needed)
            KeyManager km = KeyManager.getInstance(context);
            if (!km.initializeDBKey()) {
                // DB key already exists, load it
                km.loadDBKey();
            }
            dbKey = km.getDBKey();
            if (dbKey == null) {
                Log.e(TAG, "Migration failed: cannot obtain DB key");
                CryptoManager.zeroFill(oldMasterKey);
                restoreBackup(dbFile, backupFile);
                return false;
            }

            // Step 4: Derive new UEK from password via Argon2id
            byte[] newSalt = CryptoManager.generateSalt();
            newUEK = CryptoManager.deriveKeyArgon2(password, newSalt);
            if (newUEK == null) {
                Log.e(TAG, "Migration failed: Argon2 key derivation failed");
                CryptoManager.zeroFill(oldMasterKey);
                restoreBackup(dbFile, backupFile);
                return false;
            }

            // Step 5: Open old DB with EMPTY passphrase (old DB is plaintext)
            // and re-encrypt all field-level data
            NotesDatabaseHelper.setPassphrase("");
            boolean reEncryptSuccess = reEncryptAllData(context, oldMasterKey, newUEK);
            if (!reEncryptSuccess) {
                CryptoManager.zeroFill(oldMasterKey);
                CryptoManager.zeroFill(newUEK);
                restoreBackup(dbFile, backupFile);
                return false;
            }

            CryptoManager.zeroFill(oldMasterKey);
            oldMasterKey = null;

            // Step 5b: Convert plaintext DB to SQLCipher encrypted DB
            // Use sqlcipher_export to encrypt the database file with the DB key
            String dbKeyHex = km.getDBKeyHex();
            if (dbKeyHex != null && dbKeyHex.length() > 0) {
                boolean encryptSuccess = encryptDatabaseFile(context, dbFile, dbKeyHex);
                if (!encryptSuccess) {
                    Log.e(TAG, "Migration failed: database file encryption failed");
                    CryptoManager.zeroFill(newUEK);
                    restoreBackup(dbFile, backupFile);
                    return false;
                }
                // Set the passphrase for all future DB access
                NotesDatabaseHelper.setPassphrase(dbKeyHex);
            }

            // Step 6: Encrypt UEK with DB key via XChaCha20-Poly1305
            CryptoManager.VaultBundle bundle = CryptoManager.encryptDEK(newUEK, dbKey);
            if (bundle == null) {
                CryptoManager.zeroFill(newUEK);
                restoreBackup(dbFile, backupFile);
                return false;
            }

            // Step 7: Store vault metadata
            String saltB64 = Base64.encodeToString(newSalt, Base64.NO_WRAP);
            long createdAt = System.currentTimeMillis();
            km.storeVaultLocally(saltB64, bundle.encryptedDEK, bundle.iv, bundle.tag, createdAt);
            km.uploadVaultToFirestore();
            km.setCachedDEK(newUEK);
            newUEK = null; // Prevent zeroFill since KM now owns it

            // Step 8: Encrypt attachment files
            encryptAttachmentFiles(context, km.getDEK());

            Log.d(TAG, "[VAULT_CREATED] Migration completed successfully");

            // Step 9: Delete backup
            if (backupFile.exists()) backupFile.delete();
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Migration exception: " + e.getMessage(), e);
            restoreBackup(dbFile, backupFile);
            return false;
        } finally {
            CryptoManager.zeroFill(oldMasterKey);
            if (newUEK != null) CryptoManager.zeroFill(newUEK);
        }
    }

    /**
     * Re-encrypt all data within a SQLite transaction.
     * Decrypts with old AES-GCM key, re-encrypts with new XChaCha20-Poly1305 UEK.
     * Also encrypts previously-plaintext fields.
     */
    private static boolean reEncryptAllData(Context context, byte[] oldKey, byte[] newUEK) {
        NotesDatabaseHelper dbHelper = NotesDatabaseHelper.getInstance(context);
        SQLiteDatabase db = dbHelper.getWritableDatabase();

        db.beginTransaction();
        try {
            // Re-encrypt notes table
            reEncryptNotes(db, oldKey, newUEK);

            // Re-encrypt trash table
            reEncryptTrash(db, oldKey, newUEK);

            // Encrypt categories (previously plaintext)
            encryptCategories(db, newUEK);

            // Encrypt mantras (previously plaintext)
            encryptMantras(db, newUEK);

            // Encrypt moods (previously plaintext)
            encryptMoods(db, newUEK);

            db.setTransactionSuccessful();
            return true;

        } catch (Exception e) {
            Log.e(TAG, "Re-encryption failed: " + e.getMessage(), e);
            return false;
        } finally {
            db.endTransaction();
        }
    }

    private static void reEncryptNotes(SQLiteDatabase db, byte[] oldKey, byte[] newUEK) {
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES,
                null, null, null, null, null, null);
        if (cursor == null) return;

        while (cursor.moveToNext()) {
            long id = cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_ID));

            // Fields encrypted with old key
            String encTitle = getStringFromCursor(cursor, NotesDatabaseHelper.COL_TITLE);
            String encContent = getStringFromCursor(cursor, NotesDatabaseHelper.COL_CONTENT);
            String encChecklist = getStringFromCursor(cursor, NotesDatabaseHelper.COL_CHECKLIST_DATA);
            String encRoutine = getStringFromCursor(cursor, NotesDatabaseHelper.COL_ROUTINE_DATA);

            // Decrypt with old key
            String plainTitle = decryptOld(encTitle, oldKey);
            String plainContent = decryptOld(encContent, oldKey);
            String plainChecklist = decryptOld(encChecklist, oldKey);
            String plainRoutine = decryptOld(encRoutine, oldKey);

            // Fields that were previously plaintext
            String imagesData = getStringFromCursor(cursor, NotesDatabaseHelper.COL_IMAGES_DATA);
            String filesData = getStringFromCursor(cursor, NotesDatabaseHelper.COL_FILES_DATA);
            String audiosData = getStringFromCursor(cursor, NotesDatabaseHelper.COL_AUDIOS_DATA);
            String linkedNoteIds = getStringFromCursor(cursor, NotesDatabaseHelper.COL_LINKED_NOTE_IDS);

            ContentValues values = new ContentValues();
            values.put(NotesDatabaseHelper.COL_TITLE, encryptSafe(plainTitle, newUEK));
            values.put(NotesDatabaseHelper.COL_CONTENT, encryptSafe(plainContent, newUEK));
            values.put(NotesDatabaseHelper.COL_CHECKLIST_DATA, encryptSafe(plainChecklist, newUEK));
            values.put(NotesDatabaseHelper.COL_ROUTINE_DATA, encryptSafe(plainRoutine, newUEK));
            values.put(NotesDatabaseHelper.COL_IMAGES_DATA, encryptSafe(imagesData, newUEK));
            values.put(NotesDatabaseHelper.COL_FILES_DATA, encryptSafe(filesData, newUEK));
            values.put(NotesDatabaseHelper.COL_AUDIOS_DATA, encryptSafe(audiosData, newUEK));
            values.put(NotesDatabaseHelper.COL_LINKED_NOTE_IDS, encryptSafe(linkedNoteIds, newUEK));
            values.put(NotesDatabaseHelper.COL_SEARCH_INDEX, "");

            db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                    NotesDatabaseHelper.COL_ID + "=?",
                    new String[]{String.valueOf(id)});
        }
        cursor.close();
    }

    private static void reEncryptTrash(SQLiteDatabase db, byte[] oldKey, byte[] newUEK) {
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_TRASH,
                null, null, null, null, null, null);
        if (cursor == null) return;

        while (cursor.moveToNext()) {
            long id = cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_ID));

            String encTitle = getStringFromCursor(cursor, NotesDatabaseHelper.COL_TRASH_NOTE_TITLE);
            String encContent = getStringFromCursor(cursor, NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT);
            String encChecklist = getStringFromCursor(cursor, NotesDatabaseHelper.COL_TRASH_CHECKLIST_DATA);

            String plainTitle = decryptOld(encTitle, oldKey);
            String plainContent = decryptOld(encContent, oldKey);
            String plainChecklist = decryptOld(encChecklist, oldKey);

            // Previously-plaintext fields in trash
            String imagesData = getStringFromCursor(cursor, NotesDatabaseHelper.COL_TRASH_IMAGES_DATA);
            String filesData = getStringFromCursor(cursor, NotesDatabaseHelper.COL_TRASH_FILES_DATA);
            String audiosData = getStringFromCursor(cursor, NotesDatabaseHelper.COL_TRASH_AUDIOS_DATA);
            String linkedNoteIds = getStringFromCursor(cursor, NotesDatabaseHelper.COL_TRASH_LINKED_NOTE_IDS);

            ContentValues values = new ContentValues();
            values.put(NotesDatabaseHelper.COL_TRASH_NOTE_TITLE, encryptSafe(plainTitle, newUEK));
            values.put(NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT, encryptSafe(plainContent, newUEK));
            values.put(NotesDatabaseHelper.COL_TRASH_CHECKLIST_DATA, encryptSafe(plainChecklist, newUEK));
            values.put(NotesDatabaseHelper.COL_TRASH_IMAGES_DATA, encryptSafe(imagesData, newUEK));
            values.put(NotesDatabaseHelper.COL_TRASH_FILES_DATA, encryptSafe(filesData, newUEK));
            values.put(NotesDatabaseHelper.COL_TRASH_AUDIOS_DATA, encryptSafe(audiosData, newUEK));
            values.put(NotesDatabaseHelper.COL_TRASH_LINKED_NOTE_IDS, encryptSafe(linkedNoteIds, newUEK));

            db.update(NotesDatabaseHelper.TABLE_TRASH, values,
                    NotesDatabaseHelper.COL_TRASH_ID + "=?",
                    new String[]{String.valueOf(id)});
        }
        cursor.close();
    }

    private static void encryptCategories(SQLiteDatabase db, byte[] newUEK) {
        try {
            Cursor cursor = db.query(NotesDatabaseHelper.TABLE_CATEGORIES,
                    null, null, null, null, null, null);
            if (cursor == null) return;

            while (cursor.moveToNext()) {
                long id = cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_ID));
                String name = getStringFromCursor(cursor, NotesDatabaseHelper.COL_CAT_NAME);

                // Skip if already encrypted
                if (name != null && name.length() > 0 && !CryptoManager.isEncrypted(name)) {
                    ContentValues values = new ContentValues();
                    values.put(NotesDatabaseHelper.COL_CAT_NAME, encryptSafe(name, newUEK));
                    db.update(NotesDatabaseHelper.TABLE_CATEGORIES, values,
                            NotesDatabaseHelper.COL_CAT_ID + "=?",
                            new String[]{String.valueOf(id)});
                }
            }
            cursor.close();
        } catch (Exception e) {
            Log.w(TAG, "Category encryption during migration: " + e.getMessage());
        }
    }

    private static void encryptMantras(SQLiteDatabase db, byte[] newUEK) {
        try {
            Cursor cursor = db.query(NotesDatabaseHelper.TABLE_MANTRAS,
                    null, null, null, null, null, null);
            if (cursor == null) return;

            while (cursor.moveToNext()) {
                long id = cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_MANTRA_ID));
                String name = getStringFromCursor(cursor, NotesDatabaseHelper.COL_MANTRA_NAME);
                String audioPath = getStringFromCursor(cursor, NotesDatabaseHelper.COL_MANTRA_AUDIO_PATH);

                boolean needsUpdate = false;
                ContentValues values = new ContentValues();

                if (name != null && name.length() > 0 && !CryptoManager.isEncrypted(name)) {
                    values.put(NotesDatabaseHelper.COL_MANTRA_NAME, encryptSafe(name, newUEK));
                    needsUpdate = true;
                }
                if (audioPath != null && audioPath.length() > 0 && !CryptoManager.isEncrypted(audioPath)) {
                    values.put(NotesDatabaseHelper.COL_MANTRA_AUDIO_PATH, encryptSafe(audioPath, newUEK));
                    needsUpdate = true;
                }

                if (needsUpdate) {
                    db.update(NotesDatabaseHelper.TABLE_MANTRAS, values,
                            NotesDatabaseHelper.COL_MANTRA_ID + "=?",
                            new String[]{String.valueOf(id)});
                }
            }
            cursor.close();
        } catch (Exception e) {
            Log.w(TAG, "Mantra encryption during migration: " + e.getMessage());
        }
    }

    private static void encryptMoods(SQLiteDatabase db, byte[] newUEK) {
        try {
            Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTE_MOODS,
                    null, null, null, null, null, null);
            if (cursor == null) return;

            while (cursor.moveToNext()) {
                long id = cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_MOOD_ID));
                String emoji = getStringFromCursor(cursor, NotesDatabaseHelper.COL_MOOD_EMOJI);
                String name = getStringFromCursor(cursor, NotesDatabaseHelper.COL_MOOD_NAME);

                boolean needsUpdate = false;
                ContentValues values = new ContentValues();

                if (emoji != null && emoji.length() > 0 && !CryptoManager.isEncrypted(emoji)) {
                    values.put(NotesDatabaseHelper.COL_MOOD_EMOJI, encryptSafe(emoji, newUEK));
                    needsUpdate = true;
                }
                if (name != null && name.length() > 0 && !CryptoManager.isEncrypted(name)) {
                    values.put(NotesDatabaseHelper.COL_MOOD_NAME, encryptSafe(name, newUEK));
                    needsUpdate = true;
                }

                if (needsUpdate) {
                    db.update(NotesDatabaseHelper.TABLE_NOTE_MOODS, values,
                            NotesDatabaseHelper.COL_MOOD_ID + "=?",
                            new String[]{String.valueOf(id)});
                }
            }
            cursor.close();
        } catch (Exception e) {
            Log.w(TAG, "Mood encryption during migration: " + e.getMessage());
        }
    }

    /**
     * Encrypt all attachment files on disk using streaming XChaCha20-Poly1305.
     */
    private static void encryptAttachmentFiles(Context context, byte[] uek) {
        if (uek == null) return;
        File attachmentsRoot = new File(context.getFilesDir(), "attachments");
        if (!attachmentsRoot.exists()) return;

        File[] noteDirs = attachmentsRoot.listFiles();
        if (noteDirs == null) return;

        for (File noteDir : noteDirs) {
            if (!noteDir.isDirectory()) continue;
            encryptFilesInDir(new File(noteDir, "images"), uek);
            encryptFilesInDir(new File(noteDir, "files"), uek);
            encryptFilesInDir(new File(noteDir, "audios"), uek);
        }
    }

    private static void encryptFilesInDir(File dir, byte[] uek) {
        if (dir == null || !dir.exists() || !dir.isDirectory()) return;
        File[] files = dir.listFiles();
        if (files == null) return;

        for (File f : files) {
            if (!f.isFile() || f.length() == 0) continue;
            // Skip already-encrypted files (have .enc extension)
            if (f.getName().endsWith(".enc")) continue;

            try {
                File encFile = new File(dir, f.getName() + ".enc");
                String headerB64 = StreamingFileEncryptor.encryptFile(
                        f.getAbsolutePath(), encFile.getAbsolutePath(), uek);
                if (headerB64 != null && encFile.exists() && encFile.length() > 0) {
                    // Delete original plaintext file
                    f.delete();
                    // Rename encrypted file to original name
                    encFile.renameTo(f);
                    Log.d(TAG, "Encrypted attachment: " + f.getAbsolutePath());
                } else {
                    // Keep original if encryption failed
                    if (encFile.exists()) encFile.delete();
                    Log.w(TAG, "Failed to encrypt attachment: " + f.getAbsolutePath());
                }
            } catch (Exception e) {
                Log.w(TAG, "Attachment encryption error: " + e.getMessage());
            }
        }
    }

    // ======================== DATABASE FILE ENCRYPTION ========================

    /**
     * Convert a plaintext SQLite database to an encrypted SQLCipher database.
     * Uses sqlcipher_export to create an encrypted copy, then replaces the original.
     *
     * @param context  Application context
     * @param dbFile   The plaintext database file
     * @param passphrase The hex-encoded passphrase for encryption
     * @return true if encryption succeeded
     */
    private static boolean encryptDatabaseFile(Context context, File dbFile, String passphrase) {
        // Close any existing database connections first
        try {
            NotesDatabaseHelper helper = NotesDatabaseHelper.getInstance(context);
            helper.close();
        } catch (Exception e) {
            Log.w(TAG, "Could not close existing DB connection: " + e.getMessage());
        }

        File encryptedFile = new File(dbFile.getParentFile(), "mknotes_encrypted.db");

        net.sqlcipher.database.SQLiteDatabase plainDb = null;
        try {
            // Open the plaintext database with empty passphrase
            plainDb = net.sqlcipher.database.SQLiteDatabase.openDatabase(
                    dbFile.getAbsolutePath(), "", null,
                    net.sqlcipher.database.SQLiteDatabase.OPEN_READWRITE);

            // Attach an encrypted database and export all data to it
            plainDb.rawExecSQL("ATTACH DATABASE '" + encryptedFile.getAbsolutePath()
                    + "' AS encrypted KEY '" + passphrase + "'");
            plainDb.rawExecSQL("SELECT sqlcipher_export('encrypted')");
            plainDb.rawExecSQL("DETACH DATABASE encrypted");
            plainDb.close();
            plainDb = null;

            // Replace original with encrypted version
            if (encryptedFile.exists() && encryptedFile.length() > 0) {
                if (dbFile.delete()) {
                    if (encryptedFile.renameTo(dbFile)) {
                        Log.d(TAG, "Database file encrypted successfully");
                        return true;
                    } else {
                        Log.e(TAG, "Failed to rename encrypted DB file");
                        // Try copy as fallback
                        if (createDatabaseBackup(encryptedFile, dbFile)) {
                            encryptedFile.delete();
                            return true;
                        }
                    }
                } else {
                    Log.e(TAG, "Failed to delete original DB file");
                }
            }
            return false;

        } catch (Exception e) {
            Log.e(TAG, "encryptDatabaseFile failed: " + e.getMessage(), e);
            // Clean up
            if (encryptedFile.exists()) encryptedFile.delete();
            return false;
        } finally {
            if (plainDb != null) {
                try { plainDb.close(); } catch (Exception ignored) {}
            }
        }
    }

    // ======================== HELPER METHODS ========================

    private static String getStringFromCursor(Cursor cursor, String column) {
        int idx = cursor.getColumnIndex(column);
        if (idx < 0) return "";
        String val = cursor.getString(idx);
        return val != null ? val : "";
    }

    /**
     * Decrypt using old AES-GCM system (CryptoUtils).
     * Returns plaintext, or the original string if not encrypted or decryption fails.
     */
    private static String decryptOld(String encrypted, byte[] oldKey) {
        if (encrypted == null || encrypted.length() == 0) return "";
        // Check if it looks like old AES-GCM format (ivHex:ciphertextHex)
        if (CryptoUtils.isEncrypted(encrypted)) {
            String decrypted = CryptoUtils.decrypt(encrypted, oldKey);
            return decrypted != null ? decrypted : encrypted;
        }
        // Not encrypted (plaintext) - return as-is
        return encrypted;
    }

    private static String encryptSafe(String plaintext, byte[] uek) {
        if (plaintext == null || plaintext.length() == 0) return "";
        String encrypted = CryptoManager.encrypt(plaintext, uek);
        return encrypted != null ? encrypted : plaintext;
    }

    private static boolean createDatabaseBackup(File source, File destination) {
        if (!source.exists()) return false;
        FileInputStream fis = null;
        FileOutputStream fos = null;
        FileChannel inChannel = null;
        FileChannel outChannel = null;
        try {
            fis = new FileInputStream(source);
            fos = new FileOutputStream(destination);
            inChannel = fis.getChannel();
            outChannel = fos.getChannel();
            inChannel.transferTo(0, inChannel.size(), outChannel);
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            closeQuietly(inChannel);
            closeQuietly(outChannel);
            closeQuietly(fis);
            closeQuietly(fos);
        }
    }

    private static void restoreBackup(File dbFile, File backupFile) {
        if (!backupFile.exists()) return;
        try {
            if (dbFile.exists()) dbFile.delete();
            boolean renamed = backupFile.renameTo(dbFile);
            if (!renamed) {
                createDatabaseBackup(backupFile, dbFile);
                backupFile.delete();
            }
        } catch (Exception e) {
            Log.e(TAG, "Restore from backup failed: " + e.getMessage());
        }
    }

    private static void closeQuietly(java.io.Closeable closeable) {
        if (closeable != null) {
            try { closeable.close(); } catch (IOException ignored) {}
        }
    }

    // ======================== LEGACY CLOUD-ONLY MIGRATION ========================

    public interface LegacyMigrationCallback {
        void onSuccess();
        void onFailure(String error);
    }

    /**
     * Verify if a legacy master password can decrypt a sample cloud note.
     */
    public static void verifyLegacyPassword(final Context context, final String password,
                                             final LegacyMigrationCallback callback) {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(context);
        if (!authManager.isLoggedIn() || authManager.getUid() == null) {
            if (callback != null) callback.onFailure("Not logged in");
            return;
        }
        final String uid = authManager.getUid();

        FirebaseFirestore.getInstance()
                .collection("users").document(uid)
                .collection("notes")
                .limit(1)
                .get()
                .addOnSuccessListener(querySnapshot -> {
                    if (querySnapshot == null || querySnapshot.isEmpty()) {
                        if (callback != null) callback.onFailure("No notes found for verification");
                        return;
                    }

                    DocumentSnapshot doc = querySnapshot.getDocuments().get(0);
                    Map<String, Object> data = doc.getData();
                    if (data == null) {
                        if (callback != null) callback.onFailure("Note data is null");
                        return;
                    }

                    String sampleEncrypted = getEncryptedField(data);
                    if (sampleEncrypted == null) {
                        // Notes might be plaintext -- allow migration
                        if (callback != null) callback.onSuccess();
                        return;
                    }

                    byte[] legacyKey = null;
                    boolean decryptSuccess = false;

                    try {
                        com.mknotes.app.util.SessionManager sm =
                                com.mknotes.app.util.SessionManager.getInstance(context);
                        String oldSaltHex = sm.getOldSaltHex();

                        if (oldSaltHex != null) {
                            byte[] oldSalt = CryptoUtils.hexToBytes(oldSaltHex);
                            legacyKey = CryptoUtils.deriveKey(password, oldSalt);
                            if (legacyKey != null) {
                                String result = CryptoManager.decryptWithLegacyKey(sampleEncrypted, legacyKey);
                                if (result != null) decryptSuccess = true;
                                CryptoManager.zeroFill(legacyKey);
                                legacyKey = null;
                            }
                        }

                        if (!decryptSuccess) {
                            Object saltObj = data.get("salt");
                            if (saltObj instanceof String && ((String) saltObj).length() > 0) {
                                byte[] noteSalt = CryptoManager.hexToBytes((String) saltObj);
                                legacyKey = CryptoUtils.deriveKey(password, noteSalt);
                                if (legacyKey != null) {
                                    String result = CryptoManager.decryptWithLegacyKey(sampleEncrypted, legacyKey);
                                    if (result != null) decryptSuccess = true;
                                    CryptoManager.zeroFill(legacyKey);
                                    legacyKey = null;
                                }
                            }
                        }

                        if (!decryptSuccess && oldSaltHex != null) {
                            byte[] oldSalt = CryptoManager.hexToBytes(oldSaltHex);
                            legacyKey = CryptoManager.deriveLegacyKey(password, oldSalt);
                            if (legacyKey != null) {
                                String result = CryptoManager.decryptWithLegacyKey(sampleEncrypted, legacyKey);
                                if (result != null) decryptSuccess = true;
                                CryptoManager.zeroFill(legacyKey);
                                legacyKey = null;
                            }
                        }

                        if (decryptSuccess) {
                            if (callback != null) callback.onSuccess();
                        } else {
                            if (callback != null) callback.onFailure("Wrong master password");
                        }

                    } catch (Exception e) {
                        CryptoManager.zeroFill(legacyKey);
                        if (callback != null) callback.onFailure("Verification error: " + e.getMessage());
                    }
                })
                .addOnFailureListener(e -> {
                    if (callback != null) callback.onFailure("Could not fetch notes: " + e.getMessage());
                });
    }

    /**
     * Perform full legacy cloud migration.
     */
    public static void migrateLegacyCloudNotes(final Context context, final String password,
                                                final LegacyMigrationCallback callback) {
        FirebaseAuthManager authManager = FirebaseAuthManager.getInstance(context);
        if (!authManager.isLoggedIn() || authManager.getUid() == null) {
            if (callback != null) callback.onFailure("Not logged in");
            return;
        }
        final String uid = authManager.getUid();

        com.mknotes.app.util.SessionManager sm =
                com.mknotes.app.util.SessionManager.getInstance(context);
        final String oldSaltHex = sm.getOldSaltHex();

        new Thread(() -> {
            byte[] legacyKey = null;
            byte[] newUEK = null;
            byte[] dbKey = null;

            try {
                legacyKey = deriveLegacyKeyFromAvailableSources(context, password, oldSaltHex);
                if (legacyKey == null) {
                    postCallback(context, callback, false, "Could not derive legacy key");
                    return;
                }

                // Ensure DB key exists
                KeyManager km = KeyManager.getInstance(context);
                if (!km.initializeDBKey()) {
                    km.loadDBKey();
                }
                dbKey = km.getDBKey();
                if (dbKey == null) {
                    CryptoManager.zeroFill(legacyKey);
                    postCallback(context, callback, false, "Could not obtain DB key");
                    return;
                }

                // Derive new UEK via Argon2id
                byte[] newSalt = CryptoManager.generateSalt();
                newUEK = CryptoManager.deriveKeyArgon2(password, newSalt);
                if (newUEK == null) {
                    CryptoManager.zeroFill(legacyKey);
                    postCallback(context, callback, false, "Argon2 key derivation failed");
                    return;
                }

                // Encrypt UEK with DB key
                CryptoManager.VaultBundle bundle = CryptoManager.encryptDEK(newUEK, dbKey);
                if (bundle == null) {
                    CryptoManager.zeroFill(legacyKey);
                    CryptoManager.zeroFill(newUEK);
                    postCallback(context, callback, false, "Could not encrypt UEK");
                    return;
                }

                String saltB64 = Base64.encodeToString(newSalt, Base64.NO_WRAP);

                final byte[] finalLegacyKey = legacyKey;
                final byte[] finalNewUEK = newUEK;
                final String finalEncUEK = bundle.encryptedDEK;
                final String finalIV = bundle.iv;
                final String finalTag = bundle.tag;
                final String finalSaltB64 = saltB64;

                legacyKey = null;
                newUEK = null;

                FirebaseFirestore.getInstance()
                        .collection("users").document(uid)
                        .collection("notes")
                        .get()
                        .addOnSuccessListener(querySnapshot -> {
                            new Thread(() -> {
                                try {
                                    reEncryptAndUploadCloudNotes(
                                            context, uid, querySnapshot,
                                            finalLegacyKey, finalNewUEK,
                                            finalEncUEK, finalIV, finalTag,
                                            finalSaltB64, callback);
                                } finally {
                                    CryptoManager.zeroFill(finalLegacyKey);
                                }
                            }).start();
                        })
                        .addOnFailureListener(e -> {
                            CryptoManager.zeroFill(finalLegacyKey);
                            CryptoManager.zeroFill(finalNewUEK);
                            postCallback(context, callback, false, "Could not fetch notes: " + e.getMessage());
                        });

            } catch (Exception e) {
                CryptoManager.zeroFill(legacyKey);
                CryptoManager.zeroFill(newUEK);
                postCallback(context, callback, false, "Migration error: " + e.getMessage());
            }
        }).start();
    }

    private static void reEncryptAndUploadCloudNotes(
            Context context, String uid, QuerySnapshot querySnapshot,
            byte[] legacyKey, byte[] newUEK,
            String encUEKB64, String ivB64, String tagB64,
            String saltB64, LegacyMigrationCallback callback) {

        int totalNotes = querySnapshot.size();
        Log.d(TAG, "[MIGRATION_PROGRESS] Re-encrypting " + totalNotes + " cloud notes");

        List<Map<String, Object>> reEncryptedNotes = new ArrayList<>();
        List<String> noteIds = new ArrayList<>();
        int successCount = 0;
        int failCount = 0;
        int skipCount = 0;

        for (QueryDocumentSnapshot doc : querySnapshot) {
            String docId = doc.getId();
            Map<String, Object> data = doc.getData();

            if (data == null) { skipCount++; continue; }

            Object deletedObj = data.get("isDeleted");
            if (deletedObj instanceof Boolean && ((Boolean) deletedObj).booleanValue()) {
                skipCount++;
                continue;
            }

            try {
                Map<String, Object> reEncrypted = new HashMap<>(data);
                reEncrypted.put("title", reEncryptField(data, "title", legacyKey, newUEK));
                reEncrypted.put("content", reEncryptField(data, "content", legacyKey, newUEK));
                if (data.containsKey("checklistData")) {
                    reEncrypted.put("checklistData", reEncryptField(data, "checklistData", legacyKey, newUEK));
                }
                if (data.containsKey("routineData")) {
                    reEncrypted.put("routineData", reEncryptField(data, "routineData", legacyKey, newUEK));
                }
                // Encrypt previously-plaintext cloud fields
                if (data.containsKey("imagesData")) {
                    reEncrypted.put("imagesData", encryptCloudField(data, "imagesData", newUEK));
                }
                if (data.containsKey("filesData")) {
                    reEncrypted.put("filesData", encryptCloudField(data, "filesData", newUEK));
                }
                if (data.containsKey("audiosData")) {
                    reEncrypted.put("audiosData", encryptCloudField(data, "audiosData", newUEK));
                }
                if (data.containsKey("linkedNoteIds")) {
                    reEncrypted.put("linkedNoteIds", encryptCloudField(data, "linkedNoteIds", newUEK));
                }
                reEncrypted.put("modifiedAt", Long.valueOf(System.currentTimeMillis()));

                reEncryptedNotes.add(reEncrypted);
                noteIds.add(docId);
                successCount++;
            } catch (Exception e) {
                failCount++;
            }
        }

        if (failCount > 0 && successCount == 0) {
            postCallback(context, callback, false, "Could not re-encrypt any notes");
            return;
        }

        // Batch upload
        FirebaseFirestore db = FirebaseFirestore.getInstance();
        WriteBatch batch = db.batch();
        int batchCount = 0;

        for (int i = 0; i < reEncryptedNotes.size(); i++) {
            batch.set(
                    db.collection("users").document(uid)
                            .collection("notes").document(noteIds.get(i)),
                    reEncryptedNotes.get(i), SetOptions.merge());
            batchCount++;
            if (batchCount >= 450) {
                try {
                    com.google.android.gms.tasks.Tasks.await(batch.commit());
                } catch (Exception e) {
                    postCallback(context, callback, false, "Batch commit failed");
                    return;
                }
                batch = db.batch();
                batchCount = 0;
            }
        }

        if (batchCount > 0) {
            try {
                com.google.android.gms.tasks.Tasks.await(batch.commit());
            } catch (Exception e) {
                postCallback(context, callback, false, "Final batch commit failed");
                return;
            }
        }

        // Store vault metadata
        long createdAt = System.currentTimeMillis();
        KeyManager km = KeyManager.getInstance(context);
        km.storeVaultLocally(saltB64, encUEKB64, ivB64, tagB64, createdAt);
        km.uploadVaultToFirestore();
        km.setCachedDEK(newUEK);

        Log.d(TAG, "[VAULT_CREATED] Legacy migration completed: " + successCount + " notes migrated");
        postCallback(context, callback, true, null);
    }

    private static String reEncryptField(Map<String, Object> data, String fieldName,
                                          byte[] legacyKey, byte[] newUEK) {
        Object val = data.get(fieldName);
        if (val == null) return "";
        String strVal = val.toString();
        if (strVal.length() == 0) return "";

        if (CryptoManager.isEncrypted(strVal)) {
            String plaintext = CryptoManager.decryptWithLegacyKey(strVal, legacyKey);
            if (plaintext == null) return strVal;
            String reEncrypted = CryptoManager.encrypt(plaintext, newUEK);
            return reEncrypted != null ? reEncrypted : strVal;
        } else {
            String encrypted = CryptoManager.encrypt(strVal, newUEK);
            return encrypted != null ? encrypted : strVal;
        }
    }

    private static String encryptCloudField(Map<String, Object> data, String fieldName, byte[] newUEK) {
        Object val = data.get(fieldName);
        if (val == null) return "";
        String strVal = val.toString();
        if (strVal.length() == 0) return "";
        // Already encrypted? Leave as-is
        if (CryptoManager.isEncrypted(strVal)) return strVal;
        // Encrypt plaintext
        String encrypted = CryptoManager.encrypt(strVal, newUEK);
        return encrypted != null ? encrypted : strVal;
    }

    private static String getEncryptedField(Map<String, Object> data) {
        String[] fields = {"title", "content", "checklistData", "routineData"};
        for (String field : fields) {
            Object val = data.get(field);
            if (val instanceof String && CryptoManager.isEncrypted((String) val)) {
                return (String) val;
            }
        }
        return null;
    }

    private static byte[] deriveLegacyKeyFromAvailableSources(Context context, String password, String oldSaltHex) {
        byte[] key = null;
        if (oldSaltHex != null && oldSaltHex.length() > 0) {
            byte[] oldSalt = CryptoUtils.hexToBytes(oldSaltHex);
            key = CryptoUtils.deriveKey(password, oldSalt);
            if (key != null) return key;

            oldSalt = CryptoManager.hexToBytes(oldSaltHex);
            key = CryptoManager.deriveLegacyKey(password, oldSalt);
            if (key != null) return key;
        }
        return null;
    }

    private static void postCallback(Context context, LegacyMigrationCallback callback,
                                      boolean success, String error) {
        if (callback == null) return;
        if (context instanceof android.app.Activity) {
            ((android.app.Activity) context).runOnUiThread(() -> {
                if (success) callback.onSuccess();
                else callback.onFailure(error != null ? error : "Unknown error");
            });
        } else {
            if (success) callback.onSuccess();
            else callback.onFailure(error != null ? error : "Unknown error");
        }
    }
}
