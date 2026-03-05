package com.mknotes.app.db;

import android.content.ContentValues;
import android.content.Context;
import android.util.Log;

import net.sqlcipher.Cursor;
import net.sqlcipher.database.SQLiteDatabase;

import com.mknotes.app.crypto.CryptoManager;
import com.mknotes.app.model.Category;
import com.mknotes.app.model.Mantra;
import com.mknotes.app.model.Note;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

/**
 * NotesRepository -- SQLCipher encrypted + XChaCha20-Poly1305 field encryption.
 *
 * v4: encrypt/decrypt uses cachedDEK from KeyManager.getDEK().
 * The DEK is the random key stored in vault (wrapped by password-derived key).
 * No changes needed here -- getKey() already returns KeyManager.getDEK().
 *
 * ALL text fields that can contain user data are encrypted with DEK.
 */
public class NotesRepository {

    private static final String TAG = "NotesRepository";
    private NotesDatabaseHelper dbHelper;
    private Context appContext;
    private static NotesRepository sInstance;

    public static synchronized NotesRepository getInstance(Context context) {
        if (sInstance == null) {
            sInstance = new NotesRepository(context);
        }
        return sInstance;
    }

    private NotesRepository(Context context) {
        dbHelper   = NotesDatabaseHelper.getInstance(context);
        appContext  = context.getApplicationContext();
    }

    /**
     * Get the DEK (Data Encryption Key) from KeyManager.
     * v4: This is the random DEK unwrapped from vault using password-derived key.
     */
    private byte[] getKey() {
        return com.mknotes.app.crypto.KeyManager.getInstance(appContext).getDEK();
    }

    private String encryptField(String plaintext, byte[] key) {
        if (plaintext == null || plaintext.length() == 0) return "";
        if (key == null) {
            Log.e(TAG, "[ENCRYPT_BLOCKED] Key is null -- vault not unlocked?");
            throw new IllegalStateException("Encryption key not available. Vault must be unlocked.");
        }
        String encrypted = CryptoManager.encrypt(plaintext, key);
        if (encrypted == null) {
            throw new IllegalStateException("Encryption failed for field data.");
        }
        return encrypted;
    }

    private String decryptField(String ciphertext, byte[] key) {
        if (ciphertext == null || ciphertext.length() == 0) return "";
        if (key == null) {
            if (CryptoManager.isEncrypted(ciphertext)) return CryptoManager.DECRYPT_FAILED_MARKER;
            return ciphertext;
        }
        String decrypted = CryptoManager.decrypt(ciphertext, key);
        if (decrypted == null) return CryptoManager.DECRYPT_FAILED_MARKER;
        return decrypted;
    }

    // ============ NOTES ============

    public long insertNote(Note note) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        byte[] key = getKey();
        if (note.getCloudId() == null || note.getCloudId().length() == 0) {
            note.setCloudId(UUID.randomUUID().toString());
        }
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_TITLE, encryptField(note.getTitle(), key));
        values.put(NotesDatabaseHelper.COL_CONTENT, encryptField(note.getContent(), key));
        values.put(NotesDatabaseHelper.COL_CREATED, note.getCreatedAt());
        values.put(NotesDatabaseHelper.COL_MODIFIED, note.getModifiedAt());
        values.put(NotesDatabaseHelper.COL_COLOR, note.getColor());
        values.put(NotesDatabaseHelper.COL_FAVORITE, note.isFavorite() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_LOCKED, note.isLocked() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_PASSWORD, note.getPassword());
        values.put(NotesDatabaseHelper.COL_CATEGORY_ID, note.getCategoryId());
        values.put(NotesDatabaseHelper.COL_HAS_CHECKLIST, note.hasChecklist() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_HAS_IMAGE, note.hasImage() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_CHECKLIST_DATA, encryptField(note.getChecklistData(), key));
        values.put(NotesDatabaseHelper.COL_IS_CHECKLIST_MODE, note.isChecklistMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_IMAGES_DATA, encryptField(note.getImagesData(), key));
        values.put(NotesDatabaseHelper.COL_FILES_DATA, encryptField(note.getFilesData(), key));
        values.put(NotesDatabaseHelper.COL_AUDIOS_DATA, encryptField(note.getAudiosData(), key));
        values.put(NotesDatabaseHelper.COL_LINKED_NOTE_IDS, encryptField(note.getLinkedNoteIds(), key));
        values.put(NotesDatabaseHelper.COL_IS_ROUTINE_MODE, note.isRoutineMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_ROUTINE_DATA, encryptField(note.getRoutineData(), key));
        values.put(NotesDatabaseHelper.COL_IS_ARCHIVED, note.isArchived() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_SEARCH_INDEX, "");
        values.put(NotesDatabaseHelper.COL_CLOUD_ID, note.getCloudId());
        values.put(NotesDatabaseHelper.COL_SYNC_STATUS, Note.SYNC_STATUS_PENDING);
        return db.insert(NotesDatabaseHelper.TABLE_NOTES, null, values);
    }

    public int updateNote(Note note) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        byte[] key = getKey();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_TITLE, encryptField(note.getTitle(), key));
        values.put(NotesDatabaseHelper.COL_CONTENT, encryptField(note.getContent(), key));
        values.put(NotesDatabaseHelper.COL_MODIFIED, System.currentTimeMillis());
        values.put(NotesDatabaseHelper.COL_COLOR, note.getColor());
        values.put(NotesDatabaseHelper.COL_FAVORITE, note.isFavorite() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_LOCKED, note.isLocked() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_PASSWORD, note.getPassword());
        values.put(NotesDatabaseHelper.COL_CATEGORY_ID, note.getCategoryId());
        values.put(NotesDatabaseHelper.COL_HAS_CHECKLIST, note.hasChecklist() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_HAS_IMAGE, note.hasImage() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_CHECKLIST_DATA, encryptField(note.getChecklistData(), key));
        values.put(NotesDatabaseHelper.COL_IS_CHECKLIST_MODE, note.isChecklistMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_IMAGES_DATA, encryptField(note.getImagesData(), key));
        values.put(NotesDatabaseHelper.COL_FILES_DATA, encryptField(note.getFilesData(), key));
        values.put(NotesDatabaseHelper.COL_AUDIOS_DATA, encryptField(note.getAudiosData(), key));
        values.put(NotesDatabaseHelper.COL_LINKED_NOTE_IDS, encryptField(note.getLinkedNoteIds(), key));
        values.put(NotesDatabaseHelper.COL_IS_ROUTINE_MODE, note.isRoutineMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_ROUTINE_DATA, encryptField(note.getRoutineData(), key));
        values.put(NotesDatabaseHelper.COL_IS_ARCHIVED, note.isArchived() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_SEARCH_INDEX, "");
        values.put(NotesDatabaseHelper.COL_SYNC_STATUS, Note.SYNC_STATUS_PENDING);
        return db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                NotesDatabaseHelper.COL_ID + "=?",
                new String[]{String.valueOf(note.getId())});
    }

    public int deleteNote(long id) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        return db.delete(NotesDatabaseHelper.TABLE_NOTES,
                NotesDatabaseHelper.COL_ID + "=?",
                new String[]{String.valueOf(id)});
    }

    public Note getNoteById(long id) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES, null,
                NotesDatabaseHelper.COL_ID + "=?",
                new String[]{String.valueOf(id)}, null, null, null);
        Note note = null;
        if (cursor != null && cursor.moveToFirst()) {
            note = cursorToNote(cursor);
            cursor.close();
        }
        return note;
    }

    public List<Note> getAllNotes(String sortBy) {
        List<Note> notes = new ArrayList<>();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        boolean sortByTitleInJava = false;
        String orderBy;
        if ("created".equals(sortBy)) {
            orderBy = NotesDatabaseHelper.COL_CREATED + " DESC";
        } else if ("title".equals(sortBy)) {
            orderBy = NotesDatabaseHelper.COL_MODIFIED + " DESC";
            sortByTitleInJava = true;
        } else {
            orderBy = NotesDatabaseHelper.COL_MODIFIED + " DESC";
        }
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES, null,
                NotesDatabaseHelper.COL_IS_ARCHIVED + "=0",
                null, null, null, orderBy);
        if (cursor != null) {
            while (cursor.moveToNext()) notes.add(cursorToNote(cursor));
            cursor.close();
        }
        if (sortByTitleInJava) sortNotesByTitle(notes);
        return notes;
    }

    public List<Note> getFavoriteNotes(String sortBy) {
        List<Note> notes = new ArrayList<>();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES, null,
                NotesDatabaseHelper.COL_FAVORITE + "=1 AND " + NotesDatabaseHelper.COL_IS_ARCHIVED + "=0",
                null, null, null, NotesDatabaseHelper.COL_MODIFIED + " DESC");
        if (cursor != null) {
            while (cursor.moveToNext()) notes.add(cursorToNote(cursor));
            cursor.close();
        }
        return notes;
    }

    public List<Note> getNotesByCategory(long categoryId, String sortBy) {
        List<Note> notes = new ArrayList<>();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES, null,
                NotesDatabaseHelper.COL_CATEGORY_ID + "=? AND " + NotesDatabaseHelper.COL_IS_ARCHIVED + "=0",
                new String[]{String.valueOf(categoryId)}, null, null,
                NotesDatabaseHelper.COL_MODIFIED + " DESC");
        if (cursor != null) {
            while (cursor.moveToNext()) notes.add(cursorToNote(cursor));
            cursor.close();
        }
        return notes;
    }

    public List<Note> searchNotes(String query) {
        List<Note> results = new ArrayList<>();
        if (query == null || query.trim().length() == 0) return results;

        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES, null,
                NotesDatabaseHelper.COL_IS_ARCHIVED + "=0",
                null, null, null, NotesDatabaseHelper.COL_MODIFIED + " DESC");

        List<Note> allNotes = new ArrayList<>();
        if (cursor != null) {
            while (cursor.moveToNext()) allNotes.add(cursorToNote(cursor));
            cursor.close();
        }

        String   queryLower = query.toLowerCase().trim();
        String[] queryWords = queryLower.split("\\s+");

        for (Note note : allNotes) {
            String title    = note.getTitle() != null ? note.getTitle() : "";
            String content  = note.getContent() != null ? note.getContent() : "";
            String stripped = content.replaceAll("<[^>]*>", " ");
            String searchable = (title + " " + stripped).toLowerCase();

            boolean matchAll = true;
            for (String word : queryWords) {
                if (word.trim().length() == 0) continue;
                if (!searchable.contains(word.trim())) { matchAll = false; break; }
            }
            if (matchAll) results.add(note);
        }
        return results;
    }

    public void toggleFavorite(long noteId) {
        Note note = getNoteById(noteId);
        if (note != null) { note.setFavorite(!note.isFavorite()); updateNote(note); }
    }

    private Note cursorToNote(Cursor cursor) {
        byte[] key = getKey();
        Note note = new Note();
        note.setId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_ID)));
        note.setTitle(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TITLE)), key));
        note.setContent(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_CONTENT)), key));
        note.setCreatedAt(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_CREATED)));
        note.setModifiedAt(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_MODIFIED)));
        note.setColor(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_COLOR)));
        note.setFavorite(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_FAVORITE)) == 1);
        note.setLocked(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_LOCKED)) == 1);
        note.setPassword(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_PASSWORD)));
        note.setCategoryId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_CATEGORY_ID)));
        note.setHasChecklist(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_HAS_CHECKLIST)) == 1);
        note.setHasImage(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_HAS_IMAGE)) == 1);

        int clDataIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_CHECKLIST_DATA);
        if (clDataIdx >= 0) note.setChecklistData(decryptField(cursor.getString(clDataIdx), key));
        int clModeIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IS_CHECKLIST_MODE);
        if (clModeIdx >= 0) note.setChecklistMode(cursor.getInt(clModeIdx) == 1);

        int imgIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IMAGES_DATA);
        if (imgIdx >= 0) note.setImagesData(decryptField(cursor.getString(imgIdx), key));
        int filesIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_FILES_DATA);
        if (filesIdx >= 0) note.setFilesData(decryptField(cursor.getString(filesIdx), key));
        int audiosIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_AUDIOS_DATA);
        if (audiosIdx >= 0) note.setAudiosData(decryptField(cursor.getString(audiosIdx), key));
        int linkedIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_LINKED_NOTE_IDS);
        if (linkedIdx >= 0) note.setLinkedNoteIds(decryptField(cursor.getString(linkedIdx), key));

        int routineModeIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IS_ROUTINE_MODE);
        if (routineModeIdx >= 0) note.setRoutineMode(cursor.getInt(routineModeIdx) == 1);
        int routineDataIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_ROUTINE_DATA);
        if (routineDataIdx >= 0) note.setRoutineData(decryptField(cursor.getString(routineDataIdx), key));
        int archivedIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_IS_ARCHIVED);
        if (archivedIdx >= 0) note.setArchived(cursor.getInt(archivedIdx) == 1);
        int cloudIdIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_CLOUD_ID);
        if (cloudIdIdx >= 0) note.setCloudId(cursor.getString(cloudIdIdx));
        int syncStatusIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_SYNC_STATUS);
        if (syncStatusIdx >= 0) note.setSyncStatus(cursor.getInt(syncStatusIdx));
        return note;
    }

    // ============ ARCHIVE ============

    public void archiveNote(long noteId) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_IS_ARCHIVED, 1);
        db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                NotesDatabaseHelper.COL_ID + "=?", new String[]{String.valueOf(noteId)});
    }

    public void unarchiveNote(long noteId) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_IS_ARCHIVED, 0);
        db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                NotesDatabaseHelper.COL_ID + "=?", new String[]{String.valueOf(noteId)});
    }

    public List<Note> getArchivedNotes() {
        List<Note> notes = new ArrayList<>();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES, null,
                NotesDatabaseHelper.COL_IS_ARCHIVED + "=1",
                null, null, null, NotesDatabaseHelper.COL_MODIFIED + " DESC");
        if (cursor != null) {
            while (cursor.moveToNext()) notes.add(cursorToNote(cursor));
            cursor.close();
        }
        return notes;
    }

    // ============ CATEGORIES (encrypted names) ============

    public long insertCategory(Category category) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        byte[] key = getKey();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_CAT_NAME, encryptField(category.getName(), key));
        values.put(NotesDatabaseHelper.COL_CAT_COLOR, category.getColor());
        values.put(NotesDatabaseHelper.COL_CAT_ORDER, category.getSortOrder());
        return db.insert(NotesDatabaseHelper.TABLE_CATEGORIES, null, values);
    }

    public int updateCategory(Category category) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        byte[] key = getKey();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_CAT_NAME, encryptField(category.getName(), key));
        values.put(NotesDatabaseHelper.COL_CAT_COLOR, category.getColor());
        values.put(NotesDatabaseHelper.COL_CAT_ORDER, category.getSortOrder());
        return db.update(NotesDatabaseHelper.TABLE_CATEGORIES, values,
                NotesDatabaseHelper.COL_CAT_ID + "=?",
                new String[]{String.valueOf(category.getId())});
    }

    public int deleteCategory(long id) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_CATEGORY_ID, -1);
        db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                NotesDatabaseHelper.COL_CATEGORY_ID + "=?",
                new String[]{String.valueOf(id)});
        return db.delete(NotesDatabaseHelper.TABLE_CATEGORIES,
                NotesDatabaseHelper.COL_CAT_ID + "=?",
                new String[]{String.valueOf(id)});
    }

    public List<Category> getAllCategories() {
        List<Category> categories = new ArrayList<>();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        byte[] key = getKey();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_CATEGORIES,
                null, null, null, null, null,
                NotesDatabaseHelper.COL_CAT_ORDER + " ASC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                Category cat = new Category();
                cat.setId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_ID)));
                cat.setName(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_NAME)), key));
                cat.setColor(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_COLOR)));
                cat.setSortOrder(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_ORDER)));
                categories.add(cat);
            }
            cursor.close();
        }
        return categories;
    }

    public Category getCategoryById(long id) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        byte[] key = getKey();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_CATEGORIES, null,
                NotesDatabaseHelper.COL_CAT_ID + "=?",
                new String[]{String.valueOf(id)}, null, null, null);
        Category category = null;
        if (cursor != null && cursor.moveToFirst()) {
            category = new Category();
            category.setId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_ID)));
            category.setName(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_NAME)), key));
            category.setColor(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_COLOR)));
            category.setSortOrder(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_CAT_ORDER)));
            cursor.close();
        }
        return category;
    }

    public int getNotesCountForCategory(long categoryId) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        Cursor cursor = db.rawQuery("SELECT COUNT(*) FROM " + NotesDatabaseHelper.TABLE_NOTES +
                " WHERE " + NotesDatabaseHelper.COL_CATEGORY_ID + "=?",
                new String[]{String.valueOf(categoryId)});
        int count = 0;
        if (cursor != null && cursor.moveToFirst()) { count = cursor.getInt(0); cursor.close(); }
        return count;
    }

    // ============ TRASH (all text fields encrypted) ============

    public long moveToTrash(Note note) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        byte[] key = getKey();
        ContentValues values = new ContentValues();
        values.put(NotesDatabaseHelper.COL_TRASH_NOTE_TITLE, encryptField(note.getTitle(), key));
        values.put(NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT, encryptField(note.getContent(), key));
        values.put(NotesDatabaseHelper.COL_TRASH_NOTE_COLOR, note.getColor());
        values.put(NotesDatabaseHelper.COL_TRASH_NOTE_CATEGORY, note.getCategoryId());
        values.put(NotesDatabaseHelper.COL_TRASH_DATE, System.currentTimeMillis());
        values.put(NotesDatabaseHelper.COL_TRASH_ORIGINAL_ID, note.getId());
        values.put(NotesDatabaseHelper.COL_TRASH_CHECKLIST_DATA, encryptField(note.getChecklistData(), key));
        values.put(NotesDatabaseHelper.COL_TRASH_IS_CHECKLIST_MODE, note.isChecklistMode() ? 1 : 0);
        values.put(NotesDatabaseHelper.COL_TRASH_IMAGES_DATA, encryptField(note.getImagesData(), key));
        values.put(NotesDatabaseHelper.COL_TRASH_FILES_DATA, encryptField(note.getFilesData(), key));
        values.put(NotesDatabaseHelper.COL_TRASH_AUDIOS_DATA, encryptField(note.getAudiosData(), key));
        values.put(NotesDatabaseHelper.COL_TRASH_LINKED_NOTE_IDS, encryptField(note.getLinkedNoteIds(), key));
        long trashId = db.insert(NotesDatabaseHelper.TABLE_TRASH, null, values);
        deleteNote(note.getId());
        return trashId;
    }

    public List<Note> getTrashNotes() {
        List<Note> notes = new ArrayList<>();
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        byte[] key = getKey();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_TRASH,
                null, null, null, null, null,
                NotesDatabaseHelper.COL_TRASH_DATE + " DESC");
        if (cursor != null) {
            while (cursor.moveToNext()) {
                Note note = new Note();
                note.setId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_ID)));
                note.setTitle(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_TITLE)), key));
                note.setContent(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT)), key));
                note.setColor(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_COLOR)));
                note.setCategoryId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_CATEGORY)));
                note.setModifiedAt(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_DATE)));
                notes.add(note);
            }
            cursor.close();
        }
        return notes;
    }

    public void restoreFromTrash(long trashId) {
        SQLiteDatabase db = dbHelper.getReadableDatabase();
        byte[] key = getKey();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_TRASH, null,
                NotesDatabaseHelper.COL_TRASH_ID + "=?",
                new String[]{String.valueOf(trashId)}, null, null, null);
        if (cursor != null && cursor.moveToFirst()) {
            Note note = new Note();
            note.setTitle(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_TITLE)), key));
            note.setContent(decryptField(cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_CONTENT)), key));
            note.setColor(cursor.getInt(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_COLOR)));
            note.setCategoryId(cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_NOTE_CATEGORY)));
            note.setCreatedAt(System.currentTimeMillis());
            note.setModifiedAt(System.currentTimeMillis());
            int trashClIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_CHECKLIST_DATA);
            if (trashClIdx >= 0) note.setChecklistData(decryptField(cursor.getString(trashClIdx), key));
            int trashClModeIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_IS_CHECKLIST_MODE);
            if (trashClModeIdx >= 0) note.setChecklistMode(cursor.getInt(trashClModeIdx) == 1);
            int trashImgIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_IMAGES_DATA);
            if (trashImgIdx >= 0) note.setImagesData(decryptField(cursor.getString(trashImgIdx), key));
            int trashFilesIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_FILES_DATA);
            if (trashFilesIdx >= 0) note.setFilesData(decryptField(cursor.getString(trashFilesIdx), key));
            int trashAudiosIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_AUDIOS_DATA);
            if (trashAudiosIdx >= 0) note.setAudiosData(decryptField(cursor.getString(trashAudiosIdx), key));
            int trashLinkedIdx = cursor.getColumnIndex(NotesDatabaseHelper.COL_TRASH_LINKED_NOTE_IDS);
            if (trashLinkedIdx >= 0) note.setLinkedNoteIds(decryptField(cursor.getString(trashLinkedIdx), key));
            cursor.close();
            insertNote(note);
        }
        deleteFromTrash(trashId);
    }

    public int deleteFromTrash(long trashId) {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        return db.delete(NotesDatabaseHelper.TABLE_TRASH,
                NotesDatabaseHelper.COL_TRASH_ID + "=?",
                new String[]{String.valueOf(trashId)});
    }

    public void emptyTrash() {
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        db.delete(NotesDatabaseHelper.TABLE_TRASH, null, null);
    }

    // ============ TITLE SORT HELPER ============

    private void sortNotesByTitle(List<Note> notes) {
        Collections.sort(notes, new Comparator<Note>() {
            public int compare(Note a, Note b) {
                String ta = a.getTitle() != null ? a.getTitle().toLowerCase() : "";
                String tb = b.getTitle() != null ? b.getTitle().toLowerCase() : "";
                return ta.compareTo(tb);
            }
        });
    }

    // ============ MIGRATION HELPER ============

    public void migrateToEncrypted(byte[] dek) {
        // Encrypts any remaining plaintext notes with the DEK
        SQLiteDatabase db = dbHelper.getWritableDatabase();
        Cursor cursor = db.query(NotesDatabaseHelper.TABLE_NOTES, null,
                null, null, null, null, null);
        if (cursor != null) {
            while (cursor.moveToNext()) {
                long   id    = cursor.getLong(cursor.getColumnIndex(NotesDatabaseHelper.COL_ID));
                String title = cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_TITLE));
                String content = cursor.getString(cursor.getColumnIndex(NotesDatabaseHelper.COL_CONTENT));

                // Skip if already encrypted
                if (CryptoManager.isEncrypted(title) || CryptoManager.isEncrypted(content)) continue;

                // Skip empty
                if ((title == null || title.isEmpty()) && (content == null || content.isEmpty())) continue;

                ContentValues values = new ContentValues();
                values.put(NotesDatabaseHelper.COL_TITLE, encryptField(title, dek));
                values.put(NotesDatabaseHelper.COL_CONTENT, encryptField(content, dek));
                db.update(NotesDatabaseHelper.TABLE_NOTES, values,
                        NotesDatabaseHelper.COL_ID + "=?",
                        new String[]{String.valueOf(id)});
            }
            cursor.close();
        }
    }
}
