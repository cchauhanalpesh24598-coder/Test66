package com.mknotes.app.util;

import android.content.ContentResolver;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.provider.OpenableColumns;
import android.util.Log;
import android.webkit.MimeTypeMap;

import com.mknotes.app.crypto.KeyManager;
import com.mknotes.app.crypto.StreamingFileEncryptor;
import com.mknotes.app.model.FileAttachment;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Manages all attachment file operations using app-internal storage.
 * Structure: files/attachments/{noteId}/images|files|audios/
 *
 * ENCRYPTION: All user-generated attachment files are encrypted on disk
 * using XChaCha20-Poly1305 streaming encryption via StreamingFileEncryptor.
 * Encrypted files have a ".enc" suffix.
 * Decryption happens transparently when files are read via getDecryptedFile().
 */
public class AttachmentManager {

    private static final String TAG = "AttachmentManager";
    private static final String ATTACHMENTS_DIR = "attachments";
    private static final String IMAGES_DIR = "images";
    private static final String FILES_DIR = "files";
    private static final String AUDIOS_DIR = "audios";
    private static final String ENC_SUFFIX = ".enc";
    private static final int BUFFER_SIZE = 4096;

    public static File getAttachmentsDir(Context context, long noteId) {
        File dir = new File(context.getFilesDir(), ATTACHMENTS_DIR + "/" + noteId);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    public static File getImagesDir(Context context, long noteId) {
        File dir = new File(getAttachmentsDir(context, noteId), IMAGES_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    public static File getFilesDir(Context context, long noteId) {
        File dir = new File(getAttachmentsDir(context, noteId), FILES_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    public static File getAudiosDir(Context context, long noteId) {
        File dir = new File(getAttachmentsDir(context, noteId), AUDIOS_DIR);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        return dir;
    }

    /**
     * Copies a file from a content URI to the note's attachments directory.
     * The file is encrypted on disk using streaming XChaCha20-Poly1305.
     * Returns a FileAttachment with localName, originalName, and mimeType.
     */
    public static FileAttachment copyFileToAttachments(Context context, Uri sourceUri,
                                                        long noteId, String subDir) {
        if (context == null || sourceUri == null) return null;

        try {
            ContentResolver resolver = context.getContentResolver();
            String originalName = getFileName(context, sourceUri);
            String mimeType = resolver.getType(sourceUri);
            if (mimeType == null) {
                mimeType = "application/octet-stream";
            }

            // Generate unique local name
            String extension = getExtensionFromMime(mimeType);
            if (extension.length() == 0) {
                extension = getExtensionFromName(originalName);
            }
            String localName = System.currentTimeMillis() + "_" +
                    ((int)(Math.random() * 99999)) +
                    (extension.length() > 0 ? "." + extension : "");

            File destDir;
            if (IMAGES_DIR.equals(subDir)) {
                destDir = getImagesDir(context, noteId);
            } else if (AUDIOS_DIR.equals(subDir)) {
                destDir = getAudiosDir(context, noteId);
            } else {
                destDir = getFilesDir(context, noteId);
            }

            // First copy to a temp plaintext file
            File tempFile = new File(destDir, localName + ".tmp");
            InputStream is = resolver.openInputStream(sourceUri);
            if (is == null) return null;

            OutputStream os = new FileOutputStream(tempFile);
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = is.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
            os.flush();
            os.close();
            is.close();

            // Encrypt the file
            File encFile = new File(destDir, localName + ENC_SUFFIX);
            byte[] key = KeyManager.getInstance(context).getDEK();
            if (key != null) {
                String header = StreamingFileEncryptor.encryptFile(
                        tempFile.getAbsolutePath(), encFile.getAbsolutePath(), key);
                com.mknotes.app.crypto.CryptoManager.zeroFill(key);

                if (header != null) {
                    // Encryption succeeded, delete temp
                    tempFile.delete();
                    // Store with .enc name
                    return new FileAttachment(localName + ENC_SUFFIX, originalName, mimeType);
                }
            }

            // Encryption failed or no key -- keep plaintext (legacy compat)
            File finalFile = new File(destDir, localName);
            tempFile.renameTo(finalFile);
            return new FileAttachment(localName, originalName, mimeType);

        } catch (Exception e) {
            Log.e(TAG, "copyFileToAttachments failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * Get the decrypted image file for display.
     * If the file is encrypted (.enc suffix), decrypts to a temp file.
     * If the file is plaintext (legacy), returns the file directly.
     *
     * @return readable file, or null if not found/decrypt failed
     */
    public static File getDecryptedFile(Context context, long noteId, String localName, String subDir) {
        File dir;
        if (IMAGES_DIR.equals(subDir)) {
            dir = getImagesDir(context, noteId);
        } else if (AUDIOS_DIR.equals(subDir)) {
            dir = getAudiosDir(context, noteId);
        } else {
            dir = getFilesDir(context, noteId);
        }

        File file = new File(dir, localName);

        // Check for encrypted version if plaintext not found
        if (!file.exists()) {
            File encFile = new File(dir, localName + ENC_SUFFIX);
            if (encFile.exists()) {
                file = encFile;
                localName = localName + ENC_SUFFIX;
            }
        }

        if (!file.exists()) return null;

        // If encrypted, decrypt to temp
        if (localName.endsWith(ENC_SUFFIX)) {
            return decryptToTemp(context, file, localName);
        }

        return file;
    }

    /**
     * Decrypt an encrypted file to a temp location for reading.
     */
    private static File decryptToTemp(Context context, File encFile, String localName) {
        try {
            byte[] key = KeyManager.getInstance(context).getDEK();
            if (key == null) {
                Log.e(TAG, "decryptToTemp: DEK not available");
                return null;
            }

            // Strip .enc suffix for temp name
            String baseName = localName;
            if (baseName.endsWith(ENC_SUFFIX)) {
                baseName = baseName.substring(0, baseName.length() - ENC_SUFFIX.length());
            }

            File tempDir = new File(context.getCacheDir(), "dec_attachments");
            if (!tempDir.exists()) tempDir.mkdirs();
            File tempFile = new File(tempDir, baseName);

            // If already decrypted and recent, reuse
            if (tempFile.exists() && tempFile.length() > 0
                    && tempFile.lastModified() >= encFile.lastModified()) {
                com.mknotes.app.crypto.CryptoManager.zeroFill(key);
                return tempFile;
            }

            boolean success = StreamingFileEncryptor.decryptFile(
                    encFile.getAbsolutePath(), tempFile.getAbsolutePath(), key);
            com.mknotes.app.crypto.CryptoManager.zeroFill(key);

            if (success) {
                return tempFile;
            } else {
                Log.e(TAG, "decryptToTemp: decryption failed for " + localName);
                return null;
            }
        } catch (Exception e) {
            Log.e(TAG, "decryptToTemp exception: " + e.getMessage());
            return null;
        }
    }

    /**
     * Get the image file for a note (raw, may be encrypted).
     * For display, prefer getDecryptedFile() instead.
     */
    public static File getImageFile(Context context, long noteId, String localName) {
        return new File(getImagesDir(context, noteId), localName);
    }

    /**
     * Get the generic file for a note (raw, may be encrypted).
     */
    public static File getFileFile(Context context, long noteId, String localName) {
        return new File(getFilesDir(context, noteId), localName);
    }

    /**
     * Get the audio file for a note (raw, may be encrypted).
     */
    public static File getAudioFile(Context context, long noteId, String localName) {
        return new File(getAudiosDir(context, noteId), localName);
    }

    /**
     * Delete a specific attachment file (both plaintext and encrypted versions).
     */
    public static boolean deleteAttachmentFile(Context context, long noteId,
                                                String localName, String subDir) {
        File dir;
        if (IMAGES_DIR.equals(subDir)) {
            dir = getImagesDir(context, noteId);
        } else if (AUDIOS_DIR.equals(subDir)) {
            dir = getAudiosDir(context, noteId);
        } else {
            dir = getFilesDir(context, noteId);
        }
        boolean deleted = false;
        File file = new File(dir, localName);
        if (file.exists()) {
            deleted = file.delete();
        }
        // Also try encrypted variant
        File encFile = new File(dir, localName + ENC_SUFFIX);
        if (encFile.exists()) {
            deleted = encFile.delete() || deleted;
        }
        // Clean up temp decrypted copy
        File tempDir = new File(context.getCacheDir(), "dec_attachments");
        String baseName = localName.endsWith(ENC_SUFFIX)
                ? localName.substring(0, localName.length() - ENC_SUFFIX.length())
                : localName;
        File tempFile = new File(tempDir, baseName);
        if (tempFile.exists()) {
            tempFile.delete();
        }
        return deleted;
    }

    /**
     * Delete all attachments for a note.
     */
    public static void deleteAllAttachments(Context context, long noteId) {
        File dir = getAttachmentsDir(context, noteId);
        if (dir.exists()) {
            deleteRecursive(dir);
        }
    }

    private static void deleteRecursive(File fileOrDir) {
        if (fileOrDir.isDirectory()) {
            File[] children = fileOrDir.listFiles();
            if (children != null) {
                for (int i = 0; i < children.length; i++) {
                    deleteRecursive(children[i]);
                }
            }
        }
        fileOrDir.delete();
    }

    /**
     * Get the display name of a file from its URI.
     */
    public static String getFileName(Context context, Uri uri) {
        String name = "unknown";
        if ("content".equals(uri.getScheme())) {
            Cursor cursor = null;
            try {
                cursor = context.getContentResolver().query(uri, null, null, null, null);
                if (cursor != null && cursor.moveToFirst()) {
                    int nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                    if (nameIndex >= 0) {
                        name = cursor.getString(nameIndex);
                    }
                }
            } catch (Exception e) {
                // Fall through to path extraction
            } finally {
                if (cursor != null) {
                    cursor.close();
                }
            }
        }
        if ("unknown".equals(name)) {
            String path = uri.getPath();
            if (path != null) {
                int lastSlash = path.lastIndexOf('/');
                if (lastSlash >= 0 && lastSlash < path.length() - 1) {
                    name = path.substring(lastSlash + 1);
                }
            }
        }
        return name;
    }

    private static String getExtensionFromMime(String mimeType) {
        if (mimeType == null) return "";
        MimeTypeMap map = MimeTypeMap.getSingleton();
        String ext = map.getExtensionFromMimeType(mimeType);
        return ext != null ? ext : "";
    }

    private static String getExtensionFromName(String name) {
        if (name == null) return "";
        int dotIndex = name.lastIndexOf('.');
        if (dotIndex >= 0 && dotIndex < name.length() - 1) {
            return name.substring(dotIndex + 1);
        }
        return "";
    }

    /**
     * Create an audio output file path for recording.
     * Note: Audio is encrypted AFTER recording finishes (see AudioRecordingService).
     */
    public static File createAudioFile(Context context, long noteId) {
        File dir = getAudiosDir(context, noteId);
        String name = "audio_" + System.currentTimeMillis() + ".m4a";
        return new File(dir, name);
    }

    /**
     * Encrypt an existing plaintext file in-place.
     * Used by AudioRecordingService after recording completes.
     *
     * @return the new encrypted filename (with .enc suffix), or original name on failure
     */
    public static String encryptExistingFile(Context context, File plaintextFile) {
        if (plaintextFile == null || !plaintextFile.exists()) return null;

        try {
            byte[] key = KeyManager.getInstance(context).getDEK();
            if (key == null) {
                Log.w(TAG, "encryptExistingFile: no DEK, keeping plaintext");
                return plaintextFile.getName();
            }

            String encPath = plaintextFile.getAbsolutePath() + ENC_SUFFIX;
            String header = StreamingFileEncryptor.encryptFile(
                    plaintextFile.getAbsolutePath(), encPath, key);
            com.mknotes.app.crypto.CryptoManager.zeroFill(key);

            if (header != null) {
                // Encryption succeeded
                plaintextFile.delete();
                return plaintextFile.getName() + ENC_SUFFIX;
            } else {
                // Encryption failed, keep plaintext
                new File(encPath).delete();
                return plaintextFile.getName();
            }
        } catch (Exception e) {
            Log.e(TAG, "encryptExistingFile failed: " + e.getMessage());
            return plaintextFile.getName();
        }
    }
}
