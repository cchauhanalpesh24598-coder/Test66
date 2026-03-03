package com.mknotes.app.crypto;

import android.util.Base64;
import android.util.Log;

import com.goterl.lazysodium.LazySodiumAndroid;
import com.goterl.lazysodium.SodiumAndroid;
import com.goterl.lazysodium.interfaces.SecretStream;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

/**
 * Streaming file encryption using XChaCha20-Poly1305 via lazysodium 5.x.
 *
 * Uses crypto_secretstream_xchacha20poly1305 for large file streaming:
 * - 64KB chunk size
 * - Header (24 bytes) stored separately in metadata
 * - Each chunk is authenticated
 * - Final chunk tagged with TAG_FINAL
 *
 * FIXED for lazysodium 5.x: State is now SecretStream.State object, not byte[]
 */
public final class StreamingFileEncryptor {

    private static final String TAG = "StreamingFileEncryptor";

    private static final int CHUNK_SIZE = 64 * 1024; // 64KB
    private static final int HEADER_LENGTH = 24;      // secretstream header
    private static final int ABYTES = 17;             // auth tag per chunk

    private static final SecureRandom sRandom = new SecureRandom();

    private StreamingFileEncryptor() {}

    /**
     * Get LazySodiumAndroid instance.
     */
    private static LazySodiumAndroid getLazySodium() {
        return new LazySodiumAndroid(new SodiumAndroid());
    }

    /**
     * Encrypt a file using streaming XChaCha20-Poly1305.
     *
     * @param inputPath  path to plaintext file
     * @param outputPath path to write encrypted file
     * @param key        byte[32] encryption key
     * @return Base64-encoded header string for metadata storage, or null on failure
     */
    public static String encryptFile(String inputPath, String outputPath, byte[] key) {
        if (inputPath == null || outputPath == null || key == null) {
            Log.e(TAG, "encryptFile: null parameters");
            return null;
        }

        File inputFile = new File(inputPath);
        if (!inputFile.exists() || !inputFile.canRead()) {
            Log.e(TAG, "encryptFile: input file not readable: " + inputPath);
            return null;
        }

        FileInputStream fis = null;
        FileOutputStream fos = null;

        try {
            LazySodiumAndroid sodium = getLazySodium();

            // Initialize secretstream — lazysodium 5.x returns State object
            byte[] header = new byte[HEADER_LENGTH];

            // ✅ FIX: State is SecretStream.State, not byte[]
            SecretStream.State state = new SecretStream.State();

            boolean initOk = sodium.cryptoSecretStreamInitPush(state, header, key);
            if (!initOk) {
                Log.e(TAG, "encryptFile: init_push failed");
                return null;
            }

            fis = new FileInputStream(inputFile);
            fos = new FileOutputStream(outputPath);

            // Write header to output file
            fos.write(header);

            byte[] buffer = new byte[CHUNK_SIZE];
            byte[] cipherBuffer = new byte[CHUNK_SIZE + ABYTES];
            long[] cipherLen = new long[1];
            int bytesRead;
            long totalRead = 0;
            long fileSize = inputFile.length();

            while ((bytesRead = fis.read(buffer)) > 0) {
                totalRead += bytesRead;
                boolean isLast = (totalRead >= fileSize);

                byte msgTag = isLast
                        ? SecretStream.TAG_FINAL  // ✅ Use lazysodium constant
                        : SecretStream.TAG_MESSAGE;

                // ✅ FIX: lazysodium 5.x push signature with State object
                boolean pushOk = sodium.cryptoSecretStreamPush(
                        state,
                        cipherBuffer, cipherLen,
                        buffer, bytesRead,
                        null, 0,
                        msgTag
                );

                if (!pushOk) {
                    Log.e(TAG, "encryptFile: push failed at offset=" + (totalRead - bytesRead));
                    return null;
                }

                fos.write(cipherBuffer, 0, (int) cipherLen[0]);
            }

            fos.flush();
            return Base64.encodeToString(header, Base64.NO_WRAP);

        } catch (Exception e) {
            Log.e(TAG, "encryptFile exception: " + e.getMessage());
            try {
                File outFile = new File(outputPath);
                if (outFile.exists()) outFile.delete();
            } catch (Exception ignored) {}
            return null;
        } finally {
            closeQuietly(fis);
            closeQuietly(fos);
        }
    }

    /**
     * Decrypt a file using streaming XChaCha20-Poly1305.
     *
     * @param inputPath  path to encrypted file (header + chunks)
     * @param outputPath path to write decrypted file
     * @param key        byte[32] encryption key
     * @return true on success, false on failure
     */
    public static boolean decryptFile(String inputPath, String outputPath, byte[] key) {
        if (inputPath == null || outputPath == null || key == null) {
            Log.e(TAG, "decryptFile: null parameters");
            return false;
        }

        File inputFile = new File(inputPath);
        if (!inputFile.exists() || !inputFile.canRead()) {
            Log.e(TAG, "decryptFile: input file not readable: " + inputPath);
            return false;
        }

        FileInputStream fis = null;
        FileOutputStream fos = null;

        try {
            LazySodiumAndroid sodium = getLazySodium();

            fis = new FileInputStream(inputFile);

            // Read header from file
            byte[] header = new byte[HEADER_LENGTH];
            int headerRead = fis.read(header);
            if (headerRead != HEADER_LENGTH) {
                Log.e(TAG, "decryptFile: incomplete header");
                return false;
            }

            // ✅ FIX: State is SecretStream.State, not byte[]
            SecretStream.State state = new SecretStream.State();

            boolean initOk = sodium.cryptoSecretStreamInitPull(state, header, key);
            if (!initOk) {
                Log.e(TAG, "decryptFile: init_pull failed (wrong key?)");
                return false;
            }

            fos = new FileOutputStream(outputPath);

            int chunkReadSize = CHUNK_SIZE + ABYTES;
            byte[] cipherBuffer = new byte[chunkReadSize];
            byte[] plainBuffer = new byte[CHUNK_SIZE];
            long[] plainLen = new long[1];
            byte[] tagOut = new byte[1];
            int bytesRead;

            while ((bytesRead = fis.read(cipherBuffer)) > 0) {
                // ✅ FIX: lazysodium 5.x pull signature with State object
                boolean pullOk = sodium.cryptoSecretStreamPull(
                        state,
                        plainBuffer, plainLen,
                        tagOut,
                        cipherBuffer, bytesRead,
                        null, 0
                );

                if (!pullOk) {
                    Log.e(TAG, "decryptFile: pull failed (corrupted data or wrong key)");
                    closeQuietly(fos);
                    new File(outputPath).delete();
                    return false;
                }

                fos.write(plainBuffer, 0, (int) plainLen[0]);

                // Check for FINAL tag
                if (tagOut[0] == SecretStream.TAG_FINAL) {
                    break;
                }
            }

            fos.flush();
            return true;

        } catch (Exception e) {
            Log.e(TAG, "decryptFile exception: " + e.getMessage());
            try {
                new File(outputPath).delete();
            } catch (Exception ignored) {}
            return false;
        } finally {
            closeQuietly(fis);
            closeQuietly(fos);
        }
    }

    /**
     * Encrypt small data in-memory using XChaCha20-Poly1305 AEAD.
     */
    public static CryptoManager.EncryptedBlob encryptBytes(byte[] data, byte[] key) {
        return CryptoManager.encryptBytes(data, key);
    }

    /**
     * Decrypt small data in-memory using XChaCha20-Poly1305 AEAD.
     */
    public static byte[] decryptBytes(byte[] ciphertext, byte[] nonce, byte[] key) {
        return CryptoManager.decryptBytes(ciphertext, nonce, key);
    }

    /**
     * Generate metadata JSON for an encrypted file.
     */
    public static String buildMetadataJson(String headerB64, String originalName, long originalSize) {
        return "{\"header\":\"" + headerB64 + "\","
                + "\"originalName\":\"" + escapeJson(originalName) + "\","
                + "\"size\":" + originalSize + "}";
    }

    /**
     * Extract header Base64 from metadata JSON.
     */
    public static String extractHeader(String metadataJson) {
        return CryptoManager.extractJsonValue(metadataJson, "header");
    }

    /**
     * Extract original filename from metadata JSON.
     */
    public static String extractOriginalName(String metadataJson) {
        return CryptoManager.extractJsonValue(metadataJson, "originalName");
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static void closeQuietly(java.io.Closeable closeable) {
        if (closeable != null) {
            try { closeable.close(); } catch (IOException ignored) {}
        }
    }
}
