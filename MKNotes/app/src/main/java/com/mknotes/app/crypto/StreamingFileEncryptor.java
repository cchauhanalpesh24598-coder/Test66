package com.mknotes.app.crypto;

import android.util.Base64;
import android.util.Log;

import com.goterl.lazysodium.SodiumAndroid;
import com.goterl.lazysodium.interfaces.SecretStream;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

/**
 * Streaming file encryption using XChaCha20-Poly1305 via lazysodium.
 *
 * Uses crypto_secretstream_xchacha20poly1305 for large file streaming:
 * - 64KB chunk size
 * - Header (24 bytes) stored separately in metadata
 * - Each chunk is authenticated
 * - Final chunk tagged with TAG_FINAL
 *
 * For small files (< 1MB), uses in-memory XChaCha20-Poly1305 AEAD.
 *
 * File format:
 * - Encrypted file: [header(24 bytes)][chunk1][chunk2]...[chunkN(TAG_FINAL)]
 * - Metadata JSON: {"header":"base64","originalName":"...","size":N}
 */
public final class StreamingFileEncryptor {

    private static final String TAG = "StreamingFileEncryptor";

    /** Chunk size for streaming encryption: 64KB */
    private static final int CHUNK_SIZE = 64 * 1024;

    /** secretstream header length: 24 bytes */
    private static final int HEADER_LENGTH = 24;

    /** secretstream ABYTES (auth tag per chunk): 17 bytes */
    private static final int ABYTES = 17;

    private static final SecureRandom sRandom = new SecureRandom();

    private StreamingFileEncryptor() {
        // Static utility class
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

        SodiumAndroid sodium = CryptoManager.getSodium();
        FileInputStream fis = null;
        FileOutputStream fos = null;

        try {
            // Initialize secretstream - using proper State object
            byte[] header = new byte[HEADER_LENGTH];
            SecretStream.State state = new SecretStream.State();

            int initResult = sodium.crypto_secretstream_xchacha20poly1305_init_push(
                    state, header, key);
            if (initResult != 0) {
                Log.e(TAG, "encryptFile: init_push failed");
                return null;
            }

            fis = new FileInputStream(inputFile);
            fos = new FileOutputStream(outputPath);

            // Write header to output file
            fos.write(header);

            byte[] buffer = new byte[CHUNK_SIZE];
            byte[] cipherBuffer = new byte[CHUNK_SIZE + ABYTES];
            int[] cipherLen = new int[1];
            int bytesRead;
            long totalRead = 0;
            long fileSize = inputFile.length();

            while ((bytesRead = fis.read(buffer)) > 0) {
                totalRead += bytesRead;
                boolean isLast = (totalRead >= fileSize);

                byte msgTag = isLast
                        ? (byte) 3 // crypto_secretstream_xchacha20poly1305_TAG_FINAL
                        : (byte) 0; // crypto_secretstream_xchacha20poly1305_TAG_MESSAGE

                int pushResult = sodium.crypto_secretstream_xchacha20poly1305_push(
                        state,
                        cipherBuffer, cipherLen,
                        buffer, bytesRead,
                        null, 0,
                        msgTag
                );

                if (pushResult != 0) {
                    Log.e(TAG, "encryptFile: push failed at offset=" + (totalRead - bytesRead));
                    return null;
                }

                fos.write(cipherBuffer, 0, cipherLen[0]);
            }

            fos.flush();
            return Base64.encodeToString(header, Base64.NO_WRAP);

        } catch (Exception e) {
            Log.e(TAG, "encryptFile exception: " + e.getMessage());
            // Clean up partial output
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

        SodiumAndroid sodium = CryptoManager.getSodium();
        FileInputStream fis = null;
        FileOutputStream fos = null;

        try {
            fis = new FileInputStream(inputFile);

            // Read header from file
            byte[] header = new byte[HEADER_LENGTH];
            int headerRead = fis.read(header);
            if (headerRead != HEADER_LENGTH) {
                Log.e(TAG, "decryptFile: incomplete header");
                return false;
            }

            // Initialize secretstream for decryption - using proper State object
            SecretStream.State state = new SecretStream.State();
            int initResult = sodium.crypto_secretstream_xchacha20poly1305_init_pull(
                    state, header, key);
            if (initResult != 0) {
                Log.e(TAG, "decryptFile: init_pull failed (wrong key?)");
                return false;
            }

            fos = new FileOutputStream(outputPath);

            int chunkReadSize = CHUNK_SIZE + ABYTES;
            byte[] cipherBuffer = new byte[chunkReadSize];
            byte[] plainBuffer = new byte[CHUNK_SIZE];
            int[] plainLen = new int[1];
            byte[] tagOut = new byte[1];
            int bytesRead;

            while ((bytesRead = fis.read(cipherBuffer)) > 0) {
                int pullResult = sodium.crypto_secretstream_xchacha20poly1305_pull(
                        state,
                        plainBuffer, plainLen,
                        tagOut,
                        cipherBuffer, bytesRead,
                        null, 0
                );

                if (pullResult != 0) {
                    Log.e(TAG, "decryptFile: pull failed (corrupted data or wrong key)");
                    // Clean up partial output
                    closeQuietly(fos);
                    new File(outputPath).delete();
                    return false;
                }

                fos.write(plainBuffer, 0, plainLen[0]);

                // Check for FINAL tag
                if (tagOut[0] == 3) {
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
     *
     * @param data plaintext bytes
     * @param key  byte[32] encryption key
     * @return CryptoManager.EncryptedBlob, or null on failure
     */
    public static CryptoManager.EncryptedBlob encryptBytes(byte[] data, byte[] key) {
        return CryptoManager.encryptBytes(data, key);
    }

    /**
     * Decrypt small data in-memory using XChaCha20-Poly1305 AEAD.
     *
     * @param ciphertext encrypted bytes
     * @param nonce      24-byte nonce
     * @param key        byte[32] encryption key
     * @return plaintext bytes, or null on failure
     */
    public static byte[] decryptBytes(byte[] ciphertext, byte[] nonce, byte[] key) {
        return CryptoManager.decryptBytes(ciphertext, nonce, key);
    }

    /**
     * Generate metadata JSON for an encrypted file.
     *
     * @param headerB64    Base64-encoded secretstream header
     * @param originalName original filename
     * @param originalSize original file size in bytes
     * @return metadata JSON string
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
