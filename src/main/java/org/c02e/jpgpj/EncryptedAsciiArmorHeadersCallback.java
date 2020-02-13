package org.c02e.jpgpj;

/**
 * Used by the encryptor to allow users to configure per-file
 * armored headers instead/in addition to the global ones that
 * are set by the encryptor
 */
@FunctionalInterface
public interface EncryptedAsciiArmorHeadersCallback {
    /**
     * Invoked by the encryptor <U>after</U> updating the
     * settings with the configured global headers.
     *
     * @param encryptor The {@link Encryptor} that is handling the encryption request
     * @param meta The input plaintext {@link FileMetadata} - might be empty
     * (but not {@code null}).
     * @param manipulator The manipulator that can be used to update the headers
     */
    void prepareAsciiArmoredHeaders(
        Encryptor encryptor, FileMetadata meta, EncryptedAsciiArmorHeadersManipulator manipulator);
}
