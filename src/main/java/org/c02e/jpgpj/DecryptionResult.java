package org.c02e.jpgpj;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Holds the most detailed information about a decrypted file
 */
public class DecryptionResult {
    private final FileMetadata fileMetadata;
    private final boolean armored;
    private final List<String> armorHeaders;

    public DecryptionResult(
            FileMetadata fileMetadata, boolean armored, Collection<String> armorHeaders) {
        this.fileMetadata = fileMetadata;
        this.armored = armored;
        this.armorHeaders = ((armorHeaders == null) || armorHeaders.isEmpty())
            ? Collections.emptyList()
            : Collections.unmodifiableList(new ArrayList<>(armorHeaders));
    }

    /**
     * @return The decrypted {@link FileMetadata} - may be {@code null} if none was provided
     */
    public FileMetadata getFileMetadata() {
        return fileMetadata;
    }

    /**
     * @return {@code true} if the encrypted data was armored
     */
    public boolean isAsciiArmored() {
        return armored;
    }

    /**
     * @return An <U>unmodifiable</U> {@link List} of extracted armored
     * headers - is valid only if {@link #isAsciiArmored() armored}. <B>Note:</B>
     * might be empty if the encrypted data was armored but contained no headers.
     */
    public List<String> getArmorHeaders() {
        return armorHeaders;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
            + "[metadata=" + getFileMetadata()
            + ", armored=" + isAsciiArmored()
            + ", numArmorHeaders=" + getArmorHeaders().size()
            + "]";
    }
}
