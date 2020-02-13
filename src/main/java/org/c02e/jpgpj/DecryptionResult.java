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
    private final boolean armoured;
    private final List<String> armouredHeaders;

    public DecryptionResult(
            FileMetadata fileMetadata, boolean armoured, Collection<String> armouredHeaders) {
        this.fileMetadata = fileMetadata;
        this.armoured = armoured;
        this.armouredHeaders = ((armouredHeaders == null) || armouredHeaders.isEmpty())
            ? Collections.emptyList()
            : Collections.unmodifiableList(new ArrayList<>(armouredHeaders));
    }

    /**
     * @return The decrypted {@link FileMetadata} - may be {@code null} if none was provided
     */
    public FileMetadata getFileMetadata() {
        return fileMetadata;
    }

    /**
     * @return {@code true} if the encrypted data was armoured
     */
    public boolean isArmoured() {
        return armoured;
    }

    /**
     * @return An <U>unmodifiable</U> {@link List} of extracted armoured
     * headers - is valid only if {@link #isArmoured()}. <B>Note:</B> might
     * be empty if the encrypted data was armoured but contained no headers.
     */
    public List<String> getArmouredHeaders() {
        return armouredHeaders;
    }

    @Override
    public String toString() {
        return getClass().getSimpleName()
            + "[metadata=" + getFileMetadata()
            + ", armoured=" + isArmoured()
            + ", numArmouredHeaders=" + getArmouredHeaders().size()
            + "]";
    }


}
