package org.c02e.jpgpj;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;

/**
 * Available compression algorithms for compressing message content.
 */
public enum CompressionAlgorithm {
    Uncompressed(CompressionAlgorithmTags.UNCOMPRESSED),
    ZIP(CompressionAlgorithmTags.ZIP),
    ZLIB(CompressionAlgorithmTags.ZLIB),
    BZip2(CompressionAlgorithmTags.BZIP2);

    private final int openPgpTag;

    CompressionAlgorithm(int openPgpTag) {
        this.openPgpTag = openPgpTag;
    }

    /** OpenPGP compression algorithm tag. */
    public int getOpenPgpTag() {
        return openPgpTag;
    }
}
