package org.c02e.jpgpj;

import org.bouncycastle.bcpg.HashAlgorithmTags;

/**
 * Available hash algorithms for signing message content,
 * and for deriving a symmetric key from a passphrase.
 */
public enum HashingAlgorithm {
    /** JPGPJ sentinel for unsigned content; not passed to Bouncy Castle. */
    Unsigned(0),
    MD5(HashAlgorithmTags.MD5),
    SHA1(HashAlgorithmTags.SHA1),
    RIPEMD160(HashAlgorithmTags.RIPEMD160),
    Reserved4(HashAlgorithmTags.DOUBLE_SHA),
    Reserved5(HashAlgorithmTags.MD2),
    Reserved6(HashAlgorithmTags.TIGER_192),
    Reserved7(HashAlgorithmTags.HAVAL_5_160),
    SHA256(HashAlgorithmTags.SHA256),
    SHA384(HashAlgorithmTags.SHA384),
    SHA512(HashAlgorithmTags.SHA512),
    SHA224(HashAlgorithmTags.SHA224),
    SHA3_256(HashAlgorithmTags.SHA3_256),
    SHA3_512(HashAlgorithmTags.SHA3_512);

    private final int openPgpTag;

    HashingAlgorithm(int openPgpTag) {
        this.openPgpTag = openPgpTag;
    }

    /** OpenPGP hash algorithm tag (RFC 4880 / RFC 9580). */
    public int getOpenPgpTag() {
        return openPgpTag;
    }

    /**
     * Resolves a Bouncy Castle / OpenPGP hash tag to the matching enum value,
     * or {@code null} if unknown.
     */
    public static HashingAlgorithm fromOpenPgpTag(int tag) {
        for (HashingAlgorithm algorithm : values()) {
            if (algorithm.openPgpTag == tag) {
                return algorithm;
            }
        }
        return null;
    }
}
