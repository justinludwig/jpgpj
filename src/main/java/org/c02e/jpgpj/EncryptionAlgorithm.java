package org.c02e.jpgpj;

import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;

/**
 * Available symmetric-key encryption algorithms for encrypting message content.
 */
public enum EncryptionAlgorithm {
    Unencrypted(SymmetricKeyAlgorithmTags.NULL),
    IDEA(SymmetricKeyAlgorithmTags.IDEA),
    TripleDES(SymmetricKeyAlgorithmTags.TRIPLE_DES),
    CAST5(SymmetricKeyAlgorithmTags.CAST5),
    Blowfish(SymmetricKeyAlgorithmTags.BLOWFISH),
    Reserved5(SymmetricKeyAlgorithmTags.SAFER),
    Reserved6(SymmetricKeyAlgorithmTags.DES),
    AES128(SymmetricKeyAlgorithmTags.AES_128),
    AES192(SymmetricKeyAlgorithmTags.AES_192),
    AES256(SymmetricKeyAlgorithmTags.AES_256),
    Twofish(SymmetricKeyAlgorithmTags.TWOFISH),
    Camellia128(SymmetricKeyAlgorithmTags.CAMELLIA_128),
    Camellia192(SymmetricKeyAlgorithmTags.CAMELLIA_192),
    Camellia256(SymmetricKeyAlgorithmTags.CAMELLIA_256);

    private final int openPgpTag;

    EncryptionAlgorithm(int openPgpTag) {
        this.openPgpTag = openPgpTag;
    }

    /** OpenPGP symmetric cipher tag (RFC 4880 / RFC 9580). */
    public int getOpenPgpTag() {
        return openPgpTag;
    }

    /**
     * Resolves a Bouncy Castle / OpenPGP cipher tag to the matching enum value,
     * or {@code null} if unknown.
     */
    public static EncryptionAlgorithm fromOpenPgpTag(int tag) {
        for (EncryptionAlgorithm algorithm : values()) {
            if (algorithm.openPgpTag == tag) {
                return algorithm;
            }
        }
        return null;
    }
}
