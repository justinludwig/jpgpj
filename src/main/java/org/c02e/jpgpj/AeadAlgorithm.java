package org.c02e.jpgpj;

import org.bouncycastle.bcpg.AEADAlgorithmTags;

/**
 * AEAD mode for OpenPGP symmetric encryption (RFC 9580 / LibrePGP).
 */
public enum AeadAlgorithm {
    Eax(AEADAlgorithmTags.EAX),
    Ocb(AEADAlgorithmTags.OCB),
    Gcm(AEADAlgorithmTags.GCM);

    private final int openPgpTag;

    AeadAlgorithm(int openPgpTag) {
        this.openPgpTag = openPgpTag;
    }

    public int getOpenPgpTag() {
        return openPgpTag;
    }

    public static AeadAlgorithm fromOpenPgpTag(int tag) {
        for (AeadAlgorithm algorithm : values()) {
            if (algorithm.openPgpTag == tag) {
                return algorithm;
            }
        }
        return null;
    }
}
