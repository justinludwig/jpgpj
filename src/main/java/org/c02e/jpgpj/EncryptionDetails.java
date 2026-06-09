package org.c02e.jpgpj;

import java.util.Objects;

/**
 * Encryption parameters detected or applied to a message.
 */
public class EncryptionDetails {
    private EncryptionProtection protection;
    private EncryptionAlgorithm sessionCipher;
    private AeadAlgorithm aeadAlgorithm;
    private AeadPacketStyle aeadPacketStyle;
    private int aeadChunkSize;
    private PassphraseKeyDerivation passphraseKeyDerivation;
    private Argon2Parameters argon2Parameters;
    private OpenPgpProfile detectedProfile;

    public EncryptionProtection getProtection() {
        return protection;
    }

    public void setProtection(EncryptionProtection protection) {
        this.protection = protection;
    }

    public EncryptionAlgorithm getSessionCipher() {
        return sessionCipher;
    }

    public void setSessionCipher(EncryptionAlgorithm sessionCipher) {
        this.sessionCipher = sessionCipher;
    }

    public AeadAlgorithm getAeadAlgorithm() {
        return aeadAlgorithm;
    }

    public void setAeadAlgorithm(AeadAlgorithm aeadAlgorithm) {
        this.aeadAlgorithm = aeadAlgorithm;
    }

    public AeadPacketStyle getAeadPacketStyle() {
        return aeadPacketStyle;
    }

    public void setAeadPacketStyle(AeadPacketStyle aeadPacketStyle) {
        this.aeadPacketStyle = aeadPacketStyle;
    }

    public int getAeadChunkSize() {
        return aeadChunkSize;
    }

    public void setAeadChunkSize(int aeadChunkSize) {
        this.aeadChunkSize = aeadChunkSize;
    }

    public PassphraseKeyDerivation getPassphraseKeyDerivation() {
        return passphraseKeyDerivation;
    }

    public void setPassphraseKeyDerivation(PassphraseKeyDerivation passphraseKeyDerivation) {
        this.passphraseKeyDerivation = passphraseKeyDerivation;
    }

    public Argon2Parameters getArgon2Parameters() {
        return argon2Parameters;
    }

    public void setArgon2Parameters(Argon2Parameters argon2Parameters) {
        this.argon2Parameters = argon2Parameters;
    }

    public OpenPgpProfile getDetectedProfile() {
        return detectedProfile;
    }

    public void setDetectedProfile(OpenPgpProfile detectedProfile) {
        this.detectedProfile = detectedProfile;
    }

    public EncryptionDetails copy() {
        EncryptionDetails copy = new EncryptionDetails();
        copy.protection = protection;
        copy.sessionCipher = sessionCipher;
        copy.aeadAlgorithm = aeadAlgorithm;
        copy.aeadPacketStyle = aeadPacketStyle;
        copy.aeadChunkSize = aeadChunkSize;
        copy.passphraseKeyDerivation = passphraseKeyDerivation;
        copy.argon2Parameters = argon2Parameters;
        copy.detectedProfile = detectedProfile;
        return copy;
    }

    @Override
    public String toString() {
        return "EncryptionDetails[protection=" + protection
                + ", sessionCipher=" + sessionCipher
                + ", aeadAlgorithm=" + aeadAlgorithm
                + ", aeadPacketStyle=" + aeadPacketStyle
                + ", aeadChunkSize=" + aeadChunkSize
                + ", passphraseKeyDerivation=" + passphraseKeyDerivation
                + ", argon2Parameters=" + argon2Parameters
                + ", detectedProfile=" + detectedProfile + "]";
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) {
            return true;
        }
        if (!(o instanceof EncryptionDetails)) {
            return false;
        }
        EncryptionDetails that = (EncryptionDetails) o;
        return aeadChunkSize == that.aeadChunkSize
                && protection == that.protection
                && sessionCipher == that.sessionCipher
                && aeadAlgorithm == that.aeadAlgorithm
                && aeadPacketStyle == that.aeadPacketStyle
                && passphraseKeyDerivation == that.passphraseKeyDerivation
                && Objects.equals(argon2Parameters, that.argon2Parameters)
                && detectedProfile == that.detectedProfile;
    }

    @Override
    public int hashCode() {
        return Objects.hash(
                protection, sessionCipher, aeadAlgorithm, aeadPacketStyle,
                aeadChunkSize, passphraseKeyDerivation, argon2Parameters, detectedProfile);
    }
}
