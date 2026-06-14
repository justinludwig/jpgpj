package org.c02e.jpgpj;

import java.lang.reflect.Field;
import java.util.Objects;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encryption parameters detected or applied to a message.
 */
public class EncryptionDetails {
    /**
     * Bouncy Castle internal field name on {@link PGPPBEEncryptedData}; accessed
     * reflectively for S2K metadata. Verified by
     * {@link BouncyCastleReflectionCompatibilityTest}.
     */
    public static final String PBE_ENCRYPTED_DATA_KEY_DATA_FIELD = "keyData";

    private static final Logger log = LoggerFactory.getLogger(EncryptionDetails.class.getName());
    private static final Field PBE_KEY_DATA_FIELD = resolvePbeKeyDataField();
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

    public static EncryptionDetails fromEncryptedData(PGPEncryptedData data) throws PGPException {
        return fromEncryptedData(data, null);
    }

    public static EncryptionDetails fromEncryptedData(PGPEncryptedData data, Integer sessionCipherTag)
            throws PGPException {
        EncryptionDetails details = new EncryptionDetails();
        if (data == null) {
            return details;
        }

        if (sessionCipherTag != null) {
            details.setSessionCipher(EncryptionAlgorithm.fromOpenPgpTag(sessionCipherTag));
        }

        if (data.getEncData() instanceof SymmetricEncIntegrityPacket packet) {
            if (sessionCipherTag == null) {
                details.setSessionCipher(EncryptionAlgorithm.fromOpenPgpTag(packet.getCipherAlgorithm()));
            }
            if (data.isAEAD()) {
                details.setProtection(EncryptionProtection.Aead);
                details.setAeadAlgorithm(AeadAlgorithm.fromOpenPgpTag(packet.getAeadAlgorithm()));
                details.setAeadChunkSize(packet.getChunkSize());
            } else if (data.isIntegrityProtected()) {
                details.setProtection(EncryptionProtection.Mdc);
            } else {
                details.setProtection(EncryptionProtection.Mdc);
            }
        } else if (data.getEncData() instanceof AEADEncDataPacket packet) {
            if (sessionCipherTag == null) {
                details.setSessionCipher(EncryptionAlgorithm.fromOpenPgpTag(packet.getAlgorithm()));
            }
            details.setProtection(EncryptionProtection.Aead);
            details.setAeadAlgorithm(AeadAlgorithm.fromOpenPgpTag(packet.getAEADAlgorithm()));
            details.setAeadChunkSize(packet.getChunkSize());
            details.setAeadPacketStyle(AeadPacketStyle.V5);
        } else {
            details.setSessionCipher(EncryptionAlgorithm.fromOpenPgpTag(data.getAlgorithm()));
            if (data.isAEAD()) {
                details.setProtection(EncryptionProtection.Aead);
            } else if (data.isIntegrityProtected()) {
                details.setProtection(EncryptionProtection.Mdc);
            } else {
                details.setProtection(EncryptionProtection.Mdc);
            }
        }

        if (details.getProtection() == EncryptionProtection.Aead
                && details.getAeadPacketStyle() == null) {
            int version = data.getVersion();
            details.setAeadPacketStyle(version >= 6 ? AeadPacketStyle.V6 : AeadPacketStyle.V5);
        }

        details.inferDetectedProfile();
        return details;
    }

    public void applyPassphraseDerivation(PGPEncryptedDataList encryptedDataList) {
        if (encryptedDataList == null) {
            return;
        }
        for (PGPEncryptedData encryptedData : encryptedDataList) {
            if (encryptedData instanceof PGPPBEEncryptedData pbe) {
                applyS2kFrom(pbe);
                return;
            }
        }
    }

    public void applyS2kFrom(PGPPBEEncryptedData pbe) {
        applyS2k(getSymmetricKeyEncSessionPacket(pbe));
    }

    private void applyS2k(SymmetricKeyEncSessionPacket sessionPacket) {
        if (sessionPacket == null) {
            return;
        }
        S2K s2k = sessionPacket.getS2K();
        if (s2k == null) {
            return;
        }
        if (s2k.getType() == S2K.ARGON_2) {
            setPassphraseKeyDerivation(PassphraseKeyDerivation.Argon2);
            setArgon2Parameters(new Argon2Parameters(
                    s2k.getPasses(),
                    s2k.getParallelism(),
                    s2k.getMemorySizeExponent()));
            setDetectedProfile(OpenPgpProfile.Modern);
        } else if (s2k.getType() == S2K.SALTED_AND_ITERATED) {
            setPassphraseKeyDerivation(PassphraseKeyDerivation.IteratedSalted);
        }
    }

    private static SymmetricKeyEncSessionPacket getSymmetricKeyEncSessionPacket(PGPPBEEncryptedData pbe) {
        if (PBE_KEY_DATA_FIELD == null) {
            return null;
        }
        try {
            return (SymmetricKeyEncSessionPacket) PBE_KEY_DATA_FIELD.get(pbe);
        } catch (IllegalAccessException e) {
            log.warn("Cannot read PGPPBEEncryptedData.{}; "
                    + "passphrase key-derivation metadata will be unavailable.",
                    PBE_ENCRYPTED_DATA_KEY_DATA_FIELD, e);
            return null;
        }
    }

    private static Field resolvePbeKeyDataField() {
        try {
            Field field = PGPPBEEncryptedData.class.getDeclaredField(PBE_ENCRYPTED_DATA_KEY_DATA_FIELD);
            field.setAccessible(true);
            return field;
        } catch (NoSuchFieldException e) {
            log.warn("Cannot access PGPPBEEncryptedData.{} via reflection; "
                    + "passphrase key-derivation metadata will be unavailable. "
                    + "Update EncryptionDetails for this Bouncy Castle version.",
                    PBE_ENCRYPTED_DATA_KEY_DATA_FIELD, e);
            return null;
        }
    }

    void inferDetectedProfile() {
        if (getProtection() == EncryptionProtection.Aead
                && getAeadPacketStyle() == AeadPacketStyle.V6) {
            setDetectedProfile(OpenPgpProfile.Modern);
        } else if (getPassphraseKeyDerivation() == PassphraseKeyDerivation.Argon2) {
            setDetectedProfile(OpenPgpProfile.Modern);
        } else {
            setDetectedProfile(OpenPgpProfile.Classic);
        }
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
