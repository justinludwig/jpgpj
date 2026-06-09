package org.c02e.jpgpj.util;

import java.lang.reflect.Field;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;

import org.c02e.jpgpj.AeadAlgorithm;
import org.c02e.jpgpj.AeadPacketStyle;
import org.c02e.jpgpj.Argon2Parameters;
import org.c02e.jpgpj.EncryptionAlgorithm;
import org.c02e.jpgpj.EncryptionDetails;
import org.c02e.jpgpj.EncryptionProtection;
import org.c02e.jpgpj.OpenPgpProfile;
import org.c02e.jpgpj.PassphraseKeyDerivation;

/**
 * Extracts high-level encryption metadata from decrypted OpenPGP structures.
 */
public final class OpenPgpMetadataExtractor {
    private static final Field PBE_KEY_DATA_FIELD = resolvePbeKeyDataField();

    private OpenPgpMetadataExtractor() {
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

        details.setDetectedProfile(inferProfile(details));
        return details;
    }

    public static void applyPassphraseDerivation(
            EncryptionDetails details,
            PGPEncryptedDataList encryptedDataList) {
        if (details == null || encryptedDataList == null) {
            return;
        }
        for (PGPEncryptedData encryptedData : encryptedDataList) {
            if (encryptedData instanceof PGPPBEEncryptedData pbe) {
                applyS2k(details, getSymmetricKeyEncSessionPacket(pbe));
                return;
            }
        }
    }

    private static void applyS2k(EncryptionDetails details, SymmetricKeyEncSessionPacket sessionPacket) {
        if (details == null || sessionPacket == null) {
            return;
        }
        S2K s2k = sessionPacket.getS2K();
        if (s2k == null) {
            return;
        }
        if (s2k.getType() == S2K.ARGON_2) {
            details.setPassphraseKeyDerivation(PassphraseKeyDerivation.Argon2);
            details.setArgon2Parameters(new Argon2Parameters(
                    s2k.getPasses(),
                    s2k.getParallelism(),
                    s2k.getMemorySizeExponent()));
            details.setDetectedProfile(OpenPgpProfile.Modern);
        } else if (s2k.getType() == S2K.SALTED_AND_ITERATED) {
            details.setPassphraseKeyDerivation(PassphraseKeyDerivation.IteratedSalted);
        }
    }

    private static SymmetricKeyEncSessionPacket getSymmetricKeyEncSessionPacket(PGPPBEEncryptedData pbe) {
        if (PBE_KEY_DATA_FIELD == null) {
            return null;
        }
        try {
            return (SymmetricKeyEncSessionPacket) PBE_KEY_DATA_FIELD.get(pbe);
        } catch (IllegalAccessException e) {
            return null;
        }
    }

    private static Field resolvePbeKeyDataField() {
        try {
            Field field = PGPPBEEncryptedData.class.getDeclaredField("keyData");
            field.setAccessible(true);
            return field;
        } catch (NoSuchFieldException e) {
            return null;
        }
    }

    static OpenPgpProfile inferProfile(EncryptionDetails details) {
        if (details.getProtection() == EncryptionProtection.Aead
                && details.getAeadPacketStyle() == AeadPacketStyle.V6) {
            return OpenPgpProfile.Modern;
        }
        if (details.getPassphraseKeyDerivation() == PassphraseKeyDerivation.Argon2) {
            return OpenPgpProfile.Modern;
        }
        return OpenPgpProfile.Classic;
    }
}
