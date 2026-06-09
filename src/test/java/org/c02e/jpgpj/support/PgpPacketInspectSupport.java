package org.c02e.jpgpj.support;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Iterator;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.S2K;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.c02e.jpgpj.AeadAlgorithm;
import org.c02e.jpgpj.Encryptor;

public final class PgpPacketInspectSupport {

    private PgpPacketInspectSupport() {
    }

    public static void assertSessionPacketUsesMdc(byte[] ciphertext, TestDecryptor decryptor)
            throws Exception {
        PGPEncryptedData encryptedData = inspectedEncryptedData(ciphertext, decryptor);
        Object encData = encryptedData.getEncData();
        assertInstanceOf(SymmetricEncIntegrityPacket.class, encData);
        assertTrue(encryptedData.isIntegrityProtected());
        assertTrue(!encryptedData.isAEAD());
    }

    public static void assertSessionPacketUsesAeadV6(
            byte[] ciphertext,
            TestDecryptor decryptor,
            AeadAlgorithm expectedAlgorithm) throws Exception {
        PGPEncryptedData encryptedData = inspectedEncryptedData(ciphertext, decryptor);
        Object encData = encryptedData.getEncData();
        assertInstanceOf(SymmetricEncIntegrityPacket.class, encData);
        assertTrue(encryptedData.isAEAD());
        SymmetricEncIntegrityPacket packet = (SymmetricEncIntegrityPacket) encData;
        assertNotNull(AeadAlgorithm.fromOpenPgpTag(packet.getAeadAlgorithm()));
        assertTrue(expectedAlgorithm == AeadAlgorithm.fromOpenPgpTag(packet.getAeadAlgorithm()));
        assertTrue(encryptedData.getVersion() >= 6);
    }

    public static void assertSessionPacketUsesAeadV5(
            byte[] ciphertext,
            TestDecryptor decryptor,
            AeadAlgorithm expectedAlgorithm) throws Exception {
        PGPEncryptedData encryptedData = inspectedEncryptedData(ciphertext, decryptor);
        Object encData = encryptedData.getEncData();
        assertInstanceOf(AEADEncDataPacket.class, encData);
        AEADEncDataPacket packet = (AEADEncDataPacket) encData;
        assertTrue(expectedAlgorithm == AeadAlgorithm.fromOpenPgpTag(packet.getAEADAlgorithm()));
    }

    public static void assertSymmetricS2kIsArgon2(byte[] ciphertext) throws Exception {
        S2K s2k = symmetricSessionS2k(ciphertext);
        assertTrue(s2k.getType() == S2K.ARGON_2, "expected Argon2 S2K");
    }

    public static void assertSymmetricS2kIsIteratedSalted(byte[] ciphertext) throws Exception {
        S2K s2k = symmetricSessionS2k(ciphertext);
        assertTrue(s2k.getType() == S2K.SALTED_AND_ITERATED,
                "expected salted-and-iterated S2K");
    }

    private static S2K symmetricSessionS2k(byte[] ciphertext) throws Exception {
        PGPEncryptedDataList list = firstEncryptedDataList(ciphertext);
        Iterator<?> objects = list.getEncryptedDataObjects();
        while (objects.hasNext()) {
            Object encryptedData = objects.next();
            if (encryptedData instanceof PGPPBEEncryptedData pbe) {
                SymmetricKeyEncSessionPacket sessionPacket = pbeKeyData(pbe);
                assertNotNull(sessionPacket);
                S2K s2k = sessionPacket.getS2K();
                assertNotNull(s2k);
                return s2k;
            }
        }
        fail("no passphrase-encrypted session key packet found");
        return null;
    }

    public static byte[] encryptToBytes(Encryptor encryptor, byte[] plaintext) throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        encryptor.encrypt(new ByteArrayInputStream(plaintext), cipherOut);
        return cipherOut.toByteArray();
    }

    public static void decryptForInspection(TestDecryptor decryptor, byte[] ciphertext)
            throws Exception {
        decryptor.decryptWithFullDetails(new ByteArrayInputStream(ciphertext), new ByteArrayOutputStream());
        assertNotNull(decryptor.getLastDecryptedEncryptedData());
    }

    private static PGPEncryptedData inspectedEncryptedData(byte[] ciphertext, TestDecryptor decryptor)
            throws Exception {
        decryptForInspection(decryptor, ciphertext);
        return decryptor.getLastDecryptedEncryptedData();
    }

    public static PGPEncryptedDataList firstEncryptedDataList(byte[] ciphertext) throws PGPException {
        Iterator<?> packets = parsePackets(new ByteArrayInputStream(ciphertext));
        while (packets.hasNext()) {
            Object packet = packets.next();
            if (packet instanceof PGPEncryptedDataList list) {
                return list;
            }
            if (packet instanceof PGPCompressedData compressed) {
                packets = parsePackets(compressed.getDataStream());
            }
        }
        fail("no PGPEncryptedDataList in message");
        return null;
    }

    private static Iterator<?> parsePackets(InputStream stream) throws PGPException {
        return new PGPObjectFactory(stream, new JcaKeyFingerprintCalculator()).iterator();
    }

    private static SymmetricKeyEncSessionPacket pbeKeyData(PGPPBEEncryptedData pbe) throws Exception {
        var field = PGPPBEEncryptedData.class.getDeclaredField("keyData");
        field.setAccessible(true);
        return (SymmetricKeyEncSessionPacket) field.get(pbe);
    }
}
