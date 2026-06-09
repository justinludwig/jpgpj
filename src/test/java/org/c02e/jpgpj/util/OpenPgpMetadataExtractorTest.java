package org.c02e.jpgpj.util;

import static org.c02e.jpgpj.support.PgpPacketInspectSupport.decryptForInspection;
import static org.c02e.jpgpj.support.PgpPacketInspectSupport.encryptToBytes;
import static org.c02e.jpgpj.support.PgpPacketInspectSupport.firstEncryptedDataList;
import static org.c02e.jpgpj.support.PgpTestSupport.PASSPHRASE;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResource;
import static org.c02e.jpgpj.support.PgpTestSupport.plainText;
import static org.c02e.jpgpj.support.PgpTestSupport.plainText;
import static org.c02e.jpgpj.support.PgpTestSupport.unlockKey;
import static org.c02e.jpgpj.support.PgpTestSupport.unlockKeys;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.c02e.jpgpj.AeadAlgorithm;
import org.c02e.jpgpj.AeadPacketStyle;
import org.c02e.jpgpj.Argon2Parameters;
import org.c02e.jpgpj.Decryptor;
import org.c02e.jpgpj.DecryptionResult;
import org.c02e.jpgpj.EncryptionAlgorithm;
import org.c02e.jpgpj.Ring;
import org.c02e.jpgpj.EncryptionDetails;
import org.c02e.jpgpj.EncryptionProtection;
import org.c02e.jpgpj.Encryptor;
import org.c02e.jpgpj.HashingAlgorithm;
import org.c02e.jpgpj.Key;
import org.c02e.jpgpj.OpenPgpProfile;
import org.c02e.jpgpj.PassphraseKeyDerivation;
import org.c02e.jpgpj.support.TestDecryptor;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class OpenPgpMetadataExtractorTest {

    private static Key encryptionKey() throws Exception {
        return new Key(loadResource("test-key-2-pub.asc"));
    }

    private static Key decryptionKey() throws Exception {
        Key key = new Key(loadResource("test-key-2.asc"));
        unlockKey(key);
        return key;
    }

    private static byte[] plaintextBytes() {
        return plainText().getBytes(StandardCharsets.UTF_8);
    }

    private static int chunkSizeFromEncData(PGPEncryptedData data) {
        Object encData = data.getEncData();
        if (encData instanceof SymmetricEncIntegrityPacket packet) {
            return packet.getChunkSize();
        }
        if (encData instanceof AEADEncDataPacket packet) {
            return packet.getChunkSize();
        }
        return 0;
    }

    private static EncryptionDetails extractAfterDecrypt(Encryptor encryptor, TestDecryptor decryptor)
            throws Exception {
        byte[] ciphertext = encryptToBytes(encryptor, plaintextBytes());
        decryptForInspection(decryptor, ciphertext);
        return OpenPgpMetadataExtractor.fromEncryptedData(
                decryptor.getLastDecryptedEncryptedData(),
                decryptor.getLastSessionCipherTag());
    }

    @Nested
    class FromEncryptedDataTest {

        @Test
        void nullDataReturnsEmptyDetails() throws Exception {
            EncryptionDetails details = OpenPgpMetadataExtractor.fromEncryptedData(null);
            assertNotNull(details);
            assertNull(details.getProtection());
            assertNull(details.getSessionCipher());
        }

        @Test
        void classicMdcPublicKeyEncryption() throws Exception {
            Encryptor encryptor = new Encryptor(encryptionKey())
                    .withOpenPgpProfile(OpenPgpProfile.Classic)
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned);
            TestDecryptor decryptor = new TestDecryptor(decryptionKey())
                    .withVerificationRequired(false);

            EncryptionDetails details = extractAfterDecrypt(encryptor, decryptor);

            assertEquals(EncryptionProtection.Mdc, details.getProtection());
            assertEquals(EncryptionAlgorithm.AES128, details.getSessionCipher());
            assertEquals(OpenPgpProfile.Classic, details.getDetectedProfile());
            assertNull(details.getAeadAlgorithm());
            assertNull(details.getAeadPacketStyle());
        }

        @Test
        void aeadOcbV6IncludesChunkSizeAndStyle() throws Exception {
            Encryptor encryptor = new Encryptor(encryptionKey())
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                    .withEncryptionAlgorithm(EncryptionAlgorithm.AES256)
                    .withEncryptionProtection(EncryptionProtection.Aead)
                    .withAeadAlgorithm(AeadAlgorithm.Ocb)
                    .withAeadPacketStyle(AeadPacketStyle.V6)
                    .withAeadChunkSize(6);
            TestDecryptor decryptor = new TestDecryptor(decryptionKey())
                    .withVerificationRequired(false);

            byte[] ciphertext = encryptToBytes(encryptor, plaintextBytes());
            decryptForInspection(decryptor, ciphertext);
            PGPEncryptedData encryptedData = decryptor.getLastDecryptedEncryptedData();
            EncryptionDetails details = OpenPgpMetadataExtractor.fromEncryptedData(
                    encryptedData,
                    decryptor.getLastSessionCipherTag());

            assertEquals(EncryptionProtection.Aead, details.getProtection());
            assertEquals(AeadAlgorithm.Ocb, details.getAeadAlgorithm());
            assertEquals(AeadPacketStyle.V6, details.getAeadPacketStyle());
            assertEquals(EncryptionAlgorithm.AES256, details.getSessionCipher());
            assertEquals(chunkSizeFromEncData(encryptedData), details.getAeadChunkSize());
            assertEquals(OpenPgpProfile.Modern, details.getDetectedProfile());
        }

        @Test
        void aeadEaxV5SetsV5PacketStyle() throws Exception {
            Encryptor encryptor = new Encryptor(encryptionKey())
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                    .withEncryptionProtection(EncryptionProtection.Aead)
                    .withAeadAlgorithm(AeadAlgorithm.Eax)
                    .withAeadPacketStyle(AeadPacketStyle.V5);
            TestDecryptor decryptor = new TestDecryptor(decryptionKey())
                    .withVerificationRequired(false);

            EncryptionDetails details = extractAfterDecrypt(encryptor, decryptor);

            assertEquals(EncryptionProtection.Aead, details.getProtection());
            assertEquals(AeadAlgorithm.Eax, details.getAeadAlgorithm());
            assertEquals(AeadPacketStyle.V5, details.getAeadPacketStyle());
            assertEquals(
                    chunkSizeFromEncData(decryptor.getLastDecryptedEncryptedData()),
                    details.getAeadChunkSize());
        }

        @Test
        void sessionCipherTagOverridesPacketDefault() throws Exception {
            Encryptor encryptor = new Encryptor(encryptionKey())
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                    .withEncryptionAlgorithm(EncryptionAlgorithm.AES256)
                    .withEncryptionProtection(EncryptionProtection.Mdc);
            TestDecryptor decryptor = new TestDecryptor(decryptionKey())
                    .withVerificationRequired(false);

            byte[] ciphertext = encryptToBytes(encryptor, plaintextBytes());
            decryptForInspection(decryptor, ciphertext);

            EncryptionDetails details = OpenPgpMetadataExtractor.fromEncryptedData(
                    decryptor.getLastDecryptedEncryptedData(),
                    SymmetricKeyAlgorithmTags.AES_256);

            assertEquals(EncryptionAlgorithm.AES256, details.getSessionCipher());
            assertEquals(EncryptionProtection.Mdc, details.getProtection());
        }
    }

    @Nested
    class NullGuardTest {

        @Test
        void fromEncryptedDataNullListGuards() throws Exception {
            assertNotNull(OpenPgpMetadataExtractor.fromEncryptedData(null));
        }

        @Test
        void applyPassphraseDerivationIgnoresNullArguments() throws Exception {
            EncryptionDetails details = new EncryptionDetails();
            OpenPgpMetadataExtractor.applyPassphraseDerivation(null, null);
            OpenPgpMetadataExtractor.applyPassphraseDerivation(details, null);
            OpenPgpMetadataExtractor.applyPassphraseDerivation(null,
                    firstEncryptedDataList(encryptToBytes(
                            new Encryptor().withSigningAlgorithm(HashingAlgorithm.Unsigned)
                                    .withSymmetricPassphrase(PASSPHRASE),
                            plaintextBytes())));
            assertNull(details.getPassphraseKeyDerivation());
        }
    }

    @Nested
    class LegacyPacketTest {

        @Test
        void pgp2CompatibilityMessageDecryptsWithMetadata() throws Exception {
            Ring ring = new Ring(loadResource("test-ring.asc"));
            unlockKeys(ring);
            Decryptor decryptor = new Decryptor(ring);
            ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
            DecryptionResult result = decryptor.decryptWithFullDetails(
                    loadResource("test-encrypted-for-key-1-signed-by-key-2-with-pgp2-compatibility.txt.asc"),
                    plainOut);

            assertNotNull(result.getFileMetadata().getEncryptionDetails());
            assertEquals(plainText(), plainOut.toString(StandardCharsets.UTF_8));
        }
    }

    @Nested
    class ApplyPassphraseDerivationTest {

        @Test
        void argon2SymmetricEncryption() throws Exception {
            Encryptor encryptor = new Encryptor()
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                    .withEncryptionAlgorithm(EncryptionAlgorithm.AES256)
                    .withEncryptionProtection(EncryptionProtection.Aead)
                    .withAeadAlgorithm(AeadAlgorithm.Ocb)
                    .withAeadPacketStyle(AeadPacketStyle.V6)
                    .withPassphraseKeyDerivation(PassphraseKeyDerivation.Argon2)
                    .withArgon2Parameters(Argon2Parameters.MEMORY_CONSTRAINED)
                    .withSymmetricPassphrase(PASSPHRASE);
            Decryptor decryptor = new Decryptor()
                    .withVerificationRequired(false)
                    .withSymmetricPassphrase(PASSPHRASE);

            byte[] ciphertext = encryptToBytes(encryptor, plaintextBytes());
            decryptor.decryptWithFullDetails(
                    new java.io.ByteArrayInputStream(ciphertext),
                    new java.io.ByteArrayOutputStream());

            EncryptionDetails details = new EncryptionDetails();
            OpenPgpMetadataExtractor.applyPassphraseDerivation(
                    details,
                    firstEncryptedDataList(ciphertext));

            assertEquals(PassphraseKeyDerivation.Argon2, details.getPassphraseKeyDerivation());
            assertNotNull(details.getArgon2Parameters());
            assertEquals(Argon2Parameters.MEMORY_CONSTRAINED.getPasses(),
                    details.getArgon2Parameters().getPasses());
            assertEquals(OpenPgpProfile.Modern, details.getDetectedProfile());
        }

        @Test
        void iteratedSaltedSymmetricEncryption() throws Exception {
            Encryptor encryptor = new Encryptor()
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                    .withPassphraseKeyDerivation(PassphraseKeyDerivation.IteratedSalted)
                    .withDeriviationAlgorithm(HashingAlgorithm.SHA512)
                    .withKeyDeriviationWorkFactor(10)
                    .withSymmetricPassphrase(PASSPHRASE);

            byte[] ciphertext = encryptToBytes(encryptor, plaintextBytes());

            EncryptionDetails details = new EncryptionDetails();
            OpenPgpMetadataExtractor.applyPassphraseDerivation(
                    details,
                    firstEncryptedDataList(ciphertext));

            assertEquals(PassphraseKeyDerivation.IteratedSalted, details.getPassphraseKeyDerivation());
            assertNull(details.getArgon2Parameters());
        }
    }

    @Nested
    class InferProfileTest {

        @Test
        void aeadV6IsModern() {
            EncryptionDetails details = new EncryptionDetails();
            details.setProtection(EncryptionProtection.Aead);
            details.setAeadPacketStyle(AeadPacketStyle.V6);
            assertEquals(OpenPgpProfile.Modern, OpenPgpMetadataExtractor.inferProfile(details));
        }

        @Test
        void argon2DerivationIsModern() {
            EncryptionDetails details = new EncryptionDetails();
            details.setPassphraseKeyDerivation(PassphraseKeyDerivation.Argon2);
            assertEquals(OpenPgpProfile.Modern, OpenPgpMetadataExtractor.inferProfile(details));
        }

        @Test
        void classicMdcIsClassic() {
            EncryptionDetails details = new EncryptionDetails();
            details.setProtection(EncryptionProtection.Mdc);
            assertEquals(OpenPgpProfile.Classic, OpenPgpMetadataExtractor.inferProfile(details));
        }
    }
}
