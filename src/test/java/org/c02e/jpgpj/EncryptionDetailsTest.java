package org.c02e.jpgpj;

import static org.c02e.jpgpj.support.PgpPacketInspectSupport.decryptForInspection;
import static org.c02e.jpgpj.support.PgpPacketInspectSupport.encryptToBytes;
import static org.c02e.jpgpj.support.PgpPacketInspectSupport.firstEncryptedDataList;
import static org.c02e.jpgpj.support.PgpPacketInspectSupport.firstPublicKeyEncryptedData;
import static org.c02e.jpgpj.support.PgpTestSupport.PASSPHRASE;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResource;
import static org.c02e.jpgpj.support.PgpTestSupport.plainText;
import static org.c02e.jpgpj.support.PgpTestSupport.unlockKey;
import static org.c02e.jpgpj.support.PgpTestSupport.unlockKeys;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.c02e.jpgpj.support.TestDecryptor;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class EncryptionDetailsTest {

    private static EncryptionDetails sampleDetails() {
        EncryptionDetails details = new EncryptionDetails();
        details.setProtection(EncryptionProtection.Aead);
        details.setSessionCipher(EncryptionAlgorithm.AES256);
        details.setAeadAlgorithm(AeadAlgorithm.Ocb);
        details.setAeadPacketStyle(AeadPacketStyle.V6);
        details.setAeadChunkSize(6);
        details.setPassphraseKeyDerivation(PassphraseKeyDerivation.Argon2);
        details.setArgon2Parameters(Argon2Parameters.GPG_RECOMMENDED);
        details.setDetectedProfile(OpenPgpProfile.Modern);
        return details;
    }

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
        return decryptForInspection(decryptor, ciphertext).getFileMetadata().getEncryptionDetails();
    }

    @Test
    void copyPreservesAllFields() {
        EncryptionDetails original = sampleDetails();
        EncryptionDetails copy = original.copy();

        assertEquals(original, copy);
        assertNotSameFieldInstances(original, copy);
    }

    @Test
    void equalsAndHashCodeMatchForEqualInstances() {
        EncryptionDetails left = sampleDetails();
        EncryptionDetails right = sampleDetails();

        assertEquals(left, right);
        assertEquals(left.hashCode(), right.hashCode());
        assertEquals(left, left);
    }

    @Test
    void equalsDetectsFieldDifferences() {
        EncryptionDetails baseline = sampleDetails();

        EncryptionDetails differentChunk = sampleDetails();
        differentChunk.setAeadChunkSize(7);
        assertNotEquals(baseline, differentChunk);

        EncryptionDetails differentProfile = sampleDetails();
        differentProfile.setDetectedProfile(OpenPgpProfile.Classic);
        assertNotEquals(baseline, differentProfile);

        EncryptionDetails differentArgon2 = sampleDetails();
        differentArgon2.setArgon2Parameters(Argon2Parameters.MEMORY_CONSTRAINED);
        assertNotEquals(baseline, differentArgon2);
    }

    @Test
    void equalsRejectsNullAndOtherTypes() {
        EncryptionDetails details = sampleDetails();
        assertFalse(details.equals(null));
        assertFalse(details.equals("not-details"));
    }

    @Test
    void toStringIncludesKeyFields() {
        String text = sampleDetails().toString();
        assertTrue(text.contains("protection="));
        assertTrue(text.contains("sessionCipher="));
        assertTrue(text.contains("aeadAlgorithm="));
        assertTrue(text.contains("detectedProfile="));
        assertNotNull(text);
    }

    private static void assertNotSameFieldInstances(EncryptionDetails left, EncryptionDetails right) {
        assertNotNull(left.getArgon2Parameters());
        assertNotNull(right.getArgon2Parameters());
        assertEquals(left.getArgon2Parameters(), right.getArgon2Parameters());
    }

    @Nested
    class FromEncryptedDataTest {

        @Test
        void nullDataReturnsEmptyDetails() throws Exception {
            EncryptionDetails details = EncryptionDetails.fromEncryptedData(null);
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
            PGPEncryptedData encryptedData = firstPublicKeyEncryptedData(ciphertext);
            EncryptionDetails details = extractAfterDecrypt(encryptor, decryptor);

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

            byte[] ciphertext = encryptToBytes(encryptor, plaintextBytes());
            EncryptionDetails details = extractAfterDecrypt(encryptor, decryptor);

            assertEquals(EncryptionProtection.Aead, details.getProtection());
            assertEquals(AeadAlgorithm.Eax, details.getAeadAlgorithm());
            assertEquals(AeadPacketStyle.V5, details.getAeadPacketStyle());
            assertEquals(
                    chunkSizeFromEncData(firstPublicKeyEncryptedData(ciphertext)),
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

            EncryptionDetails details = EncryptionDetails.fromEncryptedData(
                    firstPublicKeyEncryptedData(ciphertext),
                    SymmetricKeyAlgorithmTags.AES_256);

            assertEquals(EncryptionAlgorithm.AES256, details.getSessionCipher());
            assertEquals(EncryptionProtection.Mdc, details.getProtection());
        }
    }

    @Nested
    class NullGuardTest {

        @Test
        void fromEncryptedDataNullListGuards() throws Exception {
            assertNotNull(EncryptionDetails.fromEncryptedData(null));
        }

        @Test
        void applyPassphraseDerivationIgnoresNullArguments() throws Exception {
            EncryptionDetails details = new EncryptionDetails();
            details.applyPassphraseDerivation(null);
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
                    new ByteArrayInputStream(ciphertext),
                    new ByteArrayOutputStream());

            EncryptionDetails details = new EncryptionDetails();
            details.applyPassphraseDerivation(firstEncryptedDataList(ciphertext));

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
            details.applyPassphraseDerivation(firstEncryptedDataList(ciphertext));

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
            details.inferDetectedProfile();
            assertEquals(OpenPgpProfile.Modern, details.getDetectedProfile());
        }

        @Test
        void argon2DerivationIsModern() {
            EncryptionDetails details = new EncryptionDetails();
            details.setPassphraseKeyDerivation(PassphraseKeyDerivation.Argon2);
            details.inferDetectedProfile();
            assertEquals(OpenPgpProfile.Modern, details.getDetectedProfile());
        }

        @Test
        void classicMdcIsClassic() {
            EncryptionDetails details = new EncryptionDetails();
            details.setProtection(EncryptionProtection.Mdc);
            details.inferDetectedProfile();
            assertEquals(OpenPgpProfile.Classic, details.getDetectedProfile());
        }
    }
}
