package org.c02e.jpgpj;

import static org.c02e.jpgpj.support.PgpTestSupport.PASSPHRASE;
import static org.c02e.jpgpj.support.PgpTestSupport.isVerified;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResource;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResourceFile;
import static org.c02e.jpgpj.support.PgpTestSupport.plainText;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.c02e.jpgpj.key.KeyForDecryption;
import org.c02e.jpgpj.key.KeyForEncryption;
import org.c02e.jpgpj.key.KeyForSigning;
import org.c02e.jpgpj.key.KeyForVerification;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Round-trip coverage for RSA, DSA, ECDSA, and Ed25519 public-key algorithms.
 */
class PublicKeyAlgorithmTest {

    private static ByteArrayInputStream plainIn() {
        return new ByteArrayInputStream(plainText().getBytes(StandardCharsets.UTF_8));
    }

    private static void assertRoundTrip(Encryptor encryptor, Decryptor decryptor) throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        encryptor.encrypt(plainIn(), cipherOut);

        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        FileMetadata meta = decryptor.decrypt(
                new ByteArrayInputStream(cipherOut.toByteArray()),
                plainOut);

        assertEquals(plainText(), plainOut.toString(StandardCharsets.UTF_8));
        assertTrue(isVerified(meta));
    }

    @Nested
    class DsaKeyTest {
        @Test
        void dsaSignAndRsaEncryptRoundTrip() throws Exception {
            Encryptor encryptor = new Encryptor(
                    new KeyForSigning(loadResourceFile("test-key-dsa.asc"), Key.NO_PASSPHRASE),
                    new KeyForEncryption(loadResourceFile("test-key-dsa.asc")))
                    .withSigningAlgorithm(HashingAlgorithm.SHA256)
                    .withEncryptionProtection(EncryptionProtection.Mdc);
            Decryptor decryptor = new Decryptor(
                    new KeyForVerification(loadResourceFile("test-key-dsa.asc")),
                    new KeyForDecryption(loadResourceFile("test-key-dsa.asc"), Key.NO_PASSPHRASE))
                    .withVerificationRequired(true);

            assertRoundTrip(encryptor, decryptor);
        }

        @Test
        void dsaSigningSubkeyUsesDsaAlgorithm() throws Exception {
            KeyForSigning key = new KeyForSigning(loadResourceFile("test-key-dsa.asc"), Key.NO_PASSPHRASE);
            Subkey signing = key.getSubkeys().stream()
                    .filter(Subkey::isForSigning)
                    .findFirst()
                    .orElseThrow();
            assertEquals(PublicKeyAlgorithmTags.DSA, signing.getPublicKey().getAlgorithm());
        }
    }

    @Nested
    class EcdsaKeyTest {
        @Test
        void ecdsaSignAndEcdhEncryptRoundTrip() throws Exception {
            Encryptor encryptor = new Encryptor(
                    new KeyForSigning(loadResourceFile("test-key-ecdsa.asc"), Key.NO_PASSPHRASE),
                    new KeyForEncryption(loadResourceFile("test-key-ecdsa.asc")))
                    .withSigningAlgorithm(HashingAlgorithm.SHA256)
                    .withEncryptionProtection(EncryptionProtection.Mdc);
            Decryptor decryptor = new Decryptor(
                    new KeyForVerification(loadResourceFile("test-key-ecdsa.asc")),
                    new KeyForDecryption(loadResourceFile("test-key-ecdsa.asc"), Key.NO_PASSPHRASE))
                    .withVerificationRequired(true);

            assertRoundTrip(encryptor, decryptor);
        }

        @Test
        void ecdsaKeyHasExpectedUsageFlags() throws Exception {
            Key key = new Key(loadResource("test-key-ecdsa.asc"));
            assertTrue(key.getSigning().isForSigning());
            assertTrue(key.getEncryption().isForEncryption());
            assertEquals(PublicKeyAlgorithmTags.ECDSA,
                    key.getSigning().getPublicKey().getAlgorithm());
            assertEquals(PublicKeyAlgorithmTags.ECDH,
                    key.getEncryption().getPublicKey().getAlgorithm());
        }
    }

    @Nested
    class Ed25519KeyTest {
        @Test
        void ed25519SignAndCv25519EncryptRoundTrip() throws Exception {
            Encryptor encryptor = new Encryptor(
                    new KeyForSigning(loadResourceFile("test-key-ed25519.asc"), Key.NO_PASSPHRASE),
                    new KeyForEncryption(loadResourceFile("test-key-ed25519.asc")))
                    .withSigningAlgorithm(HashingAlgorithm.SHA512)
                    .withEncryptionProtection(EncryptionProtection.Mdc);
            Decryptor decryptor = new Decryptor(
                    new KeyForVerification(loadResourceFile("test-key-ed25519.asc")),
                    new KeyForDecryption(loadResourceFile("test-key-ed25519.asc"), Key.NO_PASSPHRASE))
                    .withVerificationRequired(true);

            assertRoundTrip(encryptor, decryptor);
        }

        @Test
        void ed25519SigningSubkeyIsRecognized() throws Exception {
            Key key = new Key(loadResource("test-key-ed25519.asc"));
            int algorithm = key.getSigning().getPublicKey().getAlgorithm();
            assertTrue(algorithm == PublicKeyAlgorithmTags.EDDSA
                    || algorithm == PublicKeyAlgorithmTags.Ed25519);
            assertTrue(key.getSigning().isUsableForSigning());
            assertTrue(key.getEncryption().isUsableForEncryption());
        }
    }

    @Nested
    class GpgInteropTest {
        @Test
        void decryptGpgSignedEncryptedDsaMessage() throws Exception {
            Decryptor decryptor = new Decryptor(
                    new KeyForVerification(loadResourceFile("test-key-dsa.asc")),
                    new KeyForDecryption(loadResourceFile("test-key-dsa.asc"), Key.NO_PASSPHRASE))
                    .withVerificationRequired(true);

            ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
            FileMetadata meta = decryptor.decrypt(
                    loadResource("gpg-dsa-signed-encrypted.txt.asc"),
                    plainOut);

            assertEquals("jpgpj gpg interop plain text", plainOut.toString(StandardCharsets.UTF_8).trim());
            assertTrue(isVerified(meta));
        }

        @Test
        void decryptGpgSignedEncryptedEcdsaMessage() throws Exception {
            Decryptor decryptor = new Decryptor(
                    new KeyForVerification(loadResourceFile("test-key-ecdsa.asc")),
                    new KeyForDecryption(loadResourceFile("test-key-ecdsa.asc"), Key.NO_PASSPHRASE))
                    .withVerificationRequired(true);

            ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
            FileMetadata meta = decryptor.decrypt(
                    loadResource("gpg-ecdsa-signed-encrypted.txt.asc"),
                    plainOut);

            assertEquals("jpgpj gpg interop plain text", plainOut.toString(StandardCharsets.UTF_8).trim());
            assertTrue(isVerified(meta));
        }

        @Test
        void decryptGpgSignedEncryptedEd25519Message() throws Exception {
            Decryptor decryptor = new Decryptor(
                    new KeyForVerification(loadResourceFile("test-key-ed25519.asc")),
                    new KeyForDecryption(loadResourceFile("test-key-ed25519.asc"), Key.NO_PASSPHRASE))
                    .withVerificationRequired(true);

            ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
            FileMetadata meta = decryptor.decrypt(
                    loadResource("gpg-ed25519-signed-encrypted.txt.asc"),
                    plainOut);

            assertEquals("jpgpj gpg interop plain text", plainOut.toString(StandardCharsets.UTF_8).trim());
            assertTrue(isVerified(meta));
        }
    }

    @Test
    void jpgpjEncryptDecryptWithDsaSignerAndRsaRecipient() throws Exception {
        Encryptor encryptor = new Encryptor(
                new KeyForSigning(loadResourceFile("test-key-dsa.asc"), Key.NO_PASSPHRASE),
                new KeyForEncryption(loadResourceFile("test-key-2-pub.asc")))
                .withSigningAlgorithm(HashingAlgorithm.SHA256);
        Decryptor decryptor = new Decryptor(
                new KeyForVerification(loadResourceFile("test-key-dsa.asc")),
                new KeyForDecryption(loadResourceFile("test-key-2.asc"), PASSPHRASE))
                .withVerificationRequired(true);

        assertRoundTrip(encryptor, decryptor);
    }
}
