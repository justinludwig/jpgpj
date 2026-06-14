package org.c02e.jpgpj;

import static org.c02e.jpgpj.support.PgpPacketInspectSupport.assertSessionPacketUsesAeadV5;
import static org.c02e.jpgpj.support.PgpPacketInspectSupport.assertSessionPacketUsesAeadV6;
import static org.c02e.jpgpj.support.PgpPacketInspectSupport.assertSessionPacketUsesMdc;
import static org.c02e.jpgpj.support.PgpPacketInspectSupport.encryptToBytes;
import static org.c02e.jpgpj.support.PgpTestSupport.PASSPHRASE;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResource;
import static org.c02e.jpgpj.support.PgpTestSupport.plainText;
import static org.c02e.jpgpj.support.PgpTestSupport.unlockKey;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.c02e.jpgpj.support.TestDecryptor;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class OpenPgpModernTest {

    private static Key signingKey() throws Exception {
        Key key = new Key(loadResource("test-key-1.asc"));
        unlockKey(key);
        return key;
    }

    private static Key encryptionKey() throws Exception {
        return new Key(loadResource("test-key-2-pub.asc"));
    }

    private static Key decryptionKey() throws Exception {
        Key key = new Key(loadResource("test-key-2.asc"));
        unlockKey(key);
        return key;
    }

    private static Key verificationKey() throws Exception {
        return new Key(loadResource("test-key-1-pub.asc"));
    }

    private static String roundTrip(Encryptor encryptor, Decryptor decryptor) throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        encryptor.encrypt(new ByteArrayInputStream(plainText().getBytes(StandardCharsets.UTF_8)), cipherOut);

        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        DecryptionResult result = decryptor.decryptWithFullDetails(
                new ByteArrayInputStream(cipherOut.toByteArray()),
                plainOut);
        assertEquals(plainText(), plainOut.toString(StandardCharsets.UTF_8));
        return plainOut.toString(StandardCharsets.UTF_8);
    }

    @Nested
    class HashingAlgorithmTagsTest {
        @Test
        void sha3TagsMatchOpenPgp() {
            assertEquals(12, HashingAlgorithm.SHA3_256.getOpenPgpTag());
            assertEquals(14, HashingAlgorithm.SHA3_512.getOpenPgpTag());
            assertEquals(HashAlgorithmTags.SHA3_256, HashingAlgorithm.SHA3_256.getOpenPgpTag());
            assertEquals(HashAlgorithmTags.SHA3_512, HashingAlgorithm.SHA3_512.getOpenPgpTag());
        }

        @ParameterizedTest
        @EnumSource(value = HashingAlgorithm.class, names = {"Unsigned"}, mode = EnumSource.Mode.EXCLUDE)
        void roundTripOpenPgpTagMapping(HashingAlgorithm algorithm) {
            assertEquals(algorithm, HashingAlgorithm.fromOpenPgpTag(algorithm.getOpenPgpTag()));
        }
    }

    @Nested
    class ClassicRegressionTest {
        @Test
        void classicMdcRoundTrip() throws Exception {
            Encryptor encryptor = new Encryptor(signingKey(), encryptionKey())
                    .withOpenPgpProfile(OpenPgpProfile.Classic)
                    .withSigningAlgorithm(HashingAlgorithm.SHA256);
            Decryptor decryptor = new Decryptor(verificationKey(), decryptionKey());

            roundTrip(encryptor, decryptor);

            ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
            encryptor.encrypt(new ByteArrayInputStream(plainText().getBytes(StandardCharsets.UTF_8)), cipherOut);
            DecryptionResult result = decryptor.decryptWithFullDetails(
                    new ByteArrayInputStream(cipherOut.toByteArray()),
                    new ByteArrayOutputStream());

            EncryptionDetails details = result.getFileMetadata().getEncryptionDetails();
            assertNotNull(details);
            assertEquals(EncryptionProtection.Mdc, details.getProtection());
            assertEquals(EncryptionAlgorithm.AES128, details.getSessionCipher());
            assertEquals(OpenPgpProfile.Classic, details.getDetectedProfile());
        }
    }

    @Nested
    class Sha3SigningTest {
        @ParameterizedTest
        @EnumSource(value = HashingAlgorithm.class, names = {"SHA3_256", "SHA3_512"})
        void sha3SigningRoundTrip(HashingAlgorithm signingAlgorithm) throws Exception {
            Encryptor encryptor = new Encryptor(signingKey(), encryptionKey())
                    .withSigningAlgorithm(signingAlgorithm)
                    .withEncryptionProtection(EncryptionProtection.Mdc);
            Decryptor decryptor = new Decryptor(verificationKey(), decryptionKey())
                    .withVerificationRequired(true);

            roundTrip(encryptor, decryptor);

            ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
            encryptor.encrypt(new ByteArrayInputStream(plainText().getBytes(StandardCharsets.UTF_8)), cipherOut);
            DecryptionResult result = decryptor.decryptWithFullDetails(
                    new ByteArrayInputStream(cipherOut.toByteArray()),
                    new ByteArrayOutputStream());

            assertEquals(1, result.getFileMetadata().getSignatures().size());
            assertEquals(signingAlgorithm,
                    result.getFileMetadata().getSignatures().get(0).getHashAlgorithm());
            assertTrue(result.getFileMetadata().getVerified().getKeys().size() >= 1);
        }
    }

    @Nested
    class AeadEncryptionTest {
        @Test
        void aeadOcbV6PublicKeyRoundTrip() throws Exception {
            Encryptor encryptor = new Encryptor(encryptionKey())
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                    .withEncryptionAlgorithm(EncryptionAlgorithm.AES256)
                    .withEncryptionProtection(EncryptionProtection.Aead)
                    .withAeadAlgorithm(AeadAlgorithm.Ocb)
                    .withAeadPacketStyle(AeadPacketStyle.V6);
            Decryptor decryptor = new Decryptor(decryptionKey())
                    .withVerificationRequired(false);

            roundTrip(encryptor, decryptor);

            ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
            encryptor.encrypt(new ByteArrayInputStream(plainText().getBytes(StandardCharsets.UTF_8)), cipherOut);
            DecryptionResult result = decryptor.decryptWithFullDetails(
                    new ByteArrayInputStream(cipherOut.toByteArray()),
                    new ByteArrayOutputStream());

            EncryptionDetails details = result.getFileMetadata().getEncryptionDetails();
            assertNotNull(details);
            assertEquals(EncryptionProtection.Aead, details.getProtection());
            assertEquals(AeadAlgorithm.Ocb, details.getAeadAlgorithm());
            assertEquals(AeadPacketStyle.V6, details.getAeadPacketStyle());
            assertEquals(EncryptionAlgorithm.AES256, details.getSessionCipher());
            assertEquals(OpenPgpProfile.Modern, details.getDetectedProfile());
        }

        @Test
        void aeadEaxV5RoundTrip() throws Exception {
            Encryptor encryptor = new Encryptor(encryptionKey())
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                    .withEncryptionProtection(EncryptionProtection.Aead)
                    .withAeadAlgorithm(AeadAlgorithm.Eax)
                    .withAeadPacketStyle(AeadPacketStyle.V5);
            Decryptor decryptor = new Decryptor(decryptionKey())
                    .withVerificationRequired(false);

            roundTrip(encryptor, decryptor);

            ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
            encryptor.encrypt(new ByteArrayInputStream(plainText().getBytes(StandardCharsets.UTF_8)), cipherOut);
            DecryptionResult result = decryptor.decryptWithFullDetails(
                    new ByteArrayInputStream(cipherOut.toByteArray()),
                    new ByteArrayOutputStream());

            EncryptionDetails details = result.getFileMetadata().getEncryptionDetails();
            assertEquals(EncryptionProtection.Aead, details.getProtection());
            assertEquals(AeadAlgorithm.Eax, details.getAeadAlgorithm());
            assertEquals(AeadPacketStyle.V5, details.getAeadPacketStyle());
        }
    }

    @Nested
    class Argon2PassphraseTest {
        @Test
        void argon2SymmetricRoundTrip() throws Exception {
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

            roundTrip(encryptor, decryptor);

            ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
            encryptor.encrypt(new ByteArrayInputStream(plainText().getBytes(StandardCharsets.UTF_8)), cipherOut);
            DecryptionResult result = decryptor.decryptWithFullDetails(
                    new ByteArrayInputStream(cipherOut.toByteArray()),
                    new ByteArrayOutputStream());

            EncryptionDetails details = result.getFileMetadata().getEncryptionDetails();
            assertEquals(PassphraseKeyDerivation.Argon2, details.getPassphraseKeyDerivation());
            assertNotNull(details.getArgon2Parameters());
            assertEquals(Argon2Parameters.MEMORY_CONSTRAINED.getPasses(),
                    details.getArgon2Parameters().getPasses());
        }

        @Test
        void iteratedSaltedStillWorks() throws Exception {
            Encryptor encryptor = new Encryptor()
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                    .withPassphraseKeyDerivation(PassphraseKeyDerivation.IteratedSalted)
                    .withDeriviationAlgorithm(HashingAlgorithm.SHA512)
                    .withKeyDeriviationWorkFactor(10)
                    .withSymmetricPassphrase(PASSPHRASE);
            Decryptor decryptor = new Decryptor()
                    .withVerificationRequired(false)
                    .withSymmetricPassphrase(PASSPHRASE);

            roundTrip(encryptor, decryptor);

            ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
            encryptor.encrypt(new ByteArrayInputStream(plainText().getBytes(StandardCharsets.UTF_8)), cipherOut);
            DecryptionResult result = decryptor.decryptWithFullDetails(
                    new ByteArrayInputStream(cipherOut.toByteArray()),
                    new ByteArrayOutputStream());

            assertEquals(PassphraseKeyDerivation.IteratedSalted,
                    result.getFileMetadata().getEncryptionDetails().getPassphraseKeyDerivation());
        }
    }

    @Nested
    class OpenPgpProfileTest {
        @Test
        void modernDefaultsRoundTrip() throws Exception {
            Encryptor encryptor = new Encryptor(signingKey(), encryptionKey())
                    .withModernDefaults();
            Decryptor decryptor = new Decryptor(verificationKey(), decryptionKey());

            roundTrip(encryptor, decryptor);

            assertEquals(OpenPgpProfile.Modern, encryptor.getOpenPgpProfile());
            assertEquals(EncryptionProtection.Aead, encryptor.getEncryptionProtection());
            assertEquals(EncryptionAlgorithm.AES256, encryptor.getEncryptionAlgorithm());
            assertEquals(AeadAlgorithm.Ocb, encryptor.getAeadAlgorithm());
            assertEquals(AeadPacketStyle.V6, encryptor.getAeadPacketStyle());
            assertEquals(HashingAlgorithm.SHA384, encryptor.getSigningAlgorithm());
            assertEquals(PassphraseKeyDerivation.Argon2, encryptor.getPassphraseKeyDerivation());
            assertEquals(Argon2Parameters.GPG_RECOMMENDED, encryptor.getArgon2Parameters());
            assertEquals(CompressionAlgorithm.ZLIB, encryptor.getCompressionAlgorithm());

            byte[] ciphertext = encryptToBytes(
                    encryptor,
                    plainText().getBytes(StandardCharsets.UTF_8));
            assertSessionPacketUsesAeadV6(
                    ciphertext,
                    new TestDecryptor(decryptionKey()).withVerificationRequired(false),
                    AeadAlgorithm.Ocb);

            DecryptionResult result = decryptor.decryptWithFullDetails(
                    new ByteArrayInputStream(ciphertext),
                    new ByteArrayOutputStream());

            EncryptionDetails details = result.getFileMetadata().getEncryptionDetails();
            assertEquals(EncryptionProtection.Aead, details.getProtection());
            assertEquals(AeadAlgorithm.Ocb, details.getAeadAlgorithm());
            assertEquals(AeadPacketStyle.V6, details.getAeadPacketStyle());
            assertEquals(OpenPgpProfile.Modern, details.getDetectedProfile());
            assertNull(details.getPassphraseKeyDerivation());
        }

        @Test
        void profileCanBeOverridden() {
            Encryptor encryptor = new Encryptor()
                    .withModernDefaults()
                    .withEncryptionProtection(EncryptionProtection.Mdc)
                    .withEncryptionAlgorithm(EncryptionAlgorithm.AES128);
            assertEquals(EncryptionProtection.Mdc, encryptor.getEncryptionProtection());
            assertEquals(EncryptionAlgorithm.AES128, encryptor.getEncryptionAlgorithm());
            assertEquals(OpenPgpProfile.Modern, encryptor.getOpenPgpProfile());
        }

        @Test
        void classicProfileRestoresDefaults() throws Exception {
            Encryptor encryptor = new Encryptor()
                    .withModernDefaults()
                    .withAeadAlgorithm(AeadAlgorithm.Eax)
                    .withAeadPacketStyle(AeadPacketStyle.V5)
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                    .withDeriviationAlgorithm(HashingAlgorithm.SHA256)
                    .withKeyDeriviationWorkFactor(10)
                    .withCompressionAlgorithm(CompressionAlgorithm.Uncompressed)
                    .withOpenPgpProfile(OpenPgpProfile.Classic);

            assertEquals(OpenPgpProfile.Classic, encryptor.getOpenPgpProfile());
            assertEquals(EncryptionProtection.Mdc, encryptor.getEncryptionProtection());
            assertEquals(EncryptionAlgorithm.AES128, encryptor.getEncryptionAlgorithm());
            assertEquals(AeadAlgorithm.Ocb, encryptor.getAeadAlgorithm());
            assertEquals(AeadPacketStyle.V6, encryptor.getAeadPacketStyle());
            assertEquals(HashingAlgorithm.SHA384, encryptor.getSigningAlgorithm());
            assertEquals(HashingAlgorithm.SHA512, encryptor.getKeyDeriviationAlgorithm());
            assertEquals(255, encryptor.getKeyDeriviationWorkFactor());
            assertEquals(CompressionAlgorithm.ZLIB, encryptor.getCompressionAlgorithm());
            assertEquals(PassphraseKeyDerivation.IteratedSalted, encryptor.getPassphraseKeyDerivation());

            Encryptor encryptProbe = new Encryptor(encryptionKey())
                    .withOpenPgpProfile(OpenPgpProfile.Classic)
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned);
            byte[] ciphertext = encryptToBytes(
                    encryptProbe,
                    plainText().getBytes(StandardCharsets.UTF_8));
            assertSessionPacketUsesMdc(
                    ciphertext,
                    new TestDecryptor(decryptionKey()).withVerificationRequired(false));
        }

        @Test
        void modernProfileRestoresDefaultsFromClassicCustomizations() {
            Encryptor encryptor = new Encryptor()
                    .withEncryptionAlgorithm(EncryptionAlgorithm.AES128)
                    .withEncryptionProtection(EncryptionProtection.Mdc)
                    .withAeadAlgorithm(AeadAlgorithm.Eax)
                    .withAeadPacketStyle(AeadPacketStyle.V5)
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                    .withPassphraseKeyDerivation(PassphraseKeyDerivation.IteratedSalted)
                    .withArgon2Parameters(Argon2Parameters.MEMORY_CONSTRAINED)
                    .withCompressionAlgorithm(CompressionAlgorithm.Uncompressed)
                    .withModernDefaults();

            assertEquals(OpenPgpProfile.Modern, encryptor.getOpenPgpProfile());
            assertEquals(EncryptionProtection.Aead, encryptor.getEncryptionProtection());
            assertEquals(EncryptionAlgorithm.AES256, encryptor.getEncryptionAlgorithm());
            assertEquals(AeadAlgorithm.Ocb, encryptor.getAeadAlgorithm());
            assertEquals(AeadPacketStyle.V6, encryptor.getAeadPacketStyle());
            assertEquals(HashingAlgorithm.SHA384, encryptor.getSigningAlgorithm());
            assertEquals(PassphraseKeyDerivation.Argon2, encryptor.getPassphraseKeyDerivation());
            assertEquals(Argon2Parameters.GPG_RECOMMENDED, encryptor.getArgon2Parameters());
            assertEquals(CompressionAlgorithm.ZLIB, encryptor.getCompressionAlgorithm());
        }
    }

    @Nested
    class WireFormatTest {
        @Test
        void classicMdcUsesIntegrityProtectedSessionPacket() throws Exception {
            Encryptor encryptor = new Encryptor(encryptionKey())
                    .withOpenPgpProfile(OpenPgpProfile.Classic)
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned);
            byte[] ciphertext = encryptToBytes(
                    encryptor,
                    plainText().getBytes(StandardCharsets.UTF_8));
            assertSessionPacketUsesMdc(
                    ciphertext,
                    new TestDecryptor(decryptionKey()).withVerificationRequired(false));
        }

        @Test
        void aeadOcbV6UsesV6SessionLayout() throws Exception {
            Encryptor encryptor = new Encryptor(encryptionKey())
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                    .withEncryptionAlgorithm(EncryptionAlgorithm.AES256)
                    .withEncryptionProtection(EncryptionProtection.Aead)
                    .withAeadAlgorithm(AeadAlgorithm.Ocb)
                    .withAeadPacketStyle(AeadPacketStyle.V6);
            byte[] ciphertext = encryptToBytes(
                    encryptor,
                    plainText().getBytes(StandardCharsets.UTF_8));
            assertSessionPacketUsesAeadV6(
                    ciphertext,
                    new TestDecryptor(decryptionKey()).withVerificationRequired(false),
                    AeadAlgorithm.Ocb);
        }

        @Test
        void aeadEaxV5UsesV5AeadPacket() throws Exception {
            Encryptor encryptor = new Encryptor(encryptionKey())
                    .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                    .withEncryptionProtection(EncryptionProtection.Aead)
                    .withAeadAlgorithm(AeadAlgorithm.Eax)
                    .withAeadPacketStyle(AeadPacketStyle.V5);
            byte[] ciphertext = encryptToBytes(
                    encryptor,
                    plainText().getBytes(StandardCharsets.UTF_8));
            assertSessionPacketUsesAeadV5(
                    ciphertext,
                    new TestDecryptor(decryptionKey()).withVerificationRequired(false),
                    AeadAlgorithm.Eax);
        }
    }

    @Nested
    class Argon2ParametersTest {
        @Test
        void gpgRecommendedParameters() {
            Argon2Parameters params = Argon2Parameters.GPG_RECOMMENDED;
            assertTrue(params.getPasses() >= 1);
            assertTrue(params.getParallelism() >= 1);
            assertTrue(params.getMemorySizeExponent() >= 1);
        }

        @Test
        void customParametersEquality() {
            Argon2Parameters a = new Argon2Parameters(3, 4, 16);
            Argon2Parameters b = new Argon2Parameters(3, 4, 16);
            assertEquals(a, b);
            assertEquals(a.hashCode(), b.hashCode());
        }
    }
}
