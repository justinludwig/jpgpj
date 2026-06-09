package org.c02e.jpgpj;

import static org.c02e.jpgpj.support.PgpTestSupport.PASSPHRASE;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResource;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResourceFile;
import static org.c02e.jpgpj.support.PgpTestSupport.hasSignatures;
import static org.c02e.jpgpj.support.PgpTestSupport.isVerified;
import static org.c02e.jpgpj.support.PgpTestSupport.plainText;
import static org.c02e.jpgpj.support.PgpTestSupport.unlockKey;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.key.KeyForDecryption;
import org.c02e.jpgpj.key.KeyForEncryption;
import org.c02e.jpgpj.key.KeyForSigning;
import org.c02e.jpgpj.key.KeyForVerification;
import org.c02e.jpgpj.support.PgpPacketInspectSupport;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

class EncryptorTest {

    @Test
    void literalOnly() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor()
            .withCompressionAlgorithm(CompressionAlgorithm.Uncompressed)
            .withEncryptionAlgorithm(EncryptionAlgorithm.Unencrypted)
            .withSigningAlgorithm(HashingAlgorithm.Unsigned);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor();
        decryptor.setVerificationRequired(false);
        FileMetadata meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertEquals("", meta.getName());
        assertEquals(plainText().length(), meta.getLength());
        assertEquals(0, meta.getLastModified());
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertFalse(isVerified(meta));
        assertFalse(hasSignatures(meta));
    }

    @Test
    void compressOnly() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor();
        encryptor.setEncryptionAlgorithm(EncryptionAlgorithm.Unencrypted);
        encryptor.setSigningAlgorithm(HashingAlgorithm.Unsigned);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor();
        decryptor.setVerificationRequired(false);
        decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
    }

    @Test
    void encryptWithoutSigning() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1-pub.asc")));
        encryptor.setSigningAlgorithm(HashingAlgorithm.Unsigned);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.setVerificationRequired(false);
        decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
    }

    @Test
    void encryptWithoutCompressionOrSigning() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1-pub.asc")));
        encryptor.setCompressionAlgorithm(CompressionAlgorithm.Uncompressed);
        encryptor.setSigningAlgorithm(HashingAlgorithm.Unsigned);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.setVerificationRequired(false);
        decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
    }

    @Test
    void encryptWithoutEncryptionKeys() {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        Encryptor encryptor = new Encryptor();
        encryptor.setSigningAlgorithm(HashingAlgorithm.Unsigned);
        PGPException e = assertThrows(PGPException.class, () -> encryptor.encrypt(plainIn(), cipherOut));
        assertEquals("no suitable encryption key found", e.getMessage());
    }

    @Test
    void encryptSymmetricWithoutSigning() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor()
            .withSigningAlgorithm(HashingAlgorithm.Unsigned)
            .withSymmetricPassphrase(PASSPHRASE)
            .withKeyDeriviationWorkFactor(10);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor()
            .withSymmetricPassphrase(PASSPHRASE)
            .withVerificationRequired(false);
        decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
    }

    @Test
    void encryptWithMultipleKeys() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-ring-pub.asc")))
            .withSigningAlgorithm(HashingAlgorithm.Unsigned)
            .withSymmetricPassphrase(PASSPHRASE)
            .withKeyDeriviationWorkFactor(10);
        encryptor.encrypt(plainIn(), cipherOut);

        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.setVerificationRequired(false);
        decryptor.decrypt(cipherIn(cipherOut), plainOut);
        assertEquals(plainText(), plainOut.toString());

        plainOut = new ByteArrayOutputStream();
        decryptor = new Decryptor(new Ring(loadResource("test-key-2.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.setVerificationRequired(false);
        decryptor.decrypt(cipherIn(cipherOut), plainOut);
        assertEquals(plainText(), plainOut.toString());

        plainOut = new ByteArrayOutputStream();
        decryptor = new Decryptor();
        decryptor.setSymmetricPassphrase(PASSPHRASE);
        decryptor.setVerificationRequired(false);
        decryptor.decrypt(cipherIn(cipherOut), plainOut);
        assertEquals(plainText(), plainOut.toString());
    }

    @Test
    void signWithoutCompressingOrEncrypting() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
        encryptor.setCompressionAlgorithm(CompressionAlgorithm.Uncompressed);
        encryptor.setEncryptionAlgorithm(EncryptionAlgorithm.Unencrypted);
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1-pub.asc")));
        decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
    }

    @Test
    void signWithoutEncrypting() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
        encryptor.setEncryptionAlgorithm(EncryptionAlgorithm.Unencrypted);
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1-pub.asc")));
        decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
    }

    @Test
    void signWithoutSigningKeys() {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        Encryptor encryptor = new Encryptor();
        encryptor.setEncryptionAlgorithm(EncryptionAlgorithm.Unencrypted);
        PGPException e = assertThrows(PGPException.class, () -> encryptor.encrypt(plainIn(), cipherOut));
        assertEquals("no suitable signing key found", e.getMessage());
    }

    @Test
    void signWithoutPassphrase() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
        encryptor.setEncryptionAlgorithm(EncryptionAlgorithm.Unencrypted);
        PGPException e = assertThrows(PGPException.class, () -> encryptor.encrypt(plainIn(), cipherOut));
        assertEquals("no suitable signing key found", e.getMessage());
    }

    @Test
    void signWithWrongPassphrase() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
        encryptor.setEncryptionAlgorithm(EncryptionAlgorithm.Unencrypted);
        unlockKey(encryptor.getRing(), "wrong!");
        PassphraseException e = assertThrows(PassphraseException.class, () -> encryptor.encrypt(plainIn(), cipherOut));
        assertEquals(
            "incorrect passphrase for subkey sec+vs 013826C3 Test Key 1 <test-key-1@c02e.org>",
            e.getMessage()
        );
    }

    @Test
    void encryptAndSignWithSameKey() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        FileMetadata meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertEquals("", meta.getName());
        assertEquals(plainText().length(), meta.getLength());
        assertEquals(0, meta.getLastModified());
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertTrue(isVerified(meta));
        assertEquals(List.of(List.of("Test Key 1 <test-key-1@c02e.org>")), verifiedKeyUids(meta));
        assertEquals(List.of("Test Key 1 <test-key-1@c02e.org>"), signingUids(meta.getVerified()));
    }

    @Test
    void encryptBytes() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        String expected = "This is a test of bytes encoding";

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(encryptor.getRing(), PASSPHRASE);
        FileMetadata encMeta = encryptor.encryptBytes(expected.getBytes(), "bytesTest", cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        FileMetadata decMeta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(expected, plainOut.toString());
        assertEquals("bytesTest", decMeta.getName());
        assertEquals(expected.length(), decMeta.getLength());
        assertEquals(FileMetadata.Format.BINARY, decMeta.getFormat());
        assertEquals(encMeta, decMeta);
        assertTrue(isVerified(decMeta));
        assertEquals(List.of(List.of("Test Key 1 <test-key-1@c02e.org>")), verifiedKeyUids(decMeta));
        assertEquals(List.of("Test Key 1 <test-key-1@c02e.org>"), signingUids(decMeta.getVerified()));
    }

    @Test
    void encryptAndSignWithAsciiArmor() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
        encryptor.setAsciiArmored(true);
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        DecryptionResult result = decryptor.decryptWithFullDetails(cipherIn(cipherOut), plainOut);
        List<String> armorHeaders = result.getArmorHeaders();

        assertTrue(result.isAsciiArmored());
        assertEquals(1, armorHeaders.size());
        assertTrue(armorHeaders.get(0).startsWith("Version"));
        assertEquals(plainText(), plainOut.toString());

        String armored = cipherOut.toString();
        String[] lines = armored.split("\n", -1);
        assertEquals("-----BEGIN PGP MESSAGE-----", lines[0]);
        assertTrue(lines[1].startsWith("Version: BCPG v"));
        assertEquals("", lines[2]);
        assertTrue(java.util.Arrays.stream(lines).anyMatch(line -> line.startsWith("=")));
        assertEquals("-----END PGP MESSAGE-----", lines[lines.length - 2]);
        assertEquals("", lines[lines.length - 1]);
    }

    @Test
    void encryptArmoredWithoutVersionHeader() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")))
            .withAsciiArmored(true)
            .withRemoveDefaultArmoredVersionHeader(true);
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        DecryptionResult result = decryptor.decryptWithFullDetails(cipherIn(cipherOut), plainOut);

        assertTrue(result.isAsciiArmored());
        assertTrue(result.getArmorHeaders().isEmpty());
        assertEquals(plainText(), plainOut.toString());
    }

    @Test
    void encryptAndUseUserDefinedAsciiArmorHeaders() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")))
            .withAsciiArmored(true)
            .withArmoredHeader("Version", "3.14")
            .withArmoredHeader("Encryptor", "c02e")
            .withArmorHeadersCallback(new EncryptedAsciiArmorHeadersCallback() {
                @Override
                public void prepareAsciiArmoredHeaders(
                        Encryptor enc, FileMetadata meta, EncryptedAsciiArmorHeadersManipulator manipulator) {
                    manipulator.setHeader("Version", "2.71");
                    manipulator.setHeader("Callback", "true");
                }
            });
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        DecryptionResult result = decryptor.decryptWithFullDetails(cipherIn(cipherOut), plainOut);
        List<String> armorHeaders = new ArrayList<>(result.getArmorHeaders());
        armorHeaders.sort(Comparator.naturalOrder());

        assertTrue(result.isAsciiArmored());
        assertEquals(3, armorHeaders.size());
        assertEquals("Callback: true", armorHeaders.get(0));
        assertEquals("Encryptor: c02e", armorHeaders.get(1));
        assertEquals("Version: 2.71", armorHeaders.get(2));
        assertEquals(plainText(), plainOut.toString());
    }

    @Test
    void encryptAndSignFile(@TempDir File tempDir) throws Exception {
        File plainFile = writeTempFile(tempDir, "plain.txt", plainText());
        File cipherFile = tempDir.toPath().resolve("cipher.asc").toFile();
        File resultFile = tempDir.toPath().resolve("result.txt").toFile();

        Encryptor encryptor = new Encryptor(new Key(loadResourceFile("test-key-1.asc"), PASSPHRASE));
        encryptor.encrypt(plainFile, cipherFile);

        Decryptor decryptor = new Decryptor(new Key(loadResourceFile("test-key-1.asc"), PASSPHRASE));
        FileMetadata meta = decryptor.decrypt(cipherFile, resultFile);

        assertEquals(plainText(), Files.readString(resultFile.toPath()));
        assertEquals(plainFile.getName(), meta.getName());
        assertEquals(plainText().length(), meta.getLength());
        assertEquals(plainFile.lastModified() / 1000L, meta.getLastModified() / 1000L);
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertTrue(isVerified(meta));
    }

    @Test
    void useEncryptionFileStreamWrapper(@TempDir File tempDir) throws Exception {
        File plainFile = writeTempFile(tempDir, "plain.txt", plainText());
        File cipherFile = tempDir.toPath().resolve("cipher.asc").toFile();
        File resultFile = tempDir.toPath().resolve("result.txt").toFile();

        Encryptor encryptor = new Encryptor(new Key(loadResourceFile("test-key-1.asc"), PASSPHRASE));
        OutputStream wrapperStream = encryptor.prepareCiphertextOutputStream(new FileMetadata(plainFile), cipherFile);
        try (InputStream plainStream = new FileInputStream(plainFile)) {
            byte[] buf = new byte[0x1000];
            int numRead = plainStream.read(buf);
            while (numRead != -1) {
                wrapperStream.write(buf, 0, numRead);
                numRead = plainStream.read(buf);
            }
        } finally {
            wrapperStream.close();
        }

        Decryptor decryptor = new Decryptor(new Key(loadResourceFile("test-key-1.asc"), PASSPHRASE));
        FileMetadata meta = decryptor.decrypt(cipherFile, resultFile);

        assertEquals(plainText(), Files.readString(resultFile.toPath()));
        assertEquals(plainFile.getName(), meta.getName());
        assertEquals(plainText().length(), meta.getLength());
        assertEquals(plainFile.lastModified() / 1000L, meta.getLastModified() / 1000L);
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertTrue(isVerified(meta));
    }

    @Test
    void encryptAndSignZeroByteFile(@TempDir File tempDir) throws Exception {
        File plainFile = tempDir.toPath().resolve("empty.txt").toFile();
        Files.createFile(plainFile.toPath());
        File cipherFile = tempDir.toPath().resolve("cipher.asc").toFile();
        File resultFile = tempDir.toPath().resolve("result.txt").toFile();

        Encryptor encryptor = new Encryptor(new Key(loadResourceFile("test-key-1.asc"), PASSPHRASE));
        encryptor.encrypt(plainFile, cipherFile);

        Decryptor decryptor = new Decryptor(new Key(loadResourceFile("test-key-1.asc"), PASSPHRASE));
        FileMetadata meta = decryptor.decrypt(cipherFile, resultFile);

        assertEquals(0, resultFile.length());
        assertEquals(0, meta.getLength());
        assertTrue(isVerified(meta));
    }

    @Test
    void encryptAndSignFileWithoutPassphrase(@TempDir File tempDir) throws Exception {
        File plainFile = writeTempFile(tempDir, "plain.txt", plainText());
        File cipherFile = tempDir.toPath().resolve("cipher.asc").toFile();

        Encryptor encryptor = new Encryptor(new Key(loadResourceFile("test-key-1.asc")));
        PGPException e = assertThrows(PGPException.class, () -> encryptor.encrypt(plainFile, cipherFile));
        assertEquals("no suitable signing key found", e.getMessage());
        assertFalse(cipherFile.exists());
    }

    @Test
    void encryptAndSignSameFile(@TempDir File tempDir) throws Exception {
        File plainFile = writeTempFile(tempDir, "plain.txt", plainText());
        Encryptor encryptor = new Encryptor(new Key(loadResourceFile("test-key-1.asc"), PASSPHRASE));
        assertThrows(IOException.class, () -> encryptor.encrypt(plainFile, plainFile));
        assertEquals(plainText(), Files.readString(plainFile.toPath()));
    }

    @Test
    void encryptAndSignWithoutCompression() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
        encryptor.setCompressionAlgorithm(CompressionAlgorithm.Uncompressed);
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
    }

    @Test
    void signWithLastSigningSubkeyByDefault() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-2-master.asc")));
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-2-master.asc")));
        for (Key key : decryptor.getRing().getKeys()) {
            Subkey verification = key.getVerification();
            if (verification != null && !"BC3F6A4B".equals(verification.getShortId())) {
                verification.setForVerification(false);
            }
        }
        unlockKey(decryptor.getRing(), PASSPHRASE);
        FileMetadata meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertEquals(List.of("Test Key 2 <test-key-2@c02e.org>"), signingUids(meta.getVerified()));
    }

    @Test
    void allowSigningWithNonDefaultSubkey() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-2-master.asc")));
        for (Key key : encryptor.getRing().getKeys()) {
            Subkey signing = key.getSigning();
            if (signing != null && !"880A1469".equals(signing.getShortId())) {
                signing.setForSigning(false);
            }
        }
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-2-master.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        FileMetadata meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertEquals(List.of("Test Key 2 <test-key-2@c02e.org>"), signingUids(meta.getVerified()));
    }

    @Test
    void encryptAndSignWithDifferentKeys() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-ring.asc")));
        for (Key key : encryptor.getRing().findAll("key-1")) {
            key.getSigning().setForSigning(false);
        }
        for (Key key : encryptor.getRing().findAll("key-2")) {
            key.getEncryption().setForEncryption(false);
            key.setPassphrase(PASSPHRASE);
        }
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        for (Key key : decryptor.getRing().findAll("key-1")) {
            key.setPassphrase(PASSPHRASE);
        }
        FileMetadata meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertEquals(List.of(
            "Test Key 2 <test-key-2@c02e.org>",
            "Test 2 (CODESurvey) <test-key-2@codesurvey.org>"
        ), flattenUids(meta.getVerified()));
        assertEquals(List.of("Test Key 2 <test-key-2@c02e.org>"), signingUids(meta.getVerified()));
        assertEquals(List.of("Test Key 2 <test-key-2@c02e.org>"), verifiedKeySigningUids(meta));
    }

    @Test
    void encryptAndSignWithMultipleKeys() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.setSymmetricPassphrase(PASSPHRASE);
        encryptor.setKeyDeriviationWorkFactor(10);
        encryptor.encrypt(plainIn(), cipherOut);

        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        for (Key key : decryptor.getRing().findAll("key-1")) {
            key.setPassphrase(PASSPHRASE);
        }
        for (Key key : encryptor.getRing().findAll("key-2")) {
            key.getEncryption().setForDecryption(false);
        }
        FileMetadata meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertMultipleKeyDecryptMeta(meta);

        plainOut = new ByteArrayOutputStream();
        decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        for (Key key : encryptor.getRing().findAll("key-1")) {
            key.getEncryption().setForDecryption(false);
        }
        for (Key key : decryptor.getRing().findAll("key-2")) {
            key.setPassphrase(PASSPHRASE);
        }
        meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertMultipleKeyDecryptMeta(meta);

        plainOut = new ByteArrayOutputStream();
        decryptor = new Decryptor(new Ring(loadResource("test-key-2-pub.asc")));
        decryptor.setSymmetricPassphrase(PASSPHRASE);
        meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertEquals(List.of(
            "Test Key 2 <test-key-2@c02e.org>",
            "Test 2 (CODESurvey) <test-key-2@codesurvey.org>"
        ), flattenUids(meta.getVerified()));
        assertEquals(List.of("Test Key 2 <test-key-2@c02e.org>"), signingUids(meta.getVerified()));
        assertEquals(List.of(false, true), signatureVerified(meta));
        assertEquals(List.of(0x72A423A0013826C3L, 0xAFDB7B47BC3F6A4BL), signatureKeyIds(meta));
        assertEquals(List.of("880A1469"), signatureMasterShortIds(meta));
        assertEquals(List.of("Test Key 2 <test-key-2@c02e.org>"), verifiedKeySigningUids(meta));
    }

    @Test
    void encryptSymmetricAndClearPassphrase() throws Exception {
        char[] passphrase = PASSPHRASE.toCharArray();
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor()
            .withSigningAlgorithm(HashingAlgorithm.Unsigned)
            .withSymmetricPassphraseChars(passphrase)
            .withKeyDeriviationWorkFactor(10);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor()
            .withSymmetricPassphrase(new String(passphrase))
            .withVerificationRequired(false);
        decryptor.decrypt(cipherIn(cipherOut), plainOut);
        assertEquals(plainText(), plainOut.toString());

        passphrase[0] = 'x';
        assertEquals('x', encryptor.getSymmetricPassphraseChars()[0]);

        encryptor.clearSecrets();
        assertArrayEquals(new char[] {0, 0, 0, 0}, passphrase);
        assertArrayEquals(new char[0], encryptor.getSymmetricPassphraseChars());
        assertEquals("", encryptor.getSymmetricPassphrase());

        ByteArrayOutputStream cipherOutAfterClear = new ByteArrayOutputStream();
        PGPException e = assertThrows(PGPException.class,
            () -> encryptor.encrypt(plainIn(), cipherOutAfterClear));
        assertEquals("no suitable encryption key found", e.getMessage());
    }

    @Test
    void encryptAndSignAndClearSecrets() throws Exception {
        char[] passphrase = PASSPHRASE.toCharArray();
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Key key = new Key(loadResourceFile("test-key-1.asc"), passphrase);
        Encryptor encryptor = new Encryptor(key);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(key);
        FileMetadata meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertTrue(isVerified(meta));

        encryptor.clearSecrets();
        List<Subkey> subkeys = flattenSubkeys(encryptor.getRing());
        assertArrayEquals(new char[] {0, 0, 0, 0}, passphrase);
        assertEquals(List.of(false, false), subkeys.stream().map(Subkey::isUnlocked).collect(Collectors.toList()));
        assertTrue(subkeys.stream().allMatch(sk -> sk.getPassphraseChars().length == 0));
        assertEquals(List.of("", ""), subkeys.stream().map(Subkey::getPassphrase).collect(Collectors.toList()));

        ByteArrayOutputStream cipherOutAfterClear = new ByteArrayOutputStream();
        PGPException e = assertThrows(PGPException.class,
            () -> encryptor.encrypt(plainIn(), cipherOutAfterClear));
        assertEquals("no suitable signing key found", e.getMessage());
    }

    @Test
    void signWithoutCachingPassphrase() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
        encryptor.setEncryptionAlgorithm(EncryptionAlgorithm.Unencrypted);
        flattenSubkeys(encryptor.getRing()).stream()
            .filter(sk -> "013826C3".equals(sk.getShortId()))
            .findFirst()
            .orElseThrow()
            .unlock(PASSPHRASE.toCharArray());
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1-pub.asc")));
        decryptor.decrypt(cipherIn(cipherOut), plainOut);
        assertEquals(plainText(), plainOut.toString());

        List<Subkey> subkeys = flattenSubkeys(encryptor.getRing());
        assertEquals(List.of(true, false), subkeys.stream().map(Subkey::isUnlocked).collect(Collectors.toList()));
        assertTrue(subkeys.stream().allMatch(sk -> sk.getPassphraseChars().length == 0));
        assertEquals(List.of("", ""), subkeys.stream().map(Subkey::getPassphrase).collect(Collectors.toList()));
    }

    @Test
    void encryptAndSignWithSpecificUid() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-2.asc")));
        unlockKey(encryptor.getRing(), PASSPHRASE);
        for (Key key : encryptor.getRing().getKeys()) {
            key.setSigningUid("foo");
        }
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-2.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        FileMetadata meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertEquals(List.of(
            "Test Key 2 <test-key-2@c02e.org>",
            "Test 2 (CODESurvey) <test-key-2@codesurvey.org>"
        ), flattenUids(meta.getVerified()));
        assertEquals(List.of("foo"), signingUids(meta.getVerified()));
    }

    @Test
    void encryptWithoutSigningWithMetadata() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        FileMetadata src = new FileMetadata("test.txt", FileMetadata.Format.BINARY, plainText().length(), 12345678);

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-2-pub.asc")));
        encryptor.setSigningAlgorithm(HashingAlgorithm.Unsigned);
        encryptor.encrypt(plainIn(), cipherOut, src);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-2.asc")));
        decryptor.setVerificationRequired(false);
        unlockKey(decryptor.getRing(), PASSPHRASE);
        FileMetadata meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertEquals(src.getName(), meta.getName());
        assertEquals(src.getLength(), meta.getLength());
        assertEquals(12345L, meta.getLastModified() / 1000L);
        assertEquals(src.getFormat(), meta.getFormat());
        assertFalse(isVerified(meta));
        assertFalse(hasSignatures(meta));
    }

    @Test
    void encryptAndSignWithMetadata() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        FileMetadata src = new FileMetadata("test.txt", FileMetadata.Format.BINARY, plainText().length(), 12345678);

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-2.asc")));
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.encrypt(plainIn(), cipherOut, src);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-2.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        FileMetadata meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertEquals(src.getName(), meta.getName());
        assertEquals(src.getLength(), meta.getLength());
        assertEquals(12345L, meta.getLastModified() / 1000L);
        assertEquals(src.getFormat(), meta.getFormat());
        assertEquals(List.of(
            "Test Key 2 <test-key-2@c02e.org>",
            "Test 2 (CODESurvey) <test-key-2@codesurvey.org>"
        ), flattenUids(meta.getVerified()));
        assertEquals(List.of("Test Key 2 <test-key-2@c02e.org>"), signingUids(meta.getVerified()));
        assertEquals(List.of("Test Key 2 <test-key-2@c02e.org>"), verifiedKeySigningUids(meta));
    }

    @Test
    void encryptAndSignWithPassphraseLessKey() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-no-passphrase.asc")));
        for (Key key : encryptor.getRing().getKeys()) {
            key.setNoPassphrase(true);
        }
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-no-passphrase.asc")));
        for (Key key : decryptor.getRing().getKeys()) {
            key.setNoPassphrase(true);
        }
        FileMetadata meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertTrue(isVerified(meta));
    }

    @Test
    void encryptAndSignWithNoUsageFlags() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(
            new KeyForEncryption(loadResourceFile("test-no-usage-ec-subkeys.asc")),
            new KeyForSigning(loadResourceFile("test-no-usage-ec-subkeys.asc"), PASSPHRASE)
        );
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(
            new KeyForVerification(loadResourceFile("test-no-usage-ec-subkeys.asc")),
            new KeyForDecryption(loadResourceFile("test-no-usage-ec-subkeys.asc"), PASSPHRASE)
        );
        FileMetadata meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        assertEquals(plainText(), plainOut.toString());
        assertTrue(isVerified(meta));
    }

    @ParameterizedTest
    @CsvSource({
        "-1, 65536",
        "0, 65536",
        "1, 512",
        "4096, 8192",
        "65535, 65536",
        "65536, 65536",
        "268435456, 65536",
        "4294967295, 65536",
        "1099511627776, 65536"
    })
    void bestPacketSize(long fileSize, int packetSize) {
        Encryptor encryptor = new Encryptor();
        FileMetadata meta = new FileMetadata().withLength(fileSize);
        assertEquals(packetSize, encryptor.bestPacketSize(meta));
    }

    @ParameterizedTest
    @CsvSource({
        "-1, 65536",
        "0, 65536",
        "1, 1",
        "4096, 4096",
        "65535, 65535",
        "65536, 65536",
        "65537, 65536",
        "1048576, 65536",
        "4294967295, 65536",
        "1099511627776, 65536"
    })
    void getCopyBuffer(long inputSize, int bufferSize) {
        Encryptor encryptor = new Encryptor();
        assertEquals(bufferSize, encryptor.getCopyBuffer(inputSize).length);
    }

    @Test
    void getCopyBufferUsesMetadataLength() {
        Encryptor encryptor = new Encryptor();
        FileMetadata meta = new FileMetadata().withLength(2048);
        assertEquals(2048, encryptor.getCopyBuffer(meta).length);
        assertEquals(65536, encryptor.getCopyBuffer((FileMetadata) null).length);
    }

    @Test
    void buildSymmetricKeyEncryptorSelectsArgon2Kdf() throws Exception {
        ExposingEncryptor encryptor = (ExposingEncryptor) new ExposingEncryptor()
                .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                .withSymmetricPassphrase(PASSPHRASE)
                .withPassphraseKeyDerivation(PassphraseKeyDerivation.Argon2)
                .withArgon2Parameters(Argon2Parameters.MEMORY_CONSTRAINED);

        assertNotNull(encryptor.exposeBuildSymmetricKeyEncryptor(null));

        byte[] ciphertext = PgpPacketInspectSupport.encryptToBytes(encryptor, new byte[]{42});
        PgpPacketInspectSupport.assertSymmetricS2kIsArgon2(ciphertext);
    }

    @Test
    void buildSymmetricKeyEncryptorSelectsIteratedSaltedKdf() throws Exception {
        ExposingEncryptor encryptor = (ExposingEncryptor) new ExposingEncryptor()
                .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                .withSymmetricPassphrase(PASSPHRASE)
                .withPassphraseKeyDerivation(PassphraseKeyDerivation.IteratedSalted)
                .withDeriviationAlgorithm(HashingAlgorithm.SHA512)
                .withKeyDeriviationWorkFactor(10);

        assertNotNull(encryptor.exposeBuildSymmetricKeyEncryptor(null));

        byte[] ciphertext = PgpPacketInspectSupport.encryptToBytes(encryptor, new byte[]{42});
        PgpPacketInspectSupport.assertSymmetricS2kIsIteratedSalted(ciphertext);
    }

    @ParameterizedTest
    @MethodSource("estimateUnarmoredNoKeysCases")
    void estimateUnarmoredOutputFileSizeWithNoKeys(long inputSize, int outputSize) {
        Encryptor encryptor = new Encryptor();
        assertEquals(outputSize, encryptor.estimateOutFileBufferSize(inputSize));
    }

    @ParameterizedTest
    @MethodSource("estimateArmoredNoKeysCases")
    void estimateArmoredOutputFileSizeWithNoKeys(long inputSize, int outputSize) {
        Encryptor encryptor = new Encryptor();
        encryptor.setAsciiArmored(true);
        assertEquals(outputSize, encryptor.estimateOutFileBufferSize(inputSize));
    }

    @ParameterizedTest
    @MethodSource("estimateUnarmoredMultipleKeysCases")
    void estimateUnarmoredOutputFileSizeWithMultipleKeys(long inputSize, int outputSize) throws Exception {
        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-ring.asc")));
        for (Key key : encryptor.getRing().findAll("key-1")) {
            key.getSigning().setForSigning(false);
        }
        assertEquals(outputSize, encryptor.estimateOutFileBufferSize(inputSize));
    }

    @ParameterizedTest
    @CsvSource({
        "0", "1", "4096", "43981", "65536"
    })
    void checkEstimateAgainstActualForUnarmoredOutputFileSize(int inputSize) throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-ring.asc")));
        for (Key key : encryptor.getRing().findAll("key-1")) {
            key.getSigning().setForSigning(false);
        }
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.setCompressionAlgorithm(CompressionAlgorithm.Uncompressed);

        InputStream plainIn = new ByteArrayInputStream(new byte[inputSize]);
        encryptor.encrypt(plainIn, cipherOut);
        int estimate = encryptor.estimateOutFileBufferSize(inputSize);
        int actual = cipherOut.size();
        assertTrue(estimate > actual);
        assertTrue(estimate - actual < 0x800);
    }

    @ParameterizedTest
    @CsvSource({
        "0", "1", "4096", "43981", "65536"
    })
    void checkEstimateAgainstActualForArmoredOutputFileSize(int inputSize) throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-ring.asc")));
        encryptor.setAsciiArmored(true);
        for (Key key : encryptor.getRing().findAll("key-1")) {
            key.getSigning().setForSigning(false);
        }
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.setCompressionAlgorithm(CompressionAlgorithm.Uncompressed);

        InputStream plainIn = new ByteArrayInputStream(new byte[inputSize]);
        encryptor.encrypt(plainIn, cipherOut);
        int estimate = encryptor.estimateOutFileBufferSize(inputSize);
        int actual = cipherOut.size();
        assertTrue(estimate > actual);
        assertTrue(estimate - actual < 0x800);
    }

    @Test
    void encryptAndSignABigStream() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        InputStream plainIn = new ByteArrayInputStream(new byte[0x100000]);

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.encrypt(plainIn, cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        FileMetadata meta = decryptor.decrypt(cipherIn(cipherOut), plainOut);

        byte[] plainBytes = plainOut.toByteArray();
        assertEquals(0x100000, plainBytes.length);
        for (byte plainByte : plainBytes) {
            assertEquals(0, plainByte);
        }
        assertEquals(0x100000, meta.getLength());
        assertTrue(isVerified(meta));
    }

    @Test
    void armoredHeaderApiCrud() throws Exception {
        Encryptor encryptor = new Encryptor();
        assertSame(Collections.emptyMap(), encryptor.getArmoredHeaders());

        encryptor.setArmoredHeaders(Map.of("A", "1", "B", "2"));
        assertEquals("1", encryptor.getArmoredHeader("A"));
        assertEquals("2", encryptor.getArmoredHeader("B"));
        assertThrows(UnsupportedOperationException.class,
                () -> encryptor.getArmoredHeaders().put("Z", "9"));

        encryptor.addArmoredHeaders(Map.of("C", "3"));
        encryptor.addArmoredHeaders(null);
        assertEquals("3", encryptor.getArmoredHeader("C"));

        assertEquals("1", encryptor.removeArmoredHeader("A"));
        assertNull(encryptor.getArmoredHeader("A"));
        assertEquals("2", encryptor.updateArmoredHeader("B", null));
        assertNull(encryptor.getArmoredHeader("B"));

        assertSame(encryptor, encryptor.withArmoredHeaders(Map.of("X", "y")));
        assertEquals("y", encryptor.getArmoredHeader("X"));
        assertNull(encryptor.getArmoredHeader("A"));
        assertNull(encryptor.getArmoredHeader("B"));
        assertNull(encryptor.getArmoredHeader("C"));

        assertNull(encryptor.updateArmoredHeader("fresh", "1"));
        assertEquals("1", encryptor.updateArmoredHeader("fresh", "2"));
    }

    @Test
    void configurationFluentSetters() throws Exception {
        Ring ring = new Ring(loadResource("test-key-1-pub.asc"));
        Encryptor encryptor = new Encryptor()
                .withCompressionLevel(9)
                .withMaxFileBufferSize(8192)
                .withRing(ring)
                .withLoggingEnabled(true);

        assertEquals(9, encryptor.getCompressionLevel());
        assertEquals(8192, encryptor.getMaxFileBufferSize());
        assertSame(ring, encryptor.getRing());
        assertTrue(encryptor.isLoggingEnabled());
    }

    @Test
    void configurationFluentMutations() {
        Encryptor encryptor = new Encryptor()
                .withCompressionAlgorithm(CompressionAlgorithm.Uncompressed)
                .withDeriviationAlgorithm(HashingAlgorithm.SHA256)
                .withKeyDeriviationWorkFactor(42)
                .withAeadChunkSize(8)
                .withArgon2Parameters(Argon2Parameters.MEMORY_CONSTRAINED);

        assertEquals(CompressionAlgorithm.Uncompressed, encryptor.getCompressionAlgorithm());
        assertEquals(HashingAlgorithm.SHA256, encryptor.getKeyDeriviationAlgorithm());
        assertEquals(42, encryptor.getKeyDeriviationWorkFactor());
        assertEquals(8, encryptor.getAeadChunkSize());
        assertEquals(Argon2Parameters.MEMORY_CONSTRAINED, encryptor.getArgon2Parameters());

        encryptor.setSymmetricPassphraseChars(PASSPHRASE.toCharArray());
        assertEquals(PASSPHRASE, encryptor.getSymmetricPassphrase());

        encryptor.setArgon2Parameters(null);
        assertEquals(Argon2Parameters.GPG_RECOMMENDED, encryptor.getArgon2Parameters());
        assertSame(encryptor,
                encryptor.withArgon2Parameters(Argon2Parameters.MEMORY_CONSTRAINED));
        assertEquals(Argon2Parameters.MEMORY_CONSTRAINED, encryptor.getArgon2Parameters());
    }

    @Test
    void buildEncryptionDetailsReflectsEncryptorState() {
        ExposingEncryptor aeadEncryptor = (ExposingEncryptor) new ExposingEncryptor()
                .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                .withEncryptionProtection(EncryptionProtection.Aead)
                .withEncryptionAlgorithm(EncryptionAlgorithm.AES128)
                .withAeadAlgorithm(AeadAlgorithm.Eax)
                .withAeadPacketStyle(AeadPacketStyle.V5)
                .withAeadChunkSize(8)
                .withSymmetricPassphrase(PASSPHRASE)
                .withPassphraseKeyDerivation(PassphraseKeyDerivation.Argon2)
                .withArgon2Parameters(Argon2Parameters.MEMORY_CONSTRAINED);
        aeadEncryptor.setOpenPgpProfileWithoutDefaults(OpenPgpProfile.Modern);

        EncryptionDetails aeadDetails = aeadEncryptor.exposeBuildEncryptionDetails();
        assertEquals(EncryptionProtection.Aead, aeadDetails.getProtection());
        assertEquals(EncryptionAlgorithm.AES128, aeadDetails.getSessionCipher());
        assertEquals(AeadAlgorithm.Eax, aeadDetails.getAeadAlgorithm());
        assertEquals(AeadPacketStyle.V5, aeadDetails.getAeadPacketStyle());
        assertEquals(8, aeadDetails.getAeadChunkSize());
        assertEquals(PassphraseKeyDerivation.Argon2, aeadDetails.getPassphraseKeyDerivation());
        assertEquals(Argon2Parameters.MEMORY_CONSTRAINED, aeadDetails.getArgon2Parameters());
        assertEquals(OpenPgpProfile.Modern, aeadDetails.getDetectedProfile());

        ExposingEncryptor mdcEncryptor = (ExposingEncryptor) new ExposingEncryptor()
                .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                .withEncryptionProtection(EncryptionProtection.Mdc)
                .withSymmetricPassphrase(PASSPHRASE)
                .withPassphraseKeyDerivation(PassphraseKeyDerivation.IteratedSalted);
        mdcEncryptor.setOpenPgpProfileWithoutDefaults(OpenPgpProfile.Classic);

        EncryptionDetails mdcDetails = mdcEncryptor.exposeBuildEncryptionDetails();
        assertEquals(EncryptionProtection.Mdc, mdcDetails.getProtection());
        assertNull(mdcDetails.getAeadAlgorithm());
        assertNull(mdcDetails.getAeadPacketStyle());
        assertEquals(0, mdcDetails.getAeadChunkSize());
        assertEquals(PassphraseKeyDerivation.IteratedSalted,
                mdcDetails.getPassphraseKeyDerivation());
        assertNull(mdcDetails.getArgon2Parameters());
        assertEquals(OpenPgpProfile.Classic, mdcDetails.getDetectedProfile());

        ExposingEncryptor keyEncryptor = (ExposingEncryptor) new ExposingEncryptor()
                .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                .withModernDefaults();

        EncryptionDetails keyDetails = keyEncryptor.exposeBuildEncryptionDetails();
        assertNull(keyDetails.getPassphraseKeyDerivation());
        assertNull(keyDetails.getArgon2Parameters());
    }

    private static final class ExposingEncryptor extends Encryptor {
        void setOpenPgpProfileWithoutDefaults(OpenPgpProfile profile) {
            openPgpProfile = profile;
        }

        EncryptionDetails exposeBuildEncryptionDetails() {
            return buildEncryptionDetails();
        }

        org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator exposeBuildSymmetricKeyEncryptor(
                FileMetadata meta) throws PGPException {
            return buildSymmetricKeyEncryptor(meta);
        }
    }

    @Test
    void symmetricArgon2EncryptionDetailsOnDecrypt() throws Exception {
        Encryptor encryptor = new Encryptor()
                .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                .withEncryptionProtection(EncryptionProtection.Aead)
                .withAeadAlgorithm(AeadAlgorithm.Ocb)
                .withAeadPacketStyle(AeadPacketStyle.V6)
                .withPassphraseKeyDerivation(PassphraseKeyDerivation.Argon2)
                .withArgon2Parameters(Argon2Parameters.MEMORY_CONSTRAINED)
                .withSymmetricPassphrase(PASSPHRASE);
        Decryptor decryptor = new Decryptor()
                .withVerificationRequired(false)
                .withSymmetricPassphrase(PASSPHRASE);

        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        encryptor.encrypt(plainIn(), cipherOut);

        DecryptionResult result = decryptor.decryptWithFullDetails(
                cipherIn(cipherOut), new ByteArrayOutputStream());
        EncryptionDetails details = result.getFileMetadata().getEncryptionDetails();

        assertEquals(EncryptionProtection.Aead, details.getProtection());
        assertEquals(AeadAlgorithm.Ocb, details.getAeadAlgorithm());
        assertEquals(PassphraseKeyDerivation.Argon2, details.getPassphraseKeyDerivation());
        assertEquals(Argon2Parameters.MEMORY_CONSTRAINED, details.getArgon2Parameters());
    }

    @Test
    void encryptBytesToPathAndFile(@TempDir Path tempDir) throws Exception {
        byte[] plain = "bytes path round-trip".getBytes();
        Path cipherPath = tempDir.resolve("cipher.gpg");
        File cipherFile = tempDir.resolve("cipher-file.gpg").toFile();
        Files.write(cipherPath, "stale".getBytes());

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")))
                .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                .withLoggingEnabled(true);
        unlockKey(encryptor.getRing(), PASSPHRASE);

        FileMetadata encMeta = encryptor.encryptBytes(plain, "bytesPath", cipherPath);
        assertEquals("bytesPath", encMeta.getName());
        assertTrue(Files.exists(cipherPath));

        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1.asc")))
                .withVerificationRequired(false);
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.decrypt(new ByteArrayInputStream(Files.readAllBytes(cipherPath)), plainOut);
        assertArrayEquals(plain, plainOut.toByteArray());

        encryptor.encryptBytes(plain, "bytesFile", cipherFile);
        assertTrue(cipherFile.exists());
    }

    @Test
    void encryptSamePathThrows(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("same.txt");
        Files.writeString(file, plainText());
        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(encryptor.getRing(), PASSPHRASE);

        assertThrows(IOException.class, () -> encryptor.encrypt(file, file));
    }

    @Test
    void armorManipulatorEmptyIgnoresUpdates() {
        EncryptedAsciiArmorHeadersManipulator.EMPTY.setHeader("A", "B");
        EncryptedAsciiArmorHeadersManipulator.EMPTY.removeHeader("A");
        EncryptedAsciiArmorHeadersManipulator.EMPTY.updateHeaders(Map.of("A", "B"));
    }

    @Test
    void armorManipulatorRemoveAndUpdateHeaders() throws Exception {
        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")))
                .withAsciiArmored(true)
                .withArmorHeadersCallback((enc, meta, manipulator) -> {
                    manipulator.updateHeaders(new HashMap<>(Map.of("Callback", "yes")));
                    manipulator.removeHeader("Version");
                });
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.encrypt(plainIn(), cipherOut);

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        DecryptionResult result = decryptor.decryptWithFullDetails(cipherIn(cipherOut), plainOut);

        assertTrue(result.getArmorHeaders().stream().noneMatch(h -> h.startsWith("Version:")));
        assertTrue(result.getArmorHeaders().stream().anyMatch(h -> h.equals("Callback: yes")));
    }

    @Test
    void testClone() throws Exception {
        Encryptor original = new Encryptor(new Ring(loadResource("test-ring.asc")))
            .withSymmetricPassphraseChars(new char[] {'h', 'e', 'l', 'l', 'o'})
            .withArmoredHeader("hello", "world");
        Encryptor cloned = original.clone();
        assertNotSame(original, cloned);
        assertSame(original.log, cloned.log);
        assertNotSame(original.getRing(), cloned.getRing());
        assertNotSame(original.getSymmetricPassphraseChars(), cloned.getSymmetricPassphraseChars());
        assertArrayEquals(original.getSymmetricPassphraseChars(), cloned.getSymmetricPassphraseChars());

        Map<String, String> orgHdrs = original.getArmoredHeaders();
        Map<String, String> clnHdrs = cloned.getArmoredHeaders();
        assertNotSame(orgHdrs, clnHdrs);
        assertEquals(orgHdrs.size(), clnHdrs.size());
        for (Map.Entry<String, String> entry : orgHdrs.entrySet()) {
            assertSame(entry.getValue(), clnHdrs.get(entry.getKey()));
        }
    }

    static Stream<Arguments> estimateUnarmoredNoKeysCases() {
        return Stream.of(
            Arguments.of(-1L, 0x1ff),
            Arguments.of(0L, 0x200),
            Arguments.of(1L, 0x201),
            Arguments.of(0x1000L, 0x1200),
            Arguments.of(0xffffL, 0x101ff),
            Arguments.of(0x10000L, 0x10200),
            Arguments.of(0xfffffL, 0x100000),
            Arguments.of(0x100000L, 0x100000),
            Arguments.of(0x100001L, 0x100000),
            Arguments.of(0x10000000L, 0x100000),
            Arguments.of(0xffffffffL, 0x100000),
            Arguments.of(0x100000000000L, 0x100000)
        );
    }

    static Stream<Arguments> estimateArmoredNoKeysCases() {
        return Stream.of(
            Arguments.of(-1L, 771),
            Arguments.of(0L, 773),
            Arguments.of(1L, 774),
            Arguments.of(0x1000L, 6320),
            Arguments.of(0xffffL, 89518),
            Arguments.of(0x10000L, 89520),
            Arguments.of(0xfffffL, 0x100000),
            Arguments.of(0x100000L, 0x100000),
            Arguments.of(0x100001L, 0x100000),
            Arguments.of(0x10000000L, 0x100000),
            Arguments.of(0xffffffffL, 0x100000),
            Arguments.of(0x100000000000L, 0x100000)
        );
    }

    static Stream<Arguments> estimateUnarmoredMultipleKeysCases() {
        return Stream.of(
            Arguments.of(-1L, 0x7ff),
            Arguments.of(0L, 0x800),
            Arguments.of(1L, 0x801),
            Arguments.of(0x1000L, 0x1800),
            Arguments.of(0xffffL, 0x107ff),
            Arguments.of(0x10000L, 0x10800),
            Arguments.of(0xfffffL, 0x100000),
            Arguments.of(0x100000L, 0x100000),
            Arguments.of(0x100001L, 0x100000),
            Arguments.of(0x10000000L, 0x100000),
            Arguments.of(0xffffffffL, 0x100000),
            Arguments.of(0x100000000000L, 0x100000)
        );
    }

    private static InputStream plainIn() {
        return new ByteArrayInputStream(plainText().getBytes());
    }

    private static InputStream cipherIn(ByteArrayOutputStream cipherOut) {
        return new ByteArrayInputStream(cipherOut.toByteArray());
    }

    private static File writeTempFile(File tempDir, String name, String content) throws IOException {
        File file = tempDir.toPath().resolve(name).toFile();
        Files.writeString(file.toPath(), content);
        return file;
    }

    private static List<String> signingUids(Ring ring) {
        return ring.getKeys().stream().map(Key::getSigningUid).collect(Collectors.toList());
    }

    private static List<List<String>> verifiedKeyUids(FileMetadata meta) {
        return meta.getVerified().getKeys().stream().map(Key::getUids).collect(Collectors.toList());
    }

    private static List<String> flattenUids(Ring ring) {
        return ring.getKeys().stream().flatMap(key -> key.getUids().stream()).collect(Collectors.toList());
    }

    private static List<String> verifiedKeySigningUids(FileMetadata meta) {
        return meta.getSignatures().stream()
            .map(FileMetadata.Signature::getVerifiedKey)
            .filter(key -> key != null)
            .map(Key::getSigningUid)
            .collect(Collectors.toList());
    }

    private static List<Boolean> signatureVerified(FileMetadata meta) {
        return meta.getSignatures().stream().map(FileMetadata.Signature::isVerified).collect(Collectors.toList());
    }

    private static List<Long> signatureKeyIds(FileMetadata meta) {
        return meta.getSignatures().stream().map(FileMetadata.Signature::getKeyId).collect(Collectors.toList());
    }

    private static List<String> signatureMasterShortIds(FileMetadata meta) {
        return meta.getSignatures().stream()
            .map(FileMetadata.Signature::getKey)
            .filter(key -> key != null)
            .map(key -> key.getMaster().getShortId())
            .collect(Collectors.toList());
    }

    private static List<Subkey> flattenSubkeys(Ring ring) {
        return ring.getKeys().stream().flatMap(key -> key.getSubkeys().stream()).collect(Collectors.toList());
    }

    private static void assertMultipleKeyDecryptMeta(FileMetadata meta) {
        assertEquals(List.of(
            "Test Key 1 <test-key-1@c02e.org>",
            "Test Key 2 <test-key-2@c02e.org>",
            "Test 2 (CODESurvey) <test-key-2@codesurvey.org>"
        ), flattenUids(meta.getVerified()));
        assertEquals(List.of(
            "Test Key 1 <test-key-1@c02e.org>",
            "Test Key 2 <test-key-2@c02e.org>"
        ), signingUids(meta.getVerified()));
        assertEquals(List.of(true, true), signatureVerified(meta));
        assertEquals(List.of(0x72A423A0013826C3L, 0xAFDB7B47BC3F6A4BL), signatureKeyIds(meta));
        assertEquals(List.of(
            "Test Key 1 <test-key-1@c02e.org>",
            "Test Key 2 <test-key-2@c02e.org>"
        ), verifiedKeySigningUids(meta));
    }
}
