package org.c02e.jpgpj;

import static org.c02e.jpgpj.support.PgpTestSupport.PASSPHRASE;
import static org.c02e.jpgpj.support.PgpTestSupport.formatDateGmt;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResource;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResourceFile;
import static org.c02e.jpgpj.support.PgpTestSupport.hasSignatures;
import static org.c02e.jpgpj.support.PgpTestSupport.isVerified;
import static org.c02e.jpgpj.support.PgpTestSupport.plainText;
import static org.c02e.jpgpj.support.PgpTestSupport.unlockKey;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.bouncycastle.openpgp.PGPException;
import org.c02e.jpgpj.Decryptor.VerificationType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class DecryptorTest {

    private static final List<Key> NULL_KEY_LIST = Collections.singletonList(null);

    private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

    @Test
    void verificationTypeSynchronizedWithVerificationRequired() {
        Decryptor decryptor = new Decryptor();
        assertTrue(decryptor.isVerificationRequired());
        assertEquals(VerificationType.Required, decryptor.getVerificationType());

        decryptor.setVerificationRequired(false);
        assertFalse(decryptor.isVerificationRequired());
        assertEquals(VerificationType.None, decryptor.getVerificationType());

        decryptor.setVerificationType(VerificationType.Required);
        assertTrue(decryptor.isVerificationRequired());
        assertEquals(VerificationType.Required, decryptor.getVerificationType());

        decryptor.setVerificationType(VerificationType.Optional);
        assertFalse(decryptor.isVerificationRequired());
        assertEquals(VerificationType.Optional, decryptor.getVerificationType());

        decryptor.setVerificationType(VerificationType.None);
        assertFalse(decryptor.isVerificationRequired());
        assertEquals(VerificationType.None, decryptor.getVerificationType());
    }

    @Test
    void decryptWithoutVerification() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.setVerificationRequired(false);
        FileMetadata meta = decryptor.decrypt(loadResource("test-encrypted-for-key-1.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertEquals(5, meta.getLength());
        assertEquals("2016-03-17", formatDateGmt(meta.getLastModified()));
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertFalse(isVerified(meta));
        assertFalse(hasSignatures(meta));
    }

    @Test
    void decryptWithVerification() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        FileMetadata meta = decryptor.decrypt(
            loadResource("test-encrypted-for-key-1-signed-by-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertEquals(5, meta.getLength());
        assertEquals("2016-03-17", formatDateGmt(meta.getLastModified()));
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertTrue(isVerified(meta));
        assertEquals(
            "pub v  880A1469 Test Key 2 <test-key-2@c02e.org>, Test 2 (CODESurvey) <test-key-2@codesurvey.org>\n"
                + "pub e  AFAFA3C5\n"
                + "pub v  BC3F6A4B",
            meta.getVerified().toString().trim()
        );
        assertEquals(List.of(""), signingUids(meta.getVerified()));
        assertEquals(List.of(true), signatureVerified(meta));
        assertEquals(List.of(0xAFDB7B47BC3F6A4BL), signatureKeyIds(meta));
        assertEquals(List.of("880A1469"), signatureMasterShortIds(meta));
        assertEquals(List.of(""), signatureSigningUids(meta));
        assertEquals(List.of("880A1469"), verifiedKeyMasterShortIds(meta));
        assertFalse(meta.getVerified().getKeys().isEmpty());
        assertTrue(meta.getSignatures().stream().allMatch(FileMetadata.Signature::isVerified));
    }

    @Test
    void decryptFileWithVerification(@TempDir File tempDir) throws Exception {
        Decryptor decryptor = new Decryptor(
            new Key(loadResourceFile("test-key-1.asc"), PASSPHRASE),
            new Key(loadResourceFile("test-key-2-pub.asc"))
        );
        File plainFile = tempDir.toPath().resolve("plain.txt").toFile();
        FileMetadata meta = decryptor.decrypt(
            loadResourceFile("test-encrypted-for-key-1-signed-by-key-2.txt.asc"), plainFile);

        assertEquals(plainText(), Files.readString(plainFile.toPath()));
        assertTrue(isVerified(meta));
        assertEquals(List.of("880A1469"), verifiedKeyMasterShortIds(meta));
    }

    @Test
    void decryptSameFile(@TempDir File tempDir) throws Exception {
        Decryptor decryptor = new Decryptor(
            new Key(loadResourceFile("test-key-1.asc"), PASSPHRASE),
            new Key(loadResourceFile("test-key-2-pub.asc"))
        );
        File testFile = tempDir.toPath().resolve("same.txt").toFile();
        Files.writeString(testFile.toPath(), "foo");
        assertThrows(IOException.class, () -> decryptor.decrypt(testFile, testFile));
        assertEquals("foo", Files.readString(testFile.toPath()));
    }

    @Test
    void decryptUnsignedFileWithVerification(@TempDir File tempDir) throws Exception {
        Decryptor decryptor = new Decryptor(
            new Key(loadResourceFile("test-key-1.asc"), PASSPHRASE),
            new Key(loadResourceFile("test-key-2-pub.asc"))
        );
        File plainFile = tempDir.toPath().resolve("plain.txt").toFile();
        VerificationException e = assertThrows(VerificationException.class, () ->
            decryptor.decrypt(loadResourceFile("test-encrypted-for-key-1.txt.asc"), plainFile));
        assertEquals("content not signed with a required key", e.getMessage());
        assertFalse(plainFile.exists());
    }

    @Test
    void decryptBadSignatureFileWithVerification(@TempDir File tempDir) throws Exception {
        Decryptor decryptor = new Decryptor(
            new Key(loadResourceFile("test-key-1.asc"), PASSPHRASE),
            new Key(loadResourceFile("test-key-2-pub.asc"))
        );
        File plainFile = tempDir.toPath().resolve("plain.txt").toFile();
        VerificationException e = assertThrows(VerificationException.class, () ->
            decryptor.decrypt(
                loadResourceFile("test-encrypted-for-key-1-signed-by-key-2-with-bad-signature.txt.asc"),
                plainFile));
        assertTrue(e.getMessage().startsWith("bad signature for key pub v"));
        assertTrue(e.getMessage().contains("880A1469"));
        assertTrue(e.getMessage().contains("Test Key 2"));
        assertFalse(plainFile.exists());
    }

    @Test
    void decryptSignedWithoutVerification() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.setVerificationRequired(false);
        FileMetadata meta = decryptor.decrypt(
            loadResource("test-encrypted-for-key-1-signed-by-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertEquals(5, meta.getLength());
        assertEquals("2016-03-17", formatDateGmt(meta.getLastModified()));
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertFalse(isVerified(meta));
        assertFalse(hasSignatures(meta));
    }

    @Test
    void decryptUnsignedWithOptionalVerification() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.setVerificationType(VerificationType.Optional);
        FileMetadata meta = decryptor.decrypt(loadResource("test-encrypted-for-key-1.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertFalse(isVerified(meta));
        assertFalse(hasSignatures(meta));
    }

    @Test
    void decryptSignedWithOptionalVerification() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.setVerificationType(VerificationType.Optional);
        FileMetadata meta = decryptor.decrypt(
            loadResource("test-encrypted-for-key-1-signed-by-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertTrue(isVerified(meta));
        assertEquals(List.of("880A1469"), verifiedKeyMasterShortIds(meta));
    }

    @Test
    void decryptBadSignatureStreamWithVerification() throws Exception {
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();

        assertThrows(VerificationException.class, () ->
            decryptor.decrypt(
                loadResource("test-encrypted-for-key-1-signed-by-key-2-with-bad-signature.txt.asc"),
                plainOut));

        assertEquals(plainText(), plainOut.toString());
    }

    @ParameterizedTest
    @EnumSource(VerificationType.class)
    void unsignedMessageRespectsVerificationType(VerificationType verificationType) throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.setVerificationType(verificationType);

        if (verificationType == VerificationType.Required) {
            VerificationException e = assertThrows(VerificationException.class, () ->
                decryptor.decrypt(loadResource("test-encrypted-for-key-1.txt.asc"), buf));
            assertEquals("content not signed with a required key", e.getMessage());
            assertEquals(0, buf.size());
        } else {
            FileMetadata meta = decryptor.decrypt(loadResource("test-encrypted-for-key-1.txt.asc"), buf);
            assertEquals(plainText(), buf.toString());
            assertFalse(isVerified(meta));
            assertTrue(meta.getVerified().getKeys().isEmpty());
        }
    }

    @Test
    void decryptBadSignatureWithOptionalVerification() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.setVerificationType(VerificationType.Optional);
        FileMetadata meta = decryptor.decrypt(
            loadResource("test-encrypted-for-key-1-signed-by-key-2-with-bad-signature.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertFalse(isVerified(meta));
        assertEquals(List.of(false), signatureVerified(meta));
        assertEquals(List.of(0xAFDB7B47BC3F6A4BL), signatureKeyIds(meta));
        assertEquals(List.of("880A1469"), signatureMasterShortIds(meta));
        assertEquals(NULL_KEY_LIST, verifiedKeys(meta));
    }

    @Test
    void decryptCamellia() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.setVerificationRequired(false);
        decryptor.decrypt(loadResource("test-encrypted-for-key-1-with-camellia.txt.asc"), buf);
        assertEquals(plainText(), buf.toString());
    }

    @Test
    void decryptWithoutPassphrase() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        DecryptionException e = assertThrows(DecryptionException.class, () ->
            decryptor.decrypt(loadResource("test-encrypted-for-key-1.txt.asc"), buf));
        assertEquals("no suitable decryption key found", e.getMessage());
    }

    @Test
    void decryptWithWrongPassphrase() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), "wrong!");
        PassphraseException e = assertThrows(PassphraseException.class, () ->
            decryptor.decrypt(loadResource("test-encrypted-for-key-1.txt.asc"), buf));
        assertEquals("incorrect passphrase for subkey sec+ed 970C7061", e.getMessage());
    }

    @Test
    void decryptWithoutAnyKey() {
        buf.reset();
        Decryptor decryptor = new Decryptor();
        DecryptionException e = assertThrows(DecryptionException.class, () ->
            decryptor.decrypt(loadResource("test-encrypted-for-key-1.txt.asc"), buf));
        assertEquals("no suitable decryption key found", e.getMessage());
    }

    @Test
    void decryptWithoutSecretKey() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring-pub.asc")));
        DecryptionException e = assertThrows(DecryptionException.class, () ->
            decryptor.decrypt(loadResource("test-encrypted-for-key-1.txt.asc"), buf));
        assertEquals("no suitable decryption key found", e.getMessage());
    }

    @Test
    void decryptWithoutVerificationKey() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.getRing().setKeys(
            decryptor.getRing().getKeys().stream()
                .filter(key -> !key.findAll("key-1").isEmpty())
                .collect(Collectors.toList())
        );
        VerificationException e = assertThrows(VerificationException.class, () ->
            decryptor.decrypt(loadResource("test-encrypted-for-key-1-signed-by-key-2.txt.asc"), buf));
        assertEquals("content not signed with a required key", e.getMessage());
    }

    @Test
    void decryptWithoutVerificationKeyWithOptionalVerification() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.getRing().setKeys(
            decryptor.getRing().getKeys().stream()
                .filter(key -> !key.findAll("key-1").isEmpty())
                .collect(Collectors.toList())
        );
        decryptor.setVerificationType(VerificationType.Optional);
        FileMetadata meta = decryptor.decrypt(
            loadResource("test-encrypted-for-key-1-signed-by-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertFalse(isVerified(meta));
        assertEquals(List.of(false), signatureVerified(meta));
        assertEquals(List.of(0xAFDB7B47BC3F6A4BL), signatureKeyIds(meta));
        assertEquals(NULL_KEY_LIST, signatureKeys(meta));
        assertEquals(NULL_KEY_LIST, verifiedKeys(meta));
    }

    @Test
    void decryptWithPublicAndPrivateVersionsOfSameKey() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(
            new Key(loadResourceFile("test-key-1-pub.asc")),
            new Key(loadResourceFile("test-key-1.asc"), PASSPHRASE),
            new Key(loadResourceFile("test-key-2-pub.asc"))
        );
        FileMetadata meta = decryptor.decrypt(
            loadResource("test-encrypted-for-key-1-signed-by-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertTrue(isVerified(meta));
        assertEquals(List.of("880A1469"), verifiedKeyMasterShortIds(meta));
    }

    @Test
    void decryptSymmetricWithoutVerification() throws Exception {
        buf.reset();
        FileMetadata meta = new Decryptor()
            .withVerificationRequired(false)
            .withSymmetricPassphrase(PASSPHRASE)
            .decrypt(loadResource("test-encrypted-with-passphrase.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertEquals(5, meta.getLength());
        assertEquals("2016-03-23", formatDateGmt(meta.getLastModified()));
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertFalse(isVerified(meta));
        assertFalse(hasSignatures(meta));
    }

    @Test
    void decryptSymmetricWithWrongPassphrase() {
        buf.reset();
        PassphraseException e = assertThrows(PassphraseException.class, () ->
            new Decryptor()
                .withVerificationRequired(false)
                .withSymmetricPassphrase("foo")
                .decrypt(loadResource("test-encrypted-with-passphrase.txt.asc"), buf));
        assertEquals("incorrect passphrase for symmetric key", e.getMessage());
    }

    @Test
    void decryptSymmetricWithoutVerificationKey() {
        buf.reset();
        VerificationException e = assertThrows(VerificationException.class, () ->
            new Decryptor()
                .withSymmetricPassphrase(PASSPHRASE)
                .decrypt(loadResource("test-encrypted-with-passphrase.txt.asc"), buf));
        assertEquals("content not signed with a required key", e.getMessage());
    }

    @Test
    void decryptSymmetricWithoutVerificationKeyWithOptionalVerification() throws Exception {
        buf.reset();
        FileMetadata meta = new Decryptor()
            .withSymmetricPassphrase(PASSPHRASE)
            .withVerificationType(VerificationType.Optional)
            .decrypt(loadResource("test-encrypted-for-key-1-and-passphrase-signed-by-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertEquals(5, meta.getLength());
        assertEquals("2016-03-23", formatDateGmt(meta.getLastModified()));
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertFalse(isVerified(meta));
        assertEquals(List.of(false), signatureVerified(meta));
        assertEquals(List.of(0xAFDB7B47BC3F6A4BL), signatureKeyIds(meta));
        assertEquals(NULL_KEY_LIST, signatureKeys(meta));
        assertEquals(NULL_KEY_LIST, verifiedKeys(meta));
    }

    @Test
    void decryptSymmetricWithVerification() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring-pub.asc")))
            .withSymmetricPassphrase(PASSPHRASE);
        FileMetadata meta = decryptor.decrypt(
            loadResource("test-encrypted-for-key-1-and-passphrase-signed-by-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertEquals(5, meta.getLength());
        assertEquals("2016-03-23", formatDateGmt(meta.getLastModified()));
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertTrue(isVerified(meta));
        assertEquals(List.of("880A1469"), verifiedKeyMasterShortIds(meta));
    }

    @Test
    void decryptOptionalSymmetricWithKeyInstead() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        decryptor.setSymmetricPassphrase("foo");
        FileMetadata meta = decryptor.decrypt(
            loadResource("test-encrypted-for-key-1-and-passphrase-signed-by-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertEquals(5, meta.getLength());
        assertEquals("2016-03-23", formatDateGmt(meta.getLastModified()));
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertTrue(isVerified(meta));
        assertEquals(List.of("880A1469"), verifiedKeyMasterShortIds(meta));
    }

    @Test
    void decryptSymmetricAndClearPassphrase() throws Exception {
        buf.reset();
        char[] passphrase = PASSPHRASE.toCharArray();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring-pub.asc")))
            .withSymmetricPassphraseChars(passphrase);
        FileMetadata meta = decryptor.decrypt(
            loadResource("test-encrypted-for-key-1-and-passphrase-signed-by-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertTrue(isVerified(meta));

        passphrase[0] = 'x';
        assertEquals('x', decryptor.getSymmetricPassphraseChars()[0]);

        buf.reset();
        PassphraseException e = assertThrows(PassphraseException.class, () ->
            decryptor.decrypt(loadResource("test-encrypted-with-passphrase.txt.asc"), buf));
        assertEquals("incorrect passphrase for symmetric key", e.getMessage());

        decryptor.clearSecrets();
        assertArrayEquals(new char[] {0, 0, 0, 0}, passphrase);
        assertArrayEquals(new char[0], decryptor.getSymmetricPassphraseChars());
        assertEquals("", decryptor.getSymmetricPassphrase());

        buf.reset();
        DecryptionException de = assertThrows(DecryptionException.class, () ->
            decryptor.decrypt(loadResource("test-encrypted-with-passphrase.txt.asc"), buf));
        assertEquals("no suitable decryption key found", de.getMessage());
    }

    @Test
    void decryptAndClearSecrets() throws Exception {
        buf.reset();
        char[] passphrase = PASSPHRASE.toCharArray();
        Decryptor decryptor = new Decryptor(
            new Key(loadResourceFile("test-key-1.asc"), passphrase),
            new Key(loadResourceFile("test-key-2-pub.asc"))
        );
        FileMetadata meta = decryptor.decrypt(
            loadResource("test-encrypted-for-key-1-signed-by-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertTrue(isVerified(meta));

        decryptor.clearSecrets();
        List<Subkey> subkeys = flattenSubkeys(decryptor.getRing());
        assertArrayEquals(new char[] {0, 0, 0, 0}, passphrase);
        assertEquals(Arrays.asList(false, false, false, false, false),
            subkeys.stream().map(Subkey::isUnlocked).collect(Collectors.toList()));
        assertTrue(subkeys.stream().allMatch(sk -> sk.getPassphraseChars().length == 0));
        assertTrue(subkeys.stream().allMatch(sk -> sk.getPassphrase().isEmpty()));

        buf.reset();
        DecryptionException e = assertThrows(DecryptionException.class, () ->
            decryptor.decrypt(loadResource("test-encrypted-for-key-1-signed-by-key-2.txt.asc"), buf));
        assertEquals("no suitable decryption key found", e.getMessage());
    }

    @Test
    void decryptWithoutCachingPassphrase() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(
            new Key(loadResourceFile("test-key-1.asc")),
            new Key(loadResourceFile("test-key-2-pub.asc"))
        );
        flattenSubkeys(decryptor.getRing()).stream()
            .filter(sk -> "970C7061".equals(sk.getShortId()))
            .findFirst()
            .orElseThrow()
            .unlock(PASSPHRASE.toCharArray());
        FileMetadata meta = decryptor.decrypt(
            loadResource("test-encrypted-for-key-1-signed-by-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertTrue(isVerified(meta));

        List<Subkey> subkeys = flattenSubkeys(decryptor.getRing());
        assertEquals(Arrays.asList(false, true, false, false, false),
            subkeys.stream().map(Subkey::isUnlocked).collect(Collectors.toList()));
        assertTrue(subkeys.stream().allMatch(sk -> sk.getPassphraseChars().length == 0));
        assertTrue(subkeys.stream().allMatch(sk -> sk.getPassphrase().isEmpty()));
    }

    @Test
    void decryptWithOldStyleSignatureVerification() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);
        FileMetadata meta = decryptor.decrypt(
            loadResource("test-encrypted-for-key-1-signed-by-key-2-with-pgp2-compatibility.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertEquals(5, meta.getLength());
        assertEquals("2018-01-18", formatDateGmt(meta.getLastModified()));
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertTrue(isVerified(meta));
        assertEquals(
            "pub v  880A1469 Test Key 2 <test-key-2@c02e.org>, Test 2 (CODESurvey) <test-key-2@codesurvey.org>\n"
                + "pub e  AFAFA3C5\n"
                + "pub v  BC3F6A4B",
            meta.getVerified().toString().trim()
        );
        assertEquals(List.of(""), signingUids(meta.getVerified()));
        assertEquals(List.of("880A1469"), verifiedKeyMasterShortIds(meta));
    }

    @Test
    void verifySignedBy1Of2Keys() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring-pub.asc")));
        FileMetadata meta = decryptor.decrypt(loadResource("test-signed-by-key-1.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertEquals(5, meta.getLength());
        assertEquals("2016-03-22", formatDateGmt(meta.getLastModified()));
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertTrue(isVerified(meta));
        assertEquals(List.of("013826C3"), masterShortIds(meta.getVerified()));
        assertEquals(List.of(""), signingUids(meta.getVerified()));
        assertEquals(List.of("013826C3"), verifiedKeyMasterShortIds(meta));
    }

    @Test
    void verifySignedByMultipleKeys() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring-pub.asc")));
        FileMetadata meta = decryptor.decrypt(loadResource("test-signed-by-key-1-and-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertEquals(5, meta.getLength());
        assertEquals("2016-03-22", formatDateGmt(meta.getLastModified()));
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertTrue(isVerified(meta));
        assertEquals(List.of("880A1469", "013826C3"), masterShortIds(meta.getVerified()));
        assertEquals(List.of("", ""), signingUids(meta.getVerified()));
        assertEquals(List.of("880A1469", "013826C3"), verifiedKeyMasterShortIds(meta));
    }

    @Test
    void verifyWithoutAnyKey() {
        buf.reset();
        VerificationException e = assertThrows(VerificationException.class, () ->
            new Decryptor().decrypt(loadResource("test-signed-by-key-1.txt.asc"), buf));
        assertEquals("content not signed with a required key", e.getMessage());
    }

    @Test
    void verifyOptionallyWithoutAnyKey() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor();
        decryptor.setVerificationType(VerificationType.Optional);
        FileMetadata meta = decryptor.decrypt(loadResource("test-signed-by-key-1.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertEquals(5, meta.getLength());
        assertEquals("2016-03-22", formatDateGmt(meta.getLastModified()));
        assertEquals(FileMetadata.Format.BINARY, meta.getFormat());
        assertFalse(isVerified(meta));
        assertEquals(List.of(false), signatureVerified(meta));
        assertEquals(List.of(0x72A423A0013826C3L), signatureKeyIds(meta));
        assertEquals(NULL_KEY_LIST, signatureKeys(meta));
        assertEquals(NULL_KEY_LIST, verifiedKeys(meta));
    }

    @Test
    void decryptNullStream() {
        buf.reset();
        PGPException e = assertThrows(PGPException.class, () ->
            new Decryptor().decrypt(null, buf));
        assertEquals("not a pgp message", e.getMessage());
    }

    @Test
    void decryptEmptyMessage() {
        buf.reset();
        PGPException e = assertThrows(PGPException.class, () ->
            new Decryptor().decrypt(new ByteArrayInputStream(new byte[0]), buf));
        assertEquals("not a pgp message", e.getMessage());
    }

    @Test
    void decryptGarbage() {
        buf.reset();
        PGPException e = assertThrows(PGPException.class, () ->
            new Decryptor().decrypt(
                new ByteArrayInputStream("garbage".getBytes(StandardCharsets.UTF_8)), buf));
        assertEquals("not a pgp message", e.getMessage());
    }

    @Test
    void decryptStreamWithoutMarkSupport() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(
            new Key(markUnsupported("test-key-1.asc"), PASSPHRASE),
            new Key(markUnsupported("test-key-2-pub.asc"))
        );
        FileMetadata meta = decryptor.decrypt(
            markUnsupported("test-encrypted-for-key-1-signed-by-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertTrue(isVerified(meta));
    }

    @Test
    void configurationFluentSetters() throws Exception {
        Ring ring = new Ring(loadResource("test-ring.asc"));
        Decryptor decryptor = new Decryptor()
                .withMaxFileBufferSize(4096)
                .withCopyFileBufferSize(2048)
                .withRing(ring)
                .withLoggingEnabled(true);

        assertEquals(4096, decryptor.getMaxFileBufferSize());
        assertEquals(2048, decryptor.getCopyFileBufferSize());
        assertSame(ring, decryptor.getRing());
        assertTrue(decryptor.isLoggingEnabled());
    }

    @Test
    void decryptPathRoundTrip(@TempDir Path tempDir) throws Exception {
        Path cipherPath = tempDir.resolve("cipher.asc");
        Path plainPath = tempDir.resolve("plain.txt");
        Files.writeString(plainPath, plainText());

        Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
        unlockKey(encryptor.getRing(), PASSPHRASE);
        encryptor.encrypt(plainPath, cipherPath);

        Files.writeString(plainPath, "stale");
        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-key-1.asc")))
                .withLoggingEnabled(true);
        unlockKey(decryptor.getRing(), PASSPHRASE);
        FileMetadata meta = decryptor.decrypt(cipherPath, plainPath);

        assertEquals(plainText(), Files.readString(plainPath));
        assertEquals("plain.txt", meta.getName());
    }

    @Test
    void decryptSamePathThrows(@TempDir Path tempDir) throws Exception {
        Path cipher = tempDir.resolve("message.asc");
        Files.write(cipher, loadResource("test-encrypted-for-key-1.txt.asc").readAllBytes());

        Decryptor decryptor = new Decryptor(new Ring(loadResource("test-ring.asc")));
        unlockKey(decryptor.getRing(), PASSPHRASE);

        assertThrows(IOException.class, () -> decryptor.decrypt(cipher, cipher));
    }

    @Test
    void decryptSignedByUnknownKeyWithLoggingEnabled() throws Exception {
        buf.reset();
        Decryptor decryptor = new Decryptor(new Key(loadResource("test-key-1.asc")))
                .withVerificationRequired(false)
                .withLoggingEnabled(true);
        unlockKey(decryptor.getRing().getKeys().get(0));
        FileMetadata meta = decryptor.decrypt(
                loadResource("test-encrypted-for-key-1-signed-by-key-2.txt.asc"), buf);

        assertEquals(plainText(), buf.toString());
        assertEquals("test.txt", meta.getName());
        assertFalse(isVerified(meta));
    }

    @Test
    void testClone() throws Exception {
        Decryptor original = new Decryptor(new Ring(loadResource("test-ring.asc")))
            .withSymmetricPassphraseChars(new char[] {'h', 'e', 'l', 'l', 'o'});
        Decryptor cloned = original.clone();
        assertNotSame(original, cloned);
        assertSame(original.log, cloned.log);
        assertNotSame(original.getRing(), cloned.getRing());
        assertNotSame(original.getSymmetricPassphraseChars(), cloned.getSymmetricPassphraseChars());
        assertArrayEquals(original.getSymmetricPassphraseChars(), cloned.getSymmetricPassphraseChars());
    }

    private static InputStream markUnsupported(String resource) {
        return new MarkUnsupportedInputStream(loadResource(resource));
    }

    private static List<Subkey> flattenSubkeys(Ring ring) {
        return ring.getKeys().stream()
            .flatMap(key -> key.getSubkeys().stream())
            .collect(Collectors.toList());
    }

    private static List<String> signingUids(Ring ring) {
        return ring.getKeys().stream().map(Key::getSigningUid).collect(Collectors.toList());
    }

    private static List<String> masterShortIds(Ring ring) {
        return ring.getKeys().stream().map(key -> key.getMaster().getShortId()).collect(Collectors.toList());
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

    private static List<String> signatureSigningUids(FileMetadata meta) {
        return meta.getSignatures().stream()
            .map(FileMetadata.Signature::getKey)
            .filter(key -> key != null)
            .map(Key::getSigningUid)
            .collect(Collectors.toList());
    }

    private static List<String> verifiedKeyMasterShortIds(FileMetadata meta) {
        return meta.getSignatures().stream()
            .map(FileMetadata.Signature::getVerifiedKey)
            .filter(key -> key != null)
            .map(key -> key.getMaster().getShortId())
            .collect(Collectors.toList());
    }

    private static List<Key> signatureKeys(FileMetadata meta) {
        return meta.getSignatures().stream().map(FileMetadata.Signature::getKey).collect(Collectors.toList());
    }

    private static List<Key> verifiedKeys(FileMetadata meta) {
        return meta.getSignatures().stream().map(FileMetadata.Signature::getVerifiedKey).collect(Collectors.toList());
    }

    private static class MarkUnsupportedInputStream extends BufferedInputStream {
        MarkUnsupportedInputStream(InputStream wrapped) {
            super(wrapped);
        }

        @Override
        public boolean markSupported() {
            return false;
        }
    }
}
