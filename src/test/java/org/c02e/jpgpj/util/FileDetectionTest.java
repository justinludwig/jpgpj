package org.c02e.jpgpj.util;

import static org.c02e.jpgpj.support.PgpTestSupport.PASSPHRASE;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResource;
import static org.c02e.jpgpj.support.PgpTestSupport.plainText;
import static org.c02e.jpgpj.support.PgpTestSupport.unlockKeys;
import static org.c02e.jpgpj.util.FileDetection.ContainerType.ASCII_ARMOR;
import static org.c02e.jpgpj.util.FileDetection.ContainerType.KEYBOX;
import static org.c02e.jpgpj.util.FileDetection.ContainerType.PGP;
import static org.c02e.jpgpj.util.FileDetection.ContainerType.UNKNOWN;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.c02e.jpgpj.CompressionAlgorithm;
import org.c02e.jpgpj.Encryptor;
import org.c02e.jpgpj.EncryptionAlgorithm;
import org.c02e.jpgpj.HashingAlgorithm;
import org.c02e.jpgpj.Ring;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class FileDetectionTest {

    private ByteArrayOutputStream cipherOut;

    @BeforeEach
    void setUp() {
        cipherOut = new ByteArrayOutputStream();
    }

    @Nested
    class DetectContainer {

        @Test
        void detectUnknownContainerWhenNull() throws Exception {
            assertEquals(UNKNOWN, FileDetection.detectContainer(null).type);
        }

        @Test
        void detectUnknownContainerWhenEmpty() throws Exception {
            assertEquals(UNKNOWN, FileDetection.detectContainer(content("")).type);
        }

        @Test
        void detectUnknownContainerWhenGarbage() throws Exception {
            assertEquals(UNKNOWN, FileDetection.detectContainer(content("foo")).type);
            assertEquals(UNKNOWN, FileDetection.detectContainer(content("""
                    The quick brown fox jumps over the lazy dog!@#$%^&*() 1234567890
                    jA0EAwMCRPdXu3qZeLBgySHwRvh2vWI8YHXCNDwHDzkMr6ZoR9iZFDM8gaWyIz1T
                    """.trim())).type);
        }

        @Test
        void detectArmorContainerWhenHeaderLinePresent() throws Exception {
            assertEquals(ASCII_ARMOR, FileDetection.detectContainer(content(
                    "-----BEGIN PGP MESSAGE-----\nVersion: test\n\njA0E\n")).type);
        }

        @Test
        void detectKeyboxContainerFromSignatureBytes() throws Exception {
            byte[] prefix = new byte[12];
            prefix[8] = 'K';
            prefix[9] = 'B';
            prefix[10] = 'X';
            prefix[11] = 'f';
            assertEquals(KEYBOX, FileDetection.detectContainer(new ByteArrayInputStream(prefix)).type);
        }

        @Test
        void detectUnknownWhenArmorBodyHasInvalidCharacter() throws Exception {
            char[] chars = new char[64];
            java.util.Arrays.fill(chars, 'A');
            chars[10] = '-';
            assertEquals(UNKNOWN, FileDetection.detectContainer(content(new String(chars))).type);
        }

        @Test
        void detectArmorContainerWhenArmorBodyWithoutHeaders() throws Exception {
            assertEquals(ASCII_ARMOR, FileDetection.detectContainer(content("""
                    jA0EAwMCRPdXu3qZeLBgySHwRvh2vWI8YHXCNDwHDzkMr6ZoR9iZFDM8gaWyIz1T
                    x/o=
                    =AqCM
                    """.trim())).type);
        }

        @Test
        void detectArmorContainer() throws Exception {
            assertEquals(ASCII_ARMOR, FileDetection.detectContainer(loadResource(
                    "test-encrypted-for-key-1.txt.asc")).type);
            assertEquals(ASCII_ARMOR, FileDetection.detectContainer(loadResource(
                    "test-key-1.asc")).type);
            assertEquals(ASCII_ARMOR, FileDetection.detectContainer(loadResource(
                    "test-key-1-pub.asc")).type);
        }

        @Test
        void detectKeyboxContainer() throws Exception {
            assertEquals(KEYBOX, FileDetection.detectContainer(loadResource(
                    "test-pubring.kbx")).type);
        }

        @Test
        void detectPgpContainerSignedWithoutCompressingOrEncrypting() throws Exception {
            Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
            encryptor.setCompressionAlgorithm(CompressionAlgorithm.Uncompressed);
            encryptor.setEncryptionAlgorithm(EncryptionAlgorithm.Unencrypted);
            unlockKeys(encryptor.getRing());
            encryptor.encrypt(plainIn(), cipherOut);

            assertEquals(PGP, FileDetection.detectContainer(cipherIn()).type);
        }

        @Test
        void detectPgpContainerSignedWithoutEncrypting() throws Exception {
            Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
            encryptor.setEncryptionAlgorithm(EncryptionAlgorithm.Unencrypted);
            unlockKeys(encryptor.getRing());
            encryptor.encrypt(plainIn(), cipherOut);

            assertEquals(PGP, FileDetection.detectContainer(cipherIn()).type);
        }

        @Test
        void detectPgpContainerEncryptedAndSigned() throws Exception {
            Encryptor encryptor = new Encryptor(new Ring(loadResource("test-key-1.asc")));
            unlockKeys(encryptor.getRing());
            encryptor.encrypt(plainIn(), cipherOut);

            assertEquals(PGP, FileDetection.detectContainer(cipherIn()).type);
        }

        @Test
        void detectPgpContainerEncryptedSymmetric() throws Exception {
            Encryptor encryptor = new Encryptor();
            encryptor.setSigningAlgorithm(HashingAlgorithm.Unsigned);
            encryptor.setSymmetricPassphrase(PASSPHRASE);
            encryptor.setKeyDeriviationWorkFactor(10);
            encryptor.encrypt(plainIn(), cipherOut);

            assertEquals(PGP, FileDetection.detectContainer(cipherIn()).type);
        }
    }

    private InputStream content(String s) {
        return new ByteArrayInputStream(s.getBytes(StandardCharsets.UTF_8));
    }

    private InputStream plainIn() {
        return new ByteArrayInputStream(plainText().getBytes(StandardCharsets.UTF_8));
    }

    private InputStream cipherIn() {
        return new ByteArrayInputStream(cipherOut.toByteArray());
    }
}
