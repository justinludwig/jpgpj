package org.c02e.jpgpj;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;

import org.bouncycastle.openpgp.PGPSignature;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class FileMetadataTest {

    @ParameterizedTest
    @CsvSource({
            "b, BINARY",
            "t, TEXT",
            "u, UTF8",
    })
    void formatByCode(char code, FileMetadata.Format expected) {
        assertEquals(expected, FileMetadata.Format.byCode(code));
    }

    @Test
    void unknownFormatByCodeReturnsNull() {
        assertNull(FileMetadata.Format.byCode('x'));
    }

    @Test
    void fluentWithMethodsMutateFields() {
        EncryptionDetails details = new EncryptionDetails();
        details.setProtection(EncryptionProtection.Mdc);

        FileMetadata meta = new FileMetadata()
                .withName("doc.txt")
                .withLength(42)
                .withLastModified(1_700_000_000_000L)
                .withFormat(FileMetadata.Format.TEXT)
                .withEncryptionDetails(details);

        assertEquals("doc.txt", meta.getName());
        assertEquals(42, meta.getLength());
        assertEquals(1_700_000_000_000L, meta.getLastModified());
        assertEquals(FileMetadata.Format.TEXT, meta.getFormat());
        assertEquals(details, meta.getEncryptionDetails());
    }

    @Test
    void setFileExtractsMetadataFromPath(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("sample.bin");
        Files.writeString(file, "hello");

        FileMetadata meta = new FileMetadata();
        meta.setFile(file);

        assertEquals("sample.bin", meta.getName());
        assertEquals(5, meta.getLength());
        assertTrue(meta.getLastModified() > 0);
    }

    @Test
    void withFileDelegatesToPath(@TempDir Path tempDir) throws Exception {
        File file = tempDir.resolve("legacy.dat").toFile();
        Files.writeString(file.toPath(), "x");

        FileMetadata meta = new FileMetadata().withFile(file);

        assertEquals("legacy.dat", meta.getName());
        assertEquals(1, meta.getLength());
    }

    @Test
    void setFileIgnoresNull() {
        FileMetadata meta = new FileMetadata("keep.txt", FileMetadata.Format.BINARY, 1, 0);
        meta.setFile((File) null);
        meta.setFile((Path) null);
        assertEquals("keep.txt", meta.getName());
    }

    @Test
    void signatureSettersControlVerifiedKeyAccess() throws Exception {
        Key key = new Key();
        FileMetadata.Signature signature = new FileMetadata.Signature();

        signature.setKeyId(0x1234L);
        signature.setKey(key);
        assertEquals(0x1234L, signature.getKeyId());
        assertEquals(key, signature.getKey());
        assertNull(signature.getVerifiedKey());

        signature.setVerifiedKey(key);
        assertTrue(signature.isVerified());
        assertEquals(key, signature.getVerifiedKey());
    }

    @Test
    void textFormatUsesCanonicalSignatureType() {
        FileMetadata binary = new FileMetadata("a", FileMetadata.Format.BINARY, 0, 0);
        FileMetadata text = new FileMetadata("a", FileMetadata.Format.TEXT, 0, 0);
        FileMetadata utf8 = new FileMetadata("a", FileMetadata.Format.UTF8, 0, 0);

        assertEquals(PGPSignature.BINARY_DOCUMENT, binary.getSignatureType());
        assertEquals(PGPSignature.CANONICAL_TEXT_DOCUMENT, text.getSignatureType());
        assertEquals(PGPSignature.CANONICAL_TEXT_DOCUMENT, utf8.getSignatureType());
    }

    @Test
    void equalsHashCodeAndToString() {
        FileMetadata left = new FileMetadata("same.txt", FileMetadata.Format.BINARY, 10, 1_000L);
        FileMetadata right = new FileMetadata("same.txt", FileMetadata.Format.BINARY, 10, 1_000L);
        FileMetadata different = new FileMetadata("other.txt", FileMetadata.Format.BINARY, 10, 1_000L);

        assertEquals(left, right);
        assertEquals(left.hashCode(), right.hashCode());
        assertNotEquals(left, different);
        assertFalse(left.equals(null));
        assertTrue(left.toString().contains("same.txt"));
        assertTrue(left.toString().contains("BINARY"));
    }
}
