package org.c02e.jpgpj.key;

import static org.c02e.jpgpj.support.PgpTestSupport.SubkeyFlag.FOR_SIGNING;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResource;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResourceFile;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResourceText;
import static org.c02e.jpgpj.support.PgpTestSupport.subkeyFlags;
import static org.c02e.jpgpj.support.PgpTestSupport.subkeyPassphrases;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

class KeyForSigningTest {

    @Nested
    class LoadKey {

        @Test
        void loadKeyFromStream() throws Exception {
            KeyForSigning key = new KeyForSigning(loadResource("test-key-1.asc"), "foo");

            assertEquals(List.of("foo", "foo"), subkeyPassphrases(key));
            assertNotNull(key.getMaster().getSecretKey());
        }

        @Test
        void loadKeyFromFile() throws Exception {
            KeyForSigning key = new KeyForSigning(loadResourceFile("test-key-1.asc"), "foo");

            assertEquals(List.of("foo", "foo"), subkeyPassphrases(key));
            assertNotNull(key.getMaster().getSecretKey());
        }

        @Test
        void loadKeyFromString() throws Exception {
            KeyForSigning key = new KeyForSigning(loadResourceText("test-key-1.asc"), "foo");

            assertEquals(List.of("foo", "foo"), subkeyPassphrases(key));
            assertNotNull(key.getMaster().getSecretKey());
        }
    }

    @Test
    void publicKeyIsForNoUses() throws Exception {
        KeyForSigning key = new KeyForSigning(loadResource("test-key-1-pub.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());

        key = new KeyForSigning(loadResource("test-key-2-pub.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
    }

    @Test
    void secretKeyIsForSigningOnlyWithFlaggedSubkey() throws Exception {
        KeyForSigning key = new KeyForSigning(loadResource("test-key-1.asc"));
        assertTrue(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(true, false), subkeyFlags(key, FOR_SIGNING));

        key = new KeyForSigning(loadResource("test-key-2.asc"));
        assertTrue(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(false, false, true), subkeyFlags(key, FOR_SIGNING));
    }

    @Test
    void secretKeyWithNoFlagsIsForSigningOnlyWithSelectedSubkey() throws Exception {
        KeyForSigning key = new KeyForSigning(loadResource("test-no-usage-1-subkeys.asc"));
        assertTrue(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(true), subkeyFlags(key, FOR_SIGNING));

        key = new KeyForSigning(loadResource("test-no-usage-2-subkeys.asc"));
        assertTrue(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(true, false), subkeyFlags(key, FOR_SIGNING));

        key = new KeyForSigning(loadResource("test-no-usage-3-subkeys.asc"));
        assertTrue(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(false, false, true), subkeyFlags(key, FOR_SIGNING));

        key = new KeyForSigning(loadResource("test-no-usage-ec-subkeys.asc"));
        assertTrue(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
        // first 2 subkeys of this key are ecdsa (verification/signing)
        // and 3rd subkey is ecdh (encryption/decryption)
        assertEquals(List.of(false, true, false), subkeyFlags(key, FOR_SIGNING));
    }

    @Nested
    class EmptyKey {

        @Test
        void noSubkeysIsNotForSigning() {
            assertFalse(new KeyForSigning().isForSigning());
        }

        @Test
        void noSubkeysIsNotForVerification() {
            assertFalse(new KeyForSigning().isForVerification());
        }

        @Test
        void noSubkeysIsNotForEncryption() {
            assertFalse(new KeyForSigning().isForEncryption());
        }

        @Test
        void noSubkeysIsNotForDecryption() {
            assertFalse(new KeyForSigning().isForDecryption());
        }

        @Test
        void noSubkeysHasNoMaster() {
            assertNull(new KeyForSigning().getMaster());
        }
    }

    @Test
    void settingSubkeysToNullMakesItForNoUses() throws Exception {
        KeyForSigning key = new KeyForSigning(loadResource("test-key-1.asc"));

        key.setSubkeys(null);

        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
    }

    @Test
    void loadingEmptyKeysRaisesAnException() {
        assertThrows(PGPException.class, () -> new KeyForSigning(""));
    }
}
