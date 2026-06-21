package org.c02e.jpgpj.key;

import static org.c02e.jpgpj.support.PgpTestSupport.SubkeyFlag.FOR_ENCRYPTION;
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

class KeyForEncryptionTest {

    @Nested
    class LoadKey {

        @Test
        void loadKeyFromStream() throws Exception {
            KeyForEncryption key = new KeyForEncryption(loadResource("test-key-1.asc"));

            assertEquals(List.of("", ""), subkeyPassphrases(key));
            assertNotNull(key.getMaster().getPublicKey());
        }

        @Test
        void loadKeyFromFile() throws Exception {
            KeyForEncryption key = new KeyForEncryption(loadResourceFile("test-key-1.asc"));

            assertEquals(List.of("", ""), subkeyPassphrases(key));
            assertNotNull(key.getMaster().getPublicKey());
        }

        @Test
        void loadKeyFromString() throws Exception {
            KeyForEncryption key = new KeyForEncryption(loadResourceText("test-key-1.asc"));

            assertEquals(List.of("", ""), subkeyPassphrases(key));
            assertNotNull(key.getMaster().getPublicKey());
        }
    }

    @Test
    void publicKeyIsForEncryptionOnlyWithFlaggedSubkey() throws Exception {
        KeyForEncryption key = new KeyForEncryption(loadResource("test-key-1-pub.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertTrue(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(false, true), subkeyFlags(key, FOR_ENCRYPTION));

        key = new KeyForEncryption(loadResource("test-key-2-pub.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertTrue(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(false, true, false), subkeyFlags(key, FOR_ENCRYPTION));
    }

    @Test
    void secretKeyIsForEncryptionOnlyWithFlaggedSubkey() throws Exception {
        KeyForEncryption key = new KeyForEncryption(loadResource("test-key-1.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertTrue(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(false, true), subkeyFlags(key, FOR_ENCRYPTION));

        key = new KeyForEncryption(loadResource("test-key-2.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertTrue(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(false, true, false), subkeyFlags(key, FOR_ENCRYPTION));
    }

    @Test
    void secretKeyWithNoFlagsIsForEncryptionOnlyWithSelectedSubkey() throws Exception {
        KeyForEncryption key = new KeyForEncryption(loadResource("test-no-usage-1-subkeys.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertTrue(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(true), subkeyFlags(key, FOR_ENCRYPTION));

        key = new KeyForEncryption(loadResource("test-no-usage-2-subkeys.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertTrue(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(false, true), subkeyFlags(key, FOR_ENCRYPTION));

        key = new KeyForEncryption(loadResource("test-no-usage-3-subkeys.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertTrue(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(false, true, false), subkeyFlags(key, FOR_ENCRYPTION));

        key = new KeyForEncryption(loadResource("test-no-usage-ec-subkeys.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertTrue(key.isForEncryption());
        assertFalse(key.isForDecryption());
        // first 2 subkeys of this key are ecdsa (verification/signing)
        // and 3rd subkey is ecdh (encryption/decryption)
        assertEquals(List.of(false, false, true), subkeyFlags(key, FOR_ENCRYPTION));
    }

    @Test
    void dsaEcdsaAndEd25519KeysSelectEncryptionSubkeys() throws Exception {
        KeyForEncryption dsa = new KeyForEncryption(loadResource("test-key-dsa.asc"));
        assertTrue(dsa.isForEncryption());
        assertEquals(List.of(false, true), subkeyFlags(dsa, FOR_ENCRYPTION));

        KeyForEncryption ecdsa = new KeyForEncryption(loadResource("test-key-ecdsa.asc"));
        assertTrue(ecdsa.isForEncryption());
        assertEquals(List.of(false, true), subkeyFlags(ecdsa, FOR_ENCRYPTION));

        KeyForEncryption ed25519 = new KeyForEncryption(loadResource("test-key-ed25519.asc"));
        assertTrue(ed25519.isForEncryption());
        assertEquals(List.of(false, true), subkeyFlags(ed25519, FOR_ENCRYPTION));
    }

    @Nested
    class EmptyKey {

        @Test
        void noSubkeysIsNotForSigning() {
            assertFalse(new KeyForEncryption().isForSigning());
        }

        @Test
        void noSubkeysIsNotForVerification() {
            assertFalse(new KeyForEncryption().isForVerification());
        }

        @Test
        void noSubkeysIsNotForEncryption() {
            assertFalse(new KeyForEncryption().isForEncryption());
        }

        @Test
        void noSubkeysIsNotForDecryption() {
            assertFalse(new KeyForEncryption().isForDecryption());
        }

        @Test
        void noSubkeysHasNoMaster() {
            assertNull(new KeyForEncryption().getMaster());
        }
    }

    @Test
    void settingSubkeysToNullMakesItForNoUses() throws Exception {
        KeyForEncryption key = new KeyForEncryption(loadResource("test-key-1.asc"));

        key.setSubkeys(null);

        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
    }

    @Test
    void loadingEmptyKeysRaisesAnException() {
        assertThrows(PGPException.class, () -> new KeyForEncryption(""));
    }
}
