package org.c02e.jpgpj.key;

import static org.c02e.jpgpj.support.PgpTestSupport.SubkeyFlag.FOR_DECRYPTION;
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

class KeyForDecryptionTest {

    @Nested
    class LoadKey {

        @Test
        void loadKeyFromStream() throws Exception {
            KeyForDecryption key = new KeyForDecryption(loadResource("test-key-1.asc"), "foo");

            assertEquals(List.of("foo", "foo"), subkeyPassphrases(key));
            assertNotNull(key.getMaster().getSecretKey());
        }

        @Test
        void loadKeyFromFile() throws Exception {
            KeyForDecryption key = new KeyForDecryption(loadResourceFile("test-key-1.asc"), "foo");

            assertEquals(List.of("foo", "foo"), subkeyPassphrases(key));
            assertNotNull(key.getMaster().getSecretKey());
        }

        @Test
        void loadKeyFromString() throws Exception {
            KeyForDecryption key = new KeyForDecryption(loadResourceText("test-key-1.asc"), "foo");

            assertEquals(List.of("foo", "foo"), subkeyPassphrases(key));
            assertNotNull(key.getMaster().getSecretKey());
        }
    }

    @Test
    void publicKeyIsForNoUses() throws Exception {
        KeyForDecryption key = new KeyForDecryption(loadResource("test-key-1-pub.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());

        key = new KeyForDecryption(loadResource("test-key-2-pub.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
    }

    @Test
    void secretKeyIsForDecryptionOnlyWithEveryTechnicallyUsableSubkey() throws Exception {
        KeyForDecryption key = new KeyForDecryption(loadResource("test-key-1.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertTrue(key.isForDecryption());
        assertEquals(List.of(true, true), subkeyFlags(key, FOR_DECRYPTION));

        key = new KeyForDecryption(loadResource("test-key-2.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertTrue(key.isForDecryption());
        // secret key available only for 2nd and 3rd subkeys
        assertEquals(List.of(false, true, true), subkeyFlags(key, FOR_DECRYPTION));

        key = new KeyForDecryption(loadResource("test-no-usage-3-subkeys.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertTrue(key.isForDecryption());
        assertEquals(List.of(true, true, true), subkeyFlags(key, FOR_DECRYPTION));

        key = new KeyForDecryption(loadResource("test-no-usage-ec-subkeys.asc"));
        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertTrue(key.isForDecryption());
        // first 2 subkeys of this key are ecdsa (verification/signing)
        // and 3rd subkey is ecdh (encryption/decryption)
        assertEquals(List.of(false, false, true), subkeyFlags(key, FOR_DECRYPTION));
    }

    @Nested
    class EmptyKey {

        @Test
        void noSubkeysIsNotForSigning() {
            assertFalse(new KeyForDecryption().isForSigning());
        }

        @Test
        void noSubkeysIsNotForVerification() {
            assertFalse(new KeyForDecryption().isForVerification());
        }

        @Test
        void noSubkeysIsNotForEncryption() {
            assertFalse(new KeyForDecryption().isForEncryption());
        }

        @Test
        void noSubkeysIsNotForDecryption() {
            assertFalse(new KeyForDecryption().isForDecryption());
        }

        @Test
        void noSubkeysHasNoMaster() {
            assertNull(new KeyForDecryption().getMaster());
        }
    }

    @Test
    void settingSubkeysToNullMakesItForNoUses() throws Exception {
        KeyForDecryption key = new KeyForDecryption(loadResource("test-key-1.asc"));

        key.setSubkeys(null);

        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
    }

    @Test
    void loadingEmptyKeysRaisesAnException() {
        assertThrows(PGPException.class, () -> new KeyForDecryption(""));
    }
}
