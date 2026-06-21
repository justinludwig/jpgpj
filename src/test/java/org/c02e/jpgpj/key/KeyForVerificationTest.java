package org.c02e.jpgpj.key;

import static org.c02e.jpgpj.support.PgpTestSupport.SubkeyFlag.FOR_VERIFICATION;
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

class KeyForVerificationTest {

    @Nested
    class LoadKey {

        @Test
        void loadKeyFromStream() throws Exception {
            KeyForVerification key = new KeyForVerification(loadResource("test-key-1.asc"));

            assertEquals(List.of("", ""), subkeyPassphrases(key));
            assertNotNull(key.getMaster().getPublicKey());
        }

        @Test
        void loadKeyFromFile() throws Exception {
            KeyForVerification key = new KeyForVerification(loadResourceFile("test-key-1.asc"));

            assertEquals(List.of("", ""), subkeyPassphrases(key));
            assertNotNull(key.getMaster().getPublicKey());
        }

        @Test
        void loadKeyFromString() throws Exception {
            KeyForVerification key = new KeyForVerification(loadResourceText("test-key-1.asc"));

            assertEquals(List.of("", ""), subkeyPassphrases(key));
            assertNotNull(key.getMaster().getPublicKey());
        }
    }

    @Test
    void publicKeyIsForVerificationOnlyWithEveryTechnicallyUsableSubkey() throws Exception {
        KeyForVerification key = new KeyForVerification(loadResource("test-key-1-pub.asc"));
        assertFalse(key.isForSigning());
        assertTrue(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(true, true), subkeyFlags(key, FOR_VERIFICATION));

        key = new KeyForVerification(loadResource("test-key-2-pub.asc"));
        assertFalse(key.isForSigning());
        assertTrue(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(true, true, true), subkeyFlags(key, FOR_VERIFICATION));
    }

    @Test
    void secretKeyIsForVerificationOnlyWithEveryTechnicallyUsableSubkey() throws Exception {
        KeyForVerification key = new KeyForVerification(loadResource("test-key-1.asc"));
        assertFalse(key.isForSigning());
        assertTrue(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(true, true), subkeyFlags(key, FOR_VERIFICATION));

        key = new KeyForVerification(loadResource("test-key-2.asc"));
        assertFalse(key.isForSigning());
        assertTrue(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(true, true, true), subkeyFlags(key, FOR_VERIFICATION));

        key = new KeyForVerification(loadResource("test-no-usage-3-subkeys.asc"));
        assertFalse(key.isForSigning());
        assertTrue(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
        assertEquals(List.of(true, true, true), subkeyFlags(key, FOR_VERIFICATION));

        key = new KeyForVerification(loadResource("test-no-usage-ec-subkeys.asc"));
        assertFalse(key.isForSigning());
        assertTrue(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
        // first 2 subkeys of this key are ecdsa (verification/signing)
        // and 3rd subkey is ecdh (encryption/decryption)
        assertEquals(List.of(true, true, false), subkeyFlags(key, FOR_VERIFICATION));
    }

    @Nested
    class EmptyKey {

        @Test
        void noSubkeysIsNotForSigning() {
            assertFalse(new KeyForVerification().isForSigning());
        }

        @Test
        void noSubkeysIsNotForVerification() {
            assertFalse(new KeyForVerification().isForVerification());
        }

        @Test
        void noSubkeysIsNotForEncryption() {
            assertFalse(new KeyForVerification().isForEncryption());
        }

        @Test
        void noSubkeysIsNotForDecryption() {
            assertFalse(new KeyForVerification().isForDecryption());
        }

        @Test
        void noSubkeysHasNoMaster() {
            assertNull(new KeyForVerification().getMaster());
        }
    }

    @Test
    void settingSubkeysToNullMakesItForNoUses() throws Exception {
        KeyForVerification key = new KeyForVerification(loadResource("test-key-1.asc"));

        key.setSubkeys(null);

        assertFalse(key.isForSigning());
        assertFalse(key.isForVerification());
        assertFalse(key.isForEncryption());
        assertFalse(key.isForDecryption());
    }

    @Test
    void loadingEmptyKeysRaisesAnException() {
        assertThrows(PGPException.class, () -> new KeyForVerification(""));
    }
}
