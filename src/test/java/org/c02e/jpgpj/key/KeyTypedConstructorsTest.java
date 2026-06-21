package org.c02e.jpgpj.key;

import static org.c02e.jpgpj.support.PgpTestSupport.PASSPHRASE;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResource;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResourceAsString;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResourceFile;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;

import org.c02e.jpgpj.Key;
import org.junit.jupiter.api.Test;

class KeyTypedConstructorsTest {

    @Test
    void keyForSigningAlternateConstructors() throws Exception {
        Key baseline = new KeyForSigning(loadResource("test-key-1-pub.asc"));
        assertFalse(baseline.isForSigning());

        assertNotNull(new KeyForSigning(List.copyOf(baseline.getSubkeys())).getMaster());
        assertNotNull(new KeyForSigning(loadResourceAsString("test-key-1-pub.asc")).getMaster());
        assertNotNull(new KeyForSigning(loadResourceFile("test-key-1-pub.asc")).getMaster());
        assertNotNull(new KeyForSigning(loadResource("test-key-1.asc"), PASSPHRASE.toCharArray()).getMaster());
    }

    @Test
    void keyForDecryptionAlternateConstructors() throws Exception {
        Key baseline = new KeyForDecryption(loadResource("test-key-1.asc"));
        assertNotNull(baseline.getMaster().getSecretKey());

        assertNotNull(new KeyForDecryption(List.copyOf(baseline.getSubkeys())).getMaster());
        assertNotNull(new KeyForDecryption(loadResourceAsString("test-key-1.asc")).getMaster());
        assertNotNull(new KeyForDecryption(loadResourceFile("test-key-1.asc")).getMaster());
        assertNotNull(new KeyForDecryption(loadResource("test-key-1.asc"), PASSPHRASE.toCharArray()).getMaster());
    }

    @Test
    void keyForVerificationAlternateConstructors() throws Exception {
        Key baseline = new KeyForVerification(loadResource("test-key-1-pub.asc"));
        assertNotNull(baseline.getMaster());

        assertNotNull(new KeyForVerification(List.copyOf(baseline.getSubkeys())).getMaster());
    }

    @Test
    void keyForEncryptionAlternateConstructors() throws Exception {
        Key baseline = new KeyForEncryption(loadResource("test-key-1-pub.asc"));
        assertNotNull(baseline.getMaster());

        assertNotNull(new KeyForEncryption(List.copyOf(baseline.getSubkeys())).getMaster());
    }
}
