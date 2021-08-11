package org.c02e.jpgpj;

import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.openpgp.PGPException;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DecryptorTest extends Assert {
    public DecryptorTest() {
        super();
    }

    @Test
    public void testClone() throws IOException, PGPException {
        Decryptor original = new Decryptor(loadRing("test-ring.asc"))
            .withSymmetricPassphraseChars(new char[] { 'h', 'e', 'l', 'l', 'o' })
            ;
        Decryptor cloned = original.clone();
        assertNotSame("Cloned instance reference", original, cloned);
        assertSame("Cloned logger reference", original.log, cloned.log);
        assertNotSame("Cloned ring reference", original.getRing(), cloned.getRing());
        assertNotSame("Cloned passphrase chars reference", original.getSymmetricPassphraseChars(), cloned.getSymmetricPassphraseChars());
        assertArrayEquals("Clones passphrase chars values", original.getSymmetricPassphraseChars(), cloned.getSymmetricPassphraseChars());
    }

    protected Ring loadRing(String resourceName) throws IOException, PGPException {
        ClassLoader cl = getClass().getClassLoader();
        try (InputStream inputStream = cl.getResourceAsStream(resourceName)) {
            return new Ring(inputStream);
        }
    }
}
