package org.c02e.jpgpj;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

import org.bouncycastle.openpgp.PGPException;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class EncryptorTest extends Assert {
    public EncryptorTest() {
        super();
    }

    @Test
    public void testClone() throws IOException, PGPException {
        Encryptor original = new Encryptor(loadRing("test-ring.asc"))
            .withSymmetricPassphraseChars(new char[] { 'h', 'e', 'l', 'l', 'o' })
            .withArmoredHeader("hello", "world")
            ;
        Encryptor cloned = original.clone();
        assertNotSame("Cloned instance reference", original, cloned);
        assertSame("Cloned logger reference", original.log, cloned.log);
        assertNotSame("Cloned ring reference", original.getRing(), cloned.getRing());
        assertNotSame("Cloned passphrase chars reference", original.getSymmetricPassphraseChars(), cloned.getSymmetricPassphraseChars());
        assertArrayEquals("Clones passphrase chars values", original.getSymmetricPassphraseChars(), cloned.getSymmetricPassphraseChars());

        Map<String, String> orgHdrs = original.getArmoredHeaders();
        Map<String, String> clnHdrs = cloned.getArmoredHeaders();
        assertNotSame("Cloned armored headers map reference", orgHdrs, clnHdrs);
        assertEquals("Cloned armored headers map size", orgHdrs.size(), clnHdrs.size());
        for (Map.Entry<String, String> e : orgHdrs.entrySet()) {
            String name = e.getKey();
            String orgValue = e.getValue();
            String clnValue = clnHdrs.get(name);
            assertSame("Mismatched cloned header value for key=" + name, orgValue, clnValue);
        }

    }

    protected Ring loadRing(String resourceName) throws IOException, PGPException {
        ClassLoader cl = getClass().getClassLoader();
        try (InputStream inputStream = cl.getResourceAsStream(resourceName)) {
            return new Ring(inputStream);
        }
    }

}
