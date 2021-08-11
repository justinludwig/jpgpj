package org.c02e.jpgpj;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.junit.Assert;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class RingTest extends Assert {
    public RingTest() {
        super();
    }

    @Test
    public void testClone() throws IOException, PGPException {
        Ring original = loadRing("test-ring.asc");
        List<Key> orgKeys = original.getKeys();
        Ring cloned = original.clone();
        List<Key> clnKeys = cloned.getKeys();
        assertNotSame("Cloned instance reference", original, cloned);
        assertNotSame("Cloned keys list reference", orgKeys, clnKeys);
        assertEquals("Cloned keys count", orgKeys.size(), clnKeys.size());
        for (int index = 0; index < orgKeys.size(); index++) {
            assertSame("Mismatched ring key reference at index #" + index, orgKeys.get(index), clnKeys.get(index));
        }
    }

    protected Ring loadRing(String resourceName) throws IOException, PGPException {
        ClassLoader cl = getClass().getClassLoader();
        try (InputStream inputStream = cl.getResourceAsStream(resourceName)) {
            return new Ring(inputStream);
        }
    }
}
