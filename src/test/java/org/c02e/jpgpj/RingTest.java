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

        for (int keyIndex = 0; keyIndex < orgKeys.size(); keyIndex++) {
            Key oKey = orgKeys.get(keyIndex);
            Key cKey = clnKeys.get(keyIndex);
            assertNotSame("Uncloned ring key reference at index #" + keyIndex, oKey, cKey);
            List<Subkey> orgSubs = oKey.getSubkeys();
            List<Subkey> clnSubs = cKey.getSubkeys();
            assertNotSame("Cloned sub-keys list reference for key #" + keyIndex, orgSubs, clnSubs);
            assertEquals("Cloned sub-keys count for key #" + keyIndex, orgSubs.size(), clnSubs.size());

            for (int subIndex = 0; subIndex < orgSubs.size(); subIndex++) {
                assertNotSame("Clone sub-key #" + subIndex + " reference of key #" + keyIndex, orgSubs.get(subIndex), clnSubs.get(subIndex));
            }
        }
    }

    protected Ring loadRing(String resourceName) throws IOException, PGPException {
        ClassLoader cl = getClass().getClassLoader();
        try (InputStream inputStream = cl.getResourceAsStream(resourceName)) {
            return new Ring(inputStream);
        }
    }
}
