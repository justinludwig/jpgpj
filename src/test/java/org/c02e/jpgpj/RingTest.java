package org.c02e.jpgpj;

import static org.c02e.jpgpj.support.PgpTestSupport.loadResource;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResourceAsString;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResourceFile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;

class RingTest {

    @Test
    void loadPublicRing() throws IOException, PGPException {
        Ring ring = new Ring(loadResource("test-ring-pub.asc"));
        assertEquals(List.of(
            "Test Key 1 <test-key-1@c02e.org>",
            "Test Key 2 <test-key-2@c02e.org>",
            "Test 2 (CODESurvey) <test-key-2@codesurvey.org>"
        ), flattenUids(ring));
        assertEquals(List.of(
            "0x72A423A0013826C3", "0x29DEE78E970C7061",
            "0x2B04481E880A1469", "0x6727B00AAFAFA3C5", "0xAFDB7B47BC3F6A4B"
        ), flattenSubkeyIds(ring));
        assertEquals(List.of(false, false), keyFlags(ring, Key::isForSigning));
        assertEquals(List.of(true, true), keyFlags(ring, Key::isForVerification));
        assertEquals(List.of(true, true), keyFlags(ring, Key::isForEncryption));
        assertEquals(List.of(false, false), keyFlags(ring, Key::isForDecryption));
    }

    @Test
    void loadSecretRing() throws IOException, PGPException {
        Ring ring = new Ring(loadResource("test-ring.asc"));
        assertEquals(List.of(
            "Test Key 1 <test-key-1@c02e.org>",
            "Test Key 2 <test-key-2@c02e.org>",
            "Test 2 (CODESurvey) <test-key-2@codesurvey.org>"
        ), flattenUids(ring));
        assertEquals(List.of(
            "0x72A423A0013826C3", "0x29DEE78E970C7061",
            "0x2B04481E880A1469", "0x6727B00AAFAFA3C5", "0xAFDB7B47BC3F6A4B"
        ), flattenSubkeyIds(ring));
        assertEquals(List.of(true, true), keyFlags(ring, Key::isForSigning));
        assertEquals(List.of(true, true), keyFlags(ring, Key::isForVerification));
        assertEquals(List.of(true, true), keyFlags(ring, Key::isForEncryption));
        assertEquals(List.of(true, true), keyFlags(ring, Key::isForDecryption));
    }

    @Test
    void loadKeyboxRing() throws IOException, PGPException {
        Ring ring = new Ring(loadResource("test-pubring.kbx"));
        assertEquals(List.of(
            "Test Keybox 1 <test-kbx-1@c02e.org>",
            "Test Keybox 2 <test-kbx-2@c02e.org>",
            "Second Keybox (CODESurvey) <test-kbx-2@codesurvey.org>"
        ), flattenUids(ring));
        assertEquals(List.of(
            "0xD87CAD7157196947", "0x0077D401BA4995BA",
            "0x22B738768C6C48F8", "0x225B6180D44BFCEA", "0x96D1D02042CBE541"
        ), flattenSubkeyIds(ring));
        assertEquals(List.of(false, false), keyFlags(ring, Key::isForSigning));
        assertEquals(List.of(true, true), keyFlags(ring, Key::isForVerification));
        assertEquals(List.of(true, true), keyFlags(ring, Key::isForEncryption));
        assertEquals(List.of(false, false), keyFlags(ring, Key::isForDecryption));
    }

    @Test
    void loadRingFromFile() throws IOException, PGPException {
        Ring ring = new Ring(loadResourceFile("test-ring-pub.asc"));
        assertEquals(List.of(
            "0x72A423A0013826C3", "0x29DEE78E970C7061",
            "0x2B04481E880A1469", "0x6727B00AAFAFA3C5", "0xAFDB7B47BC3F6A4B"
        ), flattenSubkeyIds(ring));
        assertTrue(ring.getSigningKeys().isEmpty());
        assertEquals(List.of("013826C3", "880A1469"), masterShortIds(ring.getVerificationKeys()));
        assertEquals(List.of("013826C3", "880A1469"), masterShortIds(ring.getEncryptionKeys()));
        assertTrue(ring.getDecryptionKeys().isEmpty());
    }

    @Test
    void loadRingFromString() throws IOException, PGPException {
        Ring ring = new Ring(loadResourceAsString("test-ring-pub.asc"));
        assertEquals(List.of(
            "0x72A423A0013826C3", "0x29DEE78E970C7061",
            "0x2B04481E880A1469", "0x6727B00AAFAFA3C5", "0xAFDB7B47BC3F6A4B"
        ), flattenSubkeyIds(ring));
        assertTrue(ring.getSigningKeys().isEmpty());
        assertEquals(List.of("013826C3", "880A1469"), masterShortIds(ring.getVerificationKeys()));
        assertEquals(List.of("013826C3", "880A1469"), masterShortIds(ring.getEncryptionKeys()));
        assertTrue(ring.getDecryptionKeys().isEmpty());
    }

    @Test
    void findOneKeyByIdNumber() throws IOException, PGPException {
        Ring ring = new Ring(loadResourceFile("test-ring-pub.asc"));
        assertNull(ring.findById(null));
        assertNull(ring.findById(0L));
        assertNull(ring.findById(123L));
        assertEquals("013826C3", ring.findById(0x72A423A0013826C3L).getMaster().getShortId());
        assertEquals("013826C3", ring.findById(0x29DEE78E970C7061L).getMaster().getShortId());
        assertEquals("880A1469", ring.findById(0x2B04481E880A1469L).getMaster().getShortId());
        assertEquals("880A1469", ring.findById(0x6727B00AAFAFA3C5L).getMaster().getShortId());
        assertNull(ring.findById(0xAFDB7B47L));
    }

    @Test
    void findKeyByIdNumber() throws IOException, PGPException {
        Ring ring = new Ring(loadResourceFile("test-ring-pub.asc"));
        ring.load(loadResourceFile("test-key-1.asc"));

        assertTrue(ring.findAll(0L).isEmpty());
        assertTrue(ring.findAll(123L).isEmpty());
        assertTrue(ring.findAll(0xAFDB7B47L).isEmpty());

        List<Key> key1s = ring.findAll(0x72A423A0013826C3L);
        assertEquals(List.of("013826C3", "013826C3"),
            key1s.stream().map(k -> k.findById(0x72A423A0013826C3L).getShortId()).collect(Collectors.toList()));
        assertEquals(List.of(false, true),
            key1s.stream().map(k -> k.findById(0x72A423A0013826C3L).isForSigning()).collect(Collectors.toList()));
        assertEquals(List.of(true, true),
            key1s.stream().map(k -> k.findById(0x72A423A0013826C3L).isForVerification()).collect(Collectors.toList()));

        List<Key> key1e = ring.findAll(0x29DEE78E970C7061L);
        assertEquals(List.of("970C7061", "970C7061"),
            key1e.stream().map(k -> k.findById(0x29DEE78E970C7061L).getShortId()).collect(Collectors.toList()));
        assertEquals(List.of(true, true),
            key1e.stream().map(k -> k.findById(0x29DEE78E970C7061L).isForEncryption()).collect(Collectors.toList()));
        assertEquals(List.of(false, true),
            key1e.stream().map(k -> k.findById(0x29DEE78E970C7061L).isForDecryption()).collect(Collectors.toList()));

        List<Key> key2s = ring.findAll(0x2B04481E880A1469L);
        assertEquals(List.of("880A1469"),
            key2s.stream().map(k -> k.findById(0x2B04481E880A1469L).getShortId()).collect(Collectors.toList()));
        assertEquals(List.of(false),
            key2s.stream().map(k -> k.findById(0x2B04481E880A1469L).isForSigning()).collect(Collectors.toList()));
        assertEquals(List.of(true),
            key2s.stream().map(k -> k.findById(0x2B04481E880A1469L).isForVerification()).collect(Collectors.toList()));

        List<Key> key2e = ring.findAll(0x6727B00AAFAFA3C5L);
        assertEquals(List.of("AFAFA3C5"),
            key2e.stream().map(k -> k.findById(0x6727B00AAFAFA3C5L).getShortId()).collect(Collectors.toList()));
        assertEquals(List.of(true),
            key2e.stream().map(k -> k.findById(0x6727B00AAFAFA3C5L).isForEncryption()).collect(Collectors.toList()));
        assertEquals(List.of(false),
            key2e.stream().map(k -> k.findById(0x6727B00AAFAFA3C5L).isForDecryption()).collect(Collectors.toList()));
    }

    @Test
    void findKeyByUid() throws IOException, PGPException {
        Ring ring = new Ring(loadResourceFile("test-ring-pub.asc"));
        assertEquals(List.of(), masterShortIds(ring.findAll("")));
        assertEquals(List.of(), masterShortIds(ring.findAll("foo")));
        assertEquals(List.of(), masterShortIds(ring.findAll(Pattern.compile("foo"))));
        assertEquals(List.of("013826C3", "880A1469"), masterShortIds(ring.findAll("test key")));
        assertEquals(List.of("880A1469"), masterShortIds(ring.findAll("codesurvey")));
        assertEquals(List.of("013826C3", "880A1469"),
            masterShortIds(ring.findAll(Pattern.compile("test-key.*@c02e"))));
    }

    @Test
    void findKeyByShortId() throws IOException, PGPException {
        Ring ring = new Ring(loadResourceFile("test-ring-pub.asc"));
        assertEquals(List.of("013826C3"), masterShortIds(ring.findAll("013826C3")));
        assertTrue(ring.findAll("0x970C7061").isEmpty());
        assertEquals(List.of("013826C3", "880A1469"), masterShortIds(ring.findAll("a")));
        assertEquals(List.of("880A1469"), masterShortIds(ring.findAll("880A1469")));
        assertEquals(List.of("880A1469"), masterShortIds(ring.findAll("AFAFA3C5")));
        assertEquals(List.of("880A1469"), masterShortIds(ring.findAll("BC3F6A4B")));
        assertTrue(ring.findAll("0x880A1469").isEmpty());
    }

    @Test
    void findKeyByLongId() throws IOException, PGPException {
        Ring ring = new Ring(loadResourceFile("test-ring-pub.asc"));
        assertEquals(List.of("013826C3"), masterShortIds(ring.findAll("72A423A0013826C3")));
        assertEquals(List.of("013826C3"), masterShortIds(ring.findAll("0x29DEE78E970C7061")));
        assertEquals(List.of("880A1469"), masterShortIds(ring.findAll("0x2B04481E880A1469")));
        assertEquals(List.of("880A1469"), masterShortIds(ring.findAll("6727B00AAFAFA3C5")));
        assertEquals(List.of("880A1469"), masterShortIds(ring.findAll("AFDB7B47")));
    }

    @Test
    void findKeyByFingerprint() throws IOException, PGPException {
        Ring ring = new Ring(loadResourceFile("test-ring-pub.asc"));
        assertTrue(ring.findAll("B58A F7D0 AAD9 1E33 B15A  8062 72A4 23A0 0138 26C3").isEmpty());
        assertEquals(List.of("013826C3"),
            masterShortIds(ring.findAll("5C2185779AD12B6488F260E529DEE78E970C7061")));
        assertEquals(List.of("880A1469"),
            masterShortIds(ring.findAll("AE136750D165E6A4AACB1D092B04481E880A1469")));
        assertEquals(List.of("880A1469"),
            masterShortIds(ring.findAll("1F62DF843110BACAE18B38DC6727B00AAFAFA3C5")));
        assertEquals(List.of("880A1469"),
            masterShortIds(ring.findAll("66B9E5A5414E51C78F9B272AAFDB7B47BC3F6A4B")));
    }

    @Test
    void emptyRingAsStringPrintsRingEmpty() {
        assertEquals("ring empty", new Ring().toString());
    }

    @Test
    void asStringPrintsEachKeyOnSeparateLine() throws IOException, PGPException {
        Ring ring = new Ring(loadResourceFile("test-ring.asc"));
        assertEquals(
            "sec vs 013826C3 Test Key 1 <test-key-1@c02e.org>\n"
                + "sec ed 970C7061\n\n"
                + "sec v  880A1469 Test Key 2 <test-key-2@c02e.org>, Test 2 (CODESurvey) <test-key-2@codesurvey.org>\n"
                + "sec ed AFAFA3C5\n"
                + "sec vs BC3F6A4B",
            ring.toString()
        );
    }

    @Test
    void testClone() throws IOException, PGPException {
        Ring original = new Ring(loadResource("test-ring.asc"));
        List<Key> orgKeys = original.getKeys();
        Ring cloned = original.clone();
        List<Key> clnKeys = cloned.getKeys();
        assertNotSame(original, cloned);
        assertNotSame(orgKeys, clnKeys);
        assertEquals(orgKeys.size(), clnKeys.size());

        for (int keyIndex = 0; keyIndex < orgKeys.size(); keyIndex++) {
            Key oKey = orgKeys.get(keyIndex);
            Key cKey = clnKeys.get(keyIndex);
            assertNotSame(oKey, cKey);
            List<Subkey> orgSubs = oKey.getSubkeys();
            List<Subkey> clnSubs = cKey.getSubkeys();
            assertNotSame(orgSubs, clnSubs);
            assertEquals(orgSubs.size(), clnSubs.size());
            for (int subIndex = 0; subIndex < orgSubs.size(); subIndex++) {
                assertNotSame(orgSubs.get(subIndex), clnSubs.get(subIndex));
            }
        }
    }

    private static List<String> flattenUids(Ring ring) {
        return ring.getKeys().stream()
            .flatMap(key -> key.getUids().stream())
            .collect(Collectors.toList());
    }

    private static List<String> flattenSubkeyIds(Ring ring) {
        return ring.getKeys().stream()
            .flatMap(key -> key.getSubkeys().stream())
            .map(Subkey::getId)
            .collect(Collectors.toList());
    }

    private static List<Boolean> keyFlags(Ring ring, java.util.function.Function<Key, Boolean> flag) {
        return ring.getKeys().stream().map(flag).collect(Collectors.toList());
    }

    private static List<String> masterShortIds(List<Key> keys) {
        return keys.stream().map(key -> key.getMaster().getShortId()).collect(Collectors.toList());
    }
}
