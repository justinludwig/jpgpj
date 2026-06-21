package org.c02e.jpgpj;

import static org.c02e.jpgpj.support.PgpTestSupport.PASSPHRASE;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResource;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResourceAsString;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResourceFile;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;

class KeyTest {

    @Test
    void loadKeyFromStream() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1.asc"), "foo");
        assertEquals(List.of("foo", "foo"), subkeyPassphrases(key));
        assertNotNull(key.getMaster().getSecretKey());
    }

    @Test
    void loadKeyFromFile() throws IOException, PGPException {
        Key key = new Key(loadResourceFile("test-key-1.asc"), "foo");
        assertEquals(List.of("foo", "foo"), subkeyPassphrases(key));
        assertNotNull(key.getMaster().getSecretKey());
    }

    @Test
    void loadKeyFromString() throws IOException, PGPException {
        Key key = new Key(loadResourceAsString("test-key-1.asc"), "foo");
        assertEquals(List.of("foo", "foo"), subkeyPassphrases(key));
        assertNotNull(key.getMaster().getSecretKey());
    }

    @Test
    void listUidsFromMasterSubkey() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1-pub.asc"));
        assertEquals(List.of("Test Key 1 <test-key-1@c02e.org>"), key.getUids());

        key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of(
            "Test Key 2 <test-key-2@c02e.org>",
            "Test 2 (CODESurvey) <test-key-2@codesurvey.org>"
        ), key.getUids());
    }

    @Test
    void listSigningUidFromMasterSubkey() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1-pub.asc"));
        assertEquals("Test Key 1 <test-key-1@c02e.org>", key.getSigningUid());

        key = new Key(loadResource("test-key-2.asc"));
        assertEquals("Test Key 2 <test-key-2@c02e.org>", key.getSigningUid());
    }

    @Test
    void publicKeyIsForVerificationAndEncryptionOnly() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1-pub.asc"));
        assertFalse(key.isForSigning());
        assertTrue(key.isForVerification());
        assertTrue(key.isForEncryption());
        assertFalse(key.isForDecryption());

        key = new Key(loadResource("test-key-2-pub.asc"));
        assertFalse(key.isForSigning());
        assertTrue(key.isForVerification());
        assertTrue(key.isForEncryption());
        assertFalse(key.isForDecryption());
    }

    @Test
    void secretKeyIsForAllUses() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1.asc"));
        assertTrue(key.isForSigning());
        assertTrue(key.isForVerification());
        assertTrue(key.isForEncryption());
        assertTrue(key.isForDecryption());

        key = new Key(loadResource("test-key-2.asc"));
        assertTrue(key.isForSigning());
        assertTrue(key.isForVerification());
        assertTrue(key.isForEncryption());
        assertTrue(key.isForDecryption());
    }

    @Test
    void findSubkeyByIdNumber() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1-pub.asc"));
        assertNull(key.findById(null));
        assertNull(key.findById(0L));
        assertNull(key.findById(123L));
        assertEquals("013826C3", key.findById(0x72A423A0013826C3L).getShortId());
        assertEquals("970C7061", key.findById(0x29DEE78E970C7061L).getShortId());

        key = new Key(loadResource("test-key-2.asc"));
        assertEquals("880A1469", key.findById(0x2B04481E880A1469L).getShortId());
        assertEquals("AFAFA3C5", key.findById(0x6727B00AAFAFA3C5L).getShortId());
        assertNull(key.findById(0xAFDB7B47L));
    }

    @Test
    void findMasterSubkeyByUid() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1-pub.asc"));
        assertEquals(List.of(), shortIds(key.findAll("")));
        assertEquals(List.of(), shortIds(key.findAll("foo")));
        assertEquals(List.of(), shortIds(key.findAll(Pattern.compile("foo"))));
        assertEquals(List.of("013826C3"), shortIds(key.findAll("test key")));

        key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of(), shortIds(key.findAll("foo")));
        assertEquals(List.of("880A1469"), shortIds(key.findAll("test key")));
        assertEquals(List.of("880A1469"), shortIds(key.findAll("codesurvey")));
        assertEquals(List.of("880A1469"), shortIds(key.findAll(Pattern.compile("test-key.*@c02e"))));
    }

    @Test
    void findSubkeyByShortId() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1-pub.asc"));
        assertEquals(List.of("013826C3"), shortIds(key.findAll("013826C3")));
        assertTrue(key.findAll("0x970C7061").isEmpty());

        key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of("880A1469", "AFAFA3C5", "BC3F6A4B"), shortIds(key.findAll("a")));
        assertEquals(List.of("880A1469"), shortIds(key.findAll("880A1469")));
        assertEquals(List.of("AFAFA3C5"), shortIds(key.findAll("AFAFA3C5")));
        assertEquals(List.of("BC3F6A4B"), shortIds(key.findAll("BC3F6A4B")));
        assertTrue(key.findAll("0x880A1469").isEmpty());
    }

    @Test
    void findSubkeyByLongId() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1-pub.asc"));
        assertEquals(List.of("013826C3"), shortIds(key.findAll("72A423A0013826C3")));
        assertEquals(List.of("970C7061"), shortIds(key.findAll("0x29DEE78E970C7061")));

        key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of("880A1469", "AFAFA3C5", "BC3F6A4B"), shortIds(key.findAll("a")));
        assertEquals(List.of("880A1469"), shortIds(key.findAll("0x2B04481E880A1469")));
        assertEquals(List.of("AFAFA3C5"), shortIds(key.findAll("6727B00AAFAFA3C5")));
        assertEquals(List.of("BC3F6A4B"), shortIds(key.findAll("AFDB7B47")));
    }

    @Test
    void findSubkeyByFingerprint() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1-pub.asc"));
        assertTrue(key.findAll("B58A F7D0 AAD9 1E33 B15A  8062 72A4 23A0 0138 26C3").isEmpty());
        assertEquals(List.of("970C7061"),
            shortIds(key.findAll("5C2185779AD12B6488F260E529DEE78E970C7061")));

        key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of("880A1469"),
            shortIds(key.findAll("AE136750D165E6A4AACB1D092B04481E880A1469")));
        assertEquals(List.of("AFAFA3C5"),
            shortIds(key.findAll("1F62DF843110BACAE18B38DC6727B00AAFAFA3C5")));
        assertEquals(List.of("BC3F6A4B"),
            shortIds(key.findAll("66B9E5A5414E51C78F9B272AAFDB7B47BC3F6A4B")));
    }

    @Test
    void emptyKeyAsStringPrintsKeyEmpty() {
        assertEquals("key empty", new Key().toString());
    }

    @Test
    void asStringPrintsEachSubkeyOnSeparateLine() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-pub.asc"));
        assertEquals(
            "pub v  880A1469 Test Key 2 <test-key-2@c02e.org>, Test 2 (CODESurvey) <test-key-2@codesurvey.org>\n"
                + "pub e  AFAFA3C5\n"
                + "pub v  BC3F6A4B",
            key.toString()
        );
    }

    @Test
    void toPublicKeyJustCopiesPublicPartsOfSubkeys() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1.asc"), "foo");
        key.setSigningUid("bar");

        Key copy = key.toPublicKey();

        assertEquals("pub v  013826C3 Test Key 1 <test-key-1@c02e.org>\npub e  970C7061", copy.toString());
        assertEquals(List.of("", ""), subkeyPassphrases(copy));
        assertEquals("Test Key 1 <test-key-1@c02e.org>", copy.getSigningUid());
    }

    @Test
    void noSubkeysSetsNoPassphrase() {
        Key key = new Key();
        key.setPassphrase("foo");
        assertEquals(List.of(), key.getSubkeys());
    }

    @Test
    void noSubkeysHasNoUids() {
        assertEquals(List.of(), new Key().getUids());
    }

    @Test
    void noSubkeysHasNoSigningUid() {
        assertEquals("", new Key().getSigningUid());
    }

    @Test
    void noSubkeysIsNotForSigning() {
        assertFalse(new Key().isForSigning());
    }

    @Test
    void noSubkeysIsNotForVerification() {
        assertFalse(new Key().isForVerification());
    }

    @Test
    void noSubkeysIsNotForEncryption() {
        assertFalse(new Key().isForEncryption());
    }

    @Test
    void noSubkeysIsNotForDecryption() {
        assertFalse(new Key().isForDecryption());
    }

    @Test
    void noSubkeysHasNoMaster() {
        assertNull(new Key().getMaster());
    }

    @Test
    void noSubkeysHasNoSubkeysList() {
        assertEquals(List.of(), new Key().getSubkeys());
    }

    @Test
    void toPublicKeyOfNoSubkeysHasNoSubkeys() throws PGPException {
        assertEquals(List.of(), new Key().toPublicKey().getSubkeys());
    }

    @Test
    void settingSubkeysToNullMakesThemEmptyList() {
        Key key = new Key();
        key.setSubkeys(null);
        assertEquals(List.of(), key.getSubkeys());
    }

    @Test
    void loadingEmptyKeysRaisesAnException() {
        assertThrows(PGPException.class, () -> new Key(""));
    }

    @Test
    void charArrayPassphraseConstructorUnlocksSecretKey() throws Exception {
        Key key = new Key(loadResourceAsString("test-key-1.asc"), PASSPHRASE.toCharArray());
        assertNotNull(key.getMaster().getSecretKey());
    }

    @Test
    void matchesDelegatesToFindAll() throws Exception {
        Key key = new Key(loadResource("test-key-1-pub.asc"));
        assertTrue(key.matches("test-key-1"));
        assertTrue(key.matches(Pattern.compile("(?i)c02e")));
        assertFalse(key.matches("no-such-key"));
        assertFalse(key.matches(Pattern.compile("no-such-key")));
    }

    @Test
    void loadReplacesSubkeysFromArmor() throws Exception {
        Key key = new Key();
        key.load(loadResourceAsString("test-key-1-pub.asc"));
        assertEquals(List.of("013826C3", "970C7061"), shortIds(key.getSubkeys()));
    }

    @Test
    void loadFromFileAndStream() throws Exception {
        Key fromFile = new Key();
        fromFile.load(loadResourceFile("test-key-2-pub.asc"));
        assertFalse(fromFile.getSubkeys().isEmpty());

        Key fromStream = new Key();
        fromStream.load(loadResource("test-key-2-pub.asc"));
        assertFalse(fromStream.getSubkeys().isEmpty());
    }

    @Test
    void loadEmptyArmorRaisesException() {
        Key key = new Key();
        assertThrows(PGPException.class, () -> key.load(""));
    }

    private static List<String> subkeyPassphrases(Key key) {
        return key.getSubkeys().stream()
            .map(Subkey::getPassphrase)
            .collect(Collectors.toList());
    }

    private static List<String> shortIds(List<Subkey> subkeys) {
        return subkeys.stream().map(Subkey::getShortId).collect(Collectors.toList());
    }
}
