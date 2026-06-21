package org.c02e.jpgpj;

import static org.c02e.jpgpj.support.PgpTestSupport.PASSPHRASE;
import static org.c02e.jpgpj.support.PgpTestSupport.loadResource;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.junit.jupiter.api.Test;

class SubkeyTest {

    @Test
    void publicKeyFormatsFingerprint() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-pub.asc"));
        assertEquals(List.of(
            "AE136750D165E6A4AACB1D092B04481E880A1469",
            "1F62DF843110BACAE18B38DC6727B00AAFAFA3C5",
            "66B9E5A5414E51C78F9B272AAFDB7B47BC3F6A4B"
        ), fingerprints(key));
    }

    @Test
    void secretKeyFormatsFingerprint() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of(
            "AE136750D165E6A4AACB1D092B04481E880A1469",
            "1F62DF843110BACAE18B38DC6727B00AAFAFA3C5",
            "66B9E5A5414E51C78F9B272AAFDB7B47BC3F6A4B"
        ), fingerprints(key));
    }

    @Test
    void publicKeyFormatsId() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-pub.asc"));
        assertEquals(List.of(
            "0x2B04481E880A1469", "0x6727B00AAFAFA3C5", "0xAFDB7B47BC3F6A4B"
        ), ids(key));
    }

    @Test
    void secretKeyFormatsId() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of(
            "0x2B04481E880A1469", "0x6727B00AAFAFA3C5", "0xAFDB7B47BC3F6A4B"
        ), ids(key));
    }

    @Test
    void publicKeyFormatsShortId() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-pub.asc"));
        assertEquals(List.of("880A1469", "AFAFA3C5", "BC3F6A4B"), shortIds(key));
    }

    @Test
    void secretKeyFormatsShortId() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of("880A1469", "AFAFA3C5", "BC3F6A4B"), shortIds(key));
    }

    @Test
    void publicKeyListsUidsForMaster() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-pub.asc"));
        assertEquals(List.of(
            List.of(
                "Test Key 2 <test-key-2@c02e.org>",
                "Test 2 (CODESurvey) <test-key-2@codesurvey.org>"
            ),
            List.of(),
            List.of()
        ), subkeyUids(key));
    }

    @Test
    void secretKeyListsUidsForMaster() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of(
            List.of(
                "Test Key 2 <test-key-2@c02e.org>",
                "Test 2 (CODESurvey) <test-key-2@codesurvey.org>"
            ),
            List.of(),
            List.of()
        ), subkeyUids(key));
    }

    @Test
    void publicKeyMatchesMasterSubkeyByUid() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-pub.asc"));
        assertEquals(List.of(false, false, false), matchesAll(key, ""));
        assertEquals(List.of(false, false, false), matchesAll(key, "foo"));
        assertEquals(List.of(true, false, false), matchesAll(key, "test key"));
        assertEquals(List.of(true, false, false), matchesAll(key, "codesurvey"));
        assertEquals(List.of(true, false, false), matchesAll(key, Pattern.compile("test-key.*@c02e")));
    }

    @Test
    void secretKeyMatchesMasterSubkeyByUid() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of(false, false, false), matchesAll(key, ""));
        assertEquals(List.of(false, false, false), matchesAll(key, "foo"));
        assertEquals(List.of(true, false, false), matchesAll(key, "test key"));
        assertEquals(List.of(true, false, false), matchesAll(key, "codesurvey"));
        assertEquals(List.of(true, false, false), matchesAll(key, Pattern.compile("test-key.*@c02e")));
    }

    @Test
    void publicKeyMatchesByShortId() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-pub.asc"));
        assertEquals(List.of(true, true, true), matchesAll(key, "a"));
        assertEquals(List.of(true, false, false), matchesAll(key, "880A1469"));
        assertEquals(List.of(false, true, false), matchesAll(key, "AFAFA3C5"));
        assertEquals(List.of(false, false, true), matchesAll(key, "BC3F6A4B"));
        assertEquals(List.of(false, false, false), matchesAll(key, "0x880A1469"));
    }

    @Test
    void secretKeyMatchesByShortId() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of(true, true, true), matchesAll(key, "a"));
        assertEquals(List.of(true, false, false), matchesAll(key, "880A1469"));
        assertEquals(List.of(false, true, false), matchesAll(key, "AFAFA3C5"));
        assertEquals(List.of(false, false, true), matchesAll(key, "BC3F6A4B"));
        assertEquals(List.of(false, false, false), matchesAll(key, "0x880A1469"));
    }

    @Test
    void publicKeyMatchesByLongId() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-pub.asc"));
        assertEquals(List.of(true, true, true), matchesAll(key, "a"));
        assertEquals(List.of(true, false, false), matchesAll(key, "0x2B04481E880A1469"));
        assertEquals(List.of(false, true, false), matchesAll(key, "0x6727B00AAFAFA3C5"));
        assertEquals(List.of(false, false, true), matchesAll(key, "0xAFDB7B47BC3F6A4B"));
        assertEquals(List.of(true, false, false), matchesAll(key, "2B04481E880A1469"));
    }

    @Test
    void secretKeyMatchesByLongId() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of(true, true, true), matchesAll(key, "a"));
        assertEquals(List.of(true, false, false), matchesAll(key, "0x2B04481E880A1469"));
        assertEquals(List.of(false, true, false), matchesAll(key, "0x6727B00AAFAFA3C5"));
        assertEquals(List.of(false, false, true), matchesAll(key, "0xAFDB7B47BC3F6A4B"));
        assertEquals(List.of(true, false, false), matchesAll(key, "2B04481E880A1469"));
    }

    @Test
    void publicKeyMatchesByFingerprint() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-pub.asc"));
        assertEquals(List.of(true, true, true), matchesAll(key, "a"));
        assertEquals(List.of(true, false, false),
            matchesAll(key, "AE136750D165E6A4AACB1D092B04481E880A1469"));
        assertEquals(List.of(false, true, false),
            matchesAll(key, "1F62DF843110BACAE18B38DC6727B00AAFAFA3C5"));
        assertEquals(List.of(false, false, true),
            matchesAll(key, "66B9E5A5414E51C78F9B272AAFDB7B47BC3F6A4B"));
        assertEquals(List.of(false, false, false),
            matchesAll(key, "0xAE136750D165E6A4AACB1D092B04481E880A1469"));
    }

    @Test
    void secretKeyMatchesByFingerprint() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of(true, true, true), matchesAll(key, "a"));
        assertEquals(List.of(true, false, false),
            matchesAll(key, "AE136750D165E6A4AACB1D092B04481E880A1469"));
        assertEquals(List.of(false, true, false),
            matchesAll(key, "1F62DF843110BACAE18B38DC6727B00AAFAFA3C5"));
        assertEquals(List.of(false, false, true),
            matchesAll(key, "66B9E5A5414E51C78F9B272AAFDB7B47BC3F6A4B"));
        assertEquals(List.of(false, false, false),
            matchesAll(key, "0xAE136750D165E6A4AACB1D092B04481E880A1469"));
    }

    @Test
    void basicPublicKeyCanBeUsedOnlyForVerificationAndEncryption() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1-pub.asc"));
        assertEquals(List.of(false, false), forSigning(key));
        assertEquals(List.of(true, false), forVerification(key));
        assertEquals(List.of(false, true), forEncryption(key));
        assertEquals(List.of(false, false), forDecryption(key));
    }

    @Test
    void basicSecretKeyCanBeUsedForAnything() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1.asc"));
        assertEquals(List.of(true, false), forSigning(key));
        assertEquals(List.of(true, false), forVerification(key));
        assertEquals(List.of(false, true), forEncryption(key));
        assertEquals(List.of(false, true), forDecryption(key));
    }

    @Test
    void enhancedPublicKeyHasExtraSigningSubkeyForVerification() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-pub.asc"));
        assertEquals(List.of(false, false, false), forSigning(key));
        assertEquals(List.of(true, false, true), forVerification(key));
        assertEquals(List.of(false, true, false), forEncryption(key));
        assertEquals(List.of(false, false, false), forDecryption(key));
    }

    @Test
    void enhancedSecretKeyHasExtraSigningSubkeyButNoMasterPrivateKey() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of(false, false, true), forSigning(key));
        assertEquals(List.of(true, false, true), forVerification(key));
        assertEquals(List.of(false, true, false), forEncryption(key));
        assertEquals(List.of(false, true, false), forDecryption(key));
    }

    @Test
    void secretKeyWithNoUsageFlagsNotUsedForAnythingByDefault() throws IOException, PGPException {
        Key key = new Key(loadResource("test-no-usage-3-subkeys.asc"));
        assertEquals(List.of(false, false, false), forSigning(key));
        assertEquals(List.of(false, false, false), forVerification(key));
        assertEquals(List.of(false, false, false), forEncryption(key));
        assertEquals(List.of(false, false, false), forDecryption(key));
    }

    @Test
    void rsaPublicKeyIsTechnicallyUsableForVerificationAndEncryption() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-pub.asc"));
        assertEquals(List.of(false, false, false), usableForSigning(key));
        assertEquals(List.of(true, true, true), usableForVerification(key));
        assertEquals(List.of(true, true, true), usableForEncryption(key));
        assertEquals(List.of(false, false, false), usableForDecryption(key));
    }

    @Test
    void rsaSecretKeyIsTechnicallyUsableForAllUsages() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-master.asc"));
        assertEquals(List.of(true, true, true), usableForSigning(key));
        assertEquals(List.of(true, true, true), usableForVerification(key));
        assertEquals(List.of(true, true, true), usableForEncryption(key));
        assertEquals(List.of(true, true, true), usableForDecryption(key));
    }

    @Test
    void rsaSecretKeyWithNoFlagsIsTechnicallyUsableForAllUsages() throws IOException, PGPException {
        Key key = new Key(loadResource("test-no-usage-3-subkeys.asc"));
        assertEquals(List.of(true, true, true), usableForSigning(key));
        assertEquals(List.of(true, true, true), usableForVerification(key));
        assertEquals(List.of(true, true, true), usableForEncryption(key));
        assertEquals(List.of(true, true, true), usableForDecryption(key));
    }

    @Test
    void ecSecretKeyIsTechnicallyUsableOnlyForEdOrVs() throws IOException, PGPException {
        Key key = new Key(loadResource("test-no-usage-ec-subkeys.asc"));
        assertEquals(List.of(true, true, false), usableForSigning(key));
        assertEquals(List.of(true, true, false), usableForVerification(key));
        assertEquals(List.of(false, false, true), usableForEncryption(key));
        assertEquals(List.of(false, false, true), usableForDecryption(key));
    }

    @Test
    void dsaSecretKeyHasDsaPrimaryAndRsaEncryptionSubkey() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-dsa.asc"));
        // DSA primary (SCA) and RSA subkey (SEA) are both usable for signing
        assertEquals(List.of(true, true), usableForSigning(key));
        assertEquals(List.of(true, true), usableForVerification(key));
        assertEquals(List.of(false, true), usableForEncryption(key));
        assertEquals(List.of(false, true), usableForDecryption(key));
        assertEquals(List.of(true, true), forSigning(key));
        assertEquals(List.of(true, true), forVerification(key));
        assertEquals(List.of(false, true), forEncryption(key));
        assertEquals(List.of(false, true), forDecryption(key));
    }

    @Test
    void ecdsaSecretKeyWithUsageFlagsSelectsCorrectSubkeys() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-ecdsa.asc"));
        assertEquals(List.of(true, false), usableForSigning(key));
        assertEquals(List.of(true, false), usableForVerification(key));
        assertEquals(List.of(false, true), usableForEncryption(key));
        assertEquals(List.of(false, true), usableForDecryption(key));
        assertEquals(List.of(true, false), forSigning(key));
        assertEquals(List.of(true, false), forVerification(key));
        assertEquals(List.of(false, true), forEncryption(key));
        assertEquals(List.of(false, true), forDecryption(key));
    }

    @Test
    void ed25519SecretKeyIsUsableForSigningAndCv25519Encryption() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-ed25519.asc"));
        assertEquals(List.of(true, false), usableForSigning(key));
        assertEquals(List.of(true, false), usableForVerification(key));
        assertEquals(List.of(false, true), usableForEncryption(key));
        assertEquals(List.of(false, true), usableForDecryption(key));
        assertEquals(List.of(true, false), forSigning(key));
        assertEquals(List.of(true, false), forVerification(key));
        assertEquals(List.of(false, true), forEncryption(key));
        assertEquals(List.of(false, true), forDecryption(key));
    }

    @Test
    void extractPrivateKey() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2.asc"), PASSPHRASE);
        assertEquals(Arrays.asList(null, true, true), privateKeyPresent(key));
        assertEquals(List.of(false, true, true), unlocked(key));
    }

    @Test
    void extractPrivateKeyWithCharArrayPassphrase() throws Exception {
        char[] passphrase = PASSPHRASE.toCharArray();
        Key key = new Key(loadResource("test-key-2.asc"), passphrase);
        assertEquals(Arrays.asList(null, true, true), privateKeyPresent(key));
        assertEquals(List.of(false, true, true), unlocked(key));

        passphrase[0] = 'x';
        assertEquals(List.of("x02e", "x02e", "x02e"), subkeyPassphrases(key));
    }

    @Test
    void cannotExtractPrivateKeyFromPublicKey() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-pub.asc"), PASSPHRASE);
        assertEquals(Arrays.asList(null, null, null), privateKeyPresent(key));
        assertEquals(List.of(false, false, false), unlocked(key));
    }

    @Test
    void cannotExtractPrivateKeyWithoutCorrectPassphrase() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-1.asc"));
        PassphraseException e = assertThrows(PassphraseException.class, () -> {
            for (Subkey subkey : key.getSubkeys()) {
                subkey.getPrivateKey();
            }
        });
        assertEquals(
            "incorrect passphrase for subkey sec vs 013826C3 Test Key 1 <test-key-1@c02e.org>",
            e.getMessage()
        );
    }

    @Test
    void unlockPrivateKeyWithoutCachingPassphrase() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2.asc"));
        for (Subkey subkey : key.getSubkeys()) {
            subkey.unlock(PASSPHRASE.toCharArray());
        }
        assertEquals(Arrays.asList(null, true, true), privateKeyPresent(key));
        assertEquals(List.of(false, true, true), unlocked(key));
        assertEmptyPassphraseChars(key);
    }

    @Test
    void clearSecretsZerosPassphraseAndReleasesPrivateKey() throws Exception {
        char[] passphrase = PASSPHRASE.toCharArray();
        Key key = new Key(loadResource("test-key-2.asc"), passphrase);
        assertEquals(Arrays.asList(null, true, true), privateKeyPresent(key));
        assertEquals(List.of(false, true, true), unlocked(key));

        for (Subkey subkey : key.getSubkeys()) {
            subkey.clearSecrets();
        }

        assertArrayEquals(new char[] {0, 0, 0, 0}, passphrase);
        assertEquals(List.of(false, false, false), unlocked(key));
        assertEmptyPassphraseChars(key);
        assertEquals(List.of("", "", ""), subkeyPassphrases(key));
    }

    @Test
    void emptySubkeyAsStringPrintsNul() {
        assertEquals("nul", new Subkey().toString());
    }

    @Test
    void publicKeyAsString() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2-pub.asc"));
        assertEquals(List.of(
            "pub v  880A1469 Test Key 2 <test-key-2@c02e.org>, Test 2 (CODESurvey) <test-key-2@codesurvey.org>",
            "pub e  AFAFA3C5",
            "pub v  BC3F6A4B"
        ), subkeyStrings(key));
    }

    @Test
    void secretKeyWithoutPassphraseAsString() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2.asc"));
        assertEquals(List.of(
            "sec v  880A1469 Test Key 2 <test-key-2@c02e.org>, Test 2 (CODESurvey) <test-key-2@codesurvey.org>",
            "sec ed AFAFA3C5",
            "sec vs BC3F6A4B"
        ), subkeyStrings(key));
    }

    @Test
    void secretKeyWithPassphraseAsString() throws IOException, PGPException {
        Key key = new Key(loadResource("test-key-2.asc"), PASSPHRASE);
        assertEquals(List.of(
            "sec+v  880A1469 Test Key 2 <test-key-2@c02e.org>, Test 2 (CODESurvey) <test-key-2@codesurvey.org>",
            "sec+ed AFAFA3C5",
            "sec+vs BC3F6A4B"
        ), subkeyStrings(key));
    }

    private static List<String> fingerprints(Key key) {
        return key.getSubkeys().stream().map(Subkey::getFingerprint).collect(Collectors.toList());
    }

    private static List<String> ids(Key key) {
        return key.getSubkeys().stream().map(Subkey::getId).collect(Collectors.toList());
    }

    private static List<String> shortIds(Key key) {
        return key.getSubkeys().stream().map(Subkey::getShortId).collect(Collectors.toList());
    }

    private static List<List<String>> subkeyUids(Key key) {
        return key.getSubkeys().stream().map(Subkey::getUids).collect(Collectors.toList());
    }

    private static List<Boolean> matchesAll(Key key, String id) {
        return key.getSubkeys().stream().map(subkey -> subkey.matches(id)).collect(Collectors.toList());
    }

    private static List<Boolean> matchesAll(Key key, Pattern id) {
        return key.getSubkeys().stream().map(subkey -> subkey.matches(id)).collect(Collectors.toList());
    }

    private static List<Boolean> forSigning(Key key) {
        return key.getSubkeys().stream().map(Subkey::isForSigning).collect(Collectors.toList());
    }

    private static List<Boolean> forVerification(Key key) {
        return key.getSubkeys().stream().map(Subkey::isForVerification).collect(Collectors.toList());
    }

    private static List<Boolean> forEncryption(Key key) {
        return key.getSubkeys().stream().map(Subkey::isForEncryption).collect(Collectors.toList());
    }

    private static List<Boolean> forDecryption(Key key) {
        return key.getSubkeys().stream().map(Subkey::isForDecryption).collect(Collectors.toList());
    }

    private static List<Boolean> usableForSigning(Key key) {
        return key.getSubkeys().stream().map(Subkey::isUsableForSigning).collect(Collectors.toList());
    }

    private static List<Boolean> usableForVerification(Key key) {
        return key.getSubkeys().stream().map(Subkey::isUsableForVerification).collect(Collectors.toList());
    }

    private static List<Boolean> usableForEncryption(Key key) {
        return key.getSubkeys().stream().map(Subkey::isUsableForEncryption).collect(Collectors.toList());
    }

    private static List<Boolean> usableForDecryption(Key key) {
        return key.getSubkeys().stream().map(Subkey::isUsableForDecryption).collect(Collectors.toList());
    }

    private static List<Object> privateKeyPresent(Key key) throws PGPException {
        List<Object> present = new java.util.ArrayList<>();
        for (Subkey subkey : key.getSubkeys()) {
            PGPPrivateKey privateKey = subkey.getPrivateKey();
            present.add(privateKey != null ? Boolean.TRUE : null);
        }
        return present;
    }

    private static List<Boolean> unlocked(Key key) {
        return key.getSubkeys().stream().map(Subkey::isUnlocked).collect(Collectors.toList());
    }

    private static List<String> subkeyPassphrases(Key key) {
        return key.getSubkeys().stream().map(Subkey::getPassphrase).collect(Collectors.toList());
    }

    private static void assertEmptyPassphraseChars(Key key) {
        for (Subkey subkey : key.getSubkeys()) {
            char[] chars = subkey.getPassphraseChars();
            assertTrue(chars == null || chars.length == 0);
        }
    }

    private static List<char[]> subkeyPassphraseChars(Key key) {
        return key.getSubkeys().stream().map(Subkey::getPassphraseChars).collect(Collectors.toList());
    }

    private static List<String> subkeyStrings(Key key) {
        return key.getSubkeys().stream().map(Subkey::toString).collect(Collectors.toList());
    }
}
