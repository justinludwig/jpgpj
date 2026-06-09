package org.c02e.jpgpj;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class EncryptionDetailsTest {

    private static EncryptionDetails sampleDetails() {
        EncryptionDetails details = new EncryptionDetails();
        details.setProtection(EncryptionProtection.Aead);
        details.setSessionCipher(EncryptionAlgorithm.AES256);
        details.setAeadAlgorithm(AeadAlgorithm.Ocb);
        details.setAeadPacketStyle(AeadPacketStyle.V6);
        details.setAeadChunkSize(6);
        details.setPassphraseKeyDerivation(PassphraseKeyDerivation.Argon2);
        details.setArgon2Parameters(Argon2Parameters.GPG_RECOMMENDED);
        details.setDetectedProfile(OpenPgpProfile.Modern);
        return details;
    }

    @Test
    void copyPreservesAllFields() {
        EncryptionDetails original = sampleDetails();
        EncryptionDetails copy = original.copy();

        assertEquals(original, copy);
        assertNotSameFieldInstances(original, copy);
    }

    @Test
    void equalsAndHashCodeMatchForEqualInstances() {
        EncryptionDetails left = sampleDetails();
        EncryptionDetails right = sampleDetails();

        assertEquals(left, right);
        assertEquals(left.hashCode(), right.hashCode());
        assertEquals(left, left);
    }

    @Test
    void equalsDetectsFieldDifferences() {
        EncryptionDetails baseline = sampleDetails();

        EncryptionDetails differentChunk = sampleDetails();
        differentChunk.setAeadChunkSize(7);
        assertNotEquals(baseline, differentChunk);

        EncryptionDetails differentProfile = sampleDetails();
        differentProfile.setDetectedProfile(OpenPgpProfile.Classic);
        assertNotEquals(baseline, differentProfile);

        EncryptionDetails differentArgon2 = sampleDetails();
        differentArgon2.setArgon2Parameters(Argon2Parameters.MEMORY_CONSTRAINED);
        assertNotEquals(baseline, differentArgon2);
    }

    @Test
    void equalsRejectsNullAndOtherTypes() {
        EncryptionDetails details = sampleDetails();
        assertFalse(details.equals(null));
        assertFalse(details.equals("not-details"));
    }

    @Test
    void toStringIncludesKeyFields() {
        String text = sampleDetails().toString();
        assertTrue(text.contains("protection="));
        assertTrue(text.contains("sessionCipher="));
        assertTrue(text.contains("aeadAlgorithm="));
        assertTrue(text.contains("detectedProfile="));
        assertNotNull(text);
    }

    private static void assertNotSameFieldInstances(EncryptionDetails left, EncryptionDetails right) {
        assertNotNull(left.getArgon2Parameters());
        assertNotNull(right.getArgon2Parameters());
        assertEquals(left.getArgon2Parameters(), right.getArgon2Parameters());
    }
}
