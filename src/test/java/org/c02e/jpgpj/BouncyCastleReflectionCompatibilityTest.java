package org.c02e.jpgpj;

import static org.c02e.jpgpj.EncryptionDetails.PBE_ENCRYPTED_DATA_KEY_DATA_FIELD;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.lang.reflect.Field;

import org.bouncycastle.bcpg.SymmetricKeyEncSessionPacket;
import org.bouncycastle.openpgp.PGPPBEEncryptedData;
import org.junit.jupiter.api.Test;

/**
 * Build guard for {@link EncryptionDetails} reflection against Bouncy Castle internals.
 * <p>
 * {@link EncryptionDetails} reads {@code PGPPBEEncryptedData.keyData} reflectively to
 * populate passphrase key-derivation metadata (S2K / Argon2). If a Bouncy Castle upgrade
 * renames or removes that field, this test fails during {@code ./gradlew test} (and CI)
 * so maintainers can update the reflection path before release.
 */
class BouncyCastleReflectionCompatibilityTest {

    @Test
    void pgppbeEncryptedDataKeyDataFieldExistsWithExpectedType() throws Exception {
        Field field = PGPPBEEncryptedData.class.getDeclaredField(PBE_ENCRYPTED_DATA_KEY_DATA_FIELD);
        assertEquals(SymmetricKeyEncSessionPacket.class, field.getType());
    }
}
