package org.c02e.jpgpj.support;

import org.bouncycastle.openpgp.PGPEncryptedData;
import org.c02e.jpgpj.Decryptor;
import org.c02e.jpgpj.Key;

/**
 * Test-only decryptor exposing encryption metadata captured during decrypt.
 */
public final class TestDecryptor extends Decryptor {

    public TestDecryptor(Key... keys) {
        super(keys);
    }

    public PGPEncryptedData getLastDecryptedEncryptedData() {
        return lastDecryptedEncryptedData;
    }

    public Integer getLastSessionCipherTag() {
        return lastSessionCipherTag;
    }

    @Override
    public TestDecryptor withVerificationRequired(boolean x) {
        super.withVerificationRequired(x);
        return this;
    }
}
