package org.c02e.jpgpj.support;

import org.c02e.jpgpj.Decryptor;
import org.c02e.jpgpj.Key;

/**
 * Test-only decryptor with fluent helpers.
 */
public final class TestDecryptor extends Decryptor {

    public TestDecryptor(Key... keys) {
        super(keys);
    }

    @Override
    public TestDecryptor withVerificationRequired(boolean x) {
        super.withVerificationRequired(x);
        return this;
    }
}
