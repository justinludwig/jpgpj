package org.c02e.jpgpj;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Provider;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.c02e.jpgpj.HashingAlgorithm;
import org.c02e.jpgpj.PassphraseKeyDerivation;

class JcaContextHelperTest {

    @AfterEach
    void tearDown() {
        JcaContextHelper.resetSecurityProviderForTests();
    }

    @Test
    void standardBouncyCastleProviderIsDetected() {
        JcaContextHelper.resetSecurityProviderForTests();

        Provider provider = JcaContextHelper.getSecurityProvider();

        assertNotNull(provider);
        assertEquals(BouncyCastleProvider.PROVIDER_NAME, provider.getName());
    }

    @Test
    void setSecurityProviderOverridesResolution() {
        JcaContextHelper.resetSecurityProviderForTests();
        Provider custom = new BouncyCastleProvider();

        JcaContextHelper.setSecurityProvider(custom);

        assertSame(custom, JcaContextHelper.getSecurityProvider());
    }

    @Test
    void resetSecurityProviderForTestsAllowsReResolution() {
        Provider custom = new BouncyCastleProvider();
        JcaContextHelper.setSecurityProvider(custom);
        assertSame(custom, JcaContextHelper.getSecurityProvider());

        JcaContextHelper.resetSecurityProviderForTests();

        Provider resolved = JcaContextHelper.getSecurityProvider();
        assertNotNull(resolved);
        assertEquals(BouncyCastleProvider.PROVIDER_NAME, resolved.getName());
    }

    @Test
    void systemPropertySelectsProvider() {
        String key = JcaContextHelper.SECURITY_PROVIDER_PROPERTY;
        String previous = System.getProperty(key);
        try {
            JcaContextHelper.resetSecurityProviderForTests();
            System.setProperty(key, BouncyCastleProvider.class.getName());

            Provider provider = JcaContextHelper.getSecurityProvider();

            assertNotNull(provider);
            assertEquals(BouncyCastleProvider.PROVIDER_NAME, provider.getName());
        } finally {
            restoreSystemProperty(key, previous);
            JcaContextHelper.resetSecurityProviderForTests();
        }
    }

    @Test
    void missingConfiguredProviderClassFallsBackToStandardBc() {
        String key = JcaContextHelper.SECURITY_PROVIDER_PROPERTY;
        String previous = System.getProperty(key);
        try {
            JcaContextHelper.resetSecurityProviderForTests();
            System.setProperty(key, "org.example.jpgpj.DoesNotExistProvider");

            assertNull(JcaContextHelper.getSecurityProvider());
        } finally {
            restoreSystemProperty(key, previous);
            JcaContextHelper.resetSecurityProviderForTests();
        }
    }

    @Test
    void iteratedSaltedSymmetricEncryptionRoundTrip() throws Exception {
        Encryptor encryptor = new Encryptor()
                .withSigningAlgorithm(HashingAlgorithm.Unsigned)
                .withPassphraseKeyDerivation(PassphraseKeyDerivation.IteratedSalted)
                .withDeriviationAlgorithm(HashingAlgorithm.SHA512)
                .withKeyDeriviationWorkFactor(10)
                .withSymmetricPassphrase("c02e");
        Decryptor decryptor = new Decryptor()
                .withVerificationRequired(false)
                .withSymmetricPassphrase("c02e");

        ByteArrayOutputStream cipherOut = new ByteArrayOutputStream();
        encryptor.encrypt(
                new ByteArrayInputStream("test\n".getBytes(StandardCharsets.UTF_8)),
                cipherOut);

        ByteArrayOutputStream plainOut = new ByteArrayOutputStream();
        decryptor.decrypt(new ByteArrayInputStream(cipherOut.toByteArray()), plainOut);

        assertEquals("test\n", plainOut.toString(StandardCharsets.UTF_8));
    }

    private static void restoreSystemProperty(String key, String previous) {
        if (previous == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, previous);
        }
    }
}
