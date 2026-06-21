package org.c02e.jpgpj;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

@Tag("fips-conflict")
class JcaContextHelperFipsClasspathConflictTest {

    @AfterEach
    void tearDown() {
        JcaContextHelper.resetSecurityProviderForTests();
    }

    @Test
    void throwsWhenStandardAndFipsProvidersAreBothOnClasspath() {
        JcaContextHelper.resetSecurityProviderForTests();

        IllegalStateException e = assertThrows(
                IllegalStateException.class,
                JcaContextHelper::getSecurityProvider);

        assertTrue(e.getMessage().contains("Both Bouncy Castle FIPS and standard providers"));
    }
}
