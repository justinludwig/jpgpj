package org.c02e.jpgpj.support;

import org.junit.platform.launcher.LauncherSession;
import org.junit.platform.launcher.LauncherSessionListener;

/**
 * Normalizes JVM properties for tests. PIT forks an isolated JVM that does not
 * inherit Gradle {@code test} task settings; Bouncy Castle caches
 * {@code line.separator} when {@code org.bouncycastle.util.Strings} first loads.
 */
public final class TestEnvironmentListener implements LauncherSessionListener {

    static {
        System.setProperty("line.separator", "\n");
    }

    @Override
    public void launcherSessionOpened(LauncherSession session) {
        System.setProperty("line.separator", "\n");
    }
}
