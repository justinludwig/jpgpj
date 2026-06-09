package org.c02e.jpgpj;

import org.bouncycastle.gpg.keybox.jcajce.JcaKeyBoxBuilder;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.InvocationTargetException;
import java.security.Provider;
import java.security.SecureRandom;

/**
 * Helper class for Java Cryptography Architecture (JCA) context
 * consisting of {@link java.security.Provider provider}.
 * <p>
 * Provider resolution order (lazy, on first use):
 * <ol>
 *   <li>Explicit value from {@link #setSecurityProvider(Provider)}</li>
 *   <li>System property {@value #SECURITY_PROVIDER_PROPERTY} (fully-qualified class name)</li>
 *   <li>{@code org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider} if on classpath</li>
 *   <li>{@code org.bouncycastle.jce.provider.BouncyCastleProvider} if on classpath</li>
 * </ol>
 * Standard and FIPS Bouncy Castle providers must not coexist in the same JVM.
 * <p>
 * Note: This class is not thread-safe; the security provider should not be changed during PGP operations.
 */
public class JcaContextHelper {
    public static final String SECURITY_PROVIDER_PROPERTY = "jpgpj.security.provider";

    private static final String FIPS_PROVIDER_CLASS =
            "org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider";
    private static final String STANDARD_PROVIDER_CLASS =
            "org.bouncycastle.jce.provider.BouncyCastleProvider";

    private static final Logger log = LoggerFactory.getLogger(JcaContextHelper.class.getName());
    private static Provider securityProvider;
    private static boolean providerResolved;

    private JcaContextHelper() {
    }

    /**
     * Get the security provider which is used for all operations.
     */
    public static Provider getSecurityProvider() {
        resolveProvider();
        return securityProvider;
    }

    /**
     * Set the security provider to be used for all operations.
     * Call before any JPGPJ crypto operation when using Bouncy Castle FIPS artifacts.
     */
    public static void setSecurityProvider(Provider provider) {
        securityProvider = provider;
        providerResolved = true;
    }

    /**
     * Reset provider resolution state. Intended for tests only.
     */
    static void resetSecurityProviderForTests() {
        securityProvider = null;
        providerResolved = false;
    }

    static boolean isSecurityProviderNotNull() {
        return getSecurityProvider() != null;
    }

    static JcaKeyFingerprintCalculator getJcaKeyFingerprintCalculator() {
        JcaKeyFingerprintCalculator fingerPrintCalculator = new JcaKeyFingerprintCalculator();
        if (JcaContextHelper.isSecurityProviderNotNull()) {
            fingerPrintCalculator.setProvider(JcaContextHelper.getSecurityProvider());
        }
        return fingerPrintCalculator;
    }

    static PGPContentVerifierBuilderProvider getPGPContentVerifierBuilderProvider() {
        JcaPGPContentVerifierBuilderProvider provider = new JcaPGPContentVerifierBuilderProvider();
        if (JcaContextHelper.isSecurityProviderNotNull()) {
            provider.setProvider(JcaContextHelper.getSecurityProvider());
        }
        return provider;
    }

    static PGPDigestCalculatorProvider getPGPDigestCalculatorProvider() throws PGPException {
        JcaPGPDigestCalculatorProviderBuilder builder = new JcaPGPDigestCalculatorProviderBuilder();
        if (JcaContextHelper.isSecurityProviderNotNull()) {
            builder.setProvider(JcaContextHelper.getSecurityProvider());
        }
        return builder.build();
    }

    static JcePBEDataDecryptorFactoryBuilder getJcePBEDataDecryptorFactoryBuilder() throws PGPException {
        JcePBEDataDecryptorFactoryBuilder builder =
                new JcePBEDataDecryptorFactoryBuilder(JcaContextHelper.getPGPDigestCalculatorProvider());
        if (JcaContextHelper.isSecurityProviderNotNull()) {
            builder.setProvider(JcaContextHelper.getSecurityProvider());
        }
        return builder;
    }

    static JcePublicKeyDataDecryptorFactoryBuilder getJcePublicKeyDataDecryptorFactoryBuilder() {
        JcePublicKeyDataDecryptorFactoryBuilder builder = new JcePublicKeyDataDecryptorFactoryBuilder();
        if (JcaContextHelper.isSecurityProviderNotNull()) {
            builder.setProvider(JcaContextHelper.getSecurityProvider());
        }
        return builder;
    }

    static PGPDataEncryptorBuilder getPGPDataEncryptorBuilder(
            EncryptionAlgorithm cipher,
            EncryptionProtection protection,
            AeadAlgorithm aeadAlgorithm,
            AeadPacketStyle aeadPacketStyle,
            int aeadChunkSize) {
        JcePGPDataEncryptorBuilder builder =
                new JcePGPDataEncryptorBuilder(cipher.getOpenPgpTag());
        if (JcaContextHelper.isSecurityProviderNotNull()) {
            builder.setProvider(JcaContextHelper.getSecurityProvider());
        }
        if (protection == EncryptionProtection.Aead) {
            builder.setWithAEAD(aeadAlgorithm.getOpenPgpTag(), aeadChunkSize);
            if (aeadPacketStyle == AeadPacketStyle.V6) {
                builder.setUseV6AEAD();
            } else {
                builder.setUseV5AEAD();
            }
        } else {
            builder.setWithIntegrityPacket(true);
        }
        return builder;
    }

    static JcaKeyBoxBuilder getJcaKeyBoxBuilder() {
        JcaKeyBoxBuilder builder = new JcaKeyBoxBuilder();
        if (JcaContextHelper.isSecurityProviderNotNull()) {
            builder.setProvider(JcaContextHelper.getSecurityProvider());
        }
        return builder;
    }

    static JcePBESecretKeyDecryptorBuilder getJcePBESecretKeyDecryptorBuilder() throws PGPException {
        JcePBESecretKeyDecryptorBuilder builder =
                new JcePBESecretKeyDecryptorBuilder(JcaContextHelper.getPGPDigestCalculatorProvider());
        if (JcaContextHelper.isSecurityProviderNotNull()) {
            builder.setProvider(JcaContextHelper.getSecurityProvider());
        }
        return builder;
    }

    static PublicKeyKeyEncryptionMethodGenerator getPublicKeyKeyEncryptionMethodGenerator(PGPPublicKey publicKey) {
        JcePublicKeyKeyEncryptionMethodGenerator generator = new JcePublicKeyKeyEncryptionMethodGenerator(publicKey);
        if (JcaContextHelper.isSecurityProviderNotNull()) {
            generator.setProvider(JcaContextHelper.getSecurityProvider());
        }
        return generator;
    }

    static PBEKeyEncryptionMethodGenerator getPBEKeyEncryptionMethodGenerator(
            char[] symmetricPassphraseChars,
            HashingAlgorithm hashAlgorithm,
            int workFactor) throws PGPException {
        PGPDigestCalculatorProvider digestCalculatorProvider = JcaContextHelper.getPGPDigestCalculatorProvider();
        JcePBEKeyEncryptionMethodGenerator generator = new JcePBEKeyEncryptionMethodGenerator(
                symmetricPassphraseChars,
                digestCalculatorProvider.get(hashAlgorithm.getOpenPgpTag()),
                workFactor);
        configurePbeGenerator(generator);
        return generator;
    }

    static PBEKeyEncryptionMethodGenerator getPBEKeyEncryptionMethodGenerator(
            char[] symmetricPassphraseChars,
            Argon2Parameters argon2Parameters) throws PGPException {
        JcePBEKeyEncryptionMethodGenerator generator = new JcePBEKeyEncryptionMethodGenerator(
                symmetricPassphraseChars,
                argon2Parameters.toBcParams());
        configurePbeGenerator(generator);
        return generator;
    }

    private static void configurePbeGenerator(JcePBEKeyEncryptionMethodGenerator generator) {
        if (JcaContextHelper.isSecurityProviderNotNull()) {
            generator.setProvider(JcaContextHelper.getSecurityProvider());
        }
        generator.setSecureRandom(new SecureRandom());
    }

    static PGPContentSignerBuilder getPGPContentSignerBuilder(
            int keyAlgorithmCode,
            HashingAlgorithm hashAlgorithm) {
        JcaPGPContentSignerBuilder builder =
                new JcaPGPContentSignerBuilder(keyAlgorithmCode, hashAlgorithm.getOpenPgpTag());
        if (JcaContextHelper.isSecurityProviderNotNull()) {
            builder.setProvider(JcaContextHelper.getSecurityProvider());
        }
        return builder;
    }

    private static void resolveProvider() {
        if (providerResolved) {
            return;
        }
        providerResolved = true;

        String configuredClass = System.getProperty(SECURITY_PROVIDER_PROPERTY);
        if (configuredClass != null && !configuredClass.isBlank()) {
            securityProvider = loadProvider(configuredClass.trim());
            if (securityProvider == null) {
                log.warn("Configured security provider {} not found on classpath", configuredClass);
            }
            return;
        }

        boolean fipsPresent = isClassPresent(FIPS_PROVIDER_CLASS);
        boolean standardPresent = isClassPresent(STANDARD_PROVIDER_CLASS);
        if (fipsPresent && standardPresent) {
            throw new IllegalStateException(
                    "Both Bouncy Castle FIPS and standard providers are on the classpath. "
                            + "Use only one BC stack per JVM (see JPGPJ FIPS documentation).");
        }

        if (fipsPresent) {
            securityProvider = loadProvider(FIPS_PROVIDER_CLASS);
            log.debug("Using Bouncy Castle FIPS security provider");
            return;
        }

        if (standardPresent) {
            securityProvider = loadProvider(STANDARD_PROVIDER_CLASS);
            log.debug("Using Bouncy Castle standard security provider");
            return;
        }

        log.warn("No Bouncy Castle security provider found on classpath, using default JVM provider");
    }

    private static boolean isClassPresent(String className) {
        try {
            Class.forName(className, false, JcaContextHelper.class.getClassLoader());
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }
    }

    private static Provider loadProvider(String className) {
        try {
            return (Provider) Class.forName(className)
                    .getDeclaredConstructor()
                    .newInstance();
        } catch (ClassNotFoundException
                | NoSuchMethodException
                | InstantiationException
                | IllegalAccessException
                | InvocationTargetException e) {
            log.warn("Security provider class {} could not be loaded: {}", className, e.toString());
            return null;
        }
    }
}
