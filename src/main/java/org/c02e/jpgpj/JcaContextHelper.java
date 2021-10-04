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

/**
 * Helper class for Java Cryptography Architecture (JCA) context
 * consisting of {@link java.security.Provider provider}
 * Note: The following class is not thread safe, the security provider should not be changed during PGP operations
 */
public class JcaContextHelper {
	private static final Logger log = LoggerFactory.getLogger(JcaContextHelper.class.getName());
	private static Provider securityProvider = getBcProviderInstance();

	private JcaContextHelper() {
	}

	/**
	 * Get the security provider which is used for all operations
	 */
	public static Provider getSecurityProvider() {
		return securityProvider;
	}

	/**
	 * Set the security provider to be used for all operations.
	 */
	public static void setSecurityProvider(Provider securityProvider) {
		JcaContextHelper.securityProvider = securityProvider;
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

	static PGPDataEncryptorBuilder getPGPDataEncryptorBuilder(int encAlgorithm) {
		JcePGPDataEncryptorBuilder builder = new JcePGPDataEncryptorBuilder(encAlgorithm);
		if (JcaContextHelper.isSecurityProviderNotNull()) {
			builder.setProvider(JcaContextHelper.getSecurityProvider());
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
			HashingAlgorithm hashingAlgorithm,
			int workFactor) throws PGPException {
		PGPDigestCalculatorProvider digestCalculatorProvider = JcaContextHelper.getPGPDigestCalculatorProvider();
		JcePBEKeyEncryptionMethodGenerator jcePBEKeyEncryptionMethodGenerator = new JcePBEKeyEncryptionMethodGenerator(
				symmetricPassphraseChars,
				digestCalculatorProvider.get(hashingAlgorithm.ordinal()),
				workFactor);
		if (JcaContextHelper.isSecurityProviderNotNull()) {
			jcePBEKeyEncryptionMethodGenerator.setProvider(JcaContextHelper.getSecurityProvider());
		}
		return jcePBEKeyEncryptionMethodGenerator;
	}

	static PGPContentSignerBuilder getPGPContentSignerBuilder(int keyAlgorithmCode, int hashAlgorithmOrdinal) {
		JcaPGPContentSignerBuilder jcaPGPContentSignerBuilder = new JcaPGPContentSignerBuilder(keyAlgorithmCode, hashAlgorithmOrdinal);
		if (JcaContextHelper.isSecurityProviderNotNull()) {
			jcaPGPContentSignerBuilder.setProvider(JcaContextHelper.getSecurityProvider());
		}
		return jcaPGPContentSignerBuilder;
	}

	private static Provider getBcProviderInstance() {
		try {
			return (Provider) Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
					.getDeclaredConstructor()
					.newInstance();
		} catch (ClassNotFoundException |
				NoSuchMethodException |
				InstantiationException |
				IllegalAccessException |
				InvocationTargetException e) {
			log.warn("BouncyCastleProvider class not found on classpath, using default security provider");
		}
		return null;
	}
}
