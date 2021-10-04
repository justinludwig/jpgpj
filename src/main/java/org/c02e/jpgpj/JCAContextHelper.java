package org.c02e.jpgpj;

import org.bouncycastle.gpg.keybox.jcajce.JcaKeyBoxBuilder;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.Provider;
import java.security.Security;

/**
 * Helper class for Java Cryptography Architecture (JCA) context
 * consisting of {@link java.security.Provider provider}
 * Note: The following class is not thread safe, the security provider should not be changed during PGP operations
 */
public class JCAContextHelper {
	private static final Logger log = LoggerFactory.getLogger(JCAContextHelper.class.getName());
	private static Provider securityProvider = getBcProviderInstance();

	private JCAContextHelper() {
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
		JCAContextHelper.securityProvider = securityProvider;
	}

	static boolean isSecurityProviderNotNull() {
		return getSecurityProvider() != null;
	}

	static JcaKeyFingerprintCalculator getJcaKeyFingerprintCalculator() {
		JcaKeyFingerprintCalculator fingerPrintCalculator = new JcaKeyFingerprintCalculator();
		if (JCAContextHelper.isSecurityProviderNotNull()) {
			fingerPrintCalculator.setProvider(JCAContextHelper.getSecurityProvider());
		}
		return fingerPrintCalculator;
	}

	static JcaPGPContentVerifierBuilderProvider getJcaPGPContentVerifierBuilderProvider() {
		JcaPGPContentVerifierBuilderProvider provider = new JcaPGPContentVerifierBuilderProvider();
		if (JCAContextHelper.isSecurityProviderNotNull()) {
			provider.setProvider(JCAContextHelper.getSecurityProvider());
		}
		return provider;
	}

	static PGPDigestCalculatorProvider getPGPDigestCalculatorProvider() throws PGPException {
		JcaPGPDigestCalculatorProviderBuilder builder = new JcaPGPDigestCalculatorProviderBuilder();
		if (JCAContextHelper.isSecurityProviderNotNull()) {
			builder.setProvider(JCAContextHelper.getSecurityProvider());
		}
		return builder.build();
	}

	static JcePBEDataDecryptorFactoryBuilder getJcePBEDataDecryptorFactoryBuilder() throws PGPException {
		JcePBEDataDecryptorFactoryBuilder builder =
				new JcePBEDataDecryptorFactoryBuilder(JCAContextHelper.getPGPDigestCalculatorProvider());
		if (JCAContextHelper.isSecurityProviderNotNull()) {
			builder.setProvider(JCAContextHelper.getSecurityProvider());
		}
		return builder;
	}

	static JcePublicKeyDataDecryptorFactoryBuilder getJcePublicKeyDataDecryptorFactoryBuilder() {
		JcePublicKeyDataDecryptorFactoryBuilder builder = new JcePublicKeyDataDecryptorFactoryBuilder();
		if (JCAContextHelper.isSecurityProviderNotNull()) {
			builder.setProvider(JCAContextHelper.getSecurityProvider());
		}
		return builder;
	}

	static JcePGPDataEncryptorBuilder getJcePGPDataEncryptorBuilder(int encAlgorithm) {
		JcePGPDataEncryptorBuilder builder = new JcePGPDataEncryptorBuilder(encAlgorithm);
		if (JCAContextHelper.isSecurityProviderNotNull()) {
			builder.setProvider(JCAContextHelper.getSecurityProvider());
		}
		return builder;
	}

	static JcaKeyBoxBuilder getJcaKeyBoxBuilder() {
		JcaKeyBoxBuilder builder = new JcaKeyBoxBuilder();
		if (JCAContextHelper.isSecurityProviderNotNull()) {
			builder.setProvider(JCAContextHelper.getSecurityProvider());
		}
		return builder;
	}

	static JcePBESecretKeyDecryptorBuilder getJcePBESecretKeyDecryptorBuilder() throws PGPException {
		JcePBESecretKeyDecryptorBuilder builder =
				new JcePBESecretKeyDecryptorBuilder(JCAContextHelper.getPGPDigestCalculatorProvider());
		if (JCAContextHelper.isSecurityProviderNotNull()) {
			builder.setProvider(JCAContextHelper.getSecurityProvider());
		}
		return builder;
	}

	private static Provider getBcProviderInstance() {
		Provider bc = Security.getProvider("BC");
		if (bc == null) {
			try {
				bc = (Provider) JCAContextHelper.class.getClassLoader()
						.loadClass("org.bouncycastle.jce.provider.BouncyCastleProvider")
						.newInstance();
			} catch (InstantiationException | IllegalAccessException e) {
				throw new RuntimeException(e);
			} catch (ClassNotFoundException e) {
				log.info("org.bouncycastle.jce.provider.BouncyCastleProvider was not found on the classpath, " +
						"using default security provider");
			}
		}
		return  bc;
	}
}
