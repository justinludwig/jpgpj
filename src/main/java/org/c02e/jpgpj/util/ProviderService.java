package org.c02e.jpgpj.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

public class ProviderService {
	static {
		Provider[] providers = Security.getProviders();
		System.out.println();
	}
	private static Provider provider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
	public static Provider getProvider() {
		return provider;
	}

	public static void setProvider(Provider provider) {
		ProviderService.provider = provider;
	}

	public static boolean isProviderNotNull() {
		return provider != null;
	}
}
