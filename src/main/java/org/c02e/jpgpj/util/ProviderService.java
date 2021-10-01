package org.c02e.jpgpj.util;

import java.security.Provider;
import java.security.Security;

public class ProviderService {
	private static Provider provider = Security.getProvider("BC");
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
