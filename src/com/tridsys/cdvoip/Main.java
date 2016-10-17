package com.tridsys.cdvoip;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Main {

	public static void main(String[] args) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
		// write your code here
		KeyStore myKeyStore;
		myKeyStore = KeyStore.getInstance("KeychainStore", "Apple");
		myKeyStore.load(null, null);

		// Get all the aliases in a list (I thought that calling the KeyStore
		// methods during the iteration was the reason why getKey wasn't responding properly!)
		// ... it wasn't actually!
		ArrayList<String> aliases = new ArrayList<String>();
		Enumeration<String> e = myKeyStore.aliases();
		while (e.hasMoreElements()) {
			aliases.add(e.nextElement());
		}

		Set<BigInteger> seen = new HashSet<>();
		for (String alias : aliases) {
			try {
				// I read on the Internet that any ASCII password is required
				// to get the getKey method working.
				X509Certificate cert = (X509Certificate) myKeyStore.getCertificate(alias);
				String issuerDN = cert.getIssuerDN().toString();
				String subjectDN = cert.getSubjectDN().toString();
				List<String> extendedKeyUsage = cert.getExtendedKeyUsage();
//				if (issuerDN.contains("DOD EMAIL") && subjectDN.contains("FRANKLIN") && extendedKeyUsage != null) {
				if (issuerDN.contains("DOD EMAIL") && extendedKeyUsage != null) {
					BigInteger serialNumber = cert.getSerialNumber();
					if (! seen.contains(serialNumber)) {
						seen.add(serialNumber);
						System.out.println("S/N: " + serialNumber);
						System.out.println("SubjectDN: " + cert.getSubjectDN());
						System.out.println("CN: " + getCNfromDN(cert));
						System.out.println("IssuerDN: " + issuerDN);
						System.out.println("Expiration: " + cert.getNotAfter());
						System.out.println("Extended key usages: ");
						for (String usage : extendedKeyUsage) {
							if (usage.equals("1.3.6.1.5.5.7.3.2")) {
								System.out.println("\tClient Authentication");
							} else if (usage.equals("1.3.6.1.4.1.311.20.2.2")) {
								System.out.println("\tMicrosoft Smart Card Logon");
							} else if (usage.equals("1.3.6.1.5.5.7.3.4")) {
								System.out.println("\tEmail Protection");
							} else {
								System.out.println("\t" + usage);
							}
						}
						System.out.println("--------------------------");
//						System.out.println(cert);
//						System.out.println("--------------------------");
					}
//					System.out.println("WAF - " + cert);
//					Key k = myKeyStore.getKey(alias, "03021985".toCharArray());
//					if (k == null) {
//						System.out.println(alias + ": <null> (cannot retrieve the key)");
//					} else {
//						System.out.println(alias + ":");
//						System.out.println(k);
//					}
				}
			} catch (Exception ex) {
				System.out.println(alias + ": " + ex.getMessage());
			}
		}
	}

	private static String getCNfromDN(X509Certificate cert) {
		String dn = cert.getSubjectDN().toString();
		LdapName ln;
		try {
			ln = new LdapName(dn);
		} catch (InvalidNameException e) {
			return "<invalid>";
		}
		for (Rdn rdn : ln.getRdns()) {
			if (rdn.getType().equalsIgnoreCase("CN")) {
				return (String) rdn.getValue();
			}
		}
		return "<invalid>";
	}
}

