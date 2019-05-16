package org.forgerock.openig.ob.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class CertificateUtils {

	private static final Logger logger = LoggerFactory.getLogger(CertificateUtils.class);
	private static final Base64 base64 = new Base64(true);
	private static final String X509_CERT_INSTANCE = "X.509";
	private static final String OPEN_BANKING_ROLES_EXTENSTION = "1.3.6.1.5.5.7.1.3";

	public static String getCertificateSubjectDnProperty(X509Certificate certificate,
			ASN1ObjectIdentifier outputProperty) {
		String tppId = null;
		if (certificate != null) {
			logger.info("Subject DN from certificate: " + certificate.getSubjectDN().toString());
			X500Name x500name = null;
			try {
				x500name = new JcaX509CertificateHolder(certificate).getSubject();
			} catch (CertificateEncodingException e) {
				logger.error("Error getting certificate subject DN.");
				e.printStackTrace();
			}

			if (x500name != null) {
				RDN ou = x500name.getRDNs(outputProperty)[0];
				tppId = IETFUtils.valueToString(ou.getFirst().getValue());
				logger.info("Certificate {}: {}", outputProperty, tppId);
			}
		}
		return tppId;
	}

	public static String getCertificateExtensions(X509Certificate certificate) {
		byte[] extensionValue = certificate.getExtensionValue(OPEN_BANKING_ROLES_EXTENSTION);
		if (extensionValue != null) {
			ASN1Sequence sequence = null;
			try {
				byte[] octets = ((DEROctetString) DEROctetString.fromByteArray(extensionValue)).getOctets();
				sequence = (ASN1Sequence) ASN1Sequence.fromByteArray(octets);
			} catch (IOException e) {
				e.printStackTrace();
			}

			Enumeration sequenceObjects = sequence.getObjects();
			while (sequenceObjects.hasMoreElements()) {
				DLSequence next = (DLSequence) sequenceObjects.nextElement();
				if (next.size() > 1) {
					Object objectAt = next.getObjectAt(1);
					if (objectAt != null) {
						return objectAt.toString();
					}
				}
			}
		}
		return null;
	}

	public static String formatTransportCertificate(String certificate) {
		try {
			certificate = java.net.URLDecoder.decode(certificate, StandardCharsets.UTF_8.name());
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		certificate = certificate.replaceAll("-----BEGIN CERTIFICATE-----", "");
		certificate = certificate.replaceAll("-----END CERTIFICATE-----", "");
		return certificate;
	}

	public static X509Certificate initializeCertificate(String cert) {
		logger.info("Initializing certificate: {}", cert);
		X509Certificate certificate = null;
		if (cert != null) {
			byte[] decoded = base64.decode((cert.getBytes()));
			CertificateFactory cf = null;
			try {
				cf = CertificateFactory.getInstance(X509_CERT_INSTANCE);
			} catch (CertificateException e) {
				logger.error("Error getting instance of X509 certificate factory.");
				e.printStackTrace();
			}

			if (cf != null) {
				try {
					certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decoded));
				} catch (CertificateException e) {
					logger.error("Error generating certificate from input string: {}", cert);
					e.printStackTrace();
				}
			}
		}
		return certificate;
	}
}