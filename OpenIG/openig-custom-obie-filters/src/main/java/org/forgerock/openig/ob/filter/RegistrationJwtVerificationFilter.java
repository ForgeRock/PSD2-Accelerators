/***************************************************************************
 *  Copyright 2019 ForgeRock AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ***************************************************************************/
package org.forgerock.openig.ob.filter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.text.ParseException;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.ob.utils.CertificateUtils;
import org.forgerock.openig.tools.JwtUtil;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class RegistrationJwtVerificationFilter implements Filter {

	public enum Algorithms {
		RS256("SHA256withRSA"), RS384("SHA384WithRSA"), RS512("SHA512WithRSA"), PS256("SHA256WithRSAAndMGF1"),
		PS384("SHA384WithRSAAndMGF1"), PS512("SHA512WithRSAAndMGF1"), HS256("HmacSHA256"), HS384("HmacSHA384"),
		HS512("HmacSHA512"), ES256("SHA256WithECDSA"), ES384("SHA384WithECDSA"), ES512("SHA512WithECDSA"),
		EdDSA("SHA512WithEdDSA");

		private final String algorithm;

		Algorithms(final String algorithm) {
			this.algorithm = algorithm;
		}

		public String toString() {
			return algorithm;
		}

	}

	private Logger logger = LoggerFactory.getLogger(RegistrationJwtVerificationFilter.class);
	private static final Base64 base64 = new Base64(true);
	private String clientCertificateHeaderName;

	@Override
	public Promise<Response, NeverThrowsException> filter(final Context context, final Request request,
			final Handler next) {
		logger.info("Starting RegistrationJwtVerificationFilter.");
		String jwt = null;
		try {
			jwt = request.getEntity().getString();
		} catch (IOException e) {
			logger.error("Request entity is empty.");
			e.printStackTrace();
		}
		Jwt registrationJwt = JwtUtil.reconstructJwt(jwt, Jwt.class);
		Jwt ssaJwt = null;
		if (registrationJwt != null) {
			ssaJwt = JwtUtil.reconstructJwt(registrationJwt.getClaimsSet().getClaim("software_statement").toString(),
					Jwt.class);
		}

		if (ssaJwt != null) {
			X509Certificate certificate = getSigningCertificateFromJwksUri(registrationJwt, ssaJwt);
			String clientCertificateHeader = request.getHeaders().getFirst(clientCertificateHeaderName);
			logger.info("SSL Client Cert: " + clientCertificateHeader);
			if (clientCertificateHeader != null) {
				clientCertificateHeader = CertificateUtils.formatTransportCertificate(clientCertificateHeader);
				logger.info("Formatted SSL Client Cert: " + clientCertificateHeader);
				X509Certificate clientCertificate = CertificateUtils.initializeCertificate(clientCertificateHeader);
				if (certificate != null && clientCertificate != null) {
					boolean signatureOk = verifyJwtSignature(certificate, jwt, registrationJwt);
					boolean cnOk = verifyCN(clientCertificate, ssaJwt);
					if (signatureOk && cnOk) {
						return next.handle(context, request);
					}
				}
			}
		}

		Response response = new Response(Status.UNAUTHORIZED);
		return Promises.newResultPromise(response);
	}

	private X509Certificate getSigningCertificateFromJwksUri(Jwt registrationJwt, Jwt ssaJwt) {
		if (registrationJwt != null) {
			String registrationJwtKid = registrationJwt.getHeader().get("kid").asString();
			String registrationJwtSigningAlgorithm = registrationJwt.getHeader().getAlgorithm().toString();
			if (ssaJwt != null && registrationJwtKid != null && registrationJwtSigningAlgorithm != null) {
				String jwksUri = ssaJwt.getClaimsSet().getClaim("software_jwks_endpoint").toString();
				String X509Cert = null;
				JsonNode jwksUriKeys = getJwksUriKeys(jwksUri);
				String jwksKeyAlgorithm = null;
				if (jwksUriKeys != null && jwksUriKeys.isArray()) {
					for (JsonNode keyNode : jwksUriKeys) {
						String keyUsage = keyNode.get("use").asText();
						String keyId = keyNode.get("kid").asText();
						if ((keyId != null && keyId.equals(registrationJwtKid))
								&& (keyUsage != null && keyUsage.equals("sig"))) {
							JsonNode certificates = keyNode.get("x5c");
							if (certificates != null && certificates.size() > 0) {
								X509Cert = certificates.get(0).asText();
								jwksKeyAlgorithm = keyNode.get("alg").asText();
								if (jwksKeyAlgorithm != null && jwksKeyAlgorithm.equals(registrationJwtSigningAlgorithm)
										&& X509Cert != null) {
									logger.debug("X509 signature certificate found: " + X509Cert);
									return CertificateUtils.initializeCertificate(X509Cert);
								}
							}
						}
					}
				}
			}
		}
		return null;
	}

	private JsonNode getJwksUriKeys(String jwksEndpoint) {
		URL url = null;
		try {
			url = new URL(jwksEndpoint);
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		HttpURLConnection con;
		try {
			con = (HttpURLConnection) url.openConnection();
			con.setRequestMethod("GET");
			int responseCode = con.getResponseCode();
			logger.info("Sending 'GET' request to URL : " + jwksEndpoint);
			logger.info("Response Code : " + responseCode);
			BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()));
			String inputLine;
			StringBuffer response = new StringBuffer();
			while ((inputLine = in.readLine()) != null) {
				response.append(inputLine);
			}
			in.close();
			ObjectMapper mapper = new ObjectMapper();
			JsonNode actualObj = mapper.readTree(response.toString());
			JsonNode keys = actualObj.get("keys");
			logger.info("Keys found: " + keys.toString());
			return keys;
		} catch (Exception e) {
			logger.error("Cannot retrieve keys.");
			e.printStackTrace();
		}
		return null;
	}

	private boolean verifyJwtSignature(Certificate certificate, String jwt, Jwt registrationJwt) {
		Security.addProvider(new BouncyCastleProvider());
		String algorithmName = registrationJwt.getHeader().getAlgorithm().toString();
		String algorithm = getAlgorithmFromName(algorithmName);
		logger.info("Algorithm from name: " + algorithm);
		PSSParameterSpec pssSpec = getSaltParameter(algorithm);

		// - Format the JWT assertion - header.payload
		// - Extract the JWT signature
		String[] jwtTokenValues = jwt.split("\\.");
		String jwtAssertion = "";
		String jwtSignature = "";
		if (jwtTokenValues != null && jwtTokenValues.length > 2) {
			jwtAssertion = jwtTokenValues[0] + "." + jwtTokenValues[1];
			jwtSignature = jwtTokenValues[2];
		}

		try {
			if (jwtAssertion != null && jwtSignature != null && algorithm != null) {
				byte[] decodedJwtSignature = base64.decode(jwtSignature.getBytes());
				Signature signature = Signature.getInstance(algorithm);
				logger.info("pssSpec: " + pssSpec);
				if (pssSpec != null) {
					try {
						signature.setParameter(pssSpec);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
				signature.initVerify(certificate);
				signature.update(jwtAssertion.getBytes());
				boolean signatureOK = signature.verify(decodedJwtSignature);
				logger.info("Signature verified OK: " + signatureOK);
				return signatureOK;
			}
		} catch (Exception e) {
			logger.error("Exception: " + e.getMessage());
			e.printStackTrace();
		}
		logger.error("Failed verifying signature.");
		return false;
	}

	private String getAlgorithmFromName(String algorithmName) {
		if (algorithmName != null) {
			switch (algorithmName) {
			case "RS256":
				return Algorithms.RS256.toString();
			case "RS384":
				return Algorithms.RS384.toString();
			case "RS512":
				return Algorithms.RS512.toString();
			case "PS256":
				return Algorithms.PS256.toString();
			case "PS384":
				return Algorithms.PS384.toString();
			case "PS512":
				return Algorithms.PS512.toString();
			case "HS256":
				return Algorithms.HS256.toString();
			case "HS384":
				return Algorithms.HS384.toString();
			case "HS512":
				return Algorithms.HS512.toString();
			case "ES256":
				return Algorithms.ES256.toString();
			case "ES384":
				return Algorithms.ES384.toString();
			case "ES512":
				return Algorithms.ES512.toString();
			case "EdDSA":
				return Algorithms.EdDSA.toString();
			}
		}
		return null;
	}

	private static PSSParameterSpec getSaltParameter(String algorithm) {
		if (algorithm != null) {
			switch (algorithm) {
			case "SHA256WithRSAAndMGF1":
				return new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
			case "SHA384WithRSAAndMGF1":
				return new PSSParameterSpec("SHA384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
			case "SHA512WithRSAAndMGF1":
				return new PSSParameterSpec("SHA512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
			}
		}
		return null;
	}

	/**
	 * 
	 * Verifies if information from the OB Client Registration JWT is matching the
	 * information from the SSA
	 * 
	 * @param certificate
	 * @param ssaJwt
	 * @return true if all verifications passed with success
	 * @throws ParseException
	 * @throws MalformedURLException
	 */
	private boolean verifyCN(X509Certificate certificate, Jwt ssaJwt) {
		String ssaJwtSoftwareId = ssaJwt.getClaimsSet().getClaim("software_client_id").toString();
		String certificateCn = CertificateUtils.getCertificateSubjectDnProperty(certificate, BCStyle.CN);
		if (ssaJwtSoftwareId != null && certificateCn != null && certificateCn.equals(ssaJwtSoftwareId)) {
			logger.info("software_client_id is matching certificate CN: {}", certificateCn);
			return true;
		}
		logger.error("software_client_id - {} is not matching certificate CN - {}", ssaJwtSoftwareId, certificateCn);
		return false;
	}

	/**
	 * Create and initialize the filter, based on the configuration. The filter
	 * object is stored in the heap.
	 */
	public static class Heaplet extends GenericHeaplet {

		/**
		 * Create the filter object in the heap, setting the header name and value for
		 * the filter, based on the configuration.
		 *
		 * @return The filter object.
		 * @throws HeapException Failed to create the object.
		 */
		@Override
		public Object create() throws HeapException {
			RegistrationJwtVerificationFilter filter = new RegistrationJwtVerificationFilter();
			filter.clientCertificateHeaderName = config.get("clientCertificateHeaderName")
					.as(evaluatedWithHeapProperties()).required().asString();
			return filter;
		}
	}
}