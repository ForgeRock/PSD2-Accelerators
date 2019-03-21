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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.tools.JwtUtil;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class SSAVerificationFilter implements Filter {

	private Logger logger = LoggerFactory.getLogger(SSAVerificationFilter.class);

	private static final Base64 base64 = new Base64(true);

	@Override
	public Promise<Response, NeverThrowsException> filter(final Context context, final Request request,
			final Handler next) {
		try {
			logger.info("Starting SSA validations.");
			String jwt = request.getEntity().getString();
			Jwt registrationJwt = JwtUtil.reconstructJwt(jwt, Jwt.class);
			Jwt ssaJwt = JwtUtil.reconstructJwt(
					registrationJwt.getClaimsSet().getClaim("software_statement").toString(), Jwt.class);
			String jwksUri = ssaJwt.getClaimsSet().getClaim("software_jwks_endpoint").toString();
			if (!verifyJwtSignature(jwt, registrationJwt, jwksUri) || !verifyJwtClaims(registrationJwt, ssaJwt)) {
				Response response = new Response(Status.UNAUTHORIZED);
				return Promises.newResultPromise(response);
			}
		} catch (ParseException e1) {
			e1.printStackTrace();
		} catch (IOException e1) {
			e1.printStackTrace();
		}
		return next.handle(context, request);
	}

	private boolean verifyJwtSignature(String jwt, Jwt registrationJwt, String jwksUri) throws IOException {
		if (jwksUri != null) {
			JsonNode jwksUriKeys = getJwksUriKeys(jwksUri);

			// Step1:
			// - Find the signing certificate
			// - Find the algorithm used
			String X509Cert = "";
			String algorithm = "";
			// TODO - check if the assumption that first certificate found is the right one
			if (jwksUriKeys.isArray()) {
				for (JsonNode keyNode : jwksUriKeys) {
					if (keyNode.get("use").asText().equals("sig")) {
						JsonNode certificates = keyNode.get("x5c");
						if (certificates != null && certificates.size() > 0) {
							X509Cert = certificates.get(0).asText();
							algorithm = keyNode.get("alg").asText();
							logger.debug("X509 signature certificate found: " + X509Cert);
						}
					}
				}
			}

			Security.addProvider(new BouncyCastleProvider());
			String jcaAlg = null;
			PSSParameterSpec pssSpec = null;

			if (!algorithm.isEmpty()) {
				switch (algorithm) {
				case "RS256":
					jcaAlg = "SHA256withRSA";
					break;
				case "RS384":
					jcaAlg = "SHA384withRSA";
					break;
				case "RS512":
					jcaAlg = "SHA512withRSA";
					break;
				case "PS256":
					jcaAlg = "SHA256withRSAandMGF1";
					pssSpec = new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
					break;
				case "PS384":
					jcaAlg = "SHA384withRSAandMGF1";
					pssSpec = new PSSParameterSpec("SHA384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
					break;
				case "PS512":
					jcaAlg = "SHA512withRSAandMGF1";
					pssSpec = new PSSParameterSpec("SHA512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);
					break;
				}
			}
			logger.info("Algorithm: " + jcaAlg);
			// Step2:
			// - Format the JWT assertion - header.payload
			// - Extract the JWT signature
			String[] jwtTokenValues = jwt.split("\\.");
			String jwtAssertion = "";
			String jwtSignature = "";
			if (jwtTokenValues != null && jwtTokenValues.length > 2) {
				jwtAssertion = jwtTokenValues[0] + "." + jwtTokenValues[1];
				jwtSignature = jwtTokenValues[2];
			}

			if (jwtAssertion != null && jwtSignature != null && jcaAlg != null) {
				byte[] decodedJwtSignature = base64.decode(jwtSignature.getBytes());
				byte[] decodedX509Cert = base64.decode(X509Cert.getBytes());
				try {
					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(decodedX509Cert));
					Signature signature = Signature.getInstance(jcaAlg);
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
					logger.info("Signature is OK: " + signatureOK);
					return signatureOK;
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
			logger.debug("Keys: " + jwksUriKeys.toString());
		}
		return false;
	}

	private JsonNode getJwksUriKeys(String jwksEndpoint) throws IOException {
		URL obj = new URL(jwksEndpoint);
		HttpURLConnection con = (HttpURLConnection) obj.openConnection();
		con.setRequestMethod("GET");
		int responseCode = con.getResponseCode();
		logger.debug("\nSending 'GET' request to URL : " + jwksEndpoint);
		logger.debug("Response Code : " + responseCode);
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
		logger.debug("Response from jwks uri: " + response.toString());
		logger.debug("Keys: " + keys.toString());
		return keys;
	}

	/**
	 * 
	 * Verifies if information from the OB Client Registration JWT is matching the
	 * information from the SSA
	 * 
	 * @param registrationJwt
	 * @param ssaJwt
	 * @return true if all verifications passed with success
	 * @throws ParseException
	 * @throws MalformedURLException
	 */
	private boolean verifyJwtClaims(Jwt registrationJwt, Jwt ssaJwt) throws ParseException, MalformedURLException {
		String registrationJwtIssuer = registrationJwt.getClaimsSet().getClaim("iss").toString();
		String ssaJwtSoftwareId = ssaJwt.getClaimsSet().getClaim("software_client_id").toString();

		if (!ssaJwtSoftwareId.equals(registrationJwtIssuer)) {
			logger.error(
					"The iss claim of the registration request JWT, is not matching the software_client_id claim from the SSA JWT.");
			return false;
		}

		List<String> ssaRedirectUris = getClaimAsArray(ssaJwt.getClaimsSet().getClaim("software_redirect_uris"));
		List<String> registrationRedirectUris = getClaimAsArray(
				registrationJwt.getClaimsSet().getClaim("redirect_uris"));

		if (!ssaRedirectUris.isEmpty() && !registrationRedirectUris.isEmpty()) {
			for (String redirectUri : registrationRedirectUris) {
				if (validateUri(redirectUri)) {
					if (!ssaRedirectUris.contains(redirectUri)) {
						logger.error(
								"The redirect_uris claim of the registration request JWT, is not a subset of the software_redirect_uris claim from the SSA JWT.");
						return false;
					}
				} else {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * 
	 * Parses a JsonNode and transforms it into an array list.
	 * 
	 * @param arrayClaim
	 * @return
	 */
	private List<String> getClaimAsArray(Object arrayClaim) {
		List<String> redirectUris = new ArrayList<String>();
		ObjectMapper objectReader = new ObjectMapper();
		JsonNode node = objectReader.valueToTree(arrayClaim);
		if (!node.isArray()) {
			logger.warn("Expected node as array but got a different node type.");
		}

		for (int i = 0; i < node.size(); i++) {
			try {
				redirectUris.add(objectReader.treeToValue(node.get(i), String.class));
				logger.debug("URI: " + objectReader.treeToValue(node.get(i), String.class));
			} catch (JsonProcessingException e) {
				logger.debug("Couldn't map the Claim's array contents to String");
				e.printStackTrace();
			}
		}
		return redirectUris;
	}

	/**
	 * 
	 * Validates if a given URI is meeting the required criteria for the OB Client
	 * Registration request
	 * 
	 * @param uri
	 * @return
	 * @throws MalformedURLException
	 */
	private boolean validateUri(String uri) throws MalformedURLException {
		logger.debug("URI: " + uri);
		URL url = new URL(uri);
		String protocol = url.getProtocol();
		String host = url.getHost();
		if (protocol.equals("https") && !host.toLowerCase().contains("localhost")) {
			return true;
		}

		logger.error("The redirect uri " + uri
				+ " doesn't meet the validation criteria. Protocol used must be HTTP, and the host name must not contain localhost.");

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
			SSAVerificationFilter filter = new SSAVerificationFilter();
			return filter;
		}
	}
}