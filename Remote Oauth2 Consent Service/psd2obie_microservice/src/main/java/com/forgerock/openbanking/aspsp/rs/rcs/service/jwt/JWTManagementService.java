/***************************************************************************
 *  Copyright 2019 ForgeRock
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
package com.forgerock.openbanking.aspsp.rs.rcs.service.jwt;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.forgerock.openbanking.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.openbanking.aspsp.rs.rcs.service.keygenerator.IGenerateKey;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;

@Service
public class JWTManagementService {

	private static final Logger log = LoggerFactory.getLogger(JWTManagementService.class);

	@Autowired
	IGenerateKey generatedKey;

	private static RSAKey senderSignJWK;
	private static RSAKey senderEncryptedJWK;
	private static RSAKey recipientJWK;

	public RSAKey senderSignKey() throws JOSEException, NoSuchAlgorithmException, IOException, ParseException {
		if (senderSignJWK == null) {
			// senderJWK = new
			// RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).keyUse(KeyUse.SIGNATURE).generate();
			senderSignJWK = new RSAKey.Builder((RSAPublicKey) generatedKey.generateKeyPair().getPublic())
					.privateKey((RSAPrivateKey) generatedKey.generateKeyPair().getPrivate()).keyUse(KeyUse.SIGNATURE)
					.keyID(UUID.randomUUID().toString()).build();

		}

		log.debug("JWTManagementService senderkey {}", senderSignJWK.toJSONObject());

		return senderSignJWK;

	}

	public RSAKey senderEncryptionKey() throws JOSEException, NoSuchAlgorithmException, IOException, ParseException {
		if (senderEncryptedJWK == null) {

			senderEncryptedJWK = new RSAKey.Builder((RSAPublicKey) generatedKey.generateKeyPair().getPublic())
					.privateKey((RSAPrivateKey) generatedKey.generateKeyPair().getPrivate()).keyUse(KeyUse.ENCRYPTION)
					.algorithm(JWEAlgorithm.RSA_OAEP_256).keyID(UUID.randomUUID().toString()).build();

		}

		log.debug("JWTManagementService senderkey {}", senderEncryptedJWK.toJSONObject());

		return senderEncryptedJWK;

	}

	public RSAKey recipientKey() throws JOSEException, NoSuchAlgorithmException {
		if (recipientJWK == null) {
			recipientJWK = new RSAKey.Builder((RSAPublicKey) generatedKey.generateKeyPair().getPublic())
					.privateKey((RSAPrivateKey) generatedKey.generateKeyPair().getPrivate()).keyUse(KeyUse.ENCRYPTION)
					.keyID(UUID.randomUUID().toString()).build();
		}
		return recipientJWK;

	}

	private JWKSet getProviderRSAKeys(JSONObject json, String usedKeyScope) throws ParseException {
		JSONArray keyList = (JSONArray) json.get("keys");
		List<JWK> rsaKeys = new LinkedList<>();
		for (Object key : keyList) {
			JSONObject k = (JSONObject) key;
			if (k.get("use").equals(usedKeyScope) && k.get("kty").equals("RSA")) {
				rsaKeys.add(RSAKey.parse(k));
			}
		}
		if (!rsaKeys.isEmpty()) {
			return new JWKSet(rsaKeys);
		}
		throw new IllegalArgumentException("No RSA keys found");
	}

//	private RSAPublicKey verifier(String kid ,String jwkUrl) throws Exception {
//        JwkProvider provider = new UrlJwkProvider(new URL(jwkUrl));
//        Jwk jwk = provider.get(kid);
//        return (RSAPublicKey) jwk.getPublicKey());
//    }

	/*
	 * public String senderSingEncripyJWT(JWTClaimsSet jwtClaimsSet,
	 * ApplicationProperties amConfiguration) throws JOSEException,
	 * MalformedURLException, IOException, ParseException { JWKSet publicKeys =
	 * JWKSet.load(new URL(amConfiguration.getAmJwkUrl()));
	 * log.debug("publicKeys {}",publicKeys.toString());
	 * 
	 * //TODO Get Encryption algorithm, KID and signature // Create JWT SignedJWT
	 * signedJWT = new SignedJWT( new
	 * JWSHeader.Builder(JWSAlgorithm.RS256).keyID(senderKey().getKeyID()).build(),
	 * jwtClaimsSet);
	 * 
	 * // Sign the JWT signedJWT.sign(new RSASSASigner(senderKey()));
	 * 
	 * // Create JWE object with signed JWT as payload
	 * 
	 * JWEObject jweObject = new JWEObject( new
	 * JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256,
	 * EncryptionMethod.A256GCM).contentType("JWT") .build(), new
	 * Payload(signedJWT));
	 * 
	 * // Encrypt with the recipient's public key jweObject.encrypt(new
	 * RSAEncrypter(recipientKey().toPublicJWK()));
	 * 
	 * // Serialise to JWE compact form return jweObject.serialize(); }
	 */

	public String senderSignJWT(String jwtClaimsSet, ApplicationProperties amConfiguration)
			throws JOSEException, MalformedURLException, IOException, ParseException, NoSuchAlgorithmException {
		//TODO Sing with private key
		
		JWKSet publicKeys = JWKSet.load(new URL(amConfiguration.getAmJwkUrl()));
		log.debug("publicKeys {}", publicKeys.toString());

		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner(senderSignKey());

		// Prepare JWS object with simple string as payload
		JWSObject jwsObject = new JWSObject(
				new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(senderSignKey().getKeyID()).type(JOSEObjectType.JWT)
						// .contentType("JWT")
						.build(),
				new Payload(jwtClaimsSet));

		// Compute the RSA signature
		jwsObject.sign(signer);
		String s = jwsObject.serialize();
		log.debug("jwsObject {}", s);
		return s;
	}

	public String senderSignEncryptJWT( ApplicationProperties amConfiguration, String signedJWT) throws Exception {
			RSAKey remoteJWK = null;
		remoteJWK=getJWKFromRemoteURL(amConfiguration,KeyUse.ENCRYPTION,JWEAlgorithm.RSA_OAEP_256);
		if(remoteJWK==null)
			 throw new Exception("Not found public key with encryption algorithm RSA-OAEP-256.");
		// Create RSA-signer with the private key

		JWEObject jweObject = new JWEObject(
				new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
				//.contentType("JWT")
				.keyID(remoteJWK.getKeyID())
				.type(JOSEObjectType.JWT)
				.build(),
				new Payload(signedJWT));

		// Encrypt with the recipient's public key jweObject.encrypt(new
		//RSAEncrypter(remoteJWK.toPublicJWK());
		log.debug("remoteJWK.toPublicJWK(): {}", remoteJWK.toPublicJWK().toString());
		jweObject.encrypt(new RSAEncrypter( remoteJWK));

		//TODO Encrypt with the public key
		
		String s = jweObject.serialize();
		log.debug("jwsObject {}",s);	
		return s;
	}

	private RSAKey getJWKFromRemoteURL(ApplicationProperties amConfiguration, KeyUse encryption, JWEAlgorithm algorthmType )
			throws IOException, ParseException, MalformedURLException {
		RSAKey remoteJWK=null;
		JWKSet publicKeys = JWKSet.load(new URL(amConfiguration.getAmJwkUrl()),amConfiguration.getAmJwkUrlConnectTimeout(),
				amConfiguration.getAmJwkUrlReadTimeout(),amConfiguration.getAmJwkUrlSizeLimit());
		log.debug("publicKeys {}",publicKeys.toString());			
		
		for (JWK jwkItme : publicKeys.getKeys()) {			
			 
			if(jwkItme.getAlgorithm().equals(algorthmType)&&jwkItme.getKeyUse().equals(encryption)) {
				
				 if (jwkItme instanceof RSAKey) {
					  log.debug("Is RSAKey"); 
					  remoteJWK = (RSAKey)jwkItme;
				  }
				log.debug(" kid: {}, algorthmType {}, encryption {}",jwkItme.getKeyID(), algorthmType,encryption);
			}		
		}	
		return remoteJWK;
	}

	public String recipientDecriptJWT(String jweString)
			throws ParseException, JOSEException, NoSuchAlgorithmException, IOException {
		// Parse the JWE string
		JWEObject jweObject = JWEObject.parse(jweString);

		// Decrypt with private key
		jweObject.decrypt(new RSADecrypter(recipientKey()));

		// Extract payload
		SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

		// Check the signature
		signedJWT.verify(new RSASSAVerifier(senderSignKey().toPublicJWK()));

		// Retrieve the JWT claims...
		return signedJWT.getJWTClaimsSet().getSubject();
	}

}
