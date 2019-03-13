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
package com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.jwt;

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

import com.forgerock.nextgenpsd2.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.keygenerator.IGenerateKey;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
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
	
	
	private static RSAKey senderJWK;
	private static RSAKey recipientJWK;
	
	public RSAKey senderKey() throws JOSEException, NoSuchAlgorithmException, IOException, ParseException {
		if(senderJWK==null) {
			//senderJWK = new RSAKeyGenerator(2048).keyID(UUID.randomUUID().toString()).keyUse(KeyUse.SIGNATURE).generate();
			senderJWK = new RSAKey.Builder((RSAPublicKey)generatedKey.generateKeyPair().getPublic())
    	    .privateKey((RSAPrivateKey)generatedKey.generateKeyPair().getPrivate())
    	    .keyUse(KeyUse.SIGNATURE)
    	    .keyID(UUID.randomUUID().toString())
    	    .build();
    	   
		}
		
		log.debug("JWTManagementService senderkey {}",senderJWK.toJSONObject());
		
		return senderJWK;

	}

	public RSAKey recipientKey() throws JOSEException, NoSuchAlgorithmException {
		if(recipientJWK==null) {
			recipientJWK = new RSAKey.Builder((RSAPublicKey)generatedKey.generateKeyPair().getPublic())
		    	    .privateKey((RSAPrivateKey)generatedKey.generateKeyPair().getPrivate())
		    	    .keyUse(KeyUse.ENCRYPTION)
		    	    .keyID(UUID.randomUUID().toString())
		    	    .build();
		}
		return recipientJWK;

	}
	
	private JWKSet getProviderRSAKeys(JSONObject json) throws ParseException {
		JSONArray keyList = (JSONArray) json.get("keys");
		List<JWK> rsaKeys = new LinkedList<>();
		for (Object key : keyList) {
			JSONObject k = (JSONObject) key;
			if (k.get("use").equals("sig") && k.get("kty").equals("RSA")) {
				rsaKeys.add(RSAKey.parse(k));
			}
		}
		if (!rsaKeys.isEmpty()) {
			return new JWKSet(rsaKeys);
		}
		throw new IllegalArgumentException("No RSA keys found");
	}
	

	
	public String senderSingEncripyJWT(JWTClaimsSet jwtClaimsSet, ApplicationProperties amConfiguration) throws JOSEException, MalformedURLException, IOException, ParseException, NoSuchAlgorithmException {
		
		
		JWKSet publicKeys = JWKSet.load(new URL(amConfiguration.getAmJwkUrl()));
		log.debug("publicKeys {}",publicKeys.toString());			
		
		
		// Create RSA-signer with the private key
		JWSSigner signer = new RSASSASigner(senderKey());

		// Prepare JWS object with simple string as payload
		JWSObject jwsObject = new JWSObject(
		    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(senderKey().getKeyID())
		    .type(JOSEObjectType.JWT)
		    //.contentType("JWT")
		    .build(),
		    new Payload(jwtClaimsSet.toString()));

		// Compute the RSA signature
		jwsObject.sign(signer);

		// To serialize to compact form, produces something like
		// eyJhbGciOiJSUzI1NiJ9.SW4gUlNBIHdlIHRydXN0IQ.IRMQENi4nJyp4er2L
		// mZq3ivwoAjqa1uUkSBKFIX7ATndFF5ivnt-m8uApHO4kfIFOrW7w2Ezmlg3Qd
		// maXlS9DhN0nUk_hGI3amEjkKd0BWYCB8vfUbUv0XGjQip78AI4z1PrFRNidm7
		// -jPDm5Iq0SZnjKjCNS5Q15fokXZc8u0A
		String s = jwsObject.serialize();
		log.debug("jwsObject {}",s);	
		return s;
	}

	public String recipientDecriptJWT(String jweString) throws ParseException, JOSEException, NoSuchAlgorithmException, IOException {
		// Parse the JWE string
		JWEObject jweObject = JWEObject.parse(jweString);

		// Decrypt with private key
		jweObject.decrypt(new RSADecrypter(recipientKey()));

		// Extract payload
		SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

		// Check the signature
		signedJWT.verify(new RSASSAVerifier(senderKey().toPublicJWK()));

		// Retrieve the JWT claims...
		return signedJWT.getJWTClaimsSet().getSubject();
	}
	
}
