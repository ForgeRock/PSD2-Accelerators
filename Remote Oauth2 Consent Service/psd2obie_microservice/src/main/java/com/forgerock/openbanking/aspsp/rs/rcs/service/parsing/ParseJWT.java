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
package com.forgerock.openbanking.aspsp.rs.rcs.service.parsing;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.forgerock.openbanking.aspsp.rs.rcs.service.jwt.JWTManagementService;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

@Service
public class ParseJWT {

	private final Logger log = LoggerFactory.getLogger(ParseJWT.class);

	@Autowired
	JWTManagementService jwtManagementService;

	public JWTClaimsSet parseJWT(String unparsedJWT) throws Exception {
		JWT jwt = null;

		try {
			jwt = JWTParser.parse(unparsedJWT);
		} catch (java.text.ParseException e) {
			// Invalid JWT encoding
		}

		// Check the JWT type
		if (jwt instanceof PlainJWT) {
			PlainJWT plainObject = (PlainJWT) jwt;
			// continue processing of plain JWT...
			log.debug("Consent PlainJWT body {} ", plainObject.getJWTClaimsSet().toString());
			return plainObject.getJWTClaimsSet();
		} else if (jwt instanceof SignedJWT) {
			SignedJWT jwsObject = (SignedJWT) jwt;
			// continue with signature verification...
			log.debug("Consent SignedJWT body {} ", jwsObject.getJWTClaimsSet().toString());
			return jwsObject.getJWTClaimsSet();
		} else if (jwt instanceof EncryptedJWT) {
			
			EncryptedJWT jweObject = (EncryptedJWT) jwt;
			log.debug("Consent EncryptedJWT start");
			
			// Verify the JWT uses safe algorithms
			if (!jwt.getHeader().getAlgorithm().equals(JWEAlgorithm.RSA_OAEP_256))
				throw new Exception("Invalid 'alg' header, only RSA-OAEP-256 is allowed.");

			JWEDecrypter decrypter;
			try {
				decrypter = new RSADecrypter(jwtManagementService.senderEncryptionKey().toPrivateKey());
				jweObject.decrypt(decrypter);
				// Extract payload
				SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();
				if (signedJWT != null) {
					log.debug("Consent EncryptedJWT body {} ", signedJWT.getJWTClaimsSet().toString());
					return signedJWT.getJWTClaimsSet();
				} else {
					throw new Exception("Payload not a signed JWT");
				}
			} catch (NoSuchAlgorithmException e) {
				log.error("NoSuchAlgorithmException Error: {}", e.getMessage());
			} catch (JOSEException e) {
				log.error("JOSEException Error: {}", e.getMessage());
			} catch (IOException e) {
				log.error("IOException Error: {}", e.getMessage());
			}
			log.debug("Consent EncryptedJWT end");
			return null;
		}
		return null;
	}
}
