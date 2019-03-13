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
package com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.parsing;

import java.text.ParseException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;

@Service
public class ParseJWT {
	
	private final Logger log = LoggerFactory.getLogger(ParseJWT.class);
	
	public JWTClaimsSet parseJWT(String unparsedJWT) throws ParseException {
    	JWT jwt = null;
    	
    	try {
    	    jwt = JWTParser.parse(unparsedJWT);
    	} catch ( java.text.ParseException e) {
    	    // Invalid JWT encoding
    	}

    	// Check the JWT type
    	if (jwt instanceof PlainJWT) {
    	    PlainJWT plainObject = (PlainJWT)jwt;
    	    // continue processing of plain JWT...
    	    log.debug("Consent PlainJWT body {} ", plainObject.getJWTClaimsSet().toString());
    	    return plainObject.getJWTClaimsSet();
    	} else if (jwt instanceof SignedJWT) {
    	    SignedJWT jwsObject = (SignedJWT)jwt;
    	    // continue with signature verification...
    	    log.debug("Consent SignedJWT body {} ", jwsObject.getJWTClaimsSet().toString());
    	    return jwsObject.getJWTClaimsSet();
    	} else if (jwt instanceof EncryptedJWT) {
    	    EncryptedJWT jweObject = (EncryptedJWT)jwt;
    	    log.debug("Consent EncryptedJWT body {} ", jweObject.getJWTClaimsSet().toString());
    	    // continue with decryption...
    	    return jweObject.getJWTClaimsSet();
    	}
		return null;
	}
}
