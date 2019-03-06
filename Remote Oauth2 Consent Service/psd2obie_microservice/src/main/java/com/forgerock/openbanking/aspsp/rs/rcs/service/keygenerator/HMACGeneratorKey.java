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
package com.forgerock.openbanking.aspsp.rs.rcs.service.keygenerator;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.gen.*;

public class HMACGeneratorKey implements IGenerateKey {

	@Override
	public String generateKey() throws NoSuchAlgorithmException, JOSEException {
		OctetSequenceKey jwk = new OctetSequenceKeyGenerator(256)
			    .keyID(UUID.randomUUID().toString()) // give the key some ID (optional)
			    .algorithm(JWSAlgorithm.HS256) // indicate the intended key alg (optional)
			    .generate();
		return jwk.toJSONString();
	}

	@Override
	public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		// TODO Auto-generated method stub
		return null;
	}
	

}
