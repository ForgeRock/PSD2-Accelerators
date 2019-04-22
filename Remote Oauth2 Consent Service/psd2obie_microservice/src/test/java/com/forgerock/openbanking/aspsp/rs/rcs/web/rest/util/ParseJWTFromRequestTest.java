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
package com.forgerock.openbanking.aspsp.rs.rcs.web.rest.util;

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.test.context.junit4.SpringRunner;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.openbanking.aspsp.rs.rcs.constants.OpenBankingConstants;
import com.forgerock.openbanking.aspsp.rs.rcs.model.claims.Claim;
import com.forgerock.openbanking.aspsp.rs.rcs.model.claims.Claims;
import com.forgerock.openbanking.aspsp.rs.rcs.service.consent.ConsentManagementTest;
import com.forgerock.openbanking.aspsp.rs.rcs.service.parsing.ParseJWT;
import com.nimbusds.jwt.JWTClaimsSet;

import net.minidev.json.JSONObject;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class ParseJWTFromRequestTest {
	private final static Logger log = LoggerFactory.getLogger(ConsentManagementTest.class);
	@LocalServerPort
	private int port;
	@Autowired
	ParseJWT setJwtClaims;

	@Test
	public void psd2AspsConsent() throws Exception {
		JWTClaimsSet parsedSet = setJwtClaims.parseJWT("eyJ0eXAiOiJKV1QiLCJraWQiOiJ3VTNpZklJYUxPVUFSZVJCL0ZHNmVNMVAxUU09IiwiYWxnIjoiUlMyNTYifQ.eyJjbGllbnRJZCI6Imlzc19kZW1vX2NsaWVudCIsImlzcyI6Im51bGw6Ly9udWxsL29wZW5hbS9vYXV0aDIvcmVhbG1zL3Jvb3QvcmVhbG1zL29wZW5iYW5raW5nIiwiY3NyZiI6IjhCc2JiUFFRRjlQS2VGemRyNks1ZGk5UDJHTm9LRDBYRjRvWmJMQVg0aVk9IiwiY2xpZW50X2Rlc2NyaXB0aW9uIjoiIiwiYXVkIjoiZm9yZ2Vyb2NrLXJjcyIsInNhdmVfY29uc2VudF9lbmFibGVkIjpmYWxzZSwiY2xhaW1zIjp7InVzZXJfaW5mbyI6eyJvcGVuYmFua2luZ19pbnRlbnRfaWQiOnsidmFsdWUiOiI1MWJkOGI5Ny1mOTc4LTQyZWItYTU5Yi1hZTBlNGIzMTM4MDYiLCJlc3NlbnRpYWwiOnRydWV9fSwiaWRfdG9rZW4iOnsib3BlbmJhbmtpbmdfaW50ZW50X2lkIjp7InZhbHVlIjoiNTFiZDhiOTctZjk3OC00MmViLWE1OWItYWUwZTRiMzEzODA2IiwiZXNzZW50aWFsIjp0cnVlfX19LCJzY29wZXMiOnsib3BlbmlkIjpudWxsLCJwYXltZW50cyI6IlBheW1lbnRzIn0sImV4cCI6MTU0OTk3MTY2OSwiaWF0IjoxNTQ5OTcxNDg5LCJjbGllbnRfbmFtZSI6Imlzc19kZW1vX2NsaWVudCIsImNvbnNlbnRBcHByb3ZhbFJlZGlyZWN0VXJpIjoibnVsbDovL251bGwvb3BlbmFtL29hdXRoMi9yZWFsbXMvcm9vdC9yZWFsbXMvb3BlbmJhbmtpbmcvYXV0aG9yaXplP2NsaWVudF9pZD1pc3NfZGVtb19jbGllbnQmcmVzcG9uc2VfdHlwZT1jb2RlJTIwaWRfdG9rZW4mcmVkaXJlY3RfdXJpPWh0dHBzOi8vd3d3Lmdvb2dsZS5jb20mc2NvcGU9cGF5bWVudHMlMjBvcGVuaWQmc3RhdGU9c3RhdGUtMTIzNCZub25jZT1ub25jZS0xMjM0JmNsYWltcz0lN0IlMjJ1c2VyaW5mbyUyMjolN0IlMjJvcGVuYmFua2luZ19pbnRlbnRfaWQlMjI6JTdCJTIydmFsdWUlMjI6JTIyNTFiZDhiOTctZjk3OC00MmViLWE1OWItYWUwZTRiMzEzODA2JTIyLCUyMmVzc2VudGlhbCUyMjp0cnVlJTdEJTdELCUyMmlkX3Rva2VuJTIyOiU3QiUyMm9wZW5iYW5raW5nX2ludGVudF9pZCUyMjolN0IlMjJ2YWx1ZSUyMjolMjI1MWJkOGI5Ny1mOTc4LTQyZWItYTU5Yi1hZTBlNGIzMTM4MDYlMjIsJTIyZXNzZW50aWFsJTIyOnRydWUlN0QlN0QlN0QiLCJ1c2VybmFtZSI6ImRlbW8ifQ.TcA1pA02b6eKIt5Esb7NV-sctNm2HpqttLgi5IK1U9Z7UNqQIP6IUErXEaWdwD6Gs_w64WMtnK8hyPsiilmZZwAFeg-9Vbkf1wjbwbSfxgaLepmUPh4u9olbiO1bGngdwQL-ZZRtxo-La-Th5Q5qwQHJngh4HkgvcHCZ0p7oNLqhtMe8W4Rw-RsRC-pqEPxpxXgbPKVQeF9XAb08Kmimy273-KIb3OGPB9AfhuAMa8CQRTlrYktiS84uH4lzenCJwWdTJD5LAvnSwWuUniL8zuxc4IBB-cKzDzgwVYNPWT2kcfM1s-0FabJHUeC4Nu8_pWuCuRSczfuieWCe1FyTww");
		

		final Map<String, String> authInfo = new ObjectMapper().readValue(parsedSet.toString(), Map.class);

		log.info("authInfo: {} ", authInfo.toString());
		log.info("scopesList: {} ", authInfo.get("scopes"));
		log.info("parsedSet.getClaims(): {} ", parsedSet.getClaims().get("scopes"));

		
		final Map<String, String> scopesMap = new ObjectMapper()
				.readValue(parsedSet.getClaims().get("scopes").toString(), Map.class);

		List<String> scopesKey = scopesMap.keySet().stream().collect(Collectors.toList());

		log.info("scopesKey: {} ", scopesKey);
		
		//final Map<String, Claims> claimsMap = getParsedClaim(parsedSet);
		Claims claimsMap =  Claims.parseClaims(getParsedClaim(parsedSet));
		Claim instentId = claimsMap.getUserInfoClaims().get(OpenBankingConstants.IdTokenClaim.INTENT_ID);
		
		log.info("claimsMap {} ", claimsMap.toString());
		log.info("instentId.toJson() {} ", instentId.toJson());
		log.info("instentId.getValue(){} ", instentId.getValue().toString());
		//List<String> claimsKey = claimsMap.keySet().stream().collect(Collectors.toList());		
		//log.debug("claimsKey: {} ", claimsKey);
		assertTrue(claimsMap.getUserInfoClaims().containsKey(OpenBankingConstants.IdTokenClaim.INTENT_ID) );
						
		/*for (String string : claimsKey) {
			Claim claim = new Claim(true, claimsMap.get(string)) ;	
			log.info("claim.toJson() {} ", claimsMap.get(string));
			log.info("claim.getValues() {} ", claim.getValues());	
			assertTrue(claimsMap.containsKey(OpenBankingConstants.IdTokenClaim.USER_INFO) );
		}*/	
		
		
	}
	private JSONObject getParsedClaim(JWTClaimsSet parsedSet)
			throws IOException, JsonParseException, JsonMappingException, ParseException {
		return parsedSet.getJSONObjectClaim(OpenBankingConstants.IdTokenClaim.CLAIMS);
//		final Map<String, Claims> claimsMap = new ObjectMapper()
//				.readValue(parsedSet.getClaims().get(OpenBankingConstants.IdTokenClaim.CLAIMS).toString(), Map.class);
//		return claimsMap;
	}

}
