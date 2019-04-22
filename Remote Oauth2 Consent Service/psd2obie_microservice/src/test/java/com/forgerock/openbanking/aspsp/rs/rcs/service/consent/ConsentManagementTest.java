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
package com.forgerock.openbanking.aspsp.rs.rcs.service.consent;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;

import com.forgerock.openbanking.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.OBPaymentConsentResponse;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.ReqestHeaders;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.RequestConsntToIDM;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class ConsentManagementTest {
	private final static Logger log = LoggerFactory.getLogger(ConsentManagementTest.class);
	@LocalServerPort
	private int port;
	@Autowired
	ConsentManagement consentManagement;	
	@Autowired
	ApplicationProperties applicationProperties;
	
	String paymentIntentID="1dfba204-e45d-4e4c-8760-ed62892fd0c9";
	String accountIntentID="67461aa0-00a0-4cff-b9b1-dd293e13f198";
	
	
	@Test
	public void getOBPaymentConsentTest() throws Exception {		
		
		//String url = "http://localhost:8082/openidm/managed/OBPaymentIntent/"+intentID+"?_prettyPrint=true";
		StringBuilder idmURL = new StringBuilder()
				.append(applicationProperties.getIdmGetPaymentIntentConsentUrl()).append(paymentIntentID)
				.append("?_prettyPrint=true");
		log.info("idmURL {} ", idmURL.toString());
		//ResponseEntity<OBPaymentConsentResponse> entity = new TestRestTemplate().exchange(idmURL.toString(), HttpMethod.GET,
		//		new HttpEntity<Object>(headers), OBPaymentConsentResponse.class);
		ResponseEntity<String> entity =consentManagement.getOBPaymentConsent(idmURL.toString(), ReqestHeaders.builder()
				.username("openidm-admin")
				.password("openidm-admin")
				.build());
		log.info("getStatusCode {} ", entity.getStatusCode());
		//log.info("getBody().get_id() {} ", entity.getBody().get_id());
		Gson gson = new GsonBuilder().create();
		OBPaymentConsentResponse obPaymentConsentResponse = gson.fromJson(entity.getBody(), OBPaymentConsentResponse.class);
		log.info("getOBPaymentConsentTest getResult() {} ", entity.getBody());
		log.info("obPaymentConsentResponse  {} ", obPaymentConsentResponse.toString());
		log.info("getOBPaymentConsentTest getAmount() {} ", obPaymentConsentResponse.getData().getInitiation().getInstructedAmount().getAmount());
		
		assertThat(entity.getStatusCode().value()).isEqualTo(HttpStatus.OK.value());
		//assertThat(entity.getBody().get_id()).isEqualTo(paymentIntentID);
	}

	@Test
	public void updateOBPaymentConsent() throws Exception {
		//String url = "http://localhost:8082/openidm/endpoint/paymentIntent/"+intentID+"?_action=patch";
		StringBuilder idmURL = new StringBuilder()
				.append(applicationProperties.getIdmUpdatePaymentConsentUrl()).append(paymentIntentID)
				.append("?_action=patch");
		log.info("idmURL {} ", idmURL.toString());
		List<RequestConsntToIDM> body = new ArrayList<>();
//		 body.add(RequestConsntToIDM.builder()
//				.operation("replace")
//				.field("Status")
//				.value("Authorised")
//				.build());
		 log.info("body {}",body);
		 log.info("url {}",idmURL);
//		ResponseEntity<String> entity = consentManagement.updateOBPaymentConsent(idmURL.toString(),
//				ReqestHeaders.builder()
//				.username("openidm-admin")
//				.password("openidm-admin")
//				.build(),
//				body);
		
//		log.info("updateOBPaymentConsent getStatusCode {} ", entity.getStatusCode());
//		//log.info("updateOBPaymentConsent get_id() {} ", entity.getBody().getResult().get_id());
//		//log.info("updateOBPaymentConsent getResult() {} ", entity.getBody().getResult());
//		assertThat(entity.getStatusCode().value()).isEqualTo(HttpStatus.OK.value());
		//assertThat(entity.getBody().getResult().get_id()).isEqualTo(paymentIntentID);
	}
	
	@Test
	public void getOBAccountAccessConsentTest() throws Exception {		
		
		//String url = "http://localhost:8082/openidm/managed/OBPaymentIntent/"+intentID+"?_prettyPrint=true";
		StringBuilder idmURL = new StringBuilder()
				.append(applicationProperties.getIdmGetAccountIntentConsentUrl()).append(accountIntentID)
				.append("?_prettyPrint=true");
		log.info("idmURL {} ", idmURL.toString());
		//ResponseEntity<OBPaymentConsentResponse> entity = new TestRestTemplate().exchange(idmURL.toString(), HttpMethod.GET,
		//		new HttpEntity<Object>(headers), OBPaymentConsentResponse.class);
		ResponseEntity<String> entity =consentManagement.getOBPaymentConsent(idmURL.toString(), ReqestHeaders.builder()
				.username("openidm-admin")
				.password("openidm-admin")
				.build());
		log.info("getStatusCode {} ", entity.getStatusCode());
		//log.info("getBody().get_id() {} ", entity.getBody().get_id());
		log.info("getOBAccountAccessConsentTest getResult() {} ", entity.getBody());
		assertThat(entity.getStatusCode().value()).isEqualTo(HttpStatus.OK.value());
		//assertThat(entity.getBody().get_id()).isEqualTo(accountIntentID);
	}

	@Test
	public void updateOBAccountAccessConsent() throws Exception {
		//String url = "http://localhost:8082/openidm/endpoint/paymentIntent/"+intentID+"?_action=patch";
		StringBuilder idmURL = new StringBuilder()
				.append(applicationProperties.getIdmUpdateAccountConsentUrl()).append(accountIntentID)
				.append("?_action=patch");
		log.info("idmURL {} ", idmURL.toString());
		List<RequestConsntToIDM> body = new ArrayList<>();
//		 body.add(RequestConsntToIDM.builder()
//				.operation("replace")
//				.field("Status")
//				.value("Authorised")
//				.build());
		 log.info("body {}",body);
//		 log.info("url {}",idmURL);
//		ResponseEntity<String> entity = consentManagement.updateOBPaymentConsent(idmURL.toString(),
//				ReqestHeaders.builder()
//				.username("openidm-admin")
//				.password("openidm-admin")
//				.build(),
//				body);
		
//		log.info("updateOBPaymentConsent getStatusCode {} ", entity.getStatusCode());
//		//log.info("updateOBPaymentConsent get_id() {} ", entity.getBody().getResult().get_id());
//		//log.info("updateOBPaymentConsent getResult() {} ", entity.getBody().getResult());
//		assertThat(entity.getStatusCode().value()).isEqualTo(HttpStatus.OK.value());
		//assertThat(entity.getBody().getResult().get_id()).isEqualTo(accountIntentID);
	}
	
}
