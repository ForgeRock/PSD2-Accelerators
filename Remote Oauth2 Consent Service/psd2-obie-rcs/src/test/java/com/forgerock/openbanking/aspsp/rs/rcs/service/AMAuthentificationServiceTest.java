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
package com.forgerock.openbanking.aspsp.rs.rcs.service;

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
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;

import com.forgerock.openbanking.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.ReqestHeaders;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.RequestConsntToIDM;
import com.forgerock.openbanking.aspsp.rs.rcs.service.consent.ConsentManagementTest;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class AMAuthentificationServiceTest {
	private final static Logger log = LoggerFactory.getLogger(ConsentManagementTest.class);
	@LocalServerPort
	private int port;
	
	@Autowired
	AMAuthentificationService amAuthentificationService;
	@Autowired
	ApplicationProperties applicationProperties;
	@Test
	public void amAuthTest() throws Exception {		
		StringBuilder idmURL = new StringBuilder()
				.append(applicationProperties.getAmAuthUrl());
		log.info("idmURL {} ", idmURL.toString());
		List<RequestConsntToIDM> body = new ArrayList<>();		 
		 log.info("body {}",body);
		 log.info("url {}",idmURL);
		ResponseEntity<String> entity = amAuthentificationService.postAMAuthentificatin(idmURL.toString(),
				ReqestHeaders.builder()
				.username("demo")
				.password("12345678")
				.build(),
				body);
		List<String> cookie=entity.getHeaders().get(HttpHeaders.SET_COOKIE);
		log.info("amAuthTest getStatusCode {} ", entity.getStatusCode());
		log.info("amAuthTest get_id() {} ", entity.getBody());
		log.info("amAuthTest getResult() {} ", cookie);
		
		assertThat(entity.getStatusCode().value()).isEqualTo(HttpStatus.OK.value());
		
	}
}
