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

import java.text.ParseException;
import java.util.Calendar;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.test.context.junit4.SpringRunner;

import com.forgerock.openbanking.aspsp.rs.rcs.config.ApplicationProperties;
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class ConversionUtilsTest {
	 private static final Logger log = LoggerFactory.getLogger(ConversionUtilsTest.class);
	 @Autowired
	  ApplicationProperties applicationProperties;
	@Test
	public void isTimeExpired() throws ParseException {
		log.info("Start isTimeExpired");
		//log.info("Start isTimeExpired: {} ", applicationProperties.getIdmDataCreadedFormat());
		//"yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
		log.info("IS expired: {}", ConversionUtils.isTimeExpired("2019-05-13T12:08:55.649Z", applicationProperties.getScaTimeExpire(), applicationProperties.getIdmDataCreadedFormat(), Calendar.DATE));
		log.info("End isTimeExpired");
		
	}
}
