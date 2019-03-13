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
package com.forgerock.nextgenpsd2.aspsp.rs.rcs.web.rest;


import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestParam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.config.ApplicationProperties;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.constants.BerlingGroupConstants;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.constants.OIDCConstants;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.model.rcs.RedirectionAction;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.RcsService;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.jwt.JWTManagementService;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.keygenerator.IGenerateKey;
import com.forgerock.nextgenpsd2.aspsp.rs.rcs.service.parsing.ParseJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;

import io.swagger.annotations.ApiParam;
@javax.annotation.Generated(value = "io.swagger.codegen.languages.SpringCodegen", date = "2019-01-24T23:01:14.780Z")

@Controller
public class ConsentNextGenPSD2ApiController implements ConsentNextGenPSD2Api {

    private static final Logger log = LoggerFactory.getLogger(ConsentNextGenPSD2ApiController.class);

    private final ObjectMapper objectMapper;

    private final HttpServletRequest request;
    
    @Autowired
    IGenerateKey generatedKey; 
    
    @Autowired
    RcsService rcsService;
    
    @Autowired
    JWTManagementService jwtManagementService;
    
    @Autowired
    ParseJWT setJwtClaims;   
    
    @Autowired
    ApplicationProperties applicationProperties;
        

    private static String jwkPub;
    @org.springframework.beans.factory.annotation.Autowired
    public ConsentNextGenPSD2ApiController(ObjectMapper objectMapper, HttpServletRequest request) {
        this.objectMapper = objectMapper;
        this.request = request;
    }

    public ResponseEntity<String> apiConsentJwkPubGet() {        
      
            try {       
            	if(jwkPub==null) {
//            	jwkPub=((RSAGenerateKey)generatedKey).generateKey();
            		jwkPub ="{\"keys\":["+jwtManagementService.senderKey().toPublicJWK().toJSONString()+"]}";
            	}
            	log.debug("ConsentApiController senderKey(): {}", jwkPub);
                return new ResponseEntity<String>(jwkPub, HttpStatus.OK);
            } catch (NoSuchAlgorithmException | JOSEException | IOException | ParseException e) {
                log.error("Couldn't serialize response for content type application/json", e);
                return new ResponseEntity<String>(HttpStatus.INTERNAL_SERVER_ERROR);
            }
    }


}
