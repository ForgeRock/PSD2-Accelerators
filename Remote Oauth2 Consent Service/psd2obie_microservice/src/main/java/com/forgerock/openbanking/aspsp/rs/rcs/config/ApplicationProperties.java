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
package com.forgerock.openbanking.aspsp.rs.rcs.config;

import javax.validation.constraintvalidation.SupportedValidationTarget;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import lombok.Getter;
import lombok.Setter;

/**
 * Properties specific to Psd 2 RSC Sevice.
 * <p>
 * Properties are configured in the application.yml file.
 * See {@link io.github.jhipster.config.JHipsterProperties} for a good example.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "application", ignoreUnknownFields = false)
public class ApplicationProperties {
	private String jwkms;
	private String issuerID;
	private String rcsIssuerId;
	private String amCookieName;
	private String amJwkUrl;
	private Integer amJwkUrlConnectTimeout;
	private Integer amJwkUrlReadTimeout;
	private Integer amJwkUrlSizeLimit;
	
	private Resource keyStore;	    
    private String keyStorePassword;    
    private String keyPassword;  
    private String keyAlias;
    private String idmGetPaymentIntentConsentUrl;
	private String idmUpdatePaymentConsentUrl;
	private String idmGetAccountIntentConsentUrl;
	private String idmUpdateAccountConsentUrl;
	private String amAuthUrl;
	private String amUsername;
	private String amPassword;
	private String idmHeaderUsername;
	private String idmHeaderPassword;
	private String accountsEndpoint;
	private String amHostUrl;
	private String amGetCookieToken;
	private String idmConsentStatusAuthorised;
	private String idmConsentStatusRejected;
	private String idmDataCreadedFormat;
	private Integer scaTimeAutoAccept;
	private Integer scaTimeExpire;
	private String idmConsentStatusAwaiting;

}
