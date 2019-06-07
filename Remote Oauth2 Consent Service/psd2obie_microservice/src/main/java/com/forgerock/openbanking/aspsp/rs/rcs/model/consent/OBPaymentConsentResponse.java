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
package com.forgerock.openbanking.aspsp.rs.rcs.model.consent;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.data.Data;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.tpp.Tpp;
import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
@Getter
@Setter
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class OBPaymentConsentResponse implements Serializable {
	private static final long serialVersionUID = -3965748469384490956L;
	@SerializedName("_id")
	private String _id;
	@SerializedName("_rev")
	private String _rev;
	@SerializedName("Status")
	private String Status;	
	@JsonUnwrapped
	private Data Data;
	@JsonUnwrapped
	private Tpp Tpp;
	
	}