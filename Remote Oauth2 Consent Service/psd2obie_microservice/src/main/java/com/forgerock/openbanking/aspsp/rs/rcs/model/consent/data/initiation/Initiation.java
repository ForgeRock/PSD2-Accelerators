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
package com.forgerock.openbanking.aspsp.rs.rcs.model.consent.data.initiation;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class Initiation implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = -615635333484914378L;
	@SerializedName("InstructionIdentification")
	private String InstructionIdentification;
	@SerializedName("EndToEndIdentification")
	private String EndToEndIdentification;
	@JsonUnwrapped
	private InstructedAmount InstructedAmount;
	@JsonUnwrapped
	private DebtorAccount DebtorAccount;
	@JsonUnwrapped
	private CreditorAccount CreditorAccount;
	@JsonUnwrapped
	private CreditorPostalAddress CreditorPostalAddress;
	@JsonUnwrapped
	private RemittanceInformation RemittanceInformation;
}
