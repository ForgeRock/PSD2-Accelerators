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
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.google.gson.annotations.SerializedName;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@Getter
@Setter
@ToString
@JsonIgnoreProperties(ignoreUnknown = true)
public class CreditorPostalAddress implements Serializable {/**
	 * 
	 */
	private static final long serialVersionUID = -8511136546875387687L;
	@SerializedName("AddressType")
	private String addressType;
	@SerializedName("Department")
	private String department;
	@SerializedName("SubDeparment")
	private String subDeparment;
	@SerializedName("StreetName")
	private String streetName;
	@SerializedName("BuildingNumber")
	private String buildingNumber;
	@SerializedName("PostCode")
	private String postCode;
	@SerializedName("TownName")
	private String townName;
	@SerializedName("CountrySubDisivion")
	private List<String> countrySubDisivion;
	@SerializedName("Country")
	private String country;
	@SerializedName("AddressLine")
	private List<String> addressLine;
	

}
