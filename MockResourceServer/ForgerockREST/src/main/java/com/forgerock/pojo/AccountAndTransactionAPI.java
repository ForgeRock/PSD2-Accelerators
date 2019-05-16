package com.forgerock.pojo;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.annotations.ApiModelProperty;
import uk.org.openbanking.datamodel.discovery.OBDiscoveryAPILinksAccount3;

public class AccountAndTransactionAPI {

	@JsonProperty("Version")
	private String version = null;

	@JsonProperty("Links")
	@Valid
	private OBDiscoveryAPILinksAccount3 apiLinksAccount3 = null;

	/**
	 * Get version
	 * 
	 * @return version
	 **/
	@ApiModelProperty(required = true, value = "")
	@NotNull
	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	/**
	 * Get apiLinksPayment4
	 * 
	 * @return apiLinksPayment4
	 **/
	public OBDiscoveryAPILinksAccount3 getApiLinksAccount3() {
		return apiLinksAccount3;
	}

	public void setApiLinksAccount3(OBDiscoveryAPILinksAccount3 apiLinksAccount3) {
		this.apiLinksAccount3 = apiLinksAccount3;
	}

}
