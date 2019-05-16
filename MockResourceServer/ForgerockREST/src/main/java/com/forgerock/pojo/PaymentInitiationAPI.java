package com.forgerock.pojo;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.annotations.ApiModelProperty;
import uk.org.openbanking.datamodel.discovery.OBDiscoveryAPILinksPayment4;

public class PaymentInitiationAPI {

	@JsonProperty("Version")
	private String version = null;

	@JsonProperty("Links")
	@Valid
	private OBDiscoveryAPILinksPayment4 apiLinksPayment4 = null;

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
	public OBDiscoveryAPILinksPayment4 getApiLinksPayment4() {
		return apiLinksPayment4;
	}

	public void setApiLinksPayment4(OBDiscoveryAPILinksPayment4 apiLinksPayment4) {
		this.apiLinksPayment4 = apiLinksPayment4;
	}

}
