package com.forgerock.pojo;

import java.util.List;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import org.springframework.validation.annotation.Validated;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.annotations.ApiModelProperty;

@Validated
public class DiscoveryApiLinksData {

	@JsonProperty("FinancialId")
	private String financialId = null;

	// @JsonProperty("PaymentInitiationAPI")
	// private PaymentInitiationAPI paymentInitiationAPI = null;
	//
	// @JsonProperty("AccountAndTransactionAPI")
	// private AccountAndTransactionAPI accountAndTransactionAPI = null;

	@JsonProperty("PaymentInitiationAPI")
	@Valid
	private List<PaymentInitiationAPI> paymentInitiationAPIs = null;

	@JsonProperty("AccountAndTransactionAPI")
	@Valid
	private List<AccountAndTransactionAPI> accountAndTransactionAPIs = null;

	public DiscoveryApiLinksData financialId(String financialId) {
		this.financialId = financialId;
		return this;
	}

	/**
	 * Get financialId
	 * 
	 * @return financialId
	 **/
	@ApiModelProperty(required = true, value = "")
	@NotNull
	public String getFinancialId() {
		return financialId;
	}

	public void setFinancialId(String financialId) {
		this.financialId = financialId;
	}

	/**
	 * Get paymentInitiationAPI
	 * 
	 * @return paymentInitiationAPI
	 **/
	@ApiModelProperty(required = true, value = "")
	@NotNull
	@Valid
	public List<PaymentInitiationAPI> getPaymentInitiationAPIs() {
		return paymentInitiationAPIs;
	}

	public void setPaymentInitiationAPIs(List<PaymentInitiationAPI> paymentInitiationAPIs) {
		this.paymentInitiationAPIs = paymentInitiationAPIs;
	}

	/**
	 * Get accountAndTransactionAPI
	 * 
	 * @return accountAndTransactionAPI
	 **/
	@ApiModelProperty(required = true, value = "")
	@NotNull
	@Valid
	public List<AccountAndTransactionAPI> getAccountAndTransactionAPIs() {
		return accountAndTransactionAPIs;
	}

	public void setAccountAndTransactionAPIs(List<AccountAndTransactionAPI> accountAndTransactionAPIs) {
		this.accountAndTransactionAPIs = accountAndTransactionAPIs;
	}

}
