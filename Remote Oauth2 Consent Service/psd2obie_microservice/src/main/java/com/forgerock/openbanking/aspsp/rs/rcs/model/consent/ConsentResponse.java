package com.forgerock.openbanking.aspsp.rs.rcs.model.consent;


import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import javax.validation.Valid;

import org.springframework.validation.annotation.Validated;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.data.Account;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * Consent object, not Open Banking Standard
 */
@ApiModel(description = "Consent object, not Open Banking Standard")
@Validated
@javax.annotation.Generated(value = "io.swagger.codegen.languages.SpringCodegen", date = "2019-04-02T16:55:56.415Z")

public class ConsentResponse   {
	  @JsonProperty("consentRequest")
	  private String consentRequest = null;

	  @JsonProperty("consentRequestFieldName")
	  private String consentRequestFieldName = null;

	  @JsonProperty("clientName")
	  private String clientName = null;

	  @JsonProperty("state")
	  private String state = null;

	  @JsonProperty("username")
	  private String username = null;

	  @JsonProperty("scopeList")
	  @Valid
	  private List<String> scopeList = null;

	  @JsonProperty("accountList")
	  @Valid
	  private List<Account> accountList = null;

	  @JsonProperty("claims")
	  @Valid
	  private List<String> claims = null;

	  @JsonProperty("initiationClaims")
	  private String initiationClaims = null;

	  @JsonProperty("obPaymentConsentPISP")
	  private Object obPaymentConsentPISP = null;

	  @JsonProperty("flow")
	  private String flow = null;

	  @JsonProperty("obAccountsAccessConsentAIPS")
	  private Object obAccountsAccessConsentAIPS = null;

	  @JsonProperty("errorDetails")
	  private Object errorDetails = null;

	  public ConsentResponse consentRequest(String consentRequest) {
	    this.consentRequest = consentRequest;
	    return this;
	  }

	  /**
	   * Get consentRequest
	   * @return consentRequest
	  **/
	  @ApiModelProperty(value = "")


	  public String getConsentRequest() {
	    return consentRequest;
	  }

	  public void setConsentRequest(String consentRequest) {
	    this.consentRequest = consentRequest;
	  }

	  public ConsentResponse consentRequestFieldName(String consentRequestFieldName) {
	    this.consentRequestFieldName = consentRequestFieldName;
	    return this;
	  }

	  /**
	   * Get consentRequestFieldName
	   * @return consentRequestFieldName
	  **/
	  @ApiModelProperty(value = "")


	  public String getConsentRequestFieldName() {
	    return consentRequestFieldName;
	  }

	  public void setConsentRequestFieldName(String consentRequestFieldName) {
	    this.consentRequestFieldName = consentRequestFieldName;
	  }

	  public ConsentResponse clientName(String clientName) {
	    this.clientName = clientName;
	    return this;
	  }

	  /**
	   * Get clientName
	   * @return clientName
	  **/
	  @ApiModelProperty(value = "")


	  public String getClientName() {
	    return clientName;
	  }

	  public void setClientName(String clientName) {
	    this.clientName = clientName;
	  }

	  public ConsentResponse state(String state) {
	    this.state = state;
	    return this;
	  }

	  /**
	   * Get state
	   * @return state
	  **/
	  @ApiModelProperty(value = "")


	  public String getState() {
	    return state;
	  }

	  public void setState(String state) {
	    this.state = state;
	  }

	  public ConsentResponse username(String username) {
	    this.username = username;
	    return this;
	  }

	  /**
	   * Get username
	   * @return username
	  **/
	  @ApiModelProperty(value = "")


	  public String getUsername() {
	    return username;
	  }

	  public void setUsername(String username) {
	    this.username = username;
	  }

	  public ConsentResponse scopeList(List<String> scopeList) {
	    this.scopeList = scopeList;
	    return this;
	  }

	  public ConsentResponse addScopeListItem(String scopeListItem) {
	    if (this.scopeList == null) {
	      this.scopeList = new ArrayList<String>();
	    }
	    this.scopeList.add(scopeListItem);
	    return this;
	  }

	  /**
	   * Get scopeList
	   * @return scopeList
	  **/
	  @ApiModelProperty(value = "")


	  public List<String> getScopeList() {
	    return scopeList;
	  }

	  public void setScopeList(List<String> scopeList) {
	    this.scopeList = scopeList;
	  }

	  public ConsentResponse accountList(List<Account> accountList) {
	    this.accountList = accountList;
	    return this;
	  }

	  public ConsentResponse addAccountListItem(Account accountListItem) {
	    if (this.accountList == null) {
	      this.accountList = new ArrayList<Account>();
	    }
	    this.accountList.add(accountListItem);
	    return this;
	  }

	  /**
	   * Get accountList
	   * @return accountList
	  **/
	  @ApiModelProperty(value = "")

	  @Valid

	  public List<Account> getAccountList() {
	    return accountList;
	  }

	  public void setAccountList(List<Account> accountList) {
	    this.accountList = accountList;
	  }

	  public ConsentResponse claims(List<String> claims) {
	    this.claims = claims;
	    return this;
	  }

	  public ConsentResponse addClaimsItem(String claimsItem) {
	    if (this.claims == null) {
	      this.claims = new ArrayList<String>();
	    }
	    this.claims.add(claimsItem);
	    return this;
	  }

	  /**
	   * Get claims
	   * @return claims
	  **/
	  @ApiModelProperty(value = "")


	  public List<String> getClaims() {
	    return claims;
	  }

	  public void setClaims(List<String> claims) {
	    this.claims = claims;
	  }

	  public ConsentResponse initiationClaims(String initiationClaims) {
	    this.initiationClaims = initiationClaims;
	    return this;
	  }

	  /**
	   * Get initiationClaims
	   * @return initiationClaims
	  **/
	  @ApiModelProperty(value = "")


	  public String getInitiationClaims() {
	    return initiationClaims;
	  }

	  public void setInitiationClaims(String initiationClaims) {
	    this.initiationClaims = initiationClaims;
	  }

	  public ConsentResponse obPaymentConsentPISP(Object obPaymentConsentPISP) {
	    this.obPaymentConsentPISP = obPaymentConsentPISP;
	    return this;
	  }

	  /**
	   * Get obPaymentConsentPISP
	   * @return obPaymentConsentPISP
	  **/
	  @ApiModelProperty(value = "")


	  public Object getObPaymentConsentPISP() {
	    return obPaymentConsentPISP;
	  }

	  public void setObPaymentConsentPISP(Object obPaymentConsentPISP) {
	    this.obPaymentConsentPISP = obPaymentConsentPISP;
	  }

	  public ConsentResponse flow(String flow) {
	    this.flow = flow;
	    return this;
	  }

	  /**
	   * Get flow
	   * @return flow
	  **/
	  @ApiModelProperty(value = "")


	  public String getFlow() {
	    return flow;
	  }

	  public void setFlow(String flow) {
	    this.flow = flow;
	  }

	  public ConsentResponse obAccountsAccessConsentAIPS(Object obAccountsAccessConsentAIPS) {
	    this.obAccountsAccessConsentAIPS = obAccountsAccessConsentAIPS;
	    return this;
	  }

	  /**
	   * Get obAccountsAccessConsentAIPS
	   * @return obAccountsAccessConsentAIPS
	  **/
	  @ApiModelProperty(value = "")


	  public Object getObAccountsAccessConsentAIPS() {
	    return obAccountsAccessConsentAIPS;
	  }

	  public void setObAccountsAccessConsentAIPS(Object obAccountsAccessConsentAIPS) {
	    this.obAccountsAccessConsentAIPS = obAccountsAccessConsentAIPS;
	  }

	  public ConsentResponse errorDetails(Object errorDetails) {
	    this.errorDetails = errorDetails;
	    return this;
	  }

	  /**
	   * Get errorDetails
	   * @return errorDetails
	  **/
	  @ApiModelProperty(value = "")


	  public Object getErrorDetails() {
	    return errorDetails;
	  }

	  public void setErrorDetails(Object errorDetails) {
	    this.errorDetails = errorDetails;
	  }


	  @Override
	  public boolean equals(java.lang.Object o) {
	    if (this == o) {
	      return true;
	    }
	    if (o == null || getClass() != o.getClass()) {
	      return false;
	    }
	    ConsentResponse consentResponse = (ConsentResponse) o;
	    return Objects.equals(this.consentRequest, consentResponse.consentRequest) &&
	        Objects.equals(this.consentRequestFieldName, consentResponse.consentRequestFieldName) &&
	        Objects.equals(this.clientName, consentResponse.clientName) &&
	        Objects.equals(this.state, consentResponse.state) &&
	        Objects.equals(this.username, consentResponse.username) &&
	        Objects.equals(this.scopeList, consentResponse.scopeList) &&
	        Objects.equals(this.accountList, consentResponse.accountList) &&
	        Objects.equals(this.claims, consentResponse.claims) &&
	        Objects.equals(this.initiationClaims, consentResponse.initiationClaims) &&
	        Objects.equals(this.obPaymentConsentPISP, consentResponse.obPaymentConsentPISP) &&
	        Objects.equals(this.flow, consentResponse.flow) &&
	        Objects.equals(this.obAccountsAccessConsentAIPS, consentResponse.obAccountsAccessConsentAIPS) &&
	        Objects.equals(this.errorDetails, consentResponse.errorDetails);
	  }

	  @Override
	  public int hashCode() {
	    return Objects.hash(consentRequest, consentRequestFieldName, clientName, state, username, scopeList, accountList, claims, initiationClaims, obPaymentConsentPISP, flow, obAccountsAccessConsentAIPS, errorDetails);
	  }

	  @Override
	  public String toString() {
	    StringBuilder sb = new StringBuilder();
	    sb.append("class ConsentResponse {\n");
	    
	    sb.append("    consentRequest: ").append(toIndentedString(consentRequest)).append("\n");
	    sb.append("    consentRequestFieldName: ").append(toIndentedString(consentRequestFieldName)).append("\n");
	    sb.append("    clientName: ").append(toIndentedString(clientName)).append("\n");
	    sb.append("    state: ").append(toIndentedString(state)).append("\n");
	    sb.append("    username: ").append(toIndentedString(username)).append("\n");
	    sb.append("    scopeList: ").append(toIndentedString(scopeList)).append("\n");
	    sb.append("    accountList: ").append(toIndentedString(accountList)).append("\n");
	    sb.append("    claims: ").append(toIndentedString(claims)).append("\n");
	    sb.append("    initiationClaims: ").append(toIndentedString(initiationClaims)).append("\n");
	    sb.append("    obPaymentConsentPISP: ").append(toIndentedString(obPaymentConsentPISP)).append("\n");
	    sb.append("    flow: ").append(toIndentedString(flow)).append("\n");
	    sb.append("    obAccountsAccessConsentAIPS: ").append(toIndentedString(obAccountsAccessConsentAIPS)).append("\n");
	    sb.append("    errorDetails: ").append(toIndentedString(errorDetails)).append("\n");
	    sb.append("}");
	    return sb.toString();
	  }

	  /**
	   * Convert the given object to string with each line indented by 4 spaces
	   * (except the first line).
	   */
	  private String toIndentedString(java.lang.Object o) {
	    if (o == null) {
	      return "null";
	    }
	    return o.toString().replace("\n", "\n    ");
	  }
	}
