package com.forgerock.openbanking.aspsp.rs.rcs.model.consent;

import java.util.Objects;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.ArrayList;
import java.util.List;
import org.springframework.validation.annotation.Validated;
import javax.validation.Valid;
import javax.validation.constraints.*;

/**
 * ConsentRequest
 */
@Validated
@javax.annotation.Generated(value = "io.swagger.codegen.languages.SpringCodegen", date = "2019-04-12T14:41:34.216Z")

public class ConsentRequest   {
  @JsonProperty("consent_request")
  private String consentRequest = null;

  @JsonProperty("scope")
  @Valid
  private List<String> scope = null;

  @JsonProperty("account")
  @Valid
  private List<String> account = null;

  @JsonProperty("decision")
  private String decision = null;

  @JsonProperty("claims")
  private String claims = null;

  @JsonProperty("flow")
  private String flow = null;

  public ConsentRequest consentRequest(String consentRequest) {
    this.consentRequest = consentRequest;
    return this;
  }

  /**
   * Get consentRequest
   * @return consentRequest
  **/
  @ApiModelProperty(required = true, value = "")
  @NotNull


  public String getConsentRequest() {
    return consentRequest;
  }

  public void setConsentRequest(String consentRequest) {
    this.consentRequest = consentRequest;
  }

  public ConsentRequest scope(List<String> scope) {
    this.scope = scope;
    return this;
  }

  public ConsentRequest addScopeItem(String scopeItem) {
    if (this.scope == null) {
      this.scope = new ArrayList<String>();
    }
    this.scope.add(scopeItem);
    return this;
  }

  /**
   * Get scope
   * @return scope
  **/
  @ApiModelProperty(value = "")


  public List<String> getScope() {
    return scope;
  }

  public void setScope(List<String> scope) {
    this.scope = scope;
  }

  public ConsentRequest account(List<String> account) {
    this.account = account;
    return this;
  }

  public ConsentRequest addAccountItem(String accountItem) {
    if (this.account == null) {
      this.account = new ArrayList<String>();
    }
    this.account.add(accountItem);
    return this;
  }

  /**
   * Get account
   * @return account
  **/
  @ApiModelProperty(value = "")


  public List<String> getAccount() {
    return account;
  }

  public void setAccount(List<String> account) {
    this.account = account;
  }

  public ConsentRequest decision(String decision) {
    this.decision = decision;
    return this;
  }

  /**
   * Get decision
   * @return decision
  **/
  @ApiModelProperty(required = true, value = "")
  @NotNull


  public String getDecision() {
    return decision;
  }

  public void setDecision(String decision) {
    this.decision = decision;
  }

  public ConsentRequest claims(String claims) {
    this.claims = claims;
    return this;
  }

  /**
   * Get claims
   * @return claims
  **/
  @ApiModelProperty(value = "")


  public String getClaims() {
    return claims;
  }

  public void setClaims(String claims) {
    this.claims = claims;
  }

  public ConsentRequest flow(String flow) {
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


  @Override
  public boolean equals(java.lang.Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    ConsentRequest consentRequest = (ConsentRequest) o;
    return Objects.equals(this.consentRequest, consentRequest.consentRequest) &&
        Objects.equals(this.scope, consentRequest.scope) &&
        Objects.equals(this.account, consentRequest.account) &&
        Objects.equals(this.decision, consentRequest.decision) &&
        Objects.equals(this.claims, consentRequest.claims) &&
        Objects.equals(this.flow, consentRequest.flow);
  }

  @Override
  public int hashCode() {
    return Objects.hash(consentRequest, scope, account, decision, claims, flow);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class ConsentRequest {\n");
    
    sb.append("    consentRequest: ").append(toIndentedString(consentRequest)).append("\n");
    sb.append("    scope: ").append(toIndentedString(scope)).append("\n");
    sb.append("    account: ").append(toIndentedString(account)).append("\n");
    sb.append("    decision: ").append(toIndentedString(decision)).append("\n");
    sb.append("    claims: ").append(toIndentedString(claims)).append("\n");
    sb.append("    flow: ").append(toIndentedString(flow)).append("\n");
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

