package com.forgerock.pojo;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import org.springframework.validation.annotation.Validated;

import com.fasterxml.jackson.annotation.JsonProperty;

import io.swagger.annotations.ApiModelProperty;

@Validated
public class DiscoveryApiLinksResponse {

	
	  @JsonProperty("Data")
	  private DiscoveryApiLinksData data = null;

	  public DiscoveryApiLinksResponse data(DiscoveryApiLinksData data) {
		    this.data = data;
		    return this;
	  }

	  /**
	   * Get data
	   * @return data
	  **/
	  @ApiModelProperty(required = true, value = "")
	  @NotNull

	  @Valid

	  public DiscoveryApiLinksData getData() {
	    return data;
	  }

	  public void setData(DiscoveryApiLinksData data) {
	    this.data = data;
	  }
}
