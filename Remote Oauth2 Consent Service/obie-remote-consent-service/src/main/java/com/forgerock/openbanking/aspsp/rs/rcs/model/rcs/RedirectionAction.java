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
package com.forgerock.openbanking.aspsp.rs.rcs.model.rcs;

import org.springframework.http.HttpMethod;

public class RedirectionAction {
private String consentJwt;
private HttpMethod requestMethod;
private String redirectUri;
public RedirectionAction(RedirectionActionBuilder redirectionActionBuilder) {
	// TODO Auto-generated constructor stub
}

private RedirectionAction() {
	
}

public String getConsentJwt() {
	return consentJwt;
}
public void setConsentJwt(String consentJwt) {
	this.consentJwt = consentJwt;
}
public HttpMethod getRequestMethod() {
	return requestMethod;
}
public void setRequestMethod(HttpMethod requestMethod) {
	this.requestMethod = requestMethod;
}
public String getRedirectUri() {
	return redirectUri;
}
public void setRedirectUri(String redirectUri) {
	this.redirectUri = redirectUri;
}
@Override
public String toString() {
	return "RedirectionAction [consentJwt=" + consentJwt + ", requestMethod=" + requestMethod + ", redirectUri="
			+ redirectUri + "]";
}
@Override
public int hashCode() {
	final int prime = 31;
	int result = 1;
	result = prime * result + ((consentJwt == null) ? 0 : consentJwt.hashCode());
	result = prime * result + ((redirectUri == null) ? 0 : redirectUri.hashCode());
	result = prime * result + ((requestMethod == null) ? 0 : requestMethod.hashCode());
	return result;
}
@Override
public boolean equals(Object obj) {
	if (this == obj)
		return true;
	if (obj == null)
		return false;
	if (getClass() != obj.getClass())
		return false;
	RedirectionAction other = (RedirectionAction) obj;
	if (consentJwt == null) {
		if (other.consentJwt != null)
			return false;
	} else if (!consentJwt.equals(other.consentJwt))
		return false;
	if (redirectUri == null) {
		if (other.redirectUri != null)
			return false;
	} else if (!redirectUri.equals(other.redirectUri))
		return false;
	if (requestMethod == null) {
		if (other.requestMethod != null)
			return false;
	} else if (!requestMethod.equals(other.requestMethod))
		return false;
	return true;
}

public static RedirectionActionBuilder builder() {
	return new RedirectionAction().new RedirectionActionBuilder();
}

	public  class RedirectionActionBuilder {
		private String consentJwt;
		private String requestMethod;
		private String redirectUri;
		
		private RedirectionActionBuilder() {
			
		}
		
		
		public RedirectionActionBuilder setConsentJwt(String consentJwt) {
			RedirectionAction.this.consentJwt = consentJwt;
			return this;
			
		}
		
		public RedirectionActionBuilder setRequestMethod(HttpMethod post) {
			RedirectionAction.this.requestMethod = post;
			return this;
		}
		
		public RedirectionActionBuilder setRedirectUri(String redirectUri) {
			RedirectionAction.this.redirectUri = redirectUri;
			return this;
		}
		public RedirectionActionBuilder(String consentJwt, String requestMethod, String redirectUri) {		
			this.consentJwt = consentJwt;
			this.requestMethod = requestMethod;
			this.redirectUri = redirectUri;
		}
		public RedirectionAction build() {
			return  RedirectionAction.this;
		}
	}	

}

