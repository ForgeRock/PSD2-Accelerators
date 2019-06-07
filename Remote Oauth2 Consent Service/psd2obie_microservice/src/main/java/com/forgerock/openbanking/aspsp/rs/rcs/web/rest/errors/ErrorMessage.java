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
package com.forgerock.openbanking.aspsp.rs.rcs.web.rest.errors;

public enum ErrorMessage {
  ERR001("The existing AISP consent is expired and a new one is required."),
  ERR002("The AISP consent you are trying to authorize is not in the %s status."),
  ERR003("The PISP consent you are trying to authorize is not in the %s status."),
  ERR004("There is already an active AISP consent for this transaction."),
  ERR005("The intent was initiated by another TPP.");
	private String message;

	ErrorMessage(String message) {
	       this.message = message;
	   }

	   public String getMessage() {
	       return message;
	   }
}
