/***************************************************************************
 *  Copyright 2019 ForgeRock AS
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
package org.forgerock.openig.ob.alias;

import java.util.HashMap;
import java.util.Map;

import org.forgerock.openig.alias.ClassAliasResolver;
import org.forgerock.openig.ob.filter.CertificateExtensionValidatorFilter;
import org.forgerock.openig.ob.filter.CheckAuthorizeRequestJwtFilter;
import org.forgerock.openig.ob.filter.FormatJsonFilter;
import org.forgerock.openig.ob.filter.FormatRegistrationJwtFilter;
import org.forgerock.openig.ob.filter.PaymentSubmitParseFilter;
import org.forgerock.openig.ob.filter.RegisterTppForwardFilter;
import org.forgerock.openig.ob.filter.RegistrationJwtVerificationFilter;
import org.forgerock.openig.ob.filter.RetrieveSecretsFilter;
import org.forgerock.openig.ob.filter.StripSsaDynamicRegistrationFilter;
import org.forgerock.openig.ob.filter.UserInfoVerificationFilter;

public class OpenBankingAliasResolver implements ClassAliasResolver {

	private static final Map<String, Class<?>> ALIASES = new HashMap<>();

	static {
		ALIASES.put("PaymentSubmitParseFilter", PaymentSubmitParseFilter.class);
		ALIASES.put("RegisterTppForwardFilter", RegisterTppForwardFilter.class);
		ALIASES.put("RegistrationJwtVerificationFilter", RegistrationJwtVerificationFilter.class);
		ALIASES.put("FormatRegistrationJwtFilter", FormatRegistrationJwtFilter.class);
		ALIASES.put("UserInfoVerificationFilter", UserInfoVerificationFilter.class);
		ALIASES.put("StripSsaDynamicRegistrationFilter", StripSsaDynamicRegistrationFilter.class);
		ALIASES.put("CertificateExtensionValidatorFilter", CertificateExtensionValidatorFilter.class);
		ALIASES.put("RetrieveSecretsFilter", RetrieveSecretsFilter.class);
		ALIASES.put("FormatJsonFilter", FormatJsonFilter.class);
		ALIASES.put("CheckAuthorizeRequestJwtFilter", CheckAuthorizeRequestJwtFilter.class);
	}

	/**
	 * Get the class for a short name alias.
	 *
	 * @param alias Short name alias.
	 * @return The class, or null if the alias is not defined.
	 */
	@Override
	public Class<?> resolve(String alias) {
		return ALIASES.get(alias);
	}
}