/*
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
 */
package org.forgerock.openam.oauth2.yes.claims.verified_person_data.verification;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@JsonSerialize(include=JsonSerialize.Inclusion.NON_NULL)
public enum identityVerificationMethod {
    EID("eID"),
    QES("qes"),
    IDENTITY_DOCUMENT("identity_document");

    private static Map<String, identityVerificationMethod> FORMAT_MAP = Stream
            .of(identityVerificationMethod.values())
            .collect(Collectors.toMap(s -> s.formatted, Function.identity()));

    private final String formatted;

    identityVerificationMethod(String formatted) {
        this.formatted = formatted;
    }

    @JsonCreator // This is the factory method and must be static
    public static identityVerificationMethod fromString(String string) {
        return Optional
                .ofNullable(FORMAT_MAP.get(string))
                .orElseThrow(() -> new IllegalArgumentException(string));
    }

    @Override
    public String toString() {
        return "identityVerificationMethod{" +
                "formatted='" + formatted + '\'' +
                '}';
    }
}
