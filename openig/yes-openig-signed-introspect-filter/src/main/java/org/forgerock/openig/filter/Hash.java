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
package org.forgerock.openig.filter;

import org.forgerock.util.encode.Base64;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class copies the behavior that AM uses to compose the kid
 *
 */
public class Hash {

    private static String hash(String algorithm, String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            digest.update(input.getBytes(StandardCharsets.UTF_8));
            return Base64.encode(digest.digest());
        } catch (NoSuchAlgorithmException nsae) {
            return null;
        }
    }

    /**
     * Generates a SHA-1 digest of the string and returns Base64 encoded digest.
     *
     * @param input The input string that needs to be hashed using SHA-1 algorithm.
     * @return The SHA-1 digest of the provided input Base64 encoded.
     *
     * @deprecated Use a more appropriate hashing mechanism from
     */
    @Deprecated
    public static String hash(String input) {
        return hash("SHA-1", input);
    }
}
