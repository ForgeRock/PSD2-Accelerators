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
package nl.booleans.oidc.yes.rcs.utils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

public class RCSUtils {

    /**
     * Generate the keyID based on its use, the alias and the public key
     *
     * @param keyUse - KeyUse object indicating the intended usage of the key (encryption or signing)
     * @param keyAlias - alias of the key inside the keystore
     * @param publicKey - PublicKey object to generate the keyId from
     * @return - String containing the keyId
     */
    public static String generateKeyId(KeyUse keyUse, String keyAlias, PublicKey publicKey) {
        if (publicKey instanceof ECPublicKey) {
            ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
            BigInteger x = ecPublicKey.getW().getAffineX();
            BigInteger y = ecPublicKey.getW().getAffineY();

            byte[] enc = publicKey.getEncoded();
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(enc));
            AlgorithmIdentifier algid = spki.getAlgorithm();

            ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) algid.getParameters();
            Curve crv = Curve.forOID(oid.getId());

            return hash(keyAlias + ":" + keyUse.getValue() + ':' + crv.getStdName() + ':' + x.toString() + ':' + y.toString());

        } else if (publicKey instanceof RSAPublicKey) {

            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            return hash(keyAlias + ":" + keyUse.getValue() + rsaPublicKey.getModulus().toString() + rsaPublicKey.getPublicExponent().toString());
        } else {
            throw new IllegalArgumentException("Public key type '" + publicKey.getClass().getName() + "' not supported.");
        }
    }


    /**
     * Return a hash for use in the keyId
     *
     * @param input - the input string to hash
     * @return - String containing a hash to use in the keyId
     */
    public static String hash(String input) {
        String algorithm = "SHA-256";
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            digest.update(input.getBytes(StandardCharsets.UTF_8));
            return Base64.encode(digest.digest()).toString();
        } catch (NoSuchAlgorithmException nsae) {
            System.out.println("Unable to create '"+algorithm+"' hash: "+nsae.getMessage());
            return null;
        }
    }


    /**
     * Convert a string containing a jwt to a JWT object
     *
     * @param jwtString - the JWT as string
     * @return - JWT object created from the JWT string
     */
    public static JWT parseJwt(String jwtString) {
        JWT jwt = null;

        try {
            jwt = JWTParser.parse(jwtString);
        } catch (ParseException e) {
            System.out.println("Unable to convert the jwt contents ["+jwtString+"] to a JWT object: "+e.getMessage());
        }
        return jwt;
    }


    /**
     * Return the JWSAlgorithm associated with a specific algorithm string
     *
     * @param algorithm - algorithm
     * @return - JWSAlgorithm object corresponding to the input algorithm
     */
    public static JWSAlgorithm getJWSAlgorithm(String algorithm) {
        if (algorithm.equals("HMACSHA256")) {
            return JWSAlgorithm.HS256;
        } else if (algorithm.equals("HMACSHA384")) {
            return JWSAlgorithm.HS384;
        } else if (algorithm.equals("HMACSHA512")) {
            return JWSAlgorithm.HS512;
        } else if (algorithm.equals("SHA256withRSA")) {
            return JWSAlgorithm.RS256;
        } else if (algorithm.equals("SHA384withRSA")) {
            return JWSAlgorithm.RS384;
        } else if (algorithm.equals("SHA512withRSA")) {
            return JWSAlgorithm.RS512;
        } else if (algorithm.equals("SHA256withRSAandMGF1")) {
            return JWSAlgorithm.PS256;
        } else if (algorithm.equals("SHA384withRSAandMGF1")) {
            return JWSAlgorithm.PS384;
        } else if (algorithm.equals("SHA512withRSAandMGF1")) {
            return JWSAlgorithm.PS512;
        } else if (algorithm.equals("SHA256withECDSA")) {
            return JWSAlgorithm.ES256;
        } else if (algorithm.equals("SHA384withECDSA")) {
            return JWSAlgorithm.ES384;
        } else if (algorithm.equals("SHA512withECDSA")) {
            return JWSAlgorithm.ES512;
        }
        return null;
    }


    /**
     * Return a Base64 thumbprint from a certificate using SHA-1
     *
     * @param certificate - certificate object to generate the thumbprint
     * @return - Base64URL representation of the thumbprint
     */
    public static Base64URL getX509SHA1ThumbPrint(X509Certificate certificate) {
        return getX509ThumbPrint(certificate, "SHA-1");
    }


    /**
     * Return a Base64 thumbprint from a certificate using SHA-256
     *
     * @param certificate - certificate object to generate the thumbprint
     * @return - Base64URL representation of the thumbprint
     */
    public static Base64URL getX509SHA256ThumbPrint(X509Certificate certificate) {
        return getX509ThumbPrint(certificate, "SHA-256");
    }


    /**
     * Return a Base64 thumbprint from a certificate using the input algorithm
     *
     * @param certificate - certificate object to generate the thumbprint
     * @return - Base64URL representation of the thumbprint
     */
    private static Base64URL getX509ThumbPrint(X509Certificate certificate, String algorithm) {
        Base64URL thumbPrint = null;
        if (certificate != null) {
            try {
                final MessageDigest hash = MessageDigest.getInstance(algorithm);
                thumbPrint = Base64URL.encode(hash.digest(certificate.getEncoded()));
            } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
                return null;
            }
        }
        return thumbPrint;
    }


    /**
     * Loads the keystore and automatically determines the type.
     * Only JKS, JCEKS and PKCS12 are supported.
     *
     * @param keystorePath - path towards the keystore
     * @param storePass - password used to open the keystore
     * @return - Keystore object
     */
    public static KeyStore loadKeystore(final String keystorePath, final String storePass) {
        String finalStoreType = null;
        KeyStore keyStore = null;
        final char[] password = storePass.toCharArray();

        List<String> keystoreTypes = Arrays.asList("JKS", "JCEKS", "PKCS12");

        for (String storeType: keystoreTypes) {
            if (finalStoreType == null) {
                try {
                    keyStore = KeyStore.getInstance(storeType);
                    keyStore.load(new FileInputStream(keystorePath), password);
                    finalStoreType = storeType;
                } catch (FileNotFoundException | CertificateException | NoSuchAlgorithmException e) {
                    System.err.println("Caught exception while loading keystore: "+e.getMessage());
                    e.printStackTrace();
                } catch (IOException | KeyStoreException e) {
                    // ignore, onto the next type
                }
            }else{
                break;
            }
        }

        return keyStore;
    }


    /**
     * Check if the input algorithm concerns an HMAC
     *
     * @param algorithm - JWSAlgorithm object to check
     * @return - boolean indicating whether it concerns a HMAC or not
     */
    public static boolean isHMAC(JWSAlgorithm algorithm) {
        return algorithm != null && MACVerifier.SUPPORTED_ALGORITHMS.contains(algorithm);
    }


    /**
     * Return JWEDecrypter object associated with a Key to use for decryption
     *
     * @param key - private key object to use for decryption
     * @return - JWEDecrypter object associated with a private key
     */
    public static JWEDecrypter getDecrypter(final Key key) {
        try {
            if (key instanceof RSAPrivateKey) {
                return new RSADecrypter((RSAPrivateKey) key);
            } else if (key instanceof ECPrivateKey) {
                return new ECDHDecrypter((ECPrivateKey) key);
            }
        } catch (JOSEException je) {
            System.out.println("unable to instantiate a decrypter for key algorithm "+key.getAlgorithm()+": "+je.getMessage());
        }
        return null;
    }
}
