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
package nl.booleans.oidc.yes.rcs.api;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.util.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import static nl.booleans.oidc.yes.rcs.utils.RCSUtils.generateKeyId;
import static nl.booleans.oidc.yes.rcs.utils.RCSUtils.getJWSAlgorithm;
import static nl.booleans.oidc.yes.rcs.utils.RCSUtils.getX509SHA1ThumbPrint;
import static nl.booleans.oidc.yes.rcs.utils.RCSUtils.getX509SHA256ThumbPrint;
import static nl.booleans.oidc.yes.rcs.utils.RCSUtils.loadKeystore;

public class JwtHandler {
    private final String keystorePath;
    private final String keyAlias;
    private final String storePass;
    private final String keyPass;
    private final String jwksUri;
    private final KeyStore keyStore;


    /**
     *
     * @param keystorePath
     * @param keyAlias
     * @param storePass
     * @param keyPass
     * @param jwksUri
     */
    public JwtHandler(String keystorePath, String keyAlias, String storePass, String keyPass, String jwksUri) {
        this.keystorePath = keystorePath;
        this.keyAlias = keyAlias;
        this.storePass = storePass;
        this.keyPass = keyPass;
        this.jwksUri = jwksUri;
        this.keyStore = loadKeystore(this.keystorePath, this.storePass);

        // load the BouncyCastleProvider
        Security.addProvider(new BouncyCastleProvider());
    }


    /**
     * Return a JWKSet containing the key information from the associated keystore.
     *
     * @return
     */
    public JWKSet getLocalJWKSet() throws UnsupportedOperationException {
        JWKSet jwkSet = null;

        X509Certificate cer = this.getCertificateForAlias();

        if (cer != null) {
            PrivateKey privateKey = this.getPrivateKeyForAlias();
            List<JWK> jwkList = new ArrayList<>();

            if (cer.getPublicKey() instanceof ECPublicKey) {
                throw new UnsupportedOperationException("EC algorithms are currently not supported within AM for consent requests, not supporting it here. Please run this with an RSA certificate alias.");
            } else if (cer.getPublicKey() instanceof RSAPublicKey) {
                try {
                    List<Base64> chainList = new ArrayList<>();
                    chainList.add(Base64.encode(cer.getEncoded()));

                    JWK jwkEncryption = new RSAKey.Builder((RSAPublicKey) cer.getPublicKey())
                            .privateKey(privateKey)
                            .keyID(generateKeyId(KeyUse.ENCRYPTION, keyAlias, cer.getPublicKey()))
                            .algorithm(new Algorithm("RSA-OAEP-256"))
                            .x509CertChain(chainList)
                            .x509CertThumbprint(getX509SHA1ThumbPrint(cer))
                            .x509CertSHA256Thumbprint(getX509SHA256ThumbPrint(cer))
                            .keyUse(KeyUse.ENCRYPTION)
                            .build();
                    jwkList.add(jwkEncryption);


                    JWK jwkSigning = new RSAKey.Builder((RSAPublicKey) cer.getPublicKey())
                            .keyID(generateKeyId(KeyUse.SIGNATURE, keyAlias, cer.getPublicKey()))
                            .privateKey(privateKey)
                            .algorithm(getJWSAlgorithm(cer.getSigAlgName()))
                            .x509CertChain(chainList)
                            .x509CertThumbprint(getX509SHA1ThumbPrint(cer))
                            .x509CertSHA256Thumbprint(getX509SHA256ThumbPrint(cer))
                            .keyUse(KeyUse.SIGNATURE)
                            .build();

                    jwkList.add(jwkSigning);

                    jwkSet = new JWKSet(jwkList);
                } catch (CertificateEncodingException e) {
                    System.out.println("Caught exception while generating JWKSet: "+e.getMessage());
                    e.printStackTrace();
                }
            }
        } else {
            // throw an error here.
            System.err.println("No certificate for use in the JWKSet, unable to return JWKSet");
        }
        return jwkSet;
    }


    /**
     * Return a JWKSet containing the key information from the remote endpoint
     *
     * @return
     */
    public JWKSet getRemoteJWKSet() {
        try {
            return JWKSet.load(new URL(jwksUri));
        } catch (IOException | ParseException mue) {
            System.err.println("Unable to get JWKSet from URL "+jwksUri+", caught exception: "+mue.getMessage());
        }
        return new JWKSet();
    }


    /**
     *
     * @return
     */
    public JWKSource getLocalJWKSource() {
        return new ImmutableJWKSet(this.getLocalJWKSet());
    }


    /**
     *
     * @return
     */
    public JWKSource getRemoteJWKSource() {
        return new ImmutableJWKSet(this.getRemoteJWKSet());
    }


    /**
     *
     * @return
     */
    public JWK getLocalMatchingJWK() {
        X509Certificate certificate = this.getCertificateForAlias();
        if (certificate != null) {
            PublicKey publickey = certificate.getPublicKey();
            return ((ImmutableJWKSet) this.getLocalJWKSource()).getJWKSet().getKeyByKeyId(generateKeyId(KeyUse.SIGNATURE, keyAlias, publickey));
        }
        return null;
    }


    /**
     *
     * @return
     */
    private X509Certificate getCertificateForAlias() {
        KeyStore ks = loadKeystore(keystorePath, storePass);
        try {
            return (X509Certificate) ks.getCertificate(keyAlias);
        } catch (KeyStoreException e) {
            System.err.println("Unable to get the certificate for alias "+keyAlias+" from keystore "+keystorePath+": "+e.getMessage());
            e.printStackTrace();
        }
        return null;
    }


    /**
     *
     * @return
     */
    private PrivateKey getPrivateKeyForAlias() {
        try {
            return (PrivateKey)this.keyStore.getKey(keyAlias, this.keyPass.toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            System.err.println("Unable to get the private key for alias "+keyAlias+" from keystore "+keystorePath+": "+e.getMessage());
            e.printStackTrace();
        }
        return null;
    }
}
