package it.codingjam.keytool.services;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Created by pizzo on 07/05/17.
 */
public class KeyPairBuilder {

    private final KeyPairGenerator generator;

    private final KeyStoreAdapter keyStoreAdapter;

    KeyPairBuilder(String algorithm, KeyStoreAdapter keyStoreAdapter) throws NoSuchAlgorithmException {
        this.keyStoreAdapter = keyStoreAdapter;
        this.generator = KeyPairGenerator.getInstance(algorithm);
    }

    /**
     * Generates a new keypair with default algorithm RSA
     *
     * @param keyStoreAdapter
     * @throws NoSuchAlgorithmException
     */
    KeyPairBuilder(KeyStoreAdapter keyStoreAdapter) throws NoSuchAlgorithmException {
        this("RSA", keyStoreAdapter);
    }

    public KeyPairBuilder keyLength(int length) {
        this.generator.initialize(length);
        return this;
    }

    public CertificateBuilder generateWithCertificate() {
        return new CertificateBuilder(this.keyStoreAdapter, this.generator.generateKeyPair());
    }

}
