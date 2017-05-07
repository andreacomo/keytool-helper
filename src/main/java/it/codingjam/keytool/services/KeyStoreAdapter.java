package it.codingjam.keytool.services;

import it.codingjam.keytool.models.CSR;
import it.codingjam.keytool.models.P7B;
import it.codingjam.keytool.utils.Preconditions;
import sun.security.pkcs10.PKCS10;
import sun.security.x509.X500Name;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Stream;

/**
 * Created by pizzo on 06/05/17.
 */
public class KeyStoreAdapter {

    private static final Logger LOGGER = Logger.getLogger(KeyStoreAdapter.class.getName());

    private final KeyStore keyStore;

    private final String password;

    KeyStoreAdapter(KeyStore keyStore, String password) {
        this.keyStore = keyStore;
        this.password = password;
    }

    public KeyPairBuilder newKeyPair(String algorithm) throws NoSuchAlgorithmException {
        return new KeyPairBuilder(algorithm, this);
    }

    public KeyPairBuilder newKeyPair() throws NoSuchAlgorithmException {
        return new KeyPairBuilder(this);
    }

    public KeyStoreAdapter addToKeyStore(String alias, Key key, String keyPassword, Certificate... certificates) throws KeyStoreException {
        this.keyStore.setKeyEntry(alias, key, keyPassword.toCharArray(), certificates);
        return this;
    }

    public CSR generateCSR(String alias, String password) throws KeyStoreException {
        try {
            KeyPair keyPair = getKayPairFor(alias, password);
            PKCS10 pkcs10 = new PKCS10(keyPair.getPublic()); // CSR container format
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(keyPair.getPrivate());
            pkcs10.encodeAndSign(getX500Name(this.keyStore.getCertificate(alias)), signature);
            return new CSR(pkcs10);
        } catch (NoSuchAlgorithmException |
                InvalidKeyException |
                CertificateException |
                IOException |
                SignatureException e) {
            LOGGER.log(Level.SEVERE, e.getMessage(), e);
            throw new KeyStoreException(e);
        }
    }

    public CSRSigner signCSR(CSR csr, String alias, String password) throws KeyStoreException {
        KeyPair keyPair = getKayPairFor(alias, password);
        return new CSRSigner(this, csr, keyPair, (X509Certificate) this.keyStore.getCertificate(alias));
    }

    public void importCAReply(P7B p7B, String alias, String password) throws KeyStoreException {
        KeyPair keyPair = getKayPairFor(alias, password);
        addToKeyStore(alias, keyPair.getPrivate(), password, p7B.getCertificates());
    }

    public void verifyWithTrustStore(String alias, KeyStore keyStore) throws KeyStoreException, CertificateException {
        try {
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);
            for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                X509TrustManager x509TrustManager = (X509TrustManager) trustManager;
                x509TrustManager.checkClientTrusted(this.getCertificates(alias), "RSA");
            }
        } catch (NoSuchAlgorithmException e) {
            LOGGER.log(Level.SEVERE, e.getMessage(), e);
            throw new KeyStoreException(e);
        }
    }

    private X500Name getX500Name(Certificate certificate) throws IOException {
        Preconditions.checkArgument(certificate instanceof X509Certificate, "Certificate is not X.509");
        X509Certificate x509 = (X509Certificate) certificate;
        return new X500Name(x509.getSubjectX500Principal().getEncoded());
    }

    public KeyPair getKayPairFor(String alias, String password) throws KeyStoreException {
        try {
            Certificate certificate = this.keyStore.getCertificate(alias);
            Key key = this.keyStore.getKey(alias, password.toCharArray());
            return new KeyPair(certificate.getPublicKey(), (PrivateKey) key);
        } catch (NoSuchAlgorithmException | UnrecoverableKeyException e) {
            LOGGER.log(Level.SEVERE, e.getMessage(), e);
            throw new KeyStoreException(e);
        }
    }

    public X509Certificate getCertificate(String alias) throws KeyStoreException {
        return (X509Certificate) this.keyStore.getCertificate(alias);
    }

    public X509Certificate[] getCertificates(String alias) throws KeyStoreException {
        return Stream.of(this.keyStore.getCertificateChain(alias))
                .map(cert -> (X509Certificate) cert)
                .toArray(X509Certificate[]::new);
    }

    public KeyStore toKeyStore() {
        return keyStore;
    }

    public KeyStore writeTo(OutputStream outputStream) throws KeyStoreException {
        try {
            keyStore.store(outputStream, password.toCharArray());
            return keyStore;
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            LOGGER.log(Level.SEVERE, e.getMessage(), e);
            throw new KeyStoreException(e);
        }
    }
}
