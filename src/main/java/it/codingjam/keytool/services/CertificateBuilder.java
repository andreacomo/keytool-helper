package it.codingjam.keytool.services;

import it.codingjam.keytool.utils.Preconditions;
import sun.security.x509.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

/**
 * Helper builder for creating a <strong>new X509 certificate</strong>
 *
 * <br>
 * Created by acomo on 07/05/17.
 */
public class CertificateBuilder {

    private final KeyStoreAdapter keyStoreAdapter;

    private final KeyPair keyPair;

    private final X509CertInfo info;

    CertificateBuilder(KeyStoreAdapter keyStoreAdapter, KeyPair keyPair) {
        this.keyStoreAdapter = keyStoreAdapter;
        this.keyPair = keyPair;
        this.info = new X509CertInfo();
    }

    public CertificateBuilder withValidity(int period, ChronoUnit timeUnit) throws CertificateException, IOException {
        Date now = new Date();
        Instant expire = now.toInstant().plus(timeUnit.getDuration().getSeconds() * period, ChronoUnit.SECONDS);
        info.set(X509CertInfo.VALIDITY, new CertificateValidity(now, new Date(expire.toEpochMilli())));
        return this;
    }

    public CertificateBuilder withSerial(BigInteger serial) throws CertificateException, IOException {
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serial));
        return this;
    }

    public DistinguishNameBuilder withDistinguishName() {
        return new DistinguishNameBuilder(this);
    }

    public KeyStoreAdapter createInKeyStore(String alias, String password) throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException, KeyStoreException {
        Preconditions.checkState(info.get(X509CertInfo.VALIDITY) != null, "Missing Validity");
        Preconditions.checkState(info.get(X509CertInfo.SUBJECT) != null, "Missing Distinguish Name");
        Preconditions.checkState(info.get(X509CertInfo.ISSUER) != null, "Missing Issuer");

        if (info.get(X509CertInfo.SERIAL_NUMBER) == null) {
            info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(new BigInteger(64, new SecureRandom())));
        }

        info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(AlgorithmId.get("SHA256withRSA")));

        X509CertImpl x509Cert = new X509CertImpl(info);
        x509Cert.sign(keyPair.getPrivate(), "SHA256withRSA");

        this.keyStoreAdapter.addToKeyStore(alias, keyPair.getPrivate(), password, x509Cert);

        return this.keyStoreAdapter;
    }

    public static class DistinguishNameBuilder {

        private static final String SEPARATOR = ",";

        private StringBuilder stringBuilder = new StringBuilder(200);

        private CertificateBuilder certificateBuilder;

        DistinguishNameBuilder(CertificateBuilder certificateBuilder) {
            this.certificateBuilder = certificateBuilder;
        }

        public DistinguishNameBuilder commonName(String commonName) {
            stringBuilder.append("CN=").append(commonName).append(SEPARATOR);
            return this;
        }

        public DistinguishNameBuilder organizationUnit(String organizationUnit) {
            stringBuilder.append("OU=").append(organizationUnit).append(SEPARATOR);
            return this;
        }

        public DistinguishNameBuilder organizationName(String organizationName) {
            stringBuilder.append("O=").append(organizationName).append(SEPARATOR);
            return this;
        }

        public DistinguishNameBuilder locality(String locality) {
            stringBuilder.append("L=").append(locality).append(SEPARATOR);
            return this;
        }

        public DistinguishNameBuilder state(String state) {
            stringBuilder.append("ST=").append(state).append(SEPARATOR);
            return this;
        }

        public DistinguishNameBuilder country(String country) {
            stringBuilder.append("C=").append(country).append(SEPARATOR);
            return this;
        }

        public DistinguishNameBuilder email(String email) {
            stringBuilder.append("EMAILADDRESS=").append(email).append(SEPARATOR);
            return this;
        }

        public CertificateBuilder build() throws IOException, CertificateException {
            String dn = stringBuilder.toString();
            X500Name owner = new X500Name(dn.substring(0, dn.length() - 1));
            certificateBuilder.info.set(X509CertInfo.SUBJECT, owner);
            certificateBuilder.info.set(X509CertInfo.ISSUER, owner);

            return certificateBuilder;
        }

    }
}
