package it.cosenonjaviste.keytool.services;

import it.cosenonjaviste.keytool.models.CSR;
import it.cosenonjaviste.keytool.models.P7B;
import it.cosenonjaviste.keytool.models.Resource;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.io.FileOutputStream;
import java.security.KeyStoreException;
import java.security.cert.*;
import java.time.temporal.ChronoUnit;

import static org.junit.Assert.*;

/**
 * Created by pizzo on 07/05/17.
 */
public class KeyToolsTest {

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void shouldGenerateKeyStoreWithKeyPair() throws Exception {
        try (FileOutputStream out = new FileOutputStream("test.ks")) {
            KeyTools.newKeyStore("1234")
                    .newKeyPair()
                        .keyLength(2048)
                        .generateWithCertificate()
                        .withValidity(1, ChronoUnit.YEARS)
                        .withDistinguishName()
                            .commonName("Andrea Como")
                            .state("Toscana")
                            .locality("Prato")
                            .country("IT")
                            .email("test@example.com")
                            .build()
                        .createInKeyStore("test", "456")
                        .writeTo(out);
        } finally {
            File keyStoreFile = new File("test.ks");
            assertTrue(keyStoreFile.exists());
            assertTrue(keyStoreFile.delete());
        }
    }

    @Test
    public void shouldLoadKeyStoreFromClassPath() throws Exception {
        Resource resource = Resource.from("classpath:keystore.ks");
        KeyStoreAdapter keyStoreAdapter = KeyTools.keyStoreFrom(resource, "1234");

        assertNotNull(keyStoreAdapter.toKeyStore());
        Certificate certificate = keyStoreAdapter.toKeyStore().getCertificate("test");
        assertNotNull(certificate);
        assertTrue(certificate instanceof X509Certificate);

        X509Certificate x509Certificate = (X509Certificate) certificate;
        assertEquals("CN=Andrea Como, ST=Toscana, L=Prato, C=IT, EMAILADDRESS=test@example.com", x509Certificate.getSubjectDN().getName());
    }

    @Test
    public void shouldGenerateCertificateSignRequest() throws Exception {
        Resource resource = Resource.from("classpath:keystore.ks");
        KeyStoreAdapter keyStoreAdapter = KeyTools.keyStoreFrom(resource, "1234");

        CSR csr = keyStoreAdapter.generateCSR("test", "456");

        assertNotNull(csr);
        assertNotNull(csr.toPkcs10());

        assertEquals("CN=Andrea Como, ST=Toscana, L=Prato, C=IT, EMAILADDRESS=test@example.com", csr.toPkcs10().getSubjectName().toString());
    }

    @Test
    public void shouldSignCertificateSignRequest() throws Exception {
        Resource resource = Resource.from("classpath:keystore.ks");
        KeyStoreAdapter requesterKeyStore = KeyTools.keyStoreFrom(resource, "1234");

        X509Certificate[] certificates = requesterKeyStore.getCertificates("test");
        assertEquals(1, certificates.length);

        CSR csr = requesterKeyStore.generateCSR("test", "456");

        Resource ca = Resource.from("classpath:ca.ks");
        KeyStoreAdapter caKeyStore = KeyTools.keyStoreFrom(ca, "ca");

        P7B signResponse = caKeyStore.signCSR(csr, "ca", "ca")
                .withValidity(1, ChronoUnit.YEARS)
                .sign();

        requesterKeyStore.importCAReply(signResponse, "test", "456");
        certificates = requesterKeyStore.getCertificates("test");

        assertEquals(2, certificates.length);
    }

    @Test
    public void shouldVerifySignedCertificate() throws Exception {
        Resource ca = Resource.from("classpath:ca.ks");
        KeyStoreAdapter caKeyStore = KeyTools.keyStoreFrom(ca, "ca");

        Resource signedResource = Resource.from("classpath:keystore-signed-by-ca.ks");
        KeyStoreAdapter signedKeyStore = KeyTools.keyStoreFrom(signedResource, "1234");
        signedKeyStore.verifyWithTrustStore("test", caKeyStore.toKeyStore());
    }

    @Test
    public void shouldNotVerifyExpiredSignedCertificate() throws Exception {
        Resource ca = Resource.from("classpath:ca.ks");
        KeyStoreAdapter caKeyStore = KeyTools.keyStoreFrom(ca, "ca");

        Resource signedResource = Resource.from("classpath:keystore-signed-by-ca-expired.ks");
        KeyStoreAdapter signedKeyStore = KeyTools.keyStoreFrom(signedResource, "1234");

        expectedException.expect(CertificateException.class);
        expectedException.expectMessage("PKIX path validation failed: java.security.cert.CertPathValidatorException: timestamp check failed");

        signedKeyStore.verifyWithTrustStore("test", caKeyStore.toKeyStore());
    }

    @Test
    public void shouldNotVerifySignedCertificate() throws Exception {
        Resource ca = Resource.from("classpath:keystore-signed-by-ca.ks");
        KeyStoreAdapter caKeyStore = KeyTools.keyStoreFrom(ca, "1234");

        Resource signedResource = Resource.from("classpath:ca.ks");
        KeyStoreAdapter signedKeyStore = KeyTools.keyStoreFrom(signedResource, "ca");

        expectedException.expect(CertificateException.class);
        expectedException.expectMessage("unable to find valid certification path to requested target");
        signedKeyStore.verifyWithTrustStore("ca", caKeyStore.toKeyStore());
    }
}