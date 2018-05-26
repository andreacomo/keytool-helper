package it.codingjam.keytool.models;

import sun.security.pkcs10.PKCS10;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;

/**
 * Certificate Signing Request (CSR) holder
 *
 * <br>
 * https://en.wikipedia.org/wiki/Certificate_signing_request
 *
 * <br>
 * Created by acomo on 07/05/17.
 */
public class CSR {

    private PKCS10 pkcs10;

    public CSR(PKCS10 pkcs10) {
        this.pkcs10 = pkcs10;
    }

    public PKCS10 toPkcs10() {
        return pkcs10;
    }

    public void writeTo(OutputStream out) throws IOException, SignatureException {
        pkcs10.print(new PrintStream(out));
    }

    public byte[] writeToBytes() throws IOException, SignatureException {
        ByteArrayOutputStream bs = new ByteArrayOutputStream();
        writeTo(bs);
        return bs.toByteArray();
    }

    public String writeToString() throws IOException, SignatureException {
        return new String(writeToBytes(), StandardCharsets.UTF_8);
    }
}
