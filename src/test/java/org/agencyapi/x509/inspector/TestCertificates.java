package org.agencyapi.x509.inspector;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Fixture certificates from {@code src/test/resources/certificates}, generated with OpenSSL:
 * {@code example.com.pem} is issued by {@code test-ca.pem} and is valid from 2026-10-24T11:45:46Z to 2126-09-30T11:45:46Z.
 */
final class TestCertificates {
    static final String LEAF_SHA1 = "D2795970D2DB4B6C83EF7A9D269CE6E410B87342";
    static final String LEAF_SHA256 = "2D4729C130F019811A9A2E8277E71FEF42DEF1E448007878D0E489AC99BA70F4";
    static final long LEAF_NOT_BEFORE = 1792842346L;
    static final long LEAF_NOT_AFTER = 4946442346L;
    static final String LEAF_SERIAL = "279496228386524295576467227942772171335399";

    private TestCertificates() {
    }

    static X509Certificate leaf() {
        return load("certificates/example.com.pem");
    }

    static X509Certificate ca() {
        return load("certificates/test-ca.pem");
    }

    private static X509Certificate load(String resource) {
        try (var in = TestCertificates.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("Missing test resource " + resource);
            }
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
    }
}
