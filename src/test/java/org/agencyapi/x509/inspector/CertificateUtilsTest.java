package org.agencyapi.x509.inspector;

import org.junit.jupiter.api.Test;

import static org.agencyapi.x509.inspector.TestCertificates.*;
import static org.junit.jupiter.api.Assertions.*;

class CertificateUtilsTest {
    @Test
    void matchesDnsNameAndWildcard() {
        assertTrue(CertificateUtils.verifyCertificateForDomain(leaf(), "example.com"));
        assertTrue(CertificateUtils.verifyCertificateForDomain(leaf(), "api.example.com"));
        assertFalse(CertificateUtils.verifyCertificateForDomain(leaf(), "example.org"));
    }

    @Test
    void matchesDnsNameListedAfterBinarySubjectAlternativeName() {
        assertTrue(CertificateUtils.verifyCertificateForDomain(otherNameFirst(), "othername.example.com"));
    }
}
