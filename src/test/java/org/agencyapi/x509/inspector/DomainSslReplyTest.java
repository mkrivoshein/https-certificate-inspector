package org.agencyapi.x509.inspector;

import org.agencyapi.x509.inspector.DomainSslReply.DistinguishedName;
import org.agencyapi.x509.inspector.DomainSslReply.SslRecord;
import org.agencyapi.x509.inspector.DomainSslReply.Status;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.time.Instant;
import java.util.List;

import static org.agencyapi.x509.inspector.TestCertificates.*;
import static org.junit.jupiter.api.Assertions.*;

class DomainSslReplyTest {
    @Test
    void mapsCertificateToSecurityTrailsRecord() {
        var record = SslRecord.from(leaf());

        assertEquals(List.of("*.example.com", "example.com", "www.example.com"), record.dnsNames());
        assertEquals(LEAF_SHA1, record.fingerprints().sha1());
        assertEquals(LEAF_SHA256, record.fingerprints().sha256());
        assertEquals(new DistinguishedName("Example Test CA", List.of("US"), List.of("Example Trust")), record.issuer());
        assertEquals(new DistinguishedName("example.com", List.of("US"), List.of("Example Org")), record.subject());
        assertEquals(LEAF_NOT_BEFORE, record.notBefore());
        assertEquals(LEAF_NOT_AFTER, record.notAfter());
        assertEquals(LEAF_SERIAL, record.serialNumber());
    }

    @Test
    void certificateWithoutSubjectAlternativeNamesHasNoDnsNames() {
        assertEquals(List.of(), SslRecord.dnsNames(ca()));
    }

    @Test
    void emptyDistinguishedNameHasNoAttributes() {
        assertEquals(new DistinguishedName(null, List.of(), List.of()), DistinguishedName.from(new X500Principal("")));
    }

    @Test
    void distinguishedNameKeepsRepeatedAttributesInOrder() {
        var name = DistinguishedName.from(new X500Principal("CN=first,CN=second,O=Org A,O=Org B,C=GB"));

        assertEquals(new DistinguishedName("first", List.of("GB"), List.of("Org A", "Org B")), name);
    }

    @Test
    void statusFiltersByValidityAtTheGivenTime() {
        var cert = leaf();
        var beforeValidity = Instant.ofEpochSecond(LEAF_NOT_BEFORE - 1);
        var duringValidity = Instant.ofEpochSecond(LEAF_NOT_BEFORE + 1);
        var afterValidity = Instant.ofEpochSecond(LEAF_NOT_AFTER + 1);

        assertFalse(Status.VALID.matches(cert, beforeValidity));
        assertTrue(Status.VALID.matches(cert, duringValidity));
        assertFalse(Status.VALID.matches(cert, afterValidity));

        assertFalse(Status.EXPIRED.matches(cert, beforeValidity));
        assertFalse(Status.EXPIRED.matches(cert, duringValidity));
        assertTrue(Status.EXPIRED.matches(cert, afterValidity));

        assertTrue(Status.ALL.matches(cert, beforeValidity));
        assertTrue(Status.ALL.matches(cert, duringValidity));
        assertTrue(Status.ALL.matches(cert, afterValidity));
    }

    @Test
    void statusParsingIsCaseInsensitiveAndRejectsUnknownValues() {
        assertEquals(Status.VALID, Status.parse("valid"));
        assertEquals(Status.EXPIRED, Status.parse("Expired"));
        assertEquals(Status.ALL, Status.parse("ALL"));
        assertThrows(IllegalArgumentException.class, () -> Status.parse("revoked"));
    }
}
