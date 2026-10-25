package org.agencyapi.x509.inspector;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import javax.security.auth.x500.X500Principal;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;

/**
 * Response of {@code GET /v1/domain/{hostname}/ssl}, shaped like SecurityTrails' "Get Domain SSL" reply.
 */
public record DomainSslReply(
        String endpoint,
        Meta meta,
        @JsonProperty("record_count") int recordCount,
        List<SslRecord> records) {

    static DomainSslReply create(String endpoint, Query query, int page, List<X509Certificate> certificates) {
        var records = certificates.stream().map(SslRecord::from).toList();
        // certificates come from a live handshake, so there is never more than one page
        return new DomainSslReply(endpoint, new Meta(1, page, query, 1), records.size(), records);
    }

    record Meta(
            @JsonProperty("max_page") int maxPage,
            int page,
            Query query,
            @JsonProperty("total_pages") int totalPages) {
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    record Query(
            String apikey,
            String domain,
            @JsonProperty("include_subdomains") String includeSubdomains,
            String page,
            String status) {
    }

    record SslRecord(
            @JsonProperty("dns_names") List<String> dnsNames,
            Fingerprints fingerprints,
            DistinguishedName issuer,
            @JsonProperty("not_after") long notAfter,
            @JsonProperty("not_before") long notBefore,
            @JsonProperty("serial_number") String serialNumber,
            DistinguishedName subject) {
        private static final int SAN_DNS_NAME = 2;

        static SslRecord from(X509Certificate cert) {
            return new SslRecord(
                    dnsNames(cert),
                    Fingerprints.from(cert),
                    DistinguishedName.from(cert.getIssuerX500Principal()),
                    cert.getNotAfter().toInstant().getEpochSecond(),
                    cert.getNotBefore().toInstant().getEpochSecond(),
                    cert.getSerialNumber().toString(),
                    DistinguishedName.from(cert.getSubjectX500Principal())
            );
        }

        static List<String> dnsNames(X509Certificate cert) {
            try {
                var sanCollection = cert.getSubjectAlternativeNames();
                if (sanCollection == null) {
                    return List.of();
                }
                return sanCollection.stream()
                        .filter(san -> Integer.valueOf(SAN_DNS_NAME).equals(san.get(0)))
                        .map(san -> (String) san.get(1))
                        .sorted()
                        .toList();
            } catch (CertificateParsingException _) {
                return List.of();
            }
        }
    }

    record Fingerprints(String sha1, String sha256) {
        static Fingerprints from(X509Certificate cert) {
            try {
                var encoded = cert.getEncoded();
                return new Fingerprints(digest("SHA-1", encoded), digest("SHA-256", encoded));
            } catch (CertificateEncodingException e) {
                throw new IllegalStateException("Unable to encode certificate", e);
            }
        }

        private static String digest(String algorithm, byte[] data) {
            try {
                return HexFormat.of().withUpperCase().formatHex(MessageDigest.getInstance(algorithm).digest(data));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(algorithm + " is not available", e);
            }
        }
    }

    /**
     * Attributes of an X.500 name; absent attributes are left out so an empty name serialises as {@code {}}.
     */
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    record DistinguishedName(
            @JsonProperty("common_name") String commonName,
            List<String> country,
            List<String> organization) {

        static DistinguishedName from(X500Principal principal) {
            String commonName = null;
            var country = new ArrayList<String>();
            var organization = new ArrayList<String>();
            try {
                var name = new LdapName(principal.getName(X500Principal.RFC2253));
                // LdapName lists RDNs from right to left, walk them in the order they are written
                for (var rdn : name.getRdns().reversed()) {
                    // a multi-valued RDN (e.g. CN=a+O=b) holds several attributes
                    var attributes = rdn.toAttributes().getAll();
                    while (attributes.hasMore()) {
                        var attribute = attributes.next();
                        var values = attribute.getAll();
                        while (values.hasMore()) {
                            if (!(values.next() instanceof String value)) {
                                continue;
                            }
                            switch (attribute.getID().toUpperCase(Locale.ROOT)) {
                                case "CN" -> commonName = commonName == null ? value : commonName;
                                case "C" -> country.add(value);
                                case "O" -> organization.add(value);
                                default -> { }
                            }
                        }
                    }
                }
            } catch (NamingException e) {
                throw new IllegalStateException("Unable to parse distinguished name " + principal, e);
            }
            return new DistinguishedName(commonName, List.copyOf(country), List.copyOf(organization));
        }
    }

    enum Status {
        VALID, EXPIRED, ALL;

        static Status parse(String value) {
            for (var status : values()) {
                if (status.value().equalsIgnoreCase(value)) {
                    return status;
                }
            }
            throw new IllegalArgumentException("Invalid status \"" + value + "\", valid values are \"valid\", \"all\" and \"expired\"");
        }

        boolean matches(X509Certificate cert, Instant now) {
            var notBefore = cert.getNotBefore().toInstant();
            var notAfter = cert.getNotAfter().toInstant();
            return switch (this) {
                case VALID -> !now.isBefore(notBefore) && !now.isAfter(notAfter);
                case EXPIRED -> now.isAfter(notAfter);
                case ALL -> true;
            };
        }

        String value() {
            return name().toLowerCase(Locale.ROOT);
        }
    }
}
