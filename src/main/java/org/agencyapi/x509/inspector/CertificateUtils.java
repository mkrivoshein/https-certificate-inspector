package org.agencyapi.x509.inspector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import javax.security.auth.x500.X500Principal;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class CertificateUtils {
    private static final Logger logger = LoggerFactory.getLogger(CertificateUtils.class);

    /**
     * Extracts the OCSP responder URL from the certificate's Authority Information Access (AIA) extension.
     * Returns null if the extension is absent or does not contain an OCSP entry.
     */
    public static String extractOcspUrl(X509Certificate cert) {
        byte[] aiaValue = cert.getExtensionValue("1.3.6.1.5.5.7.1.1");
        if (aiaValue == null) {
            return null;
        }
        // DER encoding of OID 1.3.6.1.5.5.7.48.1 (id-ad-ocsp)
        byte[] ocspOid = {0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01};
        for (int i = 0; i <= aiaValue.length - ocspOid.length; i++) {
            if (matchBytes(aiaValue, i, ocspOid)) {
                int pos = i + ocspOid.length;
                // Tag 0x86 = context-specific [6] = uniformResourceIdentifier
                if (pos < aiaValue.length && (aiaValue[pos] & 0xFF) == 0x86) {
                    pos++;
                    if (pos < aiaValue.length) {
                        // Handle both short-form and long-form DER length encoding
                        int len;
                        int firstByte = aiaValue[pos] & 0xFF;
                        pos++;
                        if ((firstByte & 0x80) == 0) {
                            len = firstByte;
                        } else {
                            int numBytes = firstByte & 0x7F;
                            if (numBytes > 4 || pos + numBytes > aiaValue.length) {
                                continue;
                            }
                            len = 0;
                            for (int b = 0; b < numBytes; b++) {
                                len = (len << 8) | (aiaValue[pos++] & 0xFF);
                            }
                        }
                        if (pos + len <= aiaValue.length) {
                            return new String(aiaValue, pos, len, StandardCharsets.US_ASCII);
                        }
                    }
                }
            }
        }
        return null;
    }

    private static boolean matchBytes(byte[] data, int offset, byte[] pattern) {
        if (offset + pattern.length > data.length) {
            return false;
        }
        for (int i = 0; i < pattern.length; i++) {
            if (data[offset + i] != pattern[i]) return false;
        }
        return true;
    }

    /**
     * Verifies if the certificate is valid for the given domain
     */
    public static boolean verifyCertificateForDomain(X509Certificate cert, String domainName) {
        try {
            // Check Subject Alternative Names (SAN)
            var sanCollection = cert.getSubjectAlternativeNames();
            if (sanCollection != null) {
                for (var san : sanCollection) {
                    var type = (Integer) san.get(0);
                    // Type 2 is DNS name; other types (e.g. otherName) can carry binary values
                    if (type == 2 && san.get(1) instanceof String value && matchesDomain(value, domainName)) {
                        return true;
                    }
                }
            }

            // Fallback to the subject's Common Name(s), matched exactly like a SAN DNS name
            for (var commonName : commonNames(cert.getSubjectX500Principal())) {
                if (matchesDomain(commonName, domainName)) {
                    return true;
                }
            }

        } catch (Exception e) {
            return false;
        }

        return false;
    }

    /**
     * Returns every CN value in the name, including CNs inside multi-valued RDNs, decoded from RFC 2253 escaping
     */
    private static List<String> commonNames(X500Principal principal) {
        var commonNames = new ArrayList<String>();
        try {
            for (var rdn : new LdapName(principal.getName(X500Principal.RFC2253)).getRdns()) {
                var attributes = rdn.toAttributes().getAll();
                while (attributes.hasMore()) {
                    var attribute = attributes.next();
                    if (!"CN".equals(attribute.getID().toUpperCase(Locale.ROOT))) {
                        continue;
                    }
                    var values = attribute.getAll();
                    while (values.hasMore()) {
                        if (values.next() instanceof String value) {
                            commonNames.add(value);
                        }
                    }
                }
            }
        } catch (NamingException e) {
            logger.warn("Could not parse subject {}: {}", principal, e.getMessage());
        }
        return commonNames;
    }

    /**
     * Prints certificate details
     */
    public static void printCertificateDetails(X509Certificate cert) {
        logger.info("Certificate Details:");
        logger.info("Subject: " + cert.getSubjectX500Principal().getName());
        logger.info("Issuer: " + cert.getIssuerX500Principal().getName());
        logger.info("Serial Number: " + cert.getSerialNumber());
        logger.info("Valid From: " + cert.getNotBefore());
        logger.info("Valid Until: " + cert.getNotAfter());
        logger.info("Signature Algorithm: " + cert.getSigAlgName());
        logger.info("Version: " + cert.getVersion());

        // Print Subject Alternative Names
        try {
            var sanCollection = cert.getSubjectAlternativeNames();
            if (sanCollection != null) {
                logger.info("Subject Alternative Names:");
                for (var san : sanCollection) {
                    var type = (Integer) san.get(0);
                    var value = san.get(1);
                    logger.info("  Type " + type + ": " + value);
                }
            }
        } catch (Exception _) {
            logger.warn("Could not read Subject Alternative Names");
        }
    }

    /**
     * Checks if a certificate domain pattern matches the given domain
     * Supports wildcard certificates (e.g., *.example.com)
     */
    private static boolean matchesDomain(String certDomain, String requestedDomain) {
        if (certDomain.equalsIgnoreCase(requestedDomain)) {
            return true;
        }

        // Handle wildcard certificates
        if (certDomain.startsWith("*.")) {
            var wildcardBase = certDomain.substring(2);
            var requestedParts = requestedDomain.split("\\.");

            if (requestedParts.length >= 2) {
                var requestedBase = String.join(".",
                        Arrays.copyOfRange(requestedParts, 1, requestedParts.length));
                return wildcardBase.equalsIgnoreCase(requestedBase);
            }
        }

        return false;
    }
}
