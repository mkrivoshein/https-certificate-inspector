package org.agencyapi.x509.inspector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.Arrays;

public class CertificateUtils {
    private static final Logger logger = LoggerFactory.getLogger(CertificateUtils.class);

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
                    var value = (String) san.get(1);
                    // Type 2 is DNS name
                    if (type == 2 && matchesDomain(value, domainName)) {
                        return true;
                    }
                }
            }

            // Fallback to checking Common Name (CN) in subject
            var subjectDN = cert.getSubjectX500Principal().getName();
            if (subjectDN.contains("CN=" + domainName)) {
                return true;
            }

        } catch (Exception e) {
            return false;
        }

        return false;
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
