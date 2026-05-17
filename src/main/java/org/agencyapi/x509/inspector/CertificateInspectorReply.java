package org.agencyapi.x509.inspector;

import java.security.cert.X509Certificate;
import java.util.List;

public record CertificateInspectorReply(String domain, boolean ocspStaplingEnabled, List<CertificateInfo> certificates) {
    static CertificateInspectorReply create(String domain, List<X509Certificate> certificates, boolean ocspStaplingEnabled) {
        return new CertificateInspectorReply(domain, ocspStaplingEnabled, certificates.stream().map(CertificateInfo::from).toList());
    }
    record CertificateInfo(
            String subject,
            String issuer,
            String serialNumber,
            String validFrom,
            String validUntil,
            String signatureAlgorithm,
            int version,
            String ocspUrl) {
        static CertificateInfo from(X509Certificate cert) {
            return new CertificateInfo(
                    cert.getSubjectX500Principal().getName(),
                    cert.getIssuerX500Principal().getName(),
                    cert.getSerialNumber().toString(),
                    cert.getNotBefore().toString(),
                    cert.getNotAfter().toString(),
                    cert.getSigAlgName(),
                    cert.getVersion(),
                    CertificateUtils.extractOcspUrl(cert)
            );
        }
    }
}
