package org.agencyapi.x509.inspector;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.common.net.InetAddresses;

import java.net.Inet6Address;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Reply of {@code /inspect/{domain}}. {@code certificates} and {@code ocspStaplingEnabled} come from the first address
 * that completed a handshake; {@code addresses} has the result for every A and AAAA address of the domain, or the
 * single address inspected when {@code domain} is an IP address.
 */
public record CertificateInspectorReply(
        String domain,
        boolean ocspStaplingEnabled,
        List<CertificateInfo> certificates,
        List<AddressInfo> addresses) {
    static CertificateInspectorReply create(String domain, List<AddressInspector.AddressResult> results) {
        var primary = results.stream()
                .filter(AddressInspector.AddressResult::reachable)
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("No address of " + domain + " completed a handshake"))
                .handshake();
        return new CertificateInspectorReply(
                domain,
                primary.ocspStapled(),
                CertificateInfo.from(primary.certificates()),
                results.stream().map(AddressInfo::from).toList());
    }

    // ocspUrl is the only optional field; leave it out rather than send "ocspUrl": null
    @JsonInclude(JsonInclude.Include.NON_NULL)
    record CertificateInfo(
            String subject,
            String issuer,
            String serialNumber,
            String validFrom,
            String validUntil,
            String signatureAlgorithm,
            int version,
            String ocspUrl) {
        static List<CertificateInfo> from(List<X509Certificate> certificates) {
            return certificates.stream().map(CertificateInfo::from).toList();
        }

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

    /**
     * One A or AAAA address: a reachable one has {@code certificates} and {@code ocspStaplingEnabled}, an unreachable
     * one only an {@code error}. Addresses are written in their canonical form, e.g. {@code 2001:db8::1}.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    record AddressInfo(
            String address,
            String type,
            Boolean ocspStaplingEnabled,
            List<CertificateInfo> certificates,
            String error) {
        static AddressInfo from(AddressInspector.AddressResult result) {
            var address = InetAddresses.toAddrString(result.address());
            var type = result.address() instanceof Inet6Address ? "AAAA" : "A";
            if (result.reachable()) {
                var handshake = result.handshake();
                return new AddressInfo(address, type, handshake.ocspStapled(), CertificateInfo.from(handshake.certificates()), null);
            }
            var error = result.error();
            return new AddressInfo(address, type, null, null, error.getMessage() != null ? error.getMessage() : error.getClass().getSimpleName());
        }
    }
}
