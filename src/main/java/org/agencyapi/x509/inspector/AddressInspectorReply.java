package org.agencyapi.x509.inspector;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.common.net.InetAddresses;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.List;

/**
 * Reply of {@code /inspect/{domain}/addresses}: the certificate chain each of the domain's A and AAAA addresses presents.
 * Addresses are written in their canonical form, e.g. {@code 2001:db8::1} rather than {@code 2001:db8:0:0:0:0:0:1}.
 */
public record AddressInspectorReply(String domain, List<AddressInfo> addresses) {
    // a reachable address has certificates and ocspStaplingEnabled, an unreachable one only an error
    @JsonInclude(JsonInclude.Include.NON_NULL)
    record AddressInfo(
            String address,
            String type,
            Boolean ocspStaplingEnabled,
            List<CertificateInspectorReply.CertificateInfo> certificates,
            String error) {
        static AddressInfo inspected(InetAddress address, CertificateFetcher.HandshakeResult result) {
            var certificates = result.certificates().stream().map(CertificateInspectorReply.CertificateInfo::from).toList();
            return new AddressInfo(InetAddresses.toAddrString(address), type(address), result.ocspStapled(), certificates, null);
        }

        static AddressInfo failed(InetAddress address, String error) {
            return new AddressInfo(InetAddresses.toAddrString(address), type(address), null, null, error);
        }

        private static String type(InetAddress address) {
            return address instanceof Inet6Address ? "AAAA" : "A";
        }
    }
}
