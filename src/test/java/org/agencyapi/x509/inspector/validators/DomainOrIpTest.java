package org.agencyapi.x509.inspector.validators;

import com.google.common.net.InetAddresses;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.Inet4Address;

import static org.assertj.core.api.Assertions.assertThat;

class DomainOrIpTest {
    private final DomainOrIp.Validator validator = new DomainOrIp.Validator();

    @ParameterizedTest
    @ValueSource(strings = {"example.com", "192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1", "::ffff:c000:201"})
    void acceptsDomainsAndIpAddresses(String value) {
        assertThat(validator.isValid(value, null)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "fe80::1%eth0", "::ffff:192.0.2.1%eth0", "::ffff:c000:2g1", "example .com"})
    void rejectsEverythingElse(String value) {
        assertThat(validator.isValid(value, null)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {"::ffff:192.0.2.1", "::ffff:c000:201", "::FFFF:C000:0201", "0:0:0:0:0:ffff:c000:201"})
    void ipv4MappedFormsParseToTheMappedIpv4Address(String value) {
        // the controller relies on Guava turning every textual form of a mapped address into the same Inet4Address
        var address = InetAddresses.forString(value);

        assertThat(address).isInstanceOf(Inet4Address.class);
        assertThat(InetAddresses.toAddrString(address)).isEqualTo("192.0.2.1");
    }
}
