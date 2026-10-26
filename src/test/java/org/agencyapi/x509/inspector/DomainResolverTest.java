package org.agencyapi.x509.inspector;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.EDNSOption;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Message;
import org.xbill.DNS.Name;
import org.xbill.DNS.Rcode;
import org.xbill.DNS.Record;
import org.xbill.DNS.Resolver;
import org.xbill.DNS.SOARecord;
import org.xbill.DNS.Section;
import org.xbill.DNS.TSIG;
import org.xbill.DNS.Type;

import java.io.IOException;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DomainResolverTest {
    private static final Name ZONE = name("example.com.");
    private static final Name WWW = name("www.example.com.");

    @Test
    void returnsIpv4AddressesFollowedByIpv6Addresses() throws Exception {
        var resolver = new FakeResolver(Map.of(
                Type.A, List.of(a(ZONE, "192.0.2.1"), a(ZONE, "192.0.2.2")),
                Type.AAAA, List.of(aaaa(ZONE, "2001:db8::1"))));

        assertThat(new DomainResolver(resolver).resolve("example.com"))
                .containsExactly(ip("192.0.2.1"), ip("192.0.2.2"), ip("2001:db8::1"));
    }

    @Test
    void returnsIpv4AddressesWhenThereAreNoAaaaRecords() throws Exception {
        var resolver = new FakeResolver(Map.of(Type.A, List.of(a(ZONE, "192.0.2.1"))));

        assertThat(new DomainResolver(resolver).resolve("example.com")).containsExactly(ip("192.0.2.1"));
    }

    @Test
    void returnsIpv6AddressesWhenThereAreNoARecords() throws Exception {
        var resolver = new FakeResolver(Map.of(Type.AAAA, List.of(aaaa(ZONE, "2001:db8::1"))));

        assertThat(new DomainResolver(resolver).resolve("example.com")).containsExactly(ip("2001:db8::1"));
    }

    @Test
    void followsCnameToTheTargetsAddresses() throws Exception {
        var cname = new CNAMERecord(WWW, DClass.IN, 300, ZONE);
        var resolver = new FakeResolver(Map.of(
                Type.A, List.of(cname, a(ZONE, "192.0.2.1")),
                Type.AAAA, List.of(cname, aaaa(ZONE, "2001:db8::1"))));

        assertThat(new DomainResolver(resolver).resolve("www.example.com"))
                .containsExactly(ip("192.0.2.1"), ip("2001:db8::1"));
    }

    @Test
    void failsWhenTheDomainHasNoAddresses() {
        var resolver = new FakeResolver(Map.of());

        assertThatThrownBy(() -> new DomainResolver(resolver).resolve("example.com"))
                .isInstanceOf(UnknownHostException.class)
                .hasMessageContaining("example.com");
    }

    @Test
    void failsWhenTheDomainDoesNotExist() {
        var resolver = new FakeResolver(Map.of());
        resolver.rcode = Rcode.NXDOMAIN;

        assertThatThrownBy(() -> new DomainResolver(resolver).resolve("example.com"))
                .isInstanceOf(UnknownHostException.class);
    }

    @Test
    void failsRatherThanReturnPartialAnswerWhenOneLookupFails() {
        var resolver = new FakeResolver(Map.of(Type.A, List.of(a(ZONE, "192.0.2.1"))));
        resolver.failingType = Type.AAAA;

        assertThatThrownBy(() -> new DomainResolver(resolver).resolve("example.com"))
                .isInstanceOf(IOException.class)
                .isNotInstanceOf(UnknownHostException.class)
                .hasMessageContaining("AAAA");
    }

    @Test
    void rejectsInvalidDomainNames() {
        var resolver = new FakeResolver(Map.of());

        assertThatThrownBy(() -> new DomainResolver(resolver).resolve("a".repeat(64) + ".com"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private static Name name(String name) {
        try {
            return Name.fromString(name);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static InetAddress ip(String address) {
        try {
            return InetAddress.getByName(address);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private static ARecord a(Name name, String address) {
        return new ARecord(name, DClass.IN, 300, ip(address));
    }

    private static AAAARecord aaaa(Name name, String address) {
        return new AAAARecord(name, DClass.IN, 300, ip(address));
    }

    /**
     * Answers each query from {@code answers} by record type, with an SOA in the authority section of empty answers
     * as a real server sends, so no DNS traffic leaves the test.
     */
    private static final class FakeResolver implements Resolver {
        private final Map<Integer, List<Record>> answers;
        int rcode = Rcode.NOERROR;
        Integer failingType;

        FakeResolver(Map<Integer, List<Record>> answers) {
            this.answers = answers;
        }

        @Override
        public Message send(Message query) throws IOException {
            var question = query.getQuestion();
            if (failingType != null && question.getType() == failingType) {
                throw new SocketTimeoutException("timed out");
            }

            var response = new Message(query.getHeader().getID());
            response.getHeader().setFlag(Flags.QR);
            response.getHeader().setFlag(Flags.AA);
            response.getHeader().setRcode(rcode);
            response.addRecord(question, Section.QUESTION);
            var records = new ArrayList<>(answers.getOrDefault(question.getType(), List.of()));
            records.forEach(record -> response.addRecord(record, Section.ANSWER));
            if (records.isEmpty()) {
                response.addRecord(new SOARecord(ZONE, DClass.IN, 300, name("ns.example.com."),
                        name("hostmaster.example.com."), 1, 3600, 600, 86400, 300), Section.AUTHORITY);
            }
            return response;
        }

        @Override
        public void setPort(int port) {
        }

        @Override
        public void setTCP(boolean flag) {
        }

        @Override
        public void setIgnoreTruncation(boolean flag) {
        }

        @Override
        public void setEDNS(int version, int payloadSize, int flags, List<EDNSOption> options) {
        }

        @Override
        public void setTSIGKey(TSIG key) {
        }

        @Override
        public void setTimeout(Duration timeout) {
        }
    }
}
