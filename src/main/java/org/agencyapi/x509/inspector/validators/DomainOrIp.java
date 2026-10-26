package org.agencyapi.x509.inspector.validators;

import com.google.common.net.InetAddresses;
import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * A {@link Domain} or an IPv4 or IPv6 address literal such as {@code 192.0.2.1} or {@code 2001:db8::1}. IPv6 addresses
 * are accepted without brackets and without a zone ID.
 */
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = { DomainOrIp.Validator.class })
public @interface DomainOrIp {
    String message() default "value should be a valid domain or IP address";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
    class Validator implements ConstraintValidator<DomainOrIp, String> {
        private final Domain.Validator domain = new Domain.Validator();

        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            // a zone ID (e.g. fe80::1%eth0) names an interface of this service's host, which is never what's meant
            return domain.isValid(value, context) || InetAddresses.isInetAddress(value) && !value.contains("%");
        }
    }
}
