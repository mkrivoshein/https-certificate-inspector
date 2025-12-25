package org.agencyapi.x509.inspector.validators;

import jakarta.validation.Constraint;
import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import jakarta.validation.Payload;
import org.springframework.util.StringUtils;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = { Domain.Validator.class })
public @interface Domain {
    String message() default "value should be a valid domain";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
    class Validator implements ConstraintValidator<Domain, String> {
        @Override
        public boolean isValid(String value, ConstraintValidatorContext context) {
            // consider any string with a dot and without whitespace as valid domain potentially
            return !StringUtils.containsWhitespace(value) && value.contains(".");
        }
    }
}
