package tech.yump.vault.config.validation; // Or your preferred validation package

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Documented
@Constraint(validatedBy = StaticTokenConfigValidator.class) // Link to the validator class
@Target({ ElementType.TYPE }) // Apply to the class/record level
@Retention(RetentionPolicy.RUNTIME)
public @interface ValidStaticTokenConfig {
  String message() default "If static token authentication is enabled, at least one token must be provided.";
  Class<?>[] groups() default {};
  Class<? extends Payload>[] payload() default {};
}