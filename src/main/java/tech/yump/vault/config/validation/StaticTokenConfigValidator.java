package tech.yump.vault.config.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import tech.yump.vault.config.MssmProperties;

public class StaticTokenConfigValidator implements ConstraintValidator<ValidStaticTokenConfig, MssmProperties.AuthProperties.StaticTokenAuthProperties> {

  @Override
  public void initialize(
      ValidStaticTokenConfig constraintAnnotation) {
    // No initialization needed from annotation attributes
  }

  @Override
  public boolean isValid(MssmProperties.AuthProperties.StaticTokenAuthProperties value, ConstraintValidatorContext context) {
    if (value == null) {
      return true; // Let @NotNull handle null checks at the field level if needed
    }

    // The core conditional logic:
    if (value.enabled()) {
      // If enabled is true, tokens must not be null and not empty
      return value.tokens() != null && !value.tokens().isEmpty();
    } else {
      // If enabled is false, the configuration is valid regardless of the tokens set
      return true;
    }
  }
}