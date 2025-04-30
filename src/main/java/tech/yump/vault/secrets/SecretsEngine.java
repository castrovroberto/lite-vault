package tech.yump.vault.secrets;

/**
 * Base marker interface for all secrets engines within LiteVault.
 * Implementations manage different types of secrets (static, dynamic, etc.).
 */
public interface SecretsEngine {
    // Currently a marker interface.
    // Common methods like String getType() or boolean isDynamic() could be added later.
}