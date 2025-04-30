package tech.yump.vault.auth.policy;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import tech.yump.vault.config.MssmProperties;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class PolicyRepository {

    private final MssmProperties mssmProperties;
    private Map<String, PolicyDefinition> policyMap = Collections.emptyMap();

    @PostConstruct
    void initialize() {
        List<PolicyDefinition> configuredPolicies = Optional.ofNullable(mssmProperties.policies())
                .orElse(Collections.emptyList());

        if (configuredPolicies.isEmpty()) {
            log.warn("No policies defined in configuration (mssm.policies). ACL enforcement will deny access unless policies are added.");
        } else {
            this.policyMap = configuredPolicies.stream()
                    .collect(Collectors.toMap(PolicyDefinition::name, Function.identity(), (existing, replacement) -> {
                        // Handle duplicate policy names if they somehow bypass validation
                        log.warn("Duplicate policy name found in configuration: '{}'. Using the first occurrence.", existing.name());
                        return existing;
                    }));
            log.info("Loaded {} policies from configuration.", this.policyMap.size());
            log.debug("Loaded policy names: {}", this.policyMap.keySet());
        }
    }

    public Optional<PolicyDefinition> findPolicyByName(String name) {
        return Optional.ofNullable(policyMap.get(name));
    }

    public List<PolicyDefinition> findPoliciesByNames(List<String> names) {
        if (names == null || names.isEmpty()) {
            return Collections.emptyList();
        }
        return names.stream()
                .map(this::findPolicyByName)
                .flatMap(Optional::stream) // Filter out Optional.empty() and unwrap present ones
                .toList();
    }
}