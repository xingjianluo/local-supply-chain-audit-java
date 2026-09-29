package com.github.xingjianluo.localsupplychainauditjava.parse;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.localsupplychainauditjava.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Parses a local JSON dependency manifest / minimal SBOM of the form
 * <pre>
 * {"components":[{"group":"...","name":"...","version":"...","scope":"..."}]}
 * </pre>
 * Malformed JSON or a missing/non-array {@code components} member yields a
 * CORRUPT result; invalid entries inside an otherwise valid array yield a
 * PARTIALLY_PARSED result, and the valid entries are still kept.
 */
@Component
public class JsonSbomParser implements ManifestParser {

    private static final Logger log = LoggerFactory.getLogger(JsonSbomParser.class);
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public boolean supports(ManifestInput input) {
        return input.format() == ManifestFormat.JSON_SBOM;
    }

    @Override
    public ManifestResult parse(ManifestInput input) {
        String moduleId = resolveModuleId(input);
        String text;
        try {
            text = ManifestReadingSupport.read(input);
        } catch (Exception e) {
            log.warn("JSON module='{}' UNREADABLE at path='{}': {}",
                    moduleId, input.path(), e.getMessage());
            return corrupt(moduleId, input, IssueType.UNREADABLE_FILE,
                    "cannot read manifest: " + e.getMessage());
        }

        JsonNode root;
        try {
            root = mapper.readTree(text);
        } catch (Exception e) {
            log.warn("JSON module='{}' MALFORMED_JSON at path='{}': {}",
                    moduleId, input.path(), e.getMessage());
            return corrupt(moduleId, input, IssueType.MALFORMED_JSON,
                    "malformed JSON: " + e.getMessage());
        }
        if (root == null || !root.isObject()) {
            log.warn("JSON module='{}' MALFORMED_JSON: root is not an object", moduleId);
            return corrupt(moduleId, input, IssueType.MALFORMED_JSON,
                    "root JSON node must be an object");
        }
        JsonNode componentsNode = root.get("components");
        if (componentsNode == null || !componentsNode.isArray()) {
            log.warn("JSON module='{}' MALFORMED_JSON: missing 'components' array", moduleId);
            return corrupt(moduleId, input, IssueType.MALFORMED_JSON,
                    "missing or non-array 'components' member");
        }

        List<DependencyRecord> records = new ArrayList<>();
        List<ManifestIssue> entryIssues = new ArrayList<>();
        Set<ModuleRef> modules = Set.of(new ModuleRef(moduleId));

        int index = 0;
        for (JsonNode node : componentsNode) {
            if (node == null || !node.isObject()) {
                ManifestIssue issue = new ManifestIssue(IssueType.MALFORMED_JSON,
                        "components[" + index + "] is not an object and was kept aside");
                entryIssues.add(issue);
                log.warn("JSON module='{}' entry {} is not an object", moduleId, index);
                index++;
                continue;
            }
            String group = textOrNull(node, "group");
            String name = textOrNull(node, "name");
            String version = textOrNull(node, "version");
            String scope = textOrNull(node, "scope");

            List<ManifestIssue> issues = new ArrayList<>();
            if (name == null) {
                issues.add(new ManifestIssue(IssueType.MISSING_COORDINATE,
                        "components[" + index + "] without name"));
            }
            if (group == null) {
                issues.add(new ManifestIssue(IssueType.MISSING_COORDINATE,
                        "components[" + index + "] ('" + name + "') without group"));
            }
            if (version == null) {
                issues.add(new ManifestIssue(IssueType.MISSING_VERSION,
                        "component '" + group + ":" + name + "' has no declared version"));
            }
            if (!issues.isEmpty()) {
                log.warn("JSON module='{}' field issue at index {} for {}:{}:{} -> {}",
                        moduleId, index, group, name, version, issues);
                entryIssues.addAll(issues);
            }
            records.add(new DependencyRecord(group, name, version, scope,
                    new LinkedHashSet<>(modules), List.copyOf(issues)));
            index++;
        }

        ManifestStatus status = entryIssues.isEmpty() ? ManifestStatus.PARSED : ManifestStatus.PARTIALLY_PARSED;
        if (status == ManifestStatus.PARTIALLY_PARSED) {
            log.warn("JSON module='{}' PARTIALLY_PARSED: {}/{} entries had issues",
                    moduleId, entryIssues.size(), componentsNode.size());
        } else {
            log.info("JSON module='{}' PARSED, {} component(s)", moduleId, records.size());
        }
        return new ManifestResult(moduleId, ManifestFormat.JSON_SBOM, status,
                input.path(), List.copyOf(records), List.copyOf(entryIssues));
    }

    private String textOrNull(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull()) {
            return null;
        }
        if (!value.isTextual()) {
            // A numeric version is tolerable; other types are not a coordinate.
            return value.isNumber() ? value.asText() : null;
        }
        String text = value.asText();
        return text.isBlank() ? null : text.strip();
    }

    private String resolveModuleId(ManifestInput input) {
        if (input.moduleId() != null && !input.moduleId().isBlank()) {
            return input.moduleId().strip();
        }
        if (input.path() != null) {
            int slash = Math.max(input.path().lastIndexOf('/'), input.path().lastIndexOf('\\'));
            String fileName = slash >= 0 ? input.path().substring(slash + 1) : input.path();
            return fileName.isBlank() ? "module-" + System.identityHashCode(input) : fileName;
        }
        return "inline-" + System.identityHashCode(input);
    }

    private ManifestResult corrupt(String moduleId, ManifestInput input,
                                   IssueType type, String detail) {
        return new ManifestResult(moduleId, ManifestFormat.JSON_SBOM, ManifestStatus.CORRUPT,
                input.path(), List.of(), List.of(new ManifestIssue(type, detail)));
    }
}
