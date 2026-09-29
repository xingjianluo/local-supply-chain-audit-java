package com.github.xingjianluo.localsupplychainauditjava.parse;

import com.github.xingjianluo.localsupplychainauditjava.model.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Parses Maven pom.xml manifests. Dependency coordinates are extracted from
 * {@code <dependencies>} sections found anywhere in the document (project level,
 * dependencyManagement, profiles) and from {@code <plugins>}. The parser is
 * namespace agnostic and never throws for broken content: malformed XML produces
 * a CORRUPT result, entry-level field problems produce a PARTIALLY_PARSED result.
 */
@Component
public class PomManifestParser implements ManifestParser {

    private static final Logger log = LoggerFactory.getLogger(PomManifestParser.class);
    private static final String DEFAULT_PLUGIN_GROUP = "org.apache.maven.plugins";

    @Override
    public boolean supports(ManifestInput input) {
        return input.format() == ManifestFormat.MAVEN_POM;
    }

    @Override
    public ManifestResult parse(ManifestInput input) {
        String moduleId = resolveModuleId(input);
        String text;
        try {
            text = ManifestReadingSupport.read(input);
        } catch (Exception e) {
            log.warn("POM module='{}' UNREADABLE at path='{}': {}",
                    moduleId, input.path(), e.getMessage());
            return corrupt(moduleId, input, IssueType.UNREADABLE_FILE,
                    "cannot read manifest: " + e.getMessage());
        }

        Document document;
        try {
            document = buildDocument(text);
        } catch (Exception e) {
            log.warn("POM module='{}' MALFORMED_XML at path='{}': {}",
                    moduleId, input.path(), e.getMessage());
            return corrupt(moduleId, input, IssueType.MALFORMED_XML,
                    "malformed XML: " + e.getMessage());
        }

        log.info("POM module='{}' parsed structurally from path='{}', extracting coordinates",
                moduleId, input.path());
        List<DependencyRecord> records = new ArrayList<>();
        List<ManifestIssue> entryIssues = new ArrayList<>();
        Set<ModuleRef> modules = Set.of(new ModuleRef(moduleId));

        extractCoordinates(document, "dependency", false, modules, records, entryIssues, moduleId);
        extractCoordinates(document, "plugin", true, modules, records, entryIssues, moduleId);

        ManifestStatus status = entryIssues.isEmpty() ? ManifestStatus.PARSED : ManifestStatus.PARTIALLY_PARSED;
        if (status == ManifestStatus.PARTIALLY_PARSED) {
            log.warn("POM module='{}' PARTIALLY_PARSED with {} entry-level issue(s)",
                    moduleId, entryIssues.size());
        } else {
            log.info("POM module='{}' PARSED, {} coordinate(s)", moduleId, records.size());
        }
        return new ManifestResult(moduleId, ManifestFormat.MAVEN_POM, status,
                input.path(), List.copyOf(records), List.copyOf(entryIssues));
    }

    private Document buildDocument(String text) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(false);
        // Harden against XXE/doctype expansion; input is fully local but treated as untrusted.
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        try (var in = new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8))) {
            return factory.newDocumentBuilder().parse(in);
        }
    }

    private void extractCoordinates(Document document, String tagName, boolean plugin,
                                    Set<ModuleRef> modules, List<DependencyRecord> outRecords,
                                    List<ManifestIssue> outIssues, String moduleId) {
        NodeList nodes = document.getElementsByTagName(tagName);
        for (int i = 0; i < nodes.getLength(); i++) {
            if (nodes.item(i).getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            Element element = (Element) nodes.item(i);
            // A <plugin> only carries coordinates inside a <plugins> container.
            String group = childText(element, "groupId");
            String name = childText(element, "artifactId");
            String version = childText(element, "version");
            String scope = plugin ? "plugin" : childText(element, "scope");
            if (plugin && (group == null || group.isBlank())) {
                group = DEFAULT_PLUGIN_GROUP;
            }

            List<ManifestIssue> issues = new ArrayList<>();
            if (name == null || name.isBlank()) {
                issues.add(new ManifestIssue(IssueType.MISSING_COORDINATE,
                        plugin
                                ? "<plugin> without <artifactId> at index " + i
                                : "<dependency> without <artifactId> at index " + i));
            }
            if (group == null || group.isBlank()) {
                issues.add(new ManifestIssue(IssueType.MISSING_COORDINATE,
                        "<" + tagName + "> '" + name + "' without <groupId> at index " + i));
            }
            if (version == null || version.isBlank()) {
                issues.add(new ManifestIssue(IssueType.MISSING_VERSION,
                        "component '" + group + ":" + name + "' has no declared version"));
            }
            if (!issues.isEmpty()) {
                log.warn("POM module='{}' field issue for {}:{}:{} -> {}",
                        moduleId, group, name, version, issues);
                outIssues.addAll(issues);
            }
            // Keep the record even when fields are missing, so nothing is silently skipped.
            outRecords.add(new DependencyRecord(emptyToNull(group), emptyToNull(name),
                    emptyToNull(version), emptyToNull(scope), new LinkedHashSet<>(modules),
                    List.copyOf(issues)));
        }
    }

    private String childText(Element parent, String childName) {
        NodeList children = parent.getElementsByTagName(childName);
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            // Direct child only (avoid grabbing nested coordinates of the same local name).
            if (child.getParentNode() != parent || child.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            String text = child.getTextContent();
            if (text != null && !text.isBlank()) {
                return text.strip();
            }
        }
        return null;
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
        ManifestIssue issue = new ManifestIssue(type, detail);
        return new ManifestResult(moduleId, ManifestFormat.MAVEN_POM, ManifestStatus.CORRUPT,
                input.path(), List.of(), List.of(issue));
    }

    private String emptyToNull(String s) {
        return s == null || s.isBlank() ? null : s;
    }
}
