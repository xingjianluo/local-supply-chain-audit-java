package com.github.xingjianluo.localsupplychainauditjava.parser;

import com.github.xingjianluo.localsupplychainauditjava.core.CancelToken;
import com.github.xingjianluo.localsupplychainauditjava.core.ScanCancelledException;
import com.github.xingjianluo.localsupplychainauditjava.model.ComponentCoordinate;
import com.github.xingjianluo.localsupplychainauditjava.model.ManifestFormat;
import com.github.xingjianluo.localsupplychainauditjava.model.ModuleParseResult;
import com.github.xingjianluo.localsupplychainauditjava.model.ModuleSpec;
import com.github.xingjianluo.localsupplychainauditjava.model.ParseIssue;
import com.github.xingjianluo.localsupplychainauditjava.model.ParseIssueType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.github.xingjianluo.localsupplychainauditjava.service.AuditProperties;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Maven pom.xml 解析器。
 *
 * <p>处理范围：严格按直接子节点读取 project/dependencies 与
 * project/dependencyManagement/dependencies 下的依赖条目（避免两个区块交叉误收）；
 * {@code ${project.version}}、{@code ${project.groupId}} 与 pom properties 占位符解析；
 * parent GAV 作为回退坐标；离线模式下不解析远程 parent / BOM import，无法落地的版本会形成
 * 字段缺失结论。
 */
@Component
public class PomXmlParser implements ManifestParser {

    private static final Logger log = LoggerFactory.getLogger(PomXmlParser.class);
    private static final String ECOSYSTEM = ManifestFormat.POM_XML.ecosystem();
    private static final Pattern PROPERTY = Pattern.compile("\\$\\{([^}]+)}");

    private final int cancelBatchSize;

    public PomXmlParser(AuditProperties properties) {
        this.cancelBatchSize = Math.max(1, properties.getCancelBatchSize());
    }

    @Override
    public ManifestFormat format() {
        return ManifestFormat.POM_XML;
    }

    @Override
    public boolean sniff(ModuleSpec spec, String content) {
        return content != null && content.contains("<project");
    }

    @Override
    public ModuleParseResult parse(ModuleSpec spec, String content, CancelToken cancelToken) {
        DependencyCollector collector = new DependencyCollector(spec.module(), format());
        List<ParseIssue> issues = new ArrayList<>();
        try {
            Document document = parseSecure(content);
            Element root = document.getDocumentElement();

            Map<String, String> properties = readProperties(root);
            Element parent = directChild(root, "parent");
            String projectGroupId = directChildText(root, "groupId");
            String projectVersion = directChildText(root, "version");
            String parentGroupId = parent == null ? null : directChildText(parent, "groupId");
            String parentVersion = parent == null ? null : directChildText(parent, "version");
            String effectiveGroupId = firstNonBlank(projectGroupId, parentGroupId);
            String effectiveVersion = firstNonBlank(projectVersion, parentVersion);
            properties.put("project.version", nullToEmpty(effectiveVersion));
            properties.put("pom.version", nullToEmpty(effectiveVersion));
            properties.put("project.groupId", nullToEmpty(effectiveGroupId));
            properties.put("pom.groupId", nullToEmpty(effectiveGroupId));
            properties.put("project.parent.version", nullToEmpty(parentVersion));
            properties.put("project.parent.groupId", nullToEmpty(parentGroupId));

            // 实际引用
            Element directDeps = directChild(root, "dependencies");
            if (directDeps != null) {
                readDependencies(spec, directDeps, properties, collector, issues,
                        cancelToken, false);
            }
            // dependencyManagement 仅为版本声明，不重复收录，逐条给出可追溯结论
            Element management = directChild(root, "dependencyManagement");
            if (management != null) {
                Element managedDeps = directChild(management, "dependencies");
                if (managedDeps != null) {
                    readDependencies(spec, managedDeps, properties, collector, issues,
                            cancelToken, true);
                }
            }

            cancelToken.checkPoint();
        } catch (ScanCancelledException e) {
            throw e;
        } catch (Exception e) {
            issues.add(new ParseIssue(spec.module(), format(), ParseIssueType.MALFORMED_MANIFEST,
                    "pom.xml 损坏或不是合法 XML: " + e.getClass().getSimpleName()
                            + ": " + safeMessage(e), null));
            log.warn("模块[{}]pom 损坏: {}", spec.module(), e.toString());
        }

        if (collector.dependencies().isEmpty()
                && issues.stream().noneMatch(i -> i.type() == ParseIssueType.MALFORMED_MANIFEST)) {
            issues.add(ParseIssue.of(spec.module(), format(), ParseIssueType.EMPTY_MANIFEST,
                    "pom.xml 中没有任何有效依赖条目"));
        }
        log.info("模块[{}]pom 解析完成: 有效依赖={} 结论条数={}",
                spec.module(), collector.dependencies().size(), issues.size());
        return new ModuleParseResult(spec.module(), format(),
                List.copyOf(collector.dependencies()), List.copyOf(issues));
    }

    private Document parseSecure(String content) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setNamespaceAware(false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8)));
    }

    private void readDependencies(ModuleSpec spec, Element dependenciesElement,
                                  Map<String, String> properties,
                                  DependencyCollector collector, List<ParseIssue> issues,
                                  CancelToken cancelToken, boolean managedOnly) {
        List<Element> deps = childElements(dependenciesElement, "dependency");
        int index = 0;
        for (Element dep : deps) {
            index++;
            if (index % cancelBatchSize == 0) {
                cancelToken.checkPoint();
            }
            String groupId = directChildText(dep, "groupId");
            String artifactId = directChildText(dep, "artifactId");
            String versionRaw = directChildText(dep, "version");
            String scope = directChildText(dep, "scope");
            String snippet = groupId + ":" + artifactId + ":" + versionRaw;

            if (artifactId == null || artifactId.isBlank()) {
                issues.add(new ParseIssue(spec.module(), format(), ParseIssueType.FIELD_MISSING,
                        "dependency 缺少 artifactId，已跳过", snippet));
                continue;
            }
            if (groupId == null || groupId.isBlank()) {
                issues.add(new ParseIssue(spec.module(), format(), ParseIssueType.FIELD_MISSING,
                        "依赖[" + artifactId + "]缺少 groupId，已跳过", snippet));
                continue;
            }
            if ("import".equals(scope)) {
                issues.add(ParseIssue.of(spec.module(), format(), ParseIssueType.FIELD_MISSING,
                        "BOM 导入 " + groupId + ":" + artifactId
                                + " 在离线模式下不解析其传递管理版本，跳过该 import 条目"));
                continue;
            }
            String version = resolveVersion(versionRaw, properties);
            if (managedOnly) {
                String detail = version == null
                        ? "dependencyManagement 条目 " + groupId + ":" + artifactId
                                + " 无可用版本，离线模式无法解析 BOM，跳过"
                        : "dependencyManagement 中的 " + groupId + ":" + artifactId + ":" + version
                                + " 为版本声明而非实际引用，不重复计入组件清单";
                issues.add(ParseIssue.of(spec.module(), format(),
                        ParseIssueType.DUPLICATE_REFERENCE, detail));
                continue;
            }
            if (version == null || version.isBlank()) {
                issues.add(ParseIssue.of(spec.module(), format(), ParseIssueType.FIELD_MISSING,
                        "依赖 " + groupId + ":" + artifactId
                                + " 未声明可解析版本（离线不解析父 POM/依赖调解），"
                                + "无法做版本级判定，跳过"));
                continue;
            }
            if (versionRaw != null && versionRaw.contains("${")) {
                log.info("模块[{}]版本占位符解析: {} {} -> {}",
                        spec.module(), groupId + ":" + artifactId, versionRaw, version);
            }
            collector.accept(new ComponentCoordinate(ECOSYSTEM, groupId, artifactId), version, snippet);
        }
    }

    private Map<String, String> readProperties(Element root) {
        Map<String, String> properties = new HashMap<>();
        Element propsElement = directChild(root, "properties");
        if (propsElement == null) {
            return properties;
        }
        for (Element el : childElements(propsElement, null)) {
            properties.put(el.getTagName(), el.getTextContent().trim());
        }
        return properties;
    }

    private String resolveVersion(String raw, Map<String, String> properties) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String value = raw.trim();
        Matcher m = PROPERTY.matcher(value);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String key = m.group(1);
            String replacement = properties.getOrDefault(key, "");
            m.appendReplacement(sb, Matcher.quoteReplacement(replacement));
        }
        m.appendTail(sb);
        String resolved = sb.toString().trim();
        // 未解析占位符（如外部 parent 提供的属性）视为不可用版本
        return resolved.isBlank() || resolved.contains("${") ? null : resolved;
    }

    private Element directChild(Element parent, String tag) {
        if (parent == null) {
            return null;
        }
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE && tag.equals(n.getNodeName())) {
                return (Element) n;
            }
        }
        return null;
    }

    private List<Element> childElements(Element parent, String tag) {
        List<Element> result = new ArrayList<>();
        if (parent == null) {
            return result;
        }
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n.getNodeType() == Node.ELEMENT_NODE
                    && (tag == null || tag.equals(n.getNodeName()))) {
                result.add((Element) n);
            }
        }
        return result;
    }

    private String directChildText(Element parent, String tag) {
        Element el = directChild(parent, tag);
        if (el == null) {
            return null;
        }
        String text = el.getTextContent();
        return text == null ? null : text.trim();
    }

    private String firstNonBlank(String a, String b) {
        return a != null && !a.isBlank() ? a : b;
    }

    private String nullToEmpty(String s) {
        return s == null ? "" : s;
    }

    private String safeMessage(Exception e) {
        return e.getMessage() == null ? "" : (e.getMessage().length() <= 120
                ? e.getMessage() : e.getMessage().substring(0, 120) + "...");
    }
}
