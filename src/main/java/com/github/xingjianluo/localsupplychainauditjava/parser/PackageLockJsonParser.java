package com.github.xingjianluo.localsupplychainauditjava.parser;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * npm package-lock.json 流式解析器。
 *
 * <p>支持 lockfileVersion 2/3 的 {@code packages} 表（含 scoped 包
 * {@code node_modules/@scope/name} 与嵌套提升 {@code node_modules/a/node_modules/b}），
 * 也兼容 lockfileVersion 1 的嵌套 {@code dependencies}。
 *
 * <p>使用 Jackson streaming API，逐个安装路径产出依赖条目，不将整棵 JSON 树读入内存；
 * 大 lock 文件的额外内存占用近似为单条目量级。
 */
@Component
public class PackageLockJsonParser implements ManifestParser {

    private static final Logger log = LoggerFactory.getLogger(PackageLockJsonParser.class);
    private static final String ECOSYSTEM = ManifestFormat.PACKAGE_LOCK_JSON.ecosystem();
    private final int cancelCheckEntries;

    private final JsonFactory jsonFactory = new JsonFactory();

    public PackageLockJsonParser(AuditProperties properties) {
        this.cancelCheckEntries = Math.max(1, properties.getCancelBatchSize());
    }

    @Override
    public ManifestFormat format() {
        return ManifestFormat.PACKAGE_LOCK_JSON;
    }

    @Override
    public boolean sniff(ModuleSpec spec, String content) {
        return content != null && content.contains("\"lockfileVersion\"");
    }

    @Override
    public ModuleParseResult parse(ModuleSpec spec, String content, CancelToken cancelToken) {
        DependencyCollector collector = new DependencyCollector(spec.module(), format());
        List<ParseIssue> issues = new ArrayList<>();
        boolean[] sawPackagesTable = {false};
        int[] counter = {0};

        try (JsonParser parser = jsonFactory.createParser(content)) {
            JsonToken token = parser.nextToken();
            if (token != JsonToken.START_OBJECT) {
                issues.add(ParseIssue.of(spec.module(), format(), ParseIssueType.MALFORMED_MANIFEST,
                        "package-lock.json 根节点不是 JSON 对象，整份清单无法解析"));
                return finish(spec, collector, issues);
            }
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String field = parser.currentName();
                JsonToken valueToken = parser.nextToken();
                if ("packages".equals(field) && valueToken == JsonToken.START_OBJECT) {
                    sawPackagesTable[0] = true;
                    parsePackagesTable(spec, parser, collector, issues, cancelToken, counter);
                } else if ("dependencies".equals(field) && valueToken == JsonToken.START_OBJECT
                        && !sawPackagesTable[0]) {
                    parseV1Dependencies(spec, parser, collector, issues, cancelToken, counter);
                } else if (valueToken == JsonToken.START_OBJECT || valueToken == JsonToken.START_ARRAY) {
                    parser.skipChildren();
                }
            }
        } catch (ScanCancelledException e) {
            throw e;
        } catch (IOException | RuntimeException e) {
            issues.add(new ParseIssue(spec.module(), format(), ParseIssueType.MALFORMED_MANIFEST,
                    "package-lock.json 语法损坏，解析在中断处终止: "
                            + e.getClass().getSimpleName() + ": " + safeMessage(e), null));
            log.warn("模块[{}]package-lock 损坏: {}", spec.module(), e.toString());
        }

        return finish(spec, collector, issues);
    }

    /** 解析 lockfileVersion 2/3 的扁平 packages 表。 */
    private void parsePackagesTable(ModuleSpec spec, JsonParser parser,
                                    DependencyCollector collector, List<ParseIssue> issues,
                                    CancelToken cancelToken, int[] counter) throws IOException {
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            String path = parser.currentName();
            JsonToken valueStart = parser.nextToken();
            if (valueStart != JsonToken.START_OBJECT) {
                // 容错：packages 的值应当是对象
                parser.skipChildren();
                continue;
            }
            String version = null;
            boolean link = false;
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String entryField = parser.currentName();
                JsonToken vt = parser.nextToken();
                if ("version".equals(entryField) && vt == JsonToken.VALUE_STRING) {
                    version = parser.getText();
                } else if ("link".equals(entryField) && vt == JsonToken.VALUE_TRUE) {
                    link = true;
                } else if (vt == JsonToken.START_OBJECT || vt == JsonToken.START_ARRAY) {
                    parser.skipChildren();
                }
            }
            if (path.isEmpty()) {
                // "" 是工程自身根节点，不是第三方依赖
                continue;
            }
            String name = nameFromInstallPath(path);
            if (name == null) {
                issues.add(new ParseIssue(spec.module(), format(), ParseIssueType.MALFORMED_MANIFEST,
                        "无法从安装路径提取包名: " + truncate(path), truncate(path)));
                continue;
            }
            if (link) {
                issues.add(ParseIssue.of(spec.module(), format(), ParseIssueType.FIELD_MISSING,
                        "包[" + name + "]为 workspace 软链(link=true)，无已发布版本，已跳过"));
                continue;
            }
            collector.accept(new ComponentCoordinate(ECOSYSTEM, "", name), version, truncate(path));
            tick(cancelToken, counter);
        }
    }

    /** 递归解析 lockfileVersion 1 的嵌套 dependencies。 */
    private void parseV1Dependencies(ModuleSpec spec, JsonParser parser,
                                     DependencyCollector collector, List<ParseIssue> issues,
                                     CancelToken cancelToken, int[] counter) throws IOException {
        while (parser.nextToken() != JsonToken.END_OBJECT) {
            String name = parser.currentName();
            JsonToken valueStart = parser.nextToken();
            if (valueStart != JsonToken.START_OBJECT) {
                parser.skipChildren();
                continue;
            }
            String version = null;
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                String f = parser.currentName();
                JsonToken vt = parser.nextToken();
                if ("version".equals(f) && vt == JsonToken.VALUE_STRING) {
                    version = parser.getText();
                } else if ("dependencies".equals(f) && vt == JsonToken.START_OBJECT) {
                    parseV1Dependencies(spec, parser, collector, issues, cancelToken, counter);
                } else if (vt == JsonToken.START_OBJECT || vt == JsonToken.START_ARRAY) {
                    parser.skipChildren();
                }
            }
            collector.accept(new ComponentCoordinate(ECOSYSTEM, "", name), version, name);
            tick(cancelToken, counter);
        }
    }

    private void tick(CancelToken cancelToken, int[] counter) {
        counter[0]++;
        if (counter[0] % cancelCheckEntries == 0) {
            cancelToken.checkPoint();
        }
    }

    /** node_modules/a/node_modules/@scope/b -> @scope/b。 */
    String nameFromInstallPath(String path) {
        int idx = path.lastIndexOf("node_modules/");
        if (idx < 0) {
            return null;
        }
        String name = path.substring(idx + "node_modules/".length());
        return name.isBlank() ? null : name;
    }

    private ModuleParseResult finish(ModuleSpec spec, DependencyCollector collector,
                                     List<ParseIssue> issues) {
        issues.addAll(collector.issues());
        boolean malformed = issues.stream()
                .anyMatch(i -> i.type() == ParseIssueType.MALFORMED_MANIFEST);
        if (collector.dependencies().isEmpty() && !malformed) {
            issues.add(ParseIssue.of(spec.module(), format(), ParseIssueType.EMPTY_MANIFEST,
                    "package-lock.json 中没有任何有效依赖条目"));
        }
        log.info("模块[{}]package-lock 解析完成: 有效依赖={} 结论条数={}",
                spec.module(), collector.dependencies().size(), issues.size());
        return new ModuleParseResult(spec.module(), format(),
                List.copyOf(collector.dependencies()), List.copyOf(issues));
    }

    private String safeMessage(Exception e) {
        return e.getMessage() == null ? "" : truncate(e.getMessage());
    }

    private String truncate(String s) {
        if (s == null) {
            return null;
        }
        return s.length() <= 120 ? s : s.substring(0, 120) + "...";
    }
}
