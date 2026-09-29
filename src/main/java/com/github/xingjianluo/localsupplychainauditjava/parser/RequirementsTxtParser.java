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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * pip requirements.txt 解析器。
 *
 * <p>支持规则：注释/空行跳过、-r/-e/--index-url 等 pip 选项行记录为可区分结论、
 * 环境标记(;)忽略、extras([...])剥离、PEP440 常见操作符(== &gt;= &lt;= ~= != &gt; &lt; ===)，
 * 取声明版本；无版本固定的条目记为字段缺失结论而非静默丢弃。
 * 行式处理，内存占用随行数线性，不持有额外全量副本。
 */
@Component
public class RequirementsTxtParser implements ManifestParser {

    private static final Logger log = LoggerFactory.getLogger(RequirementsTxtParser.class);
    private final int cancelBatchSize;

    public RequirementsTxtParser(AuditProperties properties) {
        this.cancelBatchSize = Math.max(1, properties.getCancelBatchSize());
    }

    private static final Pattern DEP_PATTERN =
            Pattern.compile("^([A-Za-z0-9][A-Za-z0-9._-]*)(\\[[^]]*])?"
                    + "\\s*(?:(==|===|>=|<=|~=|!=|>|<)\\s*[A-Za-z0-9][A-Za-z0-9+._-]*"
                    + "(?:\\s*,\\s*(==|===|>=|<=|~=|!=|>|<)\\s*[A-Za-z0-9][A-Za-z0-9+._-]*)*"
                    + "(?:\\s*;.*)?)?$");
    private static final Pattern VERSION_PATTERN =
            Pattern.compile("(==|===|>=|<=|~=|!=|>|<)\\s*([A-Za-z0-9][A-Za-z0-9+._-]*)");

    @Override
    public ManifestFormat format() {
        return ManifestFormat.REQUIREMENTS_TXT;
    }

    @Override
    public boolean sniff(ModuleSpec spec, String content) {
        return content != null && content.stripLeading().startsWith("#");
    }

    @Override
    public ModuleParseResult parse(ModuleSpec spec, String content, CancelToken cancelToken) {
        DependencyCollector collector = new DependencyCollector(spec.module(), format());
        List<ParseIssue> issues = new ArrayList<>();
        int lineNo = 0;
        int validEntries = 0;
        try {
            for (String raw : content.split("\\R")) {
                lineNo++;
                if (lineNo % cancelBatchSize == 0) {
                    cancelToken.checkPoint();
                }
                String line = stripComment(raw).trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                if (line.startsWith("-")) {
                    issues.add(ParseIssue.of(spec.module(), format(), ParseIssueType.FIELD_MISSING,
                            "第" + lineNo + "行为 pip 选项/间接引用(" + truncate(line)
                                    + ")，非包依赖声明，已跳过"));
                    continue;
                }
                String core = line;
                Matcher m = DEP_PATTERN.matcher(core);
                if (!m.matches()) {
                    issues.add(new ParseIssue(spec.module(), format(), ParseIssueType.MALFORMED_MANIFEST,
                            "第" + lineNo + "行无法识别为依赖声明，已跳过", truncate(raw)));
                    log.warn("模块[{}]requirements 第{}行畸形: {}", spec.module(), lineNo, truncate(raw));
                    continue;
                }
                String name = normalizeName(m.group(1));
                Matcher vm = VERSION_PATTERN.matcher(core);
                if (!vm.find()) {
                    // 名称合法但没有任何版本说明符：可能是未固定版本的合法 pip 写法，记为字段缺失结论
                    collector.accept(new ComponentCoordinate(ManifestFormat.REQUIREMENTS_TXT.ecosystem(),
                            "", name), "", truncate(raw));
                    continue;
                }
                String operator = vm.group(1);
                String version = vm.group(2);
                if (!"==".equals(operator) && !"===".equals(operator)) {
                    issues.add(ParseIssue.of(spec.module(), format(), ParseIssueType.FIELD_MISSING,
                            "第" + lineNo + "行组件[" + name + "]使用范围操作符 " + operator
                                    + version + "，未固定到确切版本，以声明上界版本做尽力判定: " + version));
                }
                collector.accept(new ComponentCoordinate(ManifestFormat.REQUIREMENTS_TXT.ecosystem(),
                        "", name), version, truncate(raw));
                validEntries++;
            }
            cancelToken.checkPoint();
        } catch (ScanCancelledException e) {
            throw e;
        } catch (RuntimeException e) {
            issues.add(new ParseIssue(spec.module(), format(), ParseIssueType.MALFORMED_MANIFEST,
                    "requirements.txt 解析异常: " + e.getClass().getSimpleName() + ": " + e.getMessage(), null));
            log.warn("模块[{}]requirements 解析异常: {}", spec.module(), e.toString());
        }

        issues.addAll(collector.issues());
        boolean malformed = issues.stream()
                .anyMatch(i -> i.type() == ParseIssueType.MALFORMED_MANIFEST);
        if (validEntries == 0 && collector.dependencies().isEmpty() && !malformed) {
            issues.add(ParseIssue.of(spec.module(), format(), ParseIssueType.EMPTY_MANIFEST,
                    "清单中没有任何有效依赖条目"));
        }
        log.info("模块[{}]requirements 解析完成: 有效依赖={} 结论条数={}",
                spec.module(), collector.dependencies().size(), issues.size());
        return new ModuleParseResult(spec.module(), format(),
                List.copyOf(collector.dependencies()), List.copyOf(issues));
    }

    /** PEP503：名称统一小写并将 . _ - 归一为 -。 */
    private String normalizeName(String name) {
        return name.toLowerCase().replaceAll("[._-]+", "-");
    }

    private String stripComment(String line) {
        // 保留 URL 中的 # 不做复杂处理；requirements 行内注释前必须有空格
        int hash = line.indexOf(" #");
        return hash >= 0 ? line.substring(0, hash) : line;
    }

    private String truncate(String s) {
        if (s == null) {
            return null;
        }
        return s.length() <= 120 ? s : s.substring(0, 120) + "...";
    }
}
