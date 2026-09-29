package com.github.xingjianluo.localsupplychainauditjava.engine;

import com.github.xingjianluo.localsupplychainauditjava.core.CancelToken;
import com.github.xingjianluo.localsupplychainauditjava.model.ManifestFormat;
import com.github.xingjianluo.localsupplychainauditjava.model.MergedComponent;
import com.github.xingjianluo.localsupplychainauditjava.model.ModuleParseResult;
import com.github.xingjianluo.localsupplychainauditjava.model.ModuleSpec;
import com.github.xingjianluo.localsupplychainauditjava.model.ParseIssue;
import com.github.xingjianluo.localsupplychainauditjava.model.ParseIssueType;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanRequest;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanSnapshot;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanStatus;
import com.github.xingjianluo.localsupplychainauditjava.model.VulnLibrary;
import com.github.xingjianluo.localsupplychainauditjava.parser.FormatDetector;
import com.github.xingjianluo.localsupplychainauditjava.parser.ManifestParser;
import com.github.xingjianluo.localsupplychainauditjava.parser.ManifestParserRegistry;
import com.github.xingjianluo.localsupplychainauditjava.service.AuditProperties;
import com.github.xingjianluo.localsupplychainauditjava.vuln.JsonFileVulnLibraryLoader;
import com.github.xingjianluo.localsupplychainauditjava.vuln.VulnLibraryLoadException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * 默认扫描引擎。单模块的任何失败都转化为该模块的 ParseIssue，不影响其它模块与整次扫描；
 * 仅漏洞库不可用等整体性错误才使扫描 FAILED。每处理一个模块检查一次取消点。
 */
@Component
public class DefaultScanEngine implements ScanEngine {

    private static final Logger log = LoggerFactory.getLogger(DefaultScanEngine.class);

    private final FormatDetector formatDetector;
    private final ManifestParserRegistry parserRegistry;
    private final VulnMatcher matcher;
    private final JsonFileVulnLibraryLoader libraryLoader;
    private final AuditProperties properties;

    public DefaultScanEngine(FormatDetector formatDetector,
                             ManifestParserRegistry parserRegistry,
                             VulnMatcher matcher,
                             JsonFileVulnLibraryLoader libraryLoader,
                             AuditProperties properties) {
        this.formatDetector = formatDetector;
        this.parserRegistry = parserRegistry;
        this.matcher = matcher;
        this.libraryLoader = libraryLoader;
        this.properties = properties;
    }

    @Override
    public ScanSnapshot execute(String scanId, ScanRequest request, CancelToken cancelToken) {
        long submittedAt = System.currentTimeMillis();
        List<ModuleSpec> modules = request.safeModules();
        log.info("扫描开始: scanId={} 模块数={} 漏洞库路径={}", scanId, modules.size(),
                request.vulnLibraryPath());

        // 1) 漏洞库必须先确定版本，结论与库版本绑定；库不可用属于整体性失败
        VulnLibrary library;
        try {
            String libPath = request.vulnLibraryPath();
            library = (libPath == null || libPath.isBlank())
                    ? libraryLoader.loadDefault()
                    : libraryLoader.load(libPath);
        } catch (VulnLibraryLoadException e) {
            log.error("扫描失败: scanId={} 原因=漏洞库不可用: {}", scanId, e.getMessage());
            return snapshot(scanId, null, modules.size(), List.of(), List.of(), List.of(),
                    "漏洞库不可用: " + e.getMessage(), submittedAt);
        }
        if (cancelToken.isCancelled()) {
            return cancelled(scanId, library, modules.size(), submittedAt);
        }

        // 2) 逐模块读取+解析，坏文件只影响自己；依赖即时增量聚合，不保留逐版本中间列表
        ComponentAccumulator accumulator = new ComponentAccumulator();
        List<ParseIssue> issues = new ArrayList<>();
        int index = 0;
        try {
            for (ModuleSpec spec : modules) {
                index++;
                cancelToken.checkPoint();
                String moduleName = spec.module() != null && !spec.module().isBlank()
                        ? spec.module()
                        : ("module-" + index);
                ModuleSpec named = new ModuleSpec(moduleName, spec.path(), spec.content(), spec.format());
                log.info("扫描模块[{}/{}]: module={} path={} format={}",
                        index, modules.size(), moduleName, named.path(), named.format());
                ModuleParseResult result = processOne(named, cancelToken);
                accumulator.addAll(result.dependencies());
                issues.addAll(result.issues());
                log.info("模块处理完毕: module={} 依赖数={} 结论数={}",
                        moduleName, result.dependencies().size(), result.issues().size());
            }

            // 3) 跨模块合并去重（视图生成，不复制版本/模块集合内容之外的逐版本引用）
            cancelToken.checkPoint();
            ComponentAccumulator.MergeView merged = accumulator.snapshot();
            issues.addAll(merged.issues());

            // 4) 漏洞匹配（使用本次扫描绑定的库快照，遍历紧凑聚合视图）
            cancelToken.checkPoint();
            var findings = matcher.match(accumulator.matchingView(), library);

            // 5) 组件明细按配置上限截断，findings/issues 始终完整；统计数保持准确
            cancelToken.checkPoint();
            int totalComponents = merged.components().size();
            int limit = properties.getMaxComponentsInSnapshot();
            List<MergedComponent> kept = merged.components();
            if (limit > 0 && totalComponents > limit) {
                kept = new ArrayList<>(merged.components().subList(0, limit));
                issues.add(ParseIssue.of(null, null, ParseIssueType.COMPONENT_LIST_TRUNCATED,
                        "合并后组件总数 " + totalComponents + " 超过快照上限 " + limit
                                + "，为控制内存仅保留前 " + limit
                                + " 条组件明细；漏洞命中(findings)与全部解析结论(issues)完整保留，"
                                + "未截断组件不影响风险判定"));
                log.warn("组件明细截断: 总数={} 保留={} findings/issues 保持完整",
                        totalComponents, limit);
            }

            cancelToken.checkPoint();
            log.info("扫描完成: scanId={} lib={}/{} 组件总数={} 保留明细={} 命中={} 结论数={}",
                    scanId, library.libraryId(), library.version(),
                    totalComponents, kept.size(), findings.size(), issues.size());
            return new ScanSnapshot(scanId, ScanStatus.COMPLETED, library.libraryId(),
                    library.version(), modules.size(), totalComponents, kept, findings,
                    List.copyOf(issues), null, submittedAt, System.currentTimeMillis());
        } catch (com.github.xingjianluo.localsupplychainauditjava.core.ScanCancelledException e) {
            // 取消在任何检查点生效：不发布半成品组件/命中，仅落终态快照（仍绑定本次库版本）
            log.warn("扫描被取消: scanId={} 已处理模块数={}，半成品结论全部丢弃", scanId, index);
            return new ScanSnapshot(scanId, ScanStatus.CANCELLED, library.libraryId(),
                    library.version(), modules.size(), 0, List.of(), List.of(), List.of(),
                    "扫描在结论合并前已取消，未发布任何半成品结论",
                    submittedAt, System.currentTimeMillis());
        }
    }

    private ModuleParseResult processOne(ModuleSpec spec, CancelToken cancelToken) {
        boolean hasPath = spec.path() != null && !spec.path().isBlank();
        boolean hasContent = spec.content() != null && !spec.content().isBlank();
        if (!hasPath && !hasContent) {
            return new ModuleParseResult(spec.module(), ManifestFormat.UNKNOWN, List.of(),
                    List.of(ParseIssue.of(spec.module(), ManifestFormat.UNKNOWN,
                            ParseIssueType.MISSING_SOURCE,
                            "模块既未提供 path 也未提供 content，无法扫描，已明确跳过")));
        }

        String content = null;
        ManifestFormat declared = spec.format();
        if (hasPath) {
            Path file = Path.of(spec.path());
            if (!Files.isRegularFile(file) || !Files.isReadable(file)) {
                return new ModuleParseResult(spec.module(),
                        declared != null ? declared : ManifestFormat.UNKNOWN, List.of(),
                        List.of(ParseIssue.of(spec.module(),
                                declared != null ? declared : ManifestFormat.UNKNOWN,
                                ParseIssueType.UNREADABLE_SOURCE,
                                "清单文件不存在或不可读: " + file)));
            }
            if (!hasContent) {
                try {
                    content = Files.readString(file, StandardCharsets.UTF_8);
                } catch (IOException e) {
                    return new ModuleParseResult(spec.module(),
                            declared != null ? declared : ManifestFormat.UNKNOWN, List.of(),
                            List.of(ParseIssue.of(spec.module(),
                                    declared != null ? declared : ManifestFormat.UNKNOWN,
                                    ParseIssueType.UNREADABLE_SOURCE,
                                    "读取清单失败: " + e.getClass().getSimpleName()
                                            + ": " + e.getMessage())));
                }
            }
        }
        if (hasContent) {
            content = spec.content();
        }

        ManifestFormat format = formatDetector.detect(spec, content);
        ManifestParser parser = parserRegistry.find(format).orElse(null);
        if (parser == null) {
            return new ModuleParseResult(spec.module(), format, List.of(),
                    List.of(ParseIssue.of(spec.module(), format, ParseIssueType.UNSUPPORTED_FORMAT,
                            "不支持的清单格式(探测结果=" + format + ")，path=" + spec.path())));
        }
        try {
            return parser.parse(spec, content, cancelToken);
        } catch (RuntimeException e) {
            // 兜底：解析器约定不抛异常，这里确保单个坏文件绝不可能中断整次扫描
            log.warn("模块[{}]解析器抛出未预期异常，已隔离: {}", spec.module(), e.toString());
            return new ModuleParseResult(spec.module(), format, List.of(),
                    List.of(ParseIssue.of(spec.module(), format, ParseIssueType.MALFORMED_MANIFEST,
                            "解析器内部异常已隔离: " + e.getClass().getSimpleName()
                                    + ": " + e.getMessage())));
        }
    }

    private ScanSnapshot cancelled(String scanId, VulnLibrary library, int moduleCount, long submittedAt) {
        return new ScanSnapshot(scanId, ScanStatus.CANCELLED,
                library == null ? null : library.libraryId(),
                library == null ? null : library.version(),
                moduleCount, 0, List.of(), List.of(), List.of(),
                "扫描在合并结论前已取消，无半成品结论输出", submittedAt, System.currentTimeMillis());
    }

    private ScanSnapshot snapshot(String scanId, VulnLibrary library, int moduleCount,
                                  List<MergedComponent> components,
                                  List<com.github.xingjianluo.localsupplychainauditjava.model.Finding> findings,
                                  List<ParseIssue> issues, String error, long submittedAt) {
        return new ScanSnapshot(scanId, ScanStatus.FAILED,
                library == null ? null : library.libraryId(),
                library == null ? null : library.version(),
                moduleCount, components.size(), components, findings, issues, error, submittedAt,
                System.currentTimeMillis());
    }
}
