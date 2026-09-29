package com.github.xingjianluo.localsupplychainauditjava.tests;

import com.github.xingjianluo.localsupplychainauditjava.core.CancelToken;
import com.github.xingjianluo.localsupplychainauditjava.model.ComponentCoordinate;
import com.github.xingjianluo.localsupplychainauditjava.model.DependencyRef;
import com.github.xingjianluo.localsupplychainauditjava.model.ManifestFormat;
import com.github.xingjianluo.localsupplychainauditjava.model.ModuleParseResult;
import com.github.xingjianluo.localsupplychainauditjava.model.ModuleSpec;
import com.github.xingjianluo.localsupplychainauditjava.model.ParseIssueType;
import com.github.xingjianluo.localsupplychainauditjava.parser.PackageLockJsonParser;
import com.github.xingjianluo.localsupplychainauditjava.parser.PomXmlParser;
import com.github.xingjianluo.localsupplychainauditjava.parser.RequirementsTxtParser;
import com.github.xingjianluo.localsupplychainauditjava.service.AuditProperties;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 清单解析单测：畸形清单 / 字段缺失 / 重复引用 / 同组件多版本等场景，
 * 日志打印输入、关键状态与判定依据。
 */
class ManifestParserTest {

    private static final Logger log = LoggerFactory.getLogger(ManifestParserTest.class);
    private static final CancelToken NEVER = CancelToken.never();
    private static final AuditProperties PROPS = new AuditProperties();

    // ---------- requirements.txt ----------

    @Test
    void requirementsDuplicateAndMultipleVersionsAreDistinguished() {
        String input = """
                # comment
                requests==2.31.0
                requests==2.31.0
                urllib3>=1.26
                flask==3.0.0
                -r other-requirements.txt
                this is not a requirement line
                """;
        log.info("[输入 requirements]\n{}", input);
        ModuleParseResult result = new RequirementsTxtParser(PROPS)
                .parse(spec("m-req", ManifestFormat.REQUIREMENTS_TXT, input), input, NEVER);

        long dup = count(result, ParseIssueType.DUPLICATE_REFERENCE);
        long missing = count(result, ParseIssueType.FIELD_MISSING);
        long malformed = count(result, ParseIssueType.MALFORMED_MANIFEST);
        log.info("[关键状态变化] 依赖={} 重复引用结论={} 字段缺失={} 畸形行={}",
                result.dependencies().size(), dup, missing, malformed);

        assertEquals(1, dup, "重复的 requests==2.31.0 必须形成可区分的重复结论");
        assertTrue(missing >= 2, "范围版本与 -r 选项行都要形成字段缺失类结论");
        assertEquals(1, malformed, "无法识别的行必须给出 MALFORMED 结论而非静默丢弃");
        assertTrue(result.dependencies().stream()
                .anyMatch(d -> d.coordinate().name().equals("requests") && d.version().equals("2.31.0")));
        assertTrue(result.dependencies().stream()
                .anyMatch(d -> d.coordinate().name().equals("urllib3") && d.version().equals("1.26")));
    }

    @Test
    void requirementsEmptyAndBlankHaveExplicitConclusions() {
        String input = "# only comments\n\n   \n";
        log.info("[输入 requirements 空清单]\n{}", input);
        ModuleParseResult result = new RequirementsTxtParser(PROPS)
                .parse(spec("m-empty", ManifestFormat.REQUIREMENTS_TXT, input), input, NEVER);
        assertEquals(1, count(result, ParseIssueType.EMPTY_MANIFEST),
                "空清单必须有 EMPTY_MANIFEST 结论，不允许静默通过");
        assertTrue(result.dependencies().isEmpty());
    }

    // ---------- package-lock.json ----------

    @Test
    void packageLockV3ParsesScopedNestedAndDedups() {
        String input = """
                {
                  "name": "app",
                  "version": "1.0.0",
                  "lockfileVersion": 3,
                  "packages": {
                    "": {"name": "app", "version": "1.0.0"},
                    "node_modules/@scope/pkg-a": {"version": "2.0.0", "resolved": "x"},
                    "node_modules/lodash": {"version": "4.17.20"},
                    "node_modules/lodash": {"version": "4.17.20"},
                    "node_modules/lodash.merge/node_modules/lodash": {"version": "3.10.1"},
                    "node_modules/linked-pkg": {"version": "1.0.0", "link": true}
                  }
                }
                """;
        log.info("[输入 package-lock v3] 含 scoped/嵌套提升/重复/link");
        ModuleParseResult result = new PackageLockJsonParser(PROPS)
                .parse(spec("m-lock", ManifestFormat.PACKAGE_LOCK_JSON, input), input, NEVER);
        log.info("[关键状态变化] 依赖={} 结论类型={}",
                result.dependencies().size(), result.issues().stream().map(i -> i.type().name()).toList());

        // JSON 同名键以最后一条为准(4.17.20)，嵌套路径 lodash@3.10.1 构成同组件多版本
        assertTrue(hasDependency(result, "npm", "", "lodash", "4.17.20"));
        assertTrue(hasDependency(result, "npm", "", "lodash", "3.10.1"));
        assertTrue(hasDependency(result, "npm", "", "@scope/pkg-a", "2.0.0"));
        assertEquals(1, count(result, ParseIssueType.MULTIPLE_VERSIONS));
        assertFalse(result.dependencies().stream()
                .anyMatch(d -> d.coordinate().name().equals("linked-pkg")), "link 包不计入依赖");
    }

    @Test
    void packageLockV1NestedDependenciesSupported() {
        String input = """
                {
                  "name": "old-app",
                  "lockfileVersion": 1,
                  "dependencies": {
                    "left-pad": {
                      "version": "1.3.0",
                      "dependencies": {"nested-x": {"version": "0.0.1"}}
                    },
                    "debug": {"version": "4.3.4"}
                  }
                }
                """;
        log.info("[输入 package-lock v1] 嵌套 dependencies");
        ModuleParseResult result = new PackageLockJsonParser(PROPS)
                .parse(spec("m-v1", ManifestFormat.PACKAGE_LOCK_JSON, input), input, NEVER);
        assertTrue(hasDependency(result, "npm", "", "left-pad", "1.3.0"));
        assertTrue(hasDependency(result, "npm", "", "nested-x", "0.0.1"));
        assertTrue(hasDependency(result, "npm", "", "debug", "4.3.4"));
    }

    @Test
    void malformedPackageLockProducesIssueNotException() {
        String input = "{ \"lockfileVersion\": 3, \"packages\": { \"node_modules/x\": {\"version\": ";
        log.info("[输入 损坏 package-lock] 长度={} 内容={}", input.length(), input);
        ModuleParseResult result = new PackageLockJsonParser(PROPS)
                .parse(spec("m-bad", ManifestFormat.PACKAGE_LOCK_JSON, input), input, NEVER);
        long malformed = count(result, ParseIssueType.MALFORMED_MANIFEST);
        log.info("[判定依据] JSON 流式解析抛 IOException -> 转化为 MALFORMED_MANIFEST 结论，数量={}", malformed);
        assertTrue(malformed >= 1, "坏文件必须给出明确损坏结论");
    }

    // ---------- pom.xml ----------

    @Test
    void pomResolvesPropertiesAndReportsMissingVersion() {
        String input = """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>app</artifactId>
                  <version>1.2.0</version>
                  <properties><spring.version>6.1.2</spring.version></properties>
                  <dependencies>
                    <dependency>
                      <groupId>org.springframework</groupId>
                      <artifactId>spring-core</artifactId>
                      <version>${spring.version}</version>
                    </dependency>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>unmanaged</artifactId>
                    </dependency>
                  </dependencies>
                </project>
                """;
        log.info("[输入 pom] 含属性占位符与缺失版本依赖");
        ModuleParseResult result = new PomXmlParser(PROPS)
                .parse(spec("m-pom", ManifestFormat.POM_XML, input), input, NEVER);
        log.info("[关键状态变化] 依赖={} 结论={}", result.dependencies().size(),
                result.issues().stream().map(i -> i.type().name() + ":" + i.detail()).toList());

        assertTrue(hasDependency(result, "maven", "org.springframework", "spring-core", "6.1.2"),
                "${spring.version} 必须解析为属性值");
        assertEquals(1, count(result, ParseIssueType.FIELD_MISSING), "无版本依赖必须有字段缺失结论");
    }

    @Test
    void pomDependencyManagementIsNotDoubleCounted() {
        String input = """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>app</artifactId>
                  <version>1.0.0</version>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>org.managed</groupId>
                        <artifactId>managed-lib</artifactId>
                        <version>9.9.9</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>real-lib</artifactId>
                      <version>1.0.0</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
        log.info("[输入 pom] dependencyManagement 与 dependencies 同时存在");
        ModuleParseResult result = new PomXmlParser(PROPS)
                .parse(spec("m-dm", ManifestFormat.POM_XML, input), input, NEVER);
        log.info("[关键状态变化] 依赖={} 结论={}", result.dependencies().size(),
                result.issues().stream().map(i -> i.type().name() + ":" + i.detail()).toList());
        assertTrue(hasDependency(result, "maven", "com.example", "real-lib", "1.0.0"));
        assertFalse(result.dependencies().stream()
                        .anyMatch(d -> d.coordinate().name().equals("managed-lib")),
                "dependencyManagement 中的声明不得被当成实际依赖收录");
        assertEquals(1, count(result, ParseIssueType.DUPLICATE_REFERENCE),
                "managed 条目要有可追溯的不收录说明");
    }

    @Test
    void malformedPomIsReported() {
        String input = "<project><dependencies><dependency><groupId>g";
        log.info("[输入 损坏 pom] {}", input);
        ModuleParseResult result = new PomXmlParser(PROPS)
                .parse(spec("m-badpom", ManifestFormat.POM_XML, input), input, NEVER);
        long malformed = count(result, ParseIssueType.MALFORMED_MANIFEST);
        log.info("[判定依据] XML 解析失败 -> MALFORMED_MANIFEST 数量={}", malformed);
        assertTrue(malformed == 1);
    }

    // ---------- helpers ----------

    private static ModuleSpec spec(String module, ManifestFormat format, String content) {
        return new ModuleSpec(module, null, content, format);
    }

    private static long count(ModuleParseResult result, ParseIssueType type) {
        return result.issues().stream().filter(i -> i.type() == type).count();
    }

    private static boolean hasDependency(ModuleParseResult result, String ecosystem,
                                         String group, String name, String version) {
        ComponentCoordinate expected = new ComponentCoordinate(ecosystem, group, name);
        List<DependencyRef> deps = result.dependencies();
        boolean hit = deps.stream().anyMatch(d ->
                d.coordinate().equals(expected) && d.version().equals(version));
        log.debug("查找依赖 {}@{} -> {}", expected.normalizedKey(), version, hit);
        return hit;
    }
}
