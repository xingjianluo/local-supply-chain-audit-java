package com.github.xingjianluo.localsupplychainauditjava.parser;

import com.github.xingjianluo.localsupplychainauditjava.model.ManifestFormat;
import com.github.xingjianluo.localsupplychainauditjava.model.ModuleSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Locale;

/**
 * 清单格式探测：优先使用显式声明的 format，否则按文件名，再按内容特征嗅探。
 */
@Component
public class FormatDetector {

    private static final Logger log = LoggerFactory.getLogger(FormatDetector.class);

    public ManifestFormat detect(ModuleSpec spec, String content) {
        if (spec.format() != null) {
            log.debug("模块[{}]使用显式格式声明: {}", spec.module(), spec.format());
            return spec.format();
        }
        String path = spec.path();
        if (path != null && !path.isBlank()) {
            String lower = path.toLowerCase(Locale.ROOT);
            String name = lower.substring(lower.lastIndexOf('/') + 1);
            ManifestFormat byName = switch (name) {
                case "pom.xml" -> ManifestFormat.POM_XML;
                case "package-lock.json" -> ManifestFormat.PACKAGE_LOCK_JSON;
                case "requirements.txt" -> ManifestFormat.REQUIREMENTS_TXT;
                default -> null;
            };
            if (byName != null) {
                log.debug("模块[{}]按文件名识别格式: {} ({})", spec.module(), byName, name);
                return byName;
            }
        }
        ManifestFormat byContent = sniffContent(content);
        log.debug("模块[{}]按内容嗅探格式: {}", spec.module(), byContent);
        return byContent;
    }

    private ManifestFormat sniffContent(String content) {
        if (content == null || content.isBlank()) {
            return ManifestFormat.UNKNOWN;
        }
        String trimmed = content.stripLeading();
        if (trimmed.startsWith("<")) {
            return ManifestFormat.POM_XML;
        }
        if (trimmed.startsWith("{")) {
            return ManifestFormat.PACKAGE_LOCK_JSON;
        }
        // requirements.txt 无强结构特征，保守地在包含 PEP508 风格依赖行时识别
        for (String line : content.split("\\R", 50)) {
            String l = line.trim();
            if (!l.isEmpty() && !l.startsWith("#") && looksLikeRequirement(l)) {
                return ManifestFormat.REQUIREMENTS_TXT;
            }
        }
        return ManifestFormat.UNKNOWN;
    }

    private boolean looksLikeRequirement(String line) {
        // 去掉环境标记后，形如 name[extras]>=1.0 的简单判定
        String core = line.split(";", 2)[0];
        return core.matches("(?i)[a-z0-9._-]+(\\[[^]]*])?\\s*(==|>=|<=|~=|!=|>|<|===).*");
    }
}
