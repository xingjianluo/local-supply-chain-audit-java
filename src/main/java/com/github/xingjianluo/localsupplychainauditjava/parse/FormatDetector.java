package com.github.xingjianluo.localsupplychainauditjava.parse;

import com.github.xingjianluo.localsupplychainauditjava.model.ManifestFormat;
import com.github.xingjianluo.localsupplychainauditjava.model.ManifestInput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** Detects manifest format from path suffix or content sniffing. */
@Component
public class FormatDetector {

    private static final Logger log = LoggerFactory.getLogger(FormatDetector.class);

    /**
     * Detect the format. Explicitly requested format always wins; otherwise the path
     * suffix is consulted, then the leading non-whitespace character of the content.
     *
     * @return detected format or {@code null} when it cannot be determined
     */
    public ManifestFormat detect(ManifestInput input) {
        if (input.format() != null) {
            log.debug("Format detection: caller explicitly specified {}", input.format());
            return input.format();
        }
        String path = input.path();
        if (path != null && !path.isBlank()) {
            String lower = path.toLowerCase();
            if (lower.endsWith(".xml") || lower.endsWith("pom") || lower.contains("pom.xml")) {
                return ManifestFormat.MAVEN_POM;
            }
            if (lower.endsWith(".json")) {
                return ManifestFormat.JSON_SBOM;
            }
        }
        String content = input.content();
        if (content != null) {
            String trimmed = content.stripLeading();
            if (trimmed.startsWith("<")) {
                return ManifestFormat.MAVEN_POM;
            }
            if (trimmed.startsWith("{")) {
                return ManifestFormat.JSON_SBOM;
            }
        }
        log.warn("Format detection failed for module={}, path={}", input.moduleId(), path);
        return null;
    }
}
