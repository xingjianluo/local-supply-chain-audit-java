package com.github.xingjianluo.localsupplychainauditjava.parser;

import com.github.xingjianluo.localsupplychainauditjava.model.ManifestFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** 按 {@link ManifestFormat} 注册与查找解析器。 */
@Component
public class ManifestParserRegistry {

    private static final Logger log = LoggerFactory.getLogger(ManifestParserRegistry.class);

    private final Map<ManifestFormat, ManifestParser> parsers;

    public ManifestParserRegistry(List<ManifestParser> parserBeans) {
        Map<ManifestFormat, ManifestParser> map = new EnumMap<>(ManifestFormat.class);
        for (ManifestParser parser : parserBeans) {
            ManifestParser previous = map.put(parser.format(), parser);
            if (previous != null) {
                log.warn("格式{}存在多个解析器，后者覆盖: {} -> {}", parser.format(),
                        previous.getClass().getSimpleName(), parser.getClass().getSimpleName());
            }
        }
        this.parsers = Map.copyOf(map);
        log.info("已注册清单解析器: {}", this.parsers.keySet());
    }

    public Optional<ManifestParser> find(ManifestFormat format) {
        return Optional.ofNullable(parsers.get(format));
    }
}
