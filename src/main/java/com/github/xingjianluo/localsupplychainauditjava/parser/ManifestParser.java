package com.github.xingjianluo.localsupplychainauditjava.parser;

import com.github.xingjianluo.localsupplychainauditjava.core.CancelToken;
import com.github.xingjianluo.localsupplychainauditjava.model.ManifestFormat;
import com.github.xingjianluo.localsupplychainauditjava.model.ModuleParseResult;
import com.github.xingjianluo.localsupplychainauditjava.model.ModuleSpec;

/** 单一清单格式的解析器。 */
public interface ManifestParser {

    ManifestFormat format();

    boolean sniff(ModuleSpec spec, String content);

    /**
     * 解析模块清单。任何可预期的异常都必须转化为结果中的 ParseIssue，
     * 不得抛出异常，更不得让单个坏文件中断整次扫描。
     */
    ModuleParseResult parse(ModuleSpec spec, String content, CancelToken cancelToken);
}
