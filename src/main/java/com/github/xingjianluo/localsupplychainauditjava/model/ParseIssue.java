package com.github.xingjianluo.localsupplychainauditjava.model;

/** 针对某个模块清单的一条可追溯解析结论。 */
public record ParseIssue(String module,
                        ManifestFormat format,
                        ParseIssueType type,
                        String detail,
                        String rawSnippet) {

    public static ParseIssue of(String module, ManifestFormat format, ParseIssueType type, String detail) {
        return new ParseIssue(module, format, type, detail, null);
    }
}
