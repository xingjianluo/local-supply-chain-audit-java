package com.github.xingjianluo.localsupplychainauditjava.model;

/**
 * 一次扫描中待处理的模块输入。
 * path 与 content 至少有一个非空；format 为 null 时按文件名/内容嗅探。
 */
public record ModuleSpec(String module, String path, String content, ManifestFormat format) {
}
