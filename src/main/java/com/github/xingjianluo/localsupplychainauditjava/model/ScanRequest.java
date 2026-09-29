package com.github.xingjianluo.localsupplychainauditjava.model;

import java.util.List;

/** 提交扫描的请求体：一组模块清单 + 指定/默认漏洞库。 */
public record ScanRequest(List<ModuleSpec> modules, String vulnLibraryPath) {

    public List<ModuleSpec> safeModules() {
        return modules == null ? List.of() : modules;
    }
}
