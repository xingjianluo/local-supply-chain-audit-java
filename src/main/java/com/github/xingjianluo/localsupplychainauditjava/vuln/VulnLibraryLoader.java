package com.github.xingjianluo.localsupplychainauditjava.vuln;

import com.github.xingjianluo.localsupplychainauditjava.model.VulnLibrary;

/**
 * 本地漏洞库加载器：从本机 JSON 文件加载某个版本的漏洞库，全程不访问网络。
 * 库文件中显式携带 id/version，扫描结论与该版本绑定。
 */
public interface VulnLibraryLoader {

    /** 加载默认漏洞库（配置路径）。 */
    VulnLibrary loadDefault();

    /** 加载指定路径的漏洞库。 */
    VulnLibrary load(String path);

    /** 当前默认库（可能为 null，需在扫描时给出明确失败结论）。 */
    VulnLibrary current();
}
