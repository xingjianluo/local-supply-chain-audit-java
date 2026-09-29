package com.github.xingjianluo.localsupplychainauditjava.vuln;

/** 本地漏洞库文件缺失、不可读或内容损坏时抛出。 */
public class VulnLibraryLoadException extends RuntimeException {
    public VulnLibraryLoadException(String message) {
        super(message);
    }

    public VulnLibraryLoadException(String message, Throwable cause) {
        super(message, cause);
    }
}
