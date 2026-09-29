package com.github.xingjianluo.localsupplychainauditjava.model;

/** 受支持的本地依赖清单格式及其所属生态。 */
public enum ManifestFormat {
    POM_XML("maven", "pom.xml"),
    PACKAGE_LOCK_JSON("npm", "package-lock.json"),
    REQUIREMENTS_TXT("pypi", "requirements.txt"),
    UNKNOWN(null, null);

    private final String ecosystem;
    private final String defaultFileName;

    ManifestFormat(String ecosystem, String defaultFileName) {
        this.ecosystem = ecosystem;
        this.defaultFileName = defaultFileName;
    }

    public String ecosystem() {
        return ecosystem;
    }

    public String defaultFileName() {
        return defaultFileName;
    }
}
