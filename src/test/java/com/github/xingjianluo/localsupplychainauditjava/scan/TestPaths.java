package com.github.xingjianluo.localsupplychainauditjava.scan;

import java.net.URISyntaxException;
import java.nio.file.Path;

/** Resolves test-only local fixture directories from the classpath (fully offline). */
final class TestPaths {

    private TestPaths() {
    }

    static Path vulndbV1() {
        return resourceDir("test-vulndb");
    }

    static Path vulndbV2() {
        return resourceDir("test-vulndb-v2");
    }

    private static Path resourceDir(String name) {
        try {
            return Path.of(TestPaths.class.getClassLoader().getResource(name).toURI());
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }
}
