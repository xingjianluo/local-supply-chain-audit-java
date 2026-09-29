package com.github.xingjianluo.localsupplychainauditjava.parse;

import com.github.xingjianluo.localsupplychainauditjava.model.ManifestInput;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/** Shared helper for reading inline content or a local file, fully offline. */
final class ManifestReadingSupport {

    private static final Logger log = LoggerFactory.getLogger(ManifestReadingSupport.class);

    /** Maximum accepted manifest size (8 MiB) to keep memory bounded. */
    static final long MAX_MANIFEST_BYTES = 8L * 1024 * 1024;

    private ManifestReadingSupport() {
    }

    /**
     * Resolve manifest text: inline content takes precedence, otherwise the local
     * file at {@link ManifestInput#path()} is read with a bounded size check.
     *
     * @throws IOException when the file cannot be read or exceeds the size limit
     */
    static String read(ManifestInput input) throws IOException {
        if (input.content() != null) {
            log.debug("Reading manifest for module='{}' from inline content ({} chars)",
                    input.moduleId(), input.content().length());
            return input.content();
        }
        if (input.path() == null || input.path().isBlank()) {
            throw new IOException("manifest has neither inline content nor a path");
        }
        var path = Paths.get(input.path());
        if (!Files.isRegularFile(path)) {
            throw new IOException("manifest file does not exist or is not a regular file: " + path);
        }
        long size = Files.size(path);
        if (size > MAX_MANIFEST_BYTES) {
            throw new IOException("manifest file too large: " + size + " bytes (limit "
                    + MAX_MANIFEST_BYTES + ")");
        }
        log.debug("Reading manifest for module='{}' from local file '{}' ({} bytes)",
                input.moduleId(), path, size);
        return Files.readString(path);
    }
}
