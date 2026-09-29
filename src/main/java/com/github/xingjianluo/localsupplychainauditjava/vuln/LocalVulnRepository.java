package com.github.xingjianluo.localsupplychainauditjava.vuln;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.xingjianluo.localsupplychainauditjava.model.AffectedRange;
import com.github.xingjianluo.localsupplychainauditjava.model.RiskLevel;
import com.github.xingjianluo.localsupplychainauditjava.model.VulnDatabase;
import com.github.xingjianluo.localsupplychainauditjava.model.VulnerabilityEntry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Stream;

/**
 * File based, fully offline implementation of {@link VulnRepository}.
 * The library directory may contain one or more {@code *.json} files shaped as
 * {@code {"entries":[{...}]}}. The snapshot version id is a SHA-256 over the
 * sorted file names and their bytes, so identical content always maps to the
 * same version while updated content produces a new version. Every snapshot ever
 * loaded is retained (immutable) so historical scans can be reproduced.
 */
@Repository
public class LocalVulnRepository implements VulnRepository {

    private static final Logger log = LoggerFactory.getLogger(LocalVulnRepository.class);
    private static final long MAX_FILE_BYTES = 16L * 1024 * 1024;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final Map<String, VulnDatabase> byVersion = new ConcurrentHashMap<>();
    private volatile Path cachedDirectory;
    private volatile String cachedVersion;

    @Override
    public VulnDatabase loadSnapshot(Path directory) {
        String version = cachedVersion;
        if (directory.equals(cachedDirectory) && version != null) {
            VulnDatabase snapshot = byVersion.get(version);
            if (snapshot != null) {
                log.debug("Reusing cached vulnerability snapshot {} for '{}'", version, directory);
                return snapshot;
            }
        }
        return refresh(directory);
    }

    @Override
    public VulnDatabase getByVersion(String versionId) {
        return byVersion.get(versionId);
    }

    @Override
    public VulnDatabase refresh(Path directory) {
        log.info("Loading local vulnerability library from '{}'", directory);
        List<Path> files = listJsonFiles(directory);
        List<VulnerabilityEntry> entries = new ArrayList<>();
        MessageDigest sha256;
        try {
            sha256 = MessageDigest.getInstance("SHA-256");
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
        for (Path file : files) {
            byte[] bytes;
            try {
                long size = Files.size(file);
                if (size > MAX_FILE_BYTES) {
                    throw new IOException("vulndb file too large: " + size + " bytes");
                }
                bytes = Files.readAllBytes(file);
            } catch (IOException e) {
                // A single unreadable file must not be silently ignored.
                throw new IllegalStateException("cannot read vulndb file " + file + ": " + e.getMessage(), e);
            }
            sha256.update(file.getFileName().toString().getBytes());
            sha256.update((byte) 0);
            sha256.update(bytes);
            entries.addAll(parseEntries(file, bytes));
        }
        String versionId = "vdb-" + HexFormat.of().formatHex(sha256.digest()).substring(0, 16);
        VulnDatabase snapshot = new VulnDatabase(versionId, Instant.now(), directory,
                List.copyOf(entries));
        byVersion.put(versionId, snapshot);
        cachedDirectory = directory;
        cachedVersion = versionId;
        log.info("Vulnerability library snapshot {} loaded: {} entr(y/ies) from {} file(s)",
                versionId, entries.size(), files.size());
        return snapshot;
    }

    private List<Path> listJsonFiles(Path directory) {
        if (!Files.isDirectory(directory)) {
            throw new IllegalStateException("vulnerability library directory not found: " + directory);
        }
        try (Stream<Path> stream = Files.list(directory)) {
            List<Path> files = stream
                    .filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().toLowerCase().endsWith(".json"))
                    .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                    .toList();
            if (files.isEmpty()) {
                throw new IllegalStateException("no *.json vulnerability files in " + directory);
            }
            return files;
        } catch (IOException e) {
            throw new IllegalStateException("cannot list vulnerability library directory " + directory, e);
        }
    }

    private List<VulnerabilityEntry> parseEntries(Path file, byte[] bytes) {
        JsonNode root;
        try {
            root = MAPPER.readTree(bytes);
        } catch (IOException e) {
            throw new IllegalStateException("malformed vulndb JSON in " + file + ": " + e.getMessage(), e);
        }
        JsonNode array = root == null ? null : root.get("entries");
        if (array == null || !array.isArray()) {
            throw new IllegalStateException("vulndb file " + file + " must contain an 'entries' array");
        }
        List<VulnerabilityEntry> parsed = new ArrayList<>();
        int i = 0;
        for (JsonNode node : array) {
            parsed.add(parseEntry(node, file, i++));
        }
        return parsed;
    }

    private VulnerabilityEntry parseEntry(JsonNode node, Path file, int index) {
        String vulnId = text(node, "vulnId");
        String group = text(node, "group");
        String name = text(node, "name");
        String fixedIn = text(node, "fixedIn");
        String levelText = text(node, "level");
        String title = text(node, "title");
        String description = text(node, "description");
        if (vulnId == null || group == null || name == null || levelText == null) {
            throw new IllegalStateException("vulndb entry " + file + "[" + index
                    + "] missing required field (vulnId/group/name/level)");
        }
        RiskLevel level;
        try {
            level = RiskLevel.valueOf(levelText.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("vulndb entry " + file + "[" + index
                    + "] has unknown risk level '" + levelText + "'");
        }
        List<AffectedRange> ranges = new ArrayList<>();
        JsonNode rangesNode = node.get("ranges");
        if (rangesNode != null && rangesNode.isArray()) {
            for (JsonNode range : rangesNode) {
                ranges.add(new AffectedRange(text(range, "startInclusive"), text(range, "endExclusive")));
            }
        }
        return new VulnerabilityEntry(vulnId, group, name, List.copyOf(ranges),
                fixedIn, level, title, description);
    }

    private String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        if (value == null || value.isNull() || !value.isTextual()) {
            return null;
        }
        String text = value.asText();
        return text.isBlank() ? null : text.strip();
    }
}
