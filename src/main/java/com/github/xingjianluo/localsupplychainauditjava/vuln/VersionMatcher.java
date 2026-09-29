package com.github.xingjianluo.localsupplychainauditjava.vuln;

import com.github.xingjianluo.localsupplychainauditjava.model.AffectedRange;

/**
 * Compares dotted versions and tests range membership.
 * Splitting is done on {@code .} and {@code -}; numeric segments compare by
 * magnitude and other segments lexicographically (numbers sort before letters,
 * so {@code 1.0-rc1} &lt; {@code 1.0}). Different segment counts are handled by
 * padding the shorter version with empty segments.
 */
public final class VersionMatcher {

    private VersionMatcher() {
    }

    public static int compare(String v1, String v2) {
        if (v1 == null && v2 == null) {
            return 0;
        }
        if (v1 == null) {
            return -1;
        }
        if (v2 == null) {
            return 1;
        }
        String[] a = v1.strip().split("[.\\-]", -1);
        String[] b = v2.strip().split("[.\\-]", -1);
        int common = Math.min(a.length, b.length);
        for (int i = 0; i < common; i++) {
            int cmp = compareSegment(a[i], b[i]);
            if (cmp != 0) {
                return cmp;
            }
        }
        if (a.length == b.length) {
            return 0;
        }
        // One version is a prefix of the other. An extra numeric segment means a
        // higher release (1.0 < 1.0.1); an extra textual qualifier means a
        // pre-release, which sorts below the plain release (1.0-rc1 < 1.0).
        String[] longer = a.length > b.length ? a : b;
        String extra = longer[common];
        int qualifierOrder = isNumeric(extra) ? 1 : -1;
        return a.length > b.length ? qualifierOrder : -qualifierOrder;
    }

    private static int compareSegment(String s1, String s2) {
        boolean n1 = isNumeric(s1);
        boolean n2 = isNumeric(s2);
        if (n1 && n2) {
            return Long.compare(Long.parseLong(s1), Long.parseLong(s2));
        }
        if (n1) {
            // numeric release segment precedes a textual qualifier
            return -1;
        }
        if (n2) {
            return 1;
        }
        return s1.compareTo(s2);
    }

    private static boolean isNumeric(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Range membership with inclusive lower and exclusive upper bound.
     * A null bound means open-ended. Null/blank versions never match.
     */
    public static boolean inRange(String version, AffectedRange range) {
        if (version == null || version.isBlank() || range == null) {
            return false;
        }
        if (range.startInclusive() != null && !range.startInclusive().isBlank()
                && compare(version, range.startInclusive()) < 0) {
            return false;
        }
        if (range.endExclusive() != null && !range.endExclusive().isBlank()
                && compare(version, range.endExclusive()) >= 0) {
            return false;
        }
        return true;
    }
}
