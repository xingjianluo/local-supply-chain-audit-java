package com.github.xingjianluo.localsupplychainauditjava.model;

/**
 * Version interval affected by a vulnerability.
 * Bound comparison supports plain numeric dotted versions; non-numeric segments
 * are compared lexicographically, matching logic is in vuln package.
 *
 * @param startInclusive lower bound, null means unbounded
 * @param endExclusive   upper bound (exclusive), null means unbounded
 */
public record AffectedRange(String startInclusive, String endExclusive) {
}
