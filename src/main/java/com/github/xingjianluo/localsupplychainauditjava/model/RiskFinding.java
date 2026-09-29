package com.github.xingjianluo.localsupplychainauditjava.model;

import java.util.Set;

/**
 * One de-duplicated vulnerability finding bound to concrete versions.
 *
 * @param vulnId           vulnerability identifier
 * @param level            severity
 * @param title            vulnerability title
 * @param affectedVersions versions present in the manifests that fall in range
 * @param fixedIn          fixed version if known
 */
public record RiskFinding(String vulnId, RiskLevel level, String title,
                          Set<String> affectedVersions, String fixedIn) {
}
