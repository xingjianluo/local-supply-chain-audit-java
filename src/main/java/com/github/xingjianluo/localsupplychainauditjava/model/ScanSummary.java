package com.github.xingjianluo.localsupplychainauditjava.model;

/**
 * Aggregate counters of a scan conclusion.
 */
public record ScanSummary(int manifestTotal, int manifestParsed, int manifestPartiallyParsed,
                          int manifestCorrupt, int issueCount, int componentCount,
                          int componentsAtRisk, int findingTotal,
                          int critical, int high, int medium, int low) {
}
