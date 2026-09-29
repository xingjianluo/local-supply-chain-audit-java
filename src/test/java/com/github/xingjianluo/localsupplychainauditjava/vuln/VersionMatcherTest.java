package com.github.xingjianluo.localsupplychainauditjava.vuln;

import com.github.xingjianluo.localsupplychainauditjava.model.AffectedRange;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

/** Version comparison and range membership tests, with judgment-basis logging. */
class VersionMatcherTest {

    private static final Logger log = LoggerFactory.getLogger(VersionMatcherTest.class);

    @Test
    void comparesNumericSegmentsByMagnitude() {
        log.info("INPUT compare('1.10.0','1.9.0'); BASIS: numeric segment 10 > 9");
        assertTrue(VersionMatcher.compare("1.10.0", "1.9.0") > 0);
        log.info("STATE/VERDICT: 1.10.0 is greater than 1.9.0");
    }

    @Test
    void ordersReleaseBeforeQualifier() {
        log.info("INPUT compare('1.0-rc1','1.0'); BASIS: numeric segment precedes textual qualifier");
        assertTrue(VersionMatcher.compare("1.0-rc1", "1.0") < 0);
    }

    @Test
    void rangeChecksBoundsCorrectly() {
        AffectedRange range = new AffectedRange("1.0.0", "1.2.0");
        log.info("INPUT range=[1.0.0,1.2.0); checking boundary versions");
        assertTrue(VersionMatcher.inRange("1.0.0", range), "lower bound inclusive");
        assertTrue(VersionMatcher.inRange("1.1.9", range), "inside range");
        assertFalse(VersionMatcher.inRange("1.2.0", range), "upper bound exclusive");
        assertFalse(VersionMatcher.inRange("0.9.9", range), "below lower bound");
        log.info("STATE/VERDICT: inclusivity/exclusivity boundaries verified");
    }

    @Test
    void openEndedRangeMatchesBelowOnly() {
        AffectedRange range = new AffectedRange(null, "2.0.0");
        log.info("INPUT range=(-inf,2.0.0); BASIS: null lower bound is open ended");
        assertTrue(VersionMatcher.inRange("1.9.0", range));
        assertFalse(VersionMatcher.inRange("2.0.0", range));
    }

    @Test
    void blankVersionNeverMatches() {
        log.info("INPUT version=null/''; BASIS: unknown versions cannot be judged vulnerable");
        assertFalse(VersionMatcher.inRange(null, new AffectedRange(null, null)));
        assertFalse(VersionMatcher.inRange("  ", new AffectedRange(null, null)));
    }
}
