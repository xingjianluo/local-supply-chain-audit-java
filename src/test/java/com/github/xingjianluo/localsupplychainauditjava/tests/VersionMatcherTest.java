package com.github.xingjianluo.localsupplychainauditjava.tests;

import com.github.xingjianluo.localsupplychainauditjava.vuln.VersionMatcher;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 版本判定单测：打印输入与判定依据。
 */
class VersionMatcherTest {

    private static final Logger log = LoggerFactory.getLogger(VersionMatcherTest.class);
    private final VersionMatcher matcher = new VersionMatcher();

    @Test
    void numericSegmentsComparedNumerically() {
        log.info("[输入] compare(1.0.10, 1.0.9) 依据: 数字段按数值比较");
        assertTrue(matcher.compare("1.0.10", "1.0.9") > 0);
        assertEquals(0, matcher.compare("1.0", "1.0.0"));
        assertEquals(0, matcher.compare("4.17.21", "4.17.21"));
    }

    @Test
    void prereleaseEarlierThanRelease() {
        log.info("[输入] compare(2.0.0-rc1, 2.0.0) 依据: rc 预发布 < 正式版");
        assertTrue(matcher.compare("2.0.0-rc1", "2.0.0") < 0);
        assertTrue(matcher.compare("1.0.0-alpha", "1.0.0-beta") < 0);
    }

    @Test
    void halfOpenRangeMatching() {
        log.info("[输入] isAffected(4.17.20, low=4.0.0, high=4.17.21) 依据: 左闭右开");
        assertTrue(matcher.isAffected("4.17.20", "4.0.0", "4.17.21"));
        assertTrue(matcher.isAffected("4.0.0", "4.0.0", "4.17.21"));
        assertFalse(matcher.isAffected("4.17.21", "4.0.0", "4.17.21"));
        assertFalse(matcher.isAffected("3.9.9", "4.0.0", "4.17.21"));
        log.info("[关键状态变化] 边界版本 4.17.21 判定为不受影响(high 开区间)");
    }

    @Test
    void openEndedRangesAndBlankVersion() {
        log.info("[输入] isAffected(9.9.9, low=1.0, high=null) 依据: high 为空表示不设上界");
        assertTrue(matcher.isAffected("9.9.9", "1.0", null));
        assertTrue(matcher.isAffected("1.0", null, null));
        assertFalse(matcher.isAffected("", "1.0", "2.0"));
        assertFalse(matcher.isAffected(null, "1.0", "2.0"));
    }
}
