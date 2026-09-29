package com.github.xingjianluo.localsupplychainauditjava.vuln;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 版本号比较与受影响区间判定。
 *
 * <p>支持 Maven / npm / pypi 常见版本写法：数字段以点号分隔，可选限定符
 * （-alpha、-beta、-rc、-SNAPSHOT 等）。比较时数字按数值比较，限定符按
 * 预发布 &lt; 正式 的固定顺序比较，无法识别的限定符按字典序兜底。
 *
 * <p>漏洞区间采用左闭右开语义：[lowInclusive, highExclusive)，端界为空表示不限。
 */
@Component
public class VersionMatcher {

    private static final Logger log = LoggerFactory.getLogger(VersionMatcher.class);

    private static final Map<String, Integer> QUALIFIER_RANK = new HashMap<>();

    static {
        // 数值越小越早发布；正式版本（ga/final/release 及无限定符）排在最后
        QUALIFIER_RANK.put("alpha", 0);
        QUALIFIER_RANK.put("a", 0);
        QUALIFIER_RANK.put("beta", 1);
        QUALIFIER_RANK.put("b", 1);
        QUALIFIER_RANK.put("milestone", 2);
        QUALIFIER_RANK.put("m", 2);
        QUALIFIER_RANK.put("rc", 3);
        QUALIFIER_RANK.put("cr", 3);
        QUALIFIER_RANK.put("snapshot", 4);
        QUALIFIER_RANK.put("dev", 0);
        QUALIFIER_RANK.put("ga", 10);
        QUALIFIER_RANK.put("final", 10);
        QUALIFIER_RANK.put("release", 10);
        QUALIFIER_RANK.put("", 10);
    }

    /** 判断 version 是否落在 [lowInclusive, highExclusive) 内；空版本号一律不受影响。 */
    public boolean isAffected(String version, String lowInclusive, String highExclusive) {
        if (version == null || version.isBlank()) {
            return false;
        }
        boolean geLow = isBlank(lowInclusive) || compare(version, lowInclusive) >= 0;
        boolean ltHigh = isBlank(highExclusive) || compare(version, highExclusive) < 0;
        boolean affected = geLow && ltHigh;
        log.debug("版本判定: version={} range=[{},{}) -> {}", version, lowInclusive, highExclusive, affected);
        return affected;
    }

    /** 通用版本比较：负数 v1&lt;v2，0 相等，正数 v1&gt;v2。 */
    public int compare(String v1, String v2) {
        List<Token> t1 = tokenize(v1 == null ? "" : v1.trim());
        List<Token> t2 = tokenize(v2 == null ? "" : v2.trim());
        int n = Math.max(t1.size(), t2.size());
        for (int i = 0; i < n; i++) {
            int c = tokenAt(t1, i).compareTo(tokenAt(t2, i));
            if (c != 0) {
                return c;
            }
        }
        return 0;
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private Token tokenAt(List<Token> tokens, int idx) {
        if (idx < tokens.size()) {
            return tokens.get(idx);
        }
        // 缺失的尾部段视为数字 0，与 "1.0" 和 "1.0.0" 等价
        return new Token(true, 0L, "");
    }

    private List<Token> tokenize(String version) {
        List<Token> tokens = new ArrayList<>();
        int i = 0;
        int len = version.length();
        while (i < len) {
            char c = version.charAt(i);
            if (Character.isDigit(c)) {
                int start = i;
                while (i < len && Character.isDigit(version.charAt(i))) {
                    i++;
                }
                long value;
                try {
                    value = Long.parseLong(version.substring(start, i));
                } catch (NumberFormatException e) {
                    value = Long.MAX_VALUE;
                }
                tokens.add(new Token(true, value, ""));
            } else if (Character.isLetter(c)) {
                int start = i;
                while (i < len && Character.isLetterOrDigit(version.charAt(i))) {
                    i++;
                }
                tokens.add(new Token(false, 0L, version.substring(start, i).toLowerCase()));
            } else {
                // 分隔符 . - _ + 等
                i++;
            }
        }
        return tokens;
    }

    private record Token(boolean numeric, long number, String qualifier) implements Comparable<Token> {
        @Override
        public int compareTo(Token other) {
            if (numeric && other.numeric) {
                return Long.compare(number, other.number);
            }
            if (numeric || other.numeric) {
                // 数字段视为正式发布位，晚于限定符段：1.0-rc vs 1.0
                return numeric ? 1 : -1;
            }
            int r1 = QUALIFIER_RANK.getOrDefault(qualifier, 5);
            int r2 = QUALIFIER_RANK.getOrDefault(other.qualifier, 5);
            if (r1 != r2) {
                return Integer.compare(r1, r2);
            }
            return qualifier.compareTo(other.qualifier);
        }
    }
}
