package com.github.xingjianluo.localsupplychainauditjava.model;

import java.util.List;

/**
 * 扫描的不可变快照，用于对外查询与历史复现。
 * vulnLibraryVersion 与 vulnLibraryId 把结论与当时漏洞库版本绑定。
 *
 * <p>{@code componentCount} 为合并去重后的组件总数（统计准确）；
 * {@code components} 为进入快照的明细，超大清单按 audit.max-components-in-snapshot 截断，
 * findings/issues 始终完整保留。
 */
public record ScanSnapshot(String scanId,
                           ScanStatus status,
                           String vulnLibraryId,
                           String vulnLibraryVersion,
                           int moduleCount,
                           int componentCount,
                           List<MergedComponent> components,
                           List<Finding> findings,
                           List<ParseIssue> issues,
                           String error,
                           long submittedAtEpochMillis,
                           long finishedAtEpochMillis) {

    public static ScanSnapshot running(String scanId, String libId, String libVersion,
                                       int moduleCount, long now) {
        return new ScanSnapshot(scanId, ScanStatus.RUNNING, libId, libVersion, moduleCount,
                0, List.of(), List.of(), List.of(), null, now, 0L);
    }
}
