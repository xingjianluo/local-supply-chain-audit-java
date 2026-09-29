package com.github.xingjianluo.localsupplychainauditjava.service;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** 本地审计服务可调参数。 */
@ConfigurationProperties(prefix = "audit")
public class AuditProperties {

    /** 默认本地漏洞库 JSON 路径。 */
    private String vulnLibraryPath = "";
    /** 历史扫描保留条数（有界，防止大清单累积导致内存增长）。 */
    private int historyLimit = 10;
    /** 单个模块条目处理多少条后做一次取消检查点。 */
    private int cancelBatchSize = 256;
    /** 取消时等待执行线程退出的最大毫秒数，避免留下半成品。 */
    private long cancelAwaitMillis = 10_000L;
    /**
     * 单个扫描快照中保留的组件明细上限。findings/issues 始终完整保留；
     * 超量组件不进入快照但统计数准确，并给出一条可追溯结论，为大清单内存封顶。
     * 0 或负数表示不限制。
     */
    private int maxComponentsInSnapshot = 100_000;

    public String getVulnLibraryPath() {
        return vulnLibraryPath;
    }

    public void setVulnLibraryPath(String vulnLibraryPath) {
        this.vulnLibraryPath = vulnLibraryPath;
    }

    public int getHistoryLimit() {
        return historyLimit;
    }

    public void setHistoryLimit(int historyLimit) {
        this.historyLimit = historyLimit;
    }

    public int getCancelBatchSize() {
        return cancelBatchSize;
    }

    public void setCancelBatchSize(int cancelBatchSize) {
        this.cancelBatchSize = cancelBatchSize;
    }

    public long getCancelAwaitMillis() {
        return cancelAwaitMillis;
    }

    public void setCancelAwaitMillis(long cancelAwaitMillis) {
        this.cancelAwaitMillis = cancelAwaitMillis;
    }

    public int getMaxComponentsInSnapshot() {
        return maxComponentsInSnapshot;
    }

    public void setMaxComponentsInSnapshot(int maxComponentsInSnapshot) {
        this.maxComponentsInSnapshot = maxComponentsInSnapshot;
    }
}
