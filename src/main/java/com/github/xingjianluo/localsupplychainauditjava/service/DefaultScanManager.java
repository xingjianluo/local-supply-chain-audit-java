package com.github.xingjianluo.localsupplychainauditjava.service;

import com.github.xingjianluo.localsupplychainauditjava.core.CancelToken;
import com.github.xingjianluo.localsupplychainauditjava.engine.ScanEngine;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanRequest;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanSnapshot;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;

/**
 * 默认扫描状态管理器。
 *
 * <p>并发约定：
 * <ul>
 *   <li>用单例槽位 + CAS 保证同一时间至多一个 RUNNING 扫描；重复提交得到 409 风格的
 *       {@link ScanConflictException}，并携带正在运行的 scanId。</li>
 *   <li>扫描在单线程 executor 上异步执行；状态/历史由 {@link #stateLock} 保护，
 *       快照一旦发布即为不可变对象，并发读取互不串扰。</li>
 *   <li>取消为协作式：置位取消标记并中断执行线程，等待其产出终态快照后才释放单例槽位，
 *       因此取消不会留下半成品，也不会污染下一次扫描。</li>
 *   <li>历史有界（audit.history-limit），防止多次大清单扫描累积造成内存增长。</li>
 * </ul>
 */
@Service
public class DefaultScanManager implements ScanManager {

    private static final Logger log = LoggerFactory.getLogger(DefaultScanManager.class);

    private final ScanEngine engine;
    private final AuditProperties properties;
    private final ExecutorService executor;

    /** 单例运行槽位；非空即表示存在 RUNNING 扫描。 */
    private final AtomicReference<ActiveScan> active = new AtomicReference<>();

    private final ReentrantLock stateLock = new ReentrantLock();
    private final LinkedBoundedHistory history = new LinkedBoundedHistory();

    public DefaultScanManager(ScanEngine engine, AuditProperties properties) {
        this.engine = engine;
        this.properties = properties;
        this.executor = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "scan-engine");
            t.setDaemon(true);
            return t;
        });
    }

    @Override
    public ScanSnapshot submit(ScanRequest request) {
        validate(request);
        String scanId = UUID.randomUUID().toString();
        ActiveScan scan = new ActiveScan(scanId);

        if (!active.compareAndSet(null, scan)) {
            ActiveScan running = active.get();
            log.warn("扫描提交冲突: 被拒 scanId={} 正在运行 scanId={}", scanId,
                    running == null ? null : running.scanId);
            throw new ScanConflictException(running == null ? "(unknown)" : running.scanId);
        }
        long now = System.currentTimeMillis();
        ScanSnapshot runningSnapshot = ScanSnapshot.running(scanId, null, null,
                request.safeModules().size(), now);
        appendHistory(runningSnapshot);
        log.info("扫描已提交: scanId={} 模块数={}", scanId, request.safeModules().size());

        Future<?> future = executor.submit(() -> runScan(scan, request));
        scan.setFuture(future);
        return runningSnapshot;
    }

    private void runScan(ActiveScan scan, ScanRequest request) {
        String name = Thread.currentThread().getName();
        Thread.currentThread().setName("scan-engine-" + scan.scanId);
        try {
            ScanSnapshot result = engine.execute(scan.scanId, request, scan);
            publish(scan, result);
        } catch (com.github.xingjianluo.localsupplychainauditjava.core.ScanCancelledException e) {
            // 引擎未自行产出终态时的防御性兜底：取消一律落 CANCELLED，不能算 FAILED
            long now = System.currentTimeMillis();
            publish(scan, new ScanSnapshot(scan.scanId,
                    com.github.xingjianluo.localsupplychainauditjava.model.ScanStatus.CANCELLED,
                    null, null, request.safeModules().size(), 0,
                    List.of(), List.of(), List.of(),
                    "扫描已取消，未发布任何半成品结论", now, now));
        } catch (Throwable t) {
            log.error("扫描执行出现未捕获异常: scanId={}", scan.scanId, t);
            ScanSnapshot failed = new ScanSnapshot(scan.scanId,
                    com.github.xingjianluo.localsupplychainauditjava.model.ScanStatus.FAILED,
                    null, null, request.safeModules().size(), 0,
                    List.of(), List.of(), List.of(),
                    "内部错误: " + t.getClass().getSimpleName() + ": " + t.getMessage(),
                    System.currentTimeMillis(), System.currentTimeMillis());
            publish(scan, failed);
        } finally {
            Thread.currentThread().setName(name);
        }
    }

    /** 终态快照发布：替换历史中的 RUNNING 占位，并在执行线程退出后释放单例槽位。 */
    private void publish(ActiveScan scan, ScanSnapshot terminal) {
        stateLock.lock();
        try {
            history.replaceOrAppend(terminal, properties.getHistoryLimit());
        } finally {
            stateLock.unlock();
        }
        boolean cleared = active.compareAndSet(scan, null);
        log.info("扫描终态发布: scanId={} status={} 槽位释放={}",
                scan.scanId, terminal.status(), cleared);
    }

    @Override
    public Optional<ScanSnapshot> get(String scanId) {
        stateLock.lock();
        try {
            return Optional.ofNullable(history.get(scanId));
        } finally {
            stateLock.unlock();
        }
    }

    @Override
    public Optional<ScanSnapshot> latest() {
        stateLock.lock();
        try {
            return history.isEmpty() ? Optional.empty()
                    : Optional.of(history.asList().get(history.size() - 1));
        } finally {
            stateLock.unlock();
        }
    }

    @Override
    public List<ScanSnapshot> history() {
        stateLock.lock();
        try {
            return history.asList();
        } finally {
            stateLock.unlock();
        }
    }

    @Override
    public Optional<ScanSnapshot> cancel(String scanId) {
        ActiveScan scan = active.get();
        if (scan == null || !scan.scanId.equals(scanId)) {
            // 目标扫描不存在或已结束：返回当时快照（若有）
            log.info("取消请求忽略: scanId={} 当前无匹配的运行中扫描", scanId);
            return get(scanId);
        }
        if (scan.cancel()) {
            log.warn("请求取消扫描: scanId={}", scanId);
            Future<?> future = scan.future();
            if (future != null) {
                future.cancel(true);
            }
        }
        // 等待执行线程产出 CANCELLED/其它终态，保证取消返回后不留半成品
        long deadline = System.currentTimeMillis() + properties.getCancelAwaitMillis();
        while (active.get() == scan && System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(10L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        if (active.get() == scan) {
            log.error("取消等待超时，扫描线程仍未退出: scanId={}", scanId);
        }
        return get(scanId);
    }

    private void appendHistory(ScanSnapshot snapshot) {
        stateLock.lock();
        try {
            history.replaceOrAppend(snapshot, properties.getHistoryLimit());
        } finally {
            stateLock.unlock();
        }
    }

    private void validate(ScanRequest request) {
        if (request == null) {
            throw new IllegalArgumentException("请求体为空");
        }
        if (request.safeModules().isEmpty()) {
            throw new IllegalArgumentException("modules 不能为空：至少提供一个模块清单");
        }
    }

    /** 一次运行中的扫描句柄：取消标记 + 线程 future。 */
    private static final class ActiveScan implements CancelToken {
        private final String scanId;
        private final java.util.concurrent.atomic.AtomicBoolean cancelled =
                new java.util.concurrent.atomic.AtomicBoolean(false);
        private volatile Future<?> future;

        private ActiveScan(String scanId) {
            this.scanId = scanId;
        }

        void setFuture(Future<?> future) {
            this.future = future;
        }

        Future<?> future() {
            return future;
        }

        boolean cancel() {
            return cancelled.compareAndSet(false, true);
        }

        @Override
        public boolean isCancelled() {
            return cancelled.get();
        }
    }

    /** 保持插入顺序、按 scanId 去重更新、有界淘汰的历史容器（调用方持锁）。 */
    private static final class LinkedBoundedHistory {
        private final java.util.LinkedHashMap<String, ScanSnapshot> map = new java.util.LinkedHashMap<>();

        void replaceOrAppend(ScanSnapshot snapshot, int limit) {
            map.remove(snapshot.scanId());
            map.put(snapshot.scanId(), snapshot);
            int capacity = Math.max(1, limit);
            while (map.size() > capacity) {
                String eldest = map.keySet().iterator().next();
                map.remove(eldest);
            }
        }

        ScanSnapshot get(String scanId) {
            return map.get(scanId);
        }

        List<ScanSnapshot> asList() {
            return List.copyOf(new ArrayList<>(map.values()));
        }

        boolean isEmpty() {
            return map.isEmpty();
        }

        int size() {
            return map.size();
        }
    }
}
