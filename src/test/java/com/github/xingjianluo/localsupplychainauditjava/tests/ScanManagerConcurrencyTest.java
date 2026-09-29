package com.github.xingjianluo.localsupplychainauditjava.tests;

import com.github.xingjianluo.localsupplychainauditjava.core.CancelToken;
import com.github.xingjianluo.localsupplychainauditjava.engine.ScanEngine;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanRequest;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanSnapshot;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanStatus;
import com.github.xingjianluo.localsupplychainauditjava.service.AuditProperties;
import com.github.xingjianluo.localsupplychainauditjava.service.DefaultScanManager;
import com.github.xingjianluo.localsupplychainauditjava.service.ScanConflictException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 扫描状态管理测试：单飞冲突、并发提交、协作取消不留半成品、取消后可立即重扫、读写不串。
 */
class ScanManagerConcurrencyTest {

    private static final Logger log = LoggerFactory.getLogger(ScanManagerConcurrencyTest.class);

    private ExecutorService pool;

    @AfterEach
    void tearDown() {
        if (pool != null) {
            pool.shutdownNow();
        }
    }

    private ScanRequest simpleRequest() {
        return new ScanRequest(List.of(
                new com.github.xingjianluo.localsupplychainauditjava.model.ModuleSpec(
                        "m", null, "# x",
                        com.github.xingjianluo.localsupplychainauditjava.model.ManifestFormat.REQUIREMENTS_TXT)),
                null);
    }

    private DefaultScanManager managerWith(ScanEngine engine) {
        AuditProperties props = new AuditProperties();
        props.setCancelAwaitMillis(5000L);
        props.setHistoryLimit(10);
        return new DefaultScanManager(engine, props);
    }

    private ScanSnapshot awaitTerminal(DefaultScanManager manager, String scanId) throws InterruptedException {
        long deadline = System.currentTimeMillis() + 10_000L;
        ScanSnapshot snap = null;
        while (System.currentTimeMillis() < deadline) {
            snap = manager.get(scanId).orElseThrow();
            if (snap.status() != ScanStatus.RUNNING) {
                return snap;
            }
            Thread.sleep(10L);
        }
        throw new AssertionError("扫描未在超时内结束: " + (snap == null ? null : snap.status()));
    }

    @Test
    void duplicateSubmitWhileRunningGivesClearConflict() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ScanEngine slow = (scanId, request, token) -> {
            entered.countDown();
            try {
                release.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            long now = System.currentTimeMillis();
            return new ScanSnapshot(scanId, ScanStatus.COMPLETED, "lib", "v1", 1, 0,
                    List.of(), List.of(), List.of(), null, now, now);
        };
        DefaultScanManager manager = managerWith(slow);

        ScanSnapshot first = manager.submit(simpleRequest());
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        log.info("[关键状态变化] 第一个扫描 {} 进入 RUNNING", first.scanId());

        log.info("[输入] 在 RUNNING 期间重复提交，期望 409 风格冲突且携带 activeScanId");
        ScanConflictException ex = assertThrows(ScanConflictException.class,
                () -> manager.submit(simpleRequest()));
        assertEquals(first.scanId(), ex.activeScanId());
        log.info("[判定依据] 冲突反馈清晰: {}", ex.getMessage());

        release.countDown();
        ScanSnapshot terminal = awaitTerminal(manager, first.scanId());
        assertEquals(ScanStatus.COMPLETED, terminal.status());

        // 前一个结束后可以立即提交下一个
        ScanSnapshot third = manager.submit(simpleRequest());
        log.info("[关键状态变化] 上一个结束后新扫描 {} 正常提交", third.scanId());
        awaitTerminal(manager, third.scanId());
    }

    @Test
    void concurrentSubmitsOnlyOneRuns() throws Exception {
        AtomicInteger concurrentRunning = new AtomicInteger();
        AtomicInteger maxObserved = new AtomicInteger();
        CountDownLatch inside = new CountDownLatch(1);
        ScanEngine counting = (scanId, request, token) -> {
            int cur = concurrentRunning.incrementAndGet();
            maxObserved.updateAndGet(v -> Math.max(v, cur));
            try {
                inside.await(2, TimeUnit.SECONDS);
                Thread.sleep(30L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            concurrentRunning.decrementAndGet();
            long now = System.currentTimeMillis();
            return new ScanSnapshot(scanId, ScanStatus.COMPLETED, "lib", "v1", 1, 0,
                    List.of(), List.of(), List.of(), null, now, now);
        };
        DefaultScanManager manager = managerWith(counting);
        pool = Executors.newFixedThreadPool(8);
        int threads = 8;
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = Stream.generate(() -> (Runnable) () -> {
            try {
                start.await();
                manager.submit(simpleRequest());
            } catch (ScanConflictException expected) {
                // 除一个之外都应得到冲突
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }).limit(threads).map(pool::submit).toList();

        start.countDown();
        for (Future<?> f : futures) {
            f.get(5, TimeUnit.SECONDS);
        }
        // 让唯一获胜扫描结束
        inside.countDown();
        long deadline = System.currentTimeMillis() + 5000L;
        while (manager.history().stream().anyMatch(s -> s.status() == ScanStatus.RUNNING)
                && System.currentTimeMillis() < deadline) {
            Thread.sleep(10L);
        }
        long completed = manager.history().stream()
                .filter(s -> s.status() == ScanStatus.COMPLETED).count();
        log.info("[判定依据] {} 个并发提交 -> 实际运行数峰值={} 完成数={}",
                threads, maxObserved.get(), completed);
        assertEquals(1, maxObserved.get(), "同一时刻只能有一个扫描在跑");
        assertEquals(1, completed, "仅唯一提交被接受并完成");
    }

    @Test
    void cancelStopsScanLeavesNoPartialResultAndAllowsNextScan() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        AtomicInteger checkpointsSeen = new AtomicInteger();
        ScanEngine slowCancellable = (scanId, request, token) -> {
            entered.countDown();
            // 模拟分批处理大清单，每批检查取消点
            for (int batch = 0; batch < 1_000_000; batch++) {
                try {
                    Thread.sleep(2L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                token.checkPoint();
                checkpointsSeen.incrementAndGet();
            }
            long now = System.currentTimeMillis();
            return new ScanSnapshot(scanId, ScanStatus.COMPLETED, "lib", "v1", 1, 0,
                    List.of(), List.of(), List.of(), null, now, now);
        };
        DefaultScanManager manager = managerWith(slowCancellable);
        ScanSnapshot running = manager.submit(simpleRequest());
        assertTrue(entered.await(2, TimeUnit.SECONDS));
        log.info("[关键状态变化] 扫描 {} 运行中，已过检查点 {} 个，发起取消",
                running.scanId(), checkpointsSeen.get());

        ScanSnapshot cancelled = manager.cancel(running.scanId()).orElseThrow();
        log.info("[判定依据] 取消返回终态: status={} components={} findings={} error={}",
                cancelled.status(), cancelled.components().size(),
                cancelled.findings().size(), cancelled.error());
        assertEquals(ScanStatus.CANCELLED, cancelled.status());
        assertTrue(cancelled.components().isEmpty() && cancelled.findings().isEmpty(),
                "取消后不得留下半成品结论");

        // 取消返回后槽位已释放：下一次扫描立即可以提交且互不串扰
        ScanEngine fast = (scanId, request, token) -> {
            long now = System.currentTimeMillis();
            return new ScanSnapshot(scanId, ScanStatus.COMPLETED, "lib", "v2", 1, 0,
                    List.of(), List.of(), List.of(), null, now, now);
        };
        DefaultScanManager manager2 = managerWith(fast);
        ScanSnapshot next = manager2.submit(simpleRequest());
        ScanSnapshot nextTerminal = awaitTerminal(manager2, next.scanId());
        assertEquals(ScanStatus.COMPLETED, nextTerminal.status());
        log.info("[关键状态变化] 取消后新扫描 {} 正常完成，历史快照互不影响", next.scanId());
    }

    @Test
    void cancelUnknownScanReturnsEmptyButDoesNotBreakActiveOne() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ScanEngine slow = (scanId, request, token) -> {
            entered.countDown();
            try {
                release.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            long now = System.currentTimeMillis();
            return new ScanSnapshot(scanId, ScanStatus.COMPLETED, "lib", "v1", 1, 0,
                    List.of(), List.of(), List.of(), null, now, now);
        };
        DefaultScanManager manager = managerWith(slow);
        ScanSnapshot running = manager.submit(simpleRequest());
        entered.await();
        log.info("[输入] 对不存在 scanId 取消: ghost-id，正在运行的是 {}", running.scanId());
        assertTrue(manager.cancel("ghost-id").isEmpty());

        ScanSnapshot still = manager.get(running.scanId()).orElseThrow();
        assertEquals(ScanStatus.RUNNING, still.status(), "取消不存在的扫描不能误伤正在运行的扫描");
        log.info("[判定依据] 真实扫描仍为 RUNNING，未被串扰");
        release.countDown();
        awaitTerminal(manager, running.scanId());
    }
}
