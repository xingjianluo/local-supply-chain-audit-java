package com.github.xingjianluo.localsupplychainauditjava.web;

import com.github.xingjianluo.localsupplychainauditjava.model.ScanRequest;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanSnapshot;
import com.github.xingjianluo.localsupplychainauditjava.service.ScanManager;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * 本地依赖审计 REST 接口（提交 / 单个查询 / 历史 / 最新 / 取消）。
 * 全部行为基于本机文件与内存状态，不访问网络、数据库或外部服务。
 */
@RestController
@RequestMapping("/api/scans")
public class ScanController {

    private final ScanManager scanManager;

    public ScanController(ScanManager scanManager) {
        this.scanManager = scanManager;
    }

    /** 提交扫描：同一时间已有 RUNNING 扫描时返回 409。 */
    @PostMapping
    public ResponseEntity<ScanSnapshot> submit(@RequestBody ScanRequest request) {
        ScanSnapshot snapshot = scanManager.submit(request);
        return ResponseEntity.accepted().body(snapshot);
    }

    /** 查询某次扫描（历史可按 scanId 复现当时库版本下的结论）。 */
    @GetMapping("/{scanId}")
    public ResponseEntity<ScanSnapshot> get(@PathVariable String scanId) {
        return scanManager.get(scanId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping
    public List<ScanSnapshot> history() {
        return scanManager.history();
    }

    @GetMapping("/latest")
    public ResponseEntity<ScanSnapshot> latest() {
        return scanManager.latest()
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    /** 协作式取消：返回取消后的终态快照。 */
    @PostMapping("/{scanId}/cancel")
    public ResponseEntity<ScanSnapshot> cancel(@PathVariable String scanId) {
        return scanManager.cancel(scanId)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
