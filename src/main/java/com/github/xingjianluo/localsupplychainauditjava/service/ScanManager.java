package com.github.xingjianluo.localsupplychainauditjava.service;

import com.github.xingjianluo.localsupplychainauditjava.model.ScanRequest;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanSnapshot;

import java.util.List;
import java.util.Optional;

/**
 * 扫描状态管理：
 * 同一时刻至多一个 RUNNING 扫描；重复提交抛 {@link ScanConflictException}；
 * 取消以协作方式执行，结束后不留半成品，可立即开始下一次扫描；
 * 历史以有界方式保留，快照不可变，读写互不串扰。
 */
public interface ScanManager {

    ScanSnapshot submit(ScanRequest request);

    Optional<ScanSnapshot> get(String scanId);

    Optional<ScanSnapshot> latest();

    List<ScanSnapshot> history();

    /** @return 取消后最终快照；扫描已结束或不存在返回 empty。 */
    Optional<ScanSnapshot> cancel(String scanId);
}
