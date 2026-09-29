package com.github.xingjianluo.localsupplychainauditjava.engine;

import com.github.xingjianluo.localsupplychainauditjava.core.CancelToken;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanRequest;
import com.github.xingjianluo.localsupplychainauditjava.model.ScanSnapshot;

/**
 * 扫描执行引擎：读取模块清单 -> 归一化 -> 跨模块合并去重 -> 按漏洞库版本匹配。
 * 实现要求：分批检查取消令牌；大清单不一次性持有原始文本之外的多余副本。
 */
public interface ScanEngine {

    ScanSnapshot execute(String scanId, ScanRequest request, CancelToken cancelToken);
}
