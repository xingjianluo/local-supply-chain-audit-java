package com.github.xingjianluo.localsupplychainauditjava.core;

/** 取消令牌：扫描与解析过程中通过它协作式感知取消请求。 */
public interface CancelToken {

    boolean isCancelled();

    /** 每次批处理边界调用；若已请求取消则抛出 {@link ScanCancelledException}。 */
    default void checkPoint() {
        if (isCancelled()) {
            throw new ScanCancelledException();
        }
    }

    /** 永不取消的令牌（测试/同步场景使用）。 */
    static CancelToken never() {
        return () -> false;
    }
}
