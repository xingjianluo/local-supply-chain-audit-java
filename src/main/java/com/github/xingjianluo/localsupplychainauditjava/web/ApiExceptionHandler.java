package com.github.xingjianluo.localsupplychainauditjava.web;

import com.github.xingjianluo.localsupplychainauditjava.service.ScanConflictException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 统一异常映射：
 * <ul>
 *   <li>重复提交扫描 -&gt; 409 CONFLICT，body 携带正在运行的 scanId，冲突反馈清晰可辨；</li>
 *   <li>非法输入/请求体损坏 -&gt; 400；</li>
 *   <li>其它未预期错误 -&gt; 500。</li>
 * </ul>
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    @ExceptionHandler(ScanConflictException.class)
    public ResponseEntity<Map<String, Object>> handleConflict(ScanConflictException e) {
        log.warn("扫描冲突: activeScanId={}", e.activeScanId());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(body(
                HttpStatus.CONFLICT, "SCAN_ALREADY_RUNNING",
                e.getMessage() + "；请等待其结束或先取消后再提交", e.activeScanId()));
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleBadRequest(IllegalArgumentException e) {
        log.warn("非法请求: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body(
                HttpStatus.BAD_REQUEST, "INVALID_REQUEST", e.getMessage(), null));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleUnreadable(HttpMessageNotReadableException e) {
        log.warn("请求体无法解析: {}", e.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body(
                HttpStatus.BAD_REQUEST, "MALFORMED_REQUEST_BODY",
                "请求体不是合法 JSON 或字段类型不正确", null));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleOther(Exception e) {
        log.error("未预期异常", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body(
                HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_ERROR",
                e.getClass().getSimpleName() + ": " + e.getMessage(), null));
    }

    private Map<String, Object> body(HttpStatus status, String code, String message, String activeScanId) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("timestamp", Instant.now().toString());
        map.put("status", status.value());
        map.put("error", status.getReasonPhrase());
        map.put("code", code);
        map.put("message", message);
        if (activeScanId != null) {
            map.put("activeScanId", activeScanId);
        }
        return map;
    }
}
