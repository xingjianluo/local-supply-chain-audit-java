package com.github.xingjianluo.localsupplychainauditjava.web;

import com.github.xingjianluo.localsupplychainauditjava.scan.ScanConflictException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/** Maps domain exceptions to distinguishable HTTP responses. */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /** 409: a scan is already running. The body names the conflicting scan id. */
    @ExceptionHandler(ScanConflictException.class)
    public ResponseEntity<Map<String, Object>> handleConflict(ScanConflictException ex) {
        log.warn("Scan conflict: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                "error", "SCAN_ALREADY_RUNNING",
                "runningScanId", ex.getRunningScanId(),
                "message", ex.getMessage()));
    }

    /** 400: invalid request payload. */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleBadRequest(IllegalArgumentException ex) {
        log.warn("Bad request: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "error", "BAD_REQUEST",
                "message", String.valueOf(ex.getMessage())));
    }

    /** 400: unreadable JSON body. */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleUnreadable(HttpMessageNotReadableException ex) {
        log.warn("Unreadable request body: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                "error", "BAD_REQUEST",
                "message", "request body is missing or not valid JSON"));
    }
}
