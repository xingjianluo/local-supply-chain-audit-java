package com.github.xingjianluo.localsupplychainauditjava.tests;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Web 层测试：提交 202、重复提交 409 冲突反馈、查询/历史/取消、坏请求 400。
 */
@SpringBootTest
@AutoConfigureMockMvc
class ScanControllerWebTest {

    private static final Logger log = LoggerFactory.getLogger(ScanControllerWebTest.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    private String libPath;

    private String requestBody(String libPath) throws Exception {
        if (this.libPath == null) {
            if (libPath != null) {
                this.libPath = libPath;
            } else {
                Path f = Files.createTempFile("weblib", ".json");
                Files.writeString(f, """
                        {"id":"local-vuln-db","version":"v1","rules":[
                        {"id":"V1","ecosystem":"npm","group":"","name":"lodash",
                         "rangeLow":"4.0.0","rangeHigh":"4.17.21","fixedIn":"4.17.21",
                         "title":"t","severity":"high"}]}
                        """);
                this.libPath = f.toString();
            }
        }
        Map<String, Object> module = Map.of(
                "module", "web-module",
                "content", "{\"lockfileVersion\":3,\"packages\":{\"node_modules/lodash\":{\"version\":\"4.17.10\"}}}",
                "format", "PACKAGE_LOCK_JSON");
        return MAPPER.writeValueAsString(Map.of("modules", List.of(module),
                "vulnLibraryPath", this.libPath));
    }

    private String submitSlowRequest() throws Exception {
        // 构造一个超大 lock 内容的思路在这里不需要：通过大量模块让扫描窗口足够长
        // 改用 200 个小模块内容，制造可观察的 RUNNING 窗口
        var modules = new java.util.ArrayList<Map<String, String>>();
        for (int i = 0; i < 200; i++) {
            modules.add(Map.of("module", "m" + i,
                    "content", "pkg" + i + "==1.0.0\n",
                    "format", "REQUIREMENTS_TXT"));
        }
        return MAPPER.writeValueAsString(Map.of("modules", modules,
                "vulnLibraryPath", libPath == null ? "" : libPath));
    }

    @Test
    void submitGetHistoryAndCancelFlow() throws Exception {
        String body = requestBody(null);
        log.info("[输入] POST /api/scans 单模块 npm 扫描");
        MvcResult submitted = mockMvc.perform(post("/api/scans")
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("RUNNING"))
                .andReturn();
        JsonNode node = MAPPER.readTree(submitted.getResponse().getContentAsString());
        String scanId = node.get("scanId").asText();
        log.info("[关键状态变化] 提交成功 scanId={}", scanId);

        // 等待终态
        String status = "RUNNING";
        for (int i = 0; i < 100 && "RUNNING".equals(status); i++) {
            MvcResult got = mockMvc.perform(get("/api/scans/" + scanId))
                    .andExpect(status().isOk()).andReturn();
            status = MAPPER.readTree(got.getResponse().getContentAsString()).get("status").asText();
            Thread.sleep(20L);
        }
        log.info("[判定依据] 终态 status={}", status);
        if (!"COMPLETED".equals(status)) {
            throw new AssertionError("扫描应完成，实际 " + status);
        }

        mockMvc.perform(get("/api/scans")).andExpect(status().isOk());
        mockMvc.perform(get("/api/scans/latest")).andExpect(status().isOk());
        log.info("[关键状态变化] 历史与最新查询均返回 200");

        mockMvc.perform(get("/api/scans/no-such-id")).andExpect(status().isNotFound());
    }

    @Test
    void concurrentSubmitReturns409WithActiveScanId() throws Exception {
        requestBody(null);
        // 先保证没有活动扫描（上一个测试若并行可能干扰）；顺序执行下这里直接提一个慢扫描
        String slowBody = submitSlowRequest();
        log.info("[输入] 提交 200 模块慢扫描制造 RUNNING 窗口");
        MvcResult first = mockMvc.perform(post("/api/scans")
                        .contentType(MediaType.APPLICATION_JSON).content(slowBody))
                .andExpect(status().isAccepted()).andReturn();
        String activeId = MAPPER.readTree(first.getResponse().getContentAsString())
                .get("scanId").asText();

        log.info("[输入] RUNNING 中再次提交，期望 409");
        mockMvc.perform(post("/api/scans")
                        .contentType(MediaType.APPLICATION_JSON).content(slowBody))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("SCAN_ALREADY_RUNNING"))
                .andExpect(jsonPath("$.activeScanId").value(activeId));
        log.info("[判定依据] 409 body 携带 activeScanId={}，冲突反馈清晰可辨", activeId);

        mockMvc.perform(post("/api/scans/" + activeId + "/cancel"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("CANCELLED"));
        log.info("[关键状态变化] 取消返回 CANCELLED");
    }

    @Test
    void malformedAndEmptyRequestsRejectedWith400() throws Exception {
        log.info("[输入] 非 JSON 请求体");
        mockMvc.perform(post("/api/scans").contentType(MediaType.APPLICATION_JSON)
                        .content("{not-json"))
                .andExpect(status().isBadRequest());

        log.info("[输入] modules 为空");
        mockMvc.perform(post("/api/scans").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"modules\":[]}"))
                .andExpect(status().isBadRequest());
        log.info("[判定依据] 坏请求体 400 / 空 modules 400");
    }
}
