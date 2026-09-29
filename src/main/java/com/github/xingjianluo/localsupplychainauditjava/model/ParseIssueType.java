package com.github.xingjianluo.localsupplychainauditjava.model;

/**
 * 单条清单解析结论类型。每种异常情形都必须有明确、可区分的结论，禁止静默跳过。
 */
public enum ParseIssueType {
    /** 清单整体损坏/语法错误，无法继续解析。 */
    MALFORMED_MANIFEST,
    /** 清单中存在条目缺失关键字段（如名称/版本），该条目被跳过并记录。 */
    FIELD_MISSING,
    /** 清单可解析但没有任何有效依赖条目。 */
    EMPTY_MANIFEST,
    /** 不支持的清单格式或无法识别格式。 */
    UNSUPPORTED_FORMAT,
    /** 本地路径不存在或不可读。 */
    UNREADABLE_SOURCE,
    /** 同一模块内同坐标同版本被重复声明，去重保留一条。 */
    DUPLICATE_REFERENCE,
    /** 同一组件坐标在同一模块中出现多个不同版本。 */
    MULTIPLE_VERSIONS,
    /** 模块输入缺少内容来源（path/content 均为空）。 */
    MISSING_SOURCE,
    /** 合并后组件明细超过快照上限被截断（统计仍准确，findings/issues 完整）。 */
    COMPONENT_LIST_TRUNCATED
}
