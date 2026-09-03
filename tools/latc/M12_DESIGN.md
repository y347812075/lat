# AOT v2 M12 设计

## 三阶段编译

第一阶段由 CFG 接收最终 JIT TBSET，将其中的地址作为额外 basic-block leader，并按现有整体翻译规则扩展直接后继，输出排序去重的完整 TBSET。CFG 不生成 LoongArch 代码。无法解码输入地址时任务失败，不调用旧的递归翻译路径。

第二阶段将完整 TBSET 按 RVA 排序并切成连续区间，相同 RVA 的不同 flag 不跨片。默认每片 16384 个 TB，最多使用 `latcd --workers` 指定的全局编译槽且不超过 8。每个 fragment 只翻译清单中的 TB，保留跨片目标重定位，不增加后继。

第三阶段验证 fragment 的 source、build ID、加载基址和 guest image 一致，按地址顺序拼接代码并调整 TB、重定位和 PC map 的 host offset。合并后的 TB 表按 `(RVA, flags)` 排序，跨片直接目标在 module pack 阶段统一解析。

## 增量和发布

每个 ELF 保存一个 canonical native image。新 TB 到达后，CFG 生成增量完整清单，减去 native image 已有 TB，只翻译剩余部分，再与旧 native image 合并和重新链接。模块、native image 和清单均先写临时文件并同步，最后发布清单。清单始终只引用一个模块；失败时旧模块、native image 和 published TBSET 不变。

native image 计入缓存容量，只保留当前版本。codegen ID 更新后旧缓存直接失效，不转换旧格式。
