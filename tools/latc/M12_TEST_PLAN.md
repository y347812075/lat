# AOT v2 M12 测试计划

- CFG：覆盖 JIT 地址位于已有块起点和块内部、串行/parallel flag、条件跳转、调用、跳转、syscall 和 jump table；与修改前整体翻译导出的 TB 集合逐项比较。
- Fragment：用 1、2、4、8 片编译同一输入，验证合并后 TB 集合一致、无重复、跨片重定位和 PC map 正确。
- 增量：首次发布后追加 TB，确认只翻译新 TB，清单始终只有一个模块；片段、合并和写盘失败时旧模块继续可用且 flush 失败。
- 回归：运行现有 AOT v2 单元、协议、service、runner、fork、dlopen、invalidation 和复杂应用测试。
- 性能：在同一台 3A6000、相同 CPU 条件、干净构建和隔离缓存下交替测试修改前后版本。复杂应用 `--flush-only` 连续五次，要求 `flush_all_ms` 中位数不超过 5000、最大值不超过 6000、`failed=0`。Python、Git、SQLite、Redis 严格文件 AOT 覆盖率均为 100%，暖 AOT每个应用快于 JIT；JIT 收集回退不超过 1%，暖 AOT 相对基线不得回退。
