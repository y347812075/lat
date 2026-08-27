# AOT v2 M8 设计

## 稳定 TB 键和 profile

模块 ABI 使用稳定键 `(source_sha256, guest_rva, semantic_flags)`。
`semantic_flags` 只包含 x86-64 code mode 和 parallel-safe 变体，不把 LAT 内部
`cflags` 直接写入永久文件格式。运行时在 AOT 查找前完成映射；编译器在生成
native image 时对 TB 及 TB target relocation 使用相同映射。

profile v2 首行为 `LATC_PROFILE_V2 <source-sha256>`，后续记录为
`RVA FLAGS COUNT`。记录按 `(RVA, FLAGS)` 排序并合并计数。旧的
`ADDRESS COUNT` 输入继续兼容，作为默认非并行 code64 变体处理。

运行时只在 AOT 查找失败并准备生成 JIT TB 时记录 profile。它用已验证的 ELF
映射把 PC 转换为 source SHA 和 RVA，并将文件型 ELF 与 vDSO/匿名代码分开计数。

## 两级 guest 地址表

旧格式把每个 guest 地址直接放在 `$fp` 之前，LoongArch `ld.d` 的立即数范围
将其限制为 256 个槽。新模块使用最多 256 个一级页指针，每页保存 256 个
guest 地址：

1. 第一条 `ld.d` 从 `$fp` 相对槽读取页指针。
2. 第二条 `ld.d` 从页内读取 `guest_load_bias + guest_rva`。
3. 多余的重定位保留指令改为 NOP。

`LatAotGuestSlotV2.fp_offset` 保存一级页指针槽，原 `reserved` 字段在新模块标志
存在时保存页内字节偏移。旧模块没有该标志，继续使用原平面表。页号按排序后的
guest RVA 确定，保证相同输入生成相同模块。

打包器对删除原因分别计数。任何 profile 请求键在依赖删除后缺失都使
`compile-module` 失败；未执行的 CFG TB 仍允许形成部分模块。

## profile 合并与模块发布

latcd protocol v2 的 profile 请求携带 source FD 和密封 profile FD。latcd
重新计算 source digest，验证 RVA 位于可执行 `PT_LOAD`，再将记录合并到
`.profiles/<source-sha>.profile`。运行时在正常 guest 退出或累计 512 个新键时
提交；latcd 在最后一次更新空闲 1 秒后编译，同一 source 同时只有一个任务。
编译期间收到新记录时，完成后最多追加一个任务。

模块名为 `<source-sha>-<profile-digest>.so`，`<source-sha>.current` 通过原子
rename 指向当前不可变模块。运行时优先验证 current；没有 current 时兼容旧的
`<source-sha>.so`。当前进程不热替换已经注册的模块。

## 兼容性和安全

- protocol v1 和旧缓存名继续可读。
- native image 内部格式升级，模块 ABI 通过新 module flag 扩展，不改变旧描述符
  的字段大小。
- profile 数量、RVA、flags、计数和 FD 类型全部验证；每 source 最多 65536 个键。
- current 和 profile 使用临时文件、`fsync`、原子 rename，目录保持当前用户
  私有权限。
