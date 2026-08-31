# AOT v2 M10 验证结果

## WI-2326：loader、libc AOT 与插件 JIT 混合运行

测试日期为 2026-08-31，机器为 `3a6000`（LoongArch64 3A6000）。源码为
`73f0fe94ed3b6de18390a11dc0e5905a1b791436`，从隔离目录重新构建，不复用旧目标
文件或旧 AOT 模块。

正式 dlopen fixture 使用四种缓存组合启动全新进程：

- 空缓存：5/5 退出码为 0；
- 仅 loader AOT：5/5 退出码为 0；
- 仅 libc AOT：5/5 退出码为 0；
- loader 和 libc AOT、主程序与插件 JIT：20/20 退出码为 0。

35 次输出均为：

```text
dlopen loads=100 signals=100 concurrent_invalidation=0 result=40 moved=1
```

混合缓存代表进程报告 loader `aot_lookups=371`、libc
`aot_lookups=182`，插件保持 `module=missing` 并走 JIT。插件加载和卸载 100 次，
guest signal 100 次；`signal_pc_lookups=100`、`signal_pc_hits=0`，说明插件 JIT
宿主地址没有被错误归到两个已注册 AOT 模块。20 个混合进程共执行 2000 次插件
加载和卸载，没有发现旧执行区间被错误复用。

调试构建产物 SHA256：

- runner：`dd9e910cd583a6a1de2c4f143f22d888f1a964ad2b6bd380277116096ce67a90`；
- runtime：`c96f767cfd475b396ebeebd8a1032212acd3940658143a6982c897f0a6f97cb8`；
- latc：`54a75499c04947d809404f639ffc93329a60e40b28d8b33d6f934f6ef8983e97`；
- runner Build ID：`8f7c299d040310b6c6c4ff40a825baab2dc0d8f3`。

使用 M9 已验证的发布配置重新构建后，动态链接语义、dlopen 混合缓存、代码
失效和 fork 四项回归也全部退出 0。发布 runner SHA256 为
`4528dc499b3ad0b26e575b29155b6fd3ac9afb17a12a02ccff398919ff767c1f`，Build ID
为 `70548cfaf6920146da2cc96b834c13d9a5c4dd04`。

本次没有复现旧 SIGBUS，因此没有修改运行时代码，也不宣称已经确定旧崩溃的
根因。现有证据只能证明：当前源码、当前 runner、重新生成且身份匹配的模块在
指定 `3a6000` 上稳定通过。旧崩溃来自另一台机器上的旧 runner/module 组合，
缺少可在当前机器执行的同一产物，不能进一步归因。

## 构建参数发现

若在发布配置中额外启用 `--enable-kzt`，AOT 生成会在启动 guest 前失败：

```text
latc: unsupported native relocation kind 53
latc: native compilation failed without static missing targets
```

编号 53 对应 `LOAD_HELPER_KZT_GET_ALTERNATE`。AOT v2 导出器没有该 helper 的运行
时符号映射。M9 正式配置未启用 KZT，按该配置构建和运行均通过。后续统一构建
入口必须拒绝这个不兼容组合，或在真正支持该 helper 后才允许启用；不能生成看似
成功、实际无法生成 AOT 模块的发布 runner。

## WI-2327：AOT v2 集成源码唯一来源

新增 `aot-v2-source-map.json`，登记 32 个生成副本及其规范来源：

- 21 个主 LAT 到 `tools/latc/lat` imported 树的集成文件；
- 8 个 `tools/latc/aot-v2` 到主 runner 树的 ABI、registry、guest ELF 和 latcd
  client 文件；
- 3 个 `tools/latc/native` 到主树的 native image 和 x86 syscall ABI 头文件。

`sync-aot-v2-sources.py` 负责生成和逐字节检查。`check-import.py` 每次先执行该
检查。手工修改任意一类生成副本、删除来源或目标、设置重复目标、使用越界路径，
测试都会稳定失败并打印规范来源和生成文件。`prepare-runner-source.py` 删除了另一
份手工文件列表，普通 AOT v2 runner 和 `--without-aot-v2` stub 都从同一清单选择
输入。

本地 `make -C tools/latc test` 通过，包括 100000 次固定 seed ELF 变异、源码不同
步失败测试、staging 规范来源测试和 import 检查。3a6000 上完成两次干净构建：

- 主 Meson runner：
  `a303d2303bede9f76eb6f5f5d5481247f621e066ef21724083df67f108eed02a`；
- 隔离 runner：
  `da669fc486c84ecb0783379bc27a9b1f2249fa683ac3d13a4fb96ce7f6cb89ef`；
- 两者使用的 runtime：
  `cab0f0ab4787036981f9fbaf64ddcaf0de7eccda4984b915bc824fc30e700c35`。

主构建的 `ninja -t inputs latx-x86_64` 没有 `tools/latc/lat` 生成副本。隔离 staging
的 runner、latcd client 和 native image 头分别与规范来源逐字节相同。两套 runner
分别执行正式 dlopen 混合缓存 fixture，均退出 0 并输出 PASS。

当前 `LATC_BUILD_ID` 仍使用 imported LAT 基线提交 `42c042…` 和固定后缀 `v3`，
尚未把 AOT v2 集成源码的变化纳入 codegen 身份。这不会改变本项的源码选择，但会
让不同集成版本产生相同 codegen-id；WI-2328 的产物版本校验必须一并修正。
