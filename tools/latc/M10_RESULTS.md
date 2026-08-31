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

## WI-2328：统一构建、安装和产物身份

主 Meson 构建现在同时生成并安装 `latx-x86_64`、
`liblat-aot-runtime.so.2`、`latcd` 和 `latc`，编译模块所需脚本、ABI 头文件和
version script 安装到同一 prefix 的 `libexec/latc`。`latc` 不再依赖源码树中
的脚本位置。

四个产物使用 AOT v2 相关规范源码内容计算相同的 64 位十六进制身份。身份计算
排除了 `configure` 在源码目录生成的五个 LATX 表文件；回归测试证明这些文件在
配置前后出现或变化都不会改变身份。`latcd` 在创建 socket 或 cache 之前检查
`latc`、runner、runtime ABI 和 runtime 身份，任一不匹配都会打印明确错误并退出。
旧 codegen-id 的模块不再当作 cache hit，并会按当前身份重新编译发布。

2026-08-31 在 `3a6000` 从当前源码和空构建目录完成 429 个 Ninja 步骤，安装到
`/home/zenglu/latc-m10-wi2328-install`。源码与四个安装产物的共同身份为
`f11d49ddde5be8cb6aa7da62fcaecbb075800c9f8a5c051165433d6e45a0023d`。
安装树集成测试使用 `/home/zenglu/t311-debug-rootfs/usr/bin/echo`：JIT、冷缓存和
暖缓存 stdout 逐字节相同；冷编译无失败，暖运行没有文件 TB JIT 尝试。伪造的
latc、runner 和 runtime 身份都在创建 socket/cache 前被拒绝。安装产物无
RPATH，runner 通过 ELF `NEEDED` 使用 `liblat-aot-runtime.so.2`。完整测试退出码
为 0，并输出 `test-aot-v2-install: PASS`。

## WI-2329：cache 单写者和退出恢复

`latcd` 现在先保护 cache 目录，再打开 `.latcd.lock` 并取得内核 `flock()` 非阻塞
独占锁。锁成功后才会创建 socket、`.tmp`、profile、模块或 `current`。文件描述符
在服务全程保持打开；正常退出和 `SIGKILL` 后均由内核释放。锁文件保留的 PID、
socket 和 build-id 只用于诊断，不用于判断旧进程是否仍然存在。stats JSON 新增
`cache_owner_pid`。

2026-08-31 在 `3a6000` 使用空目录完成 429 步主构建并安装最终产物，共同身份为
`4836c3f7d266cac658327a93dce8e0b56039ccd029ac9e33cd60eccd68d94464`。
两个不同 socket 的 latcd 同时指向同一 cache 时，第二个在创建 socket 前退出并
打印 `cache is already owned by another latcd`。对已经包含真实模块和 `current` 的
cache 重复测试，失败前后两个文件的 SHA256 完全一致。第一个实例正常退出后可
立即启动新实例；新实例再被 `SIGKILL` 后，第三个实例也能取得锁、编译一个模块，
stats 为 `compiled=1`、`failed=0`。

最终安装树的 `test-latcd-service.sh` 和 `test-latcd-once.sh` 均退出 0。覆盖结果
包括 20 个同源并发请求只编译一次、双 worker、同源 profile 合并、negative
cache、CPU 限制、优先级、队列容量、退出清理、普通和 versioned cache eviction。
新锁版本再次通过 `test-aot-v2-install.sh`，JIT、冷缓存和暖缓存行为没有退化。

## WI-2330：当前设计和复杂应用测试调度

设计文档现在明确区分 source、module、instance、generation、profile 和 `current`。
`fork()` 后父进程保持原状态；子进程丢弃继承的 AOT 实例、跳转缓存、发现状态和
 latcd 连接，直到 `exec()` 前只使用 JIT。`exec()` 会创建新注册表。`current` 只在
 模块完全写入并校验后，通过临时文件、文件同步、原子 `rename()` 和目录同步发布；
 读者遇到缺失、损坏或身份不符时回退 JIT。

复杂应用脚本为 JIT、冷 AOT、暖 AOT 和五个故障用例分别创建目录。每个阶段有独立
 `HOME`；每个 guest 命令使用 `setsid` 新建进程组，并把命令、环境、整数退出码、
 stdout/stderr 路径写入该阶段的 `commands.jsonl`。阶段汇总写入 `result.json`。
冷、暖阶段结束后等待 latcd 的活动编译数和队列深度都变为 0，避免后台编译进入
下一个阶段。只读 cache 用 `/proc` 中不可创建的路径测试，避免测试进程以目录所有者
身份重新加写权限而产生假通过。

2026-08-31 在 `3a6000` 使用安装树
`/home/zenglu/latc-m10-wi2329-install` 和复杂应用 rootfs 执行最终测试。四个阶段均
退出 0：JIT 10 秒、冷 AOT 17 秒、暖 AOT 18 秒、故障回退 5/5。每个普通阶段记录
44 条命令，其中 42 条退出 0，2 条退出 1 是 Redis 服务就绪前的预期 `PING`；随后
均得到 `PONG`。Python、Git、SQLite WAL 和 Redis 的成功标记在三个运行阶段全部
存在，暖阶段确认至少一个模块已注册。

主 latcd 最终统计为 `requests=96`、`queued=8`、`deduplicated=88`、`compiled=4`、
`failed=4`、`active_jobs=0`、`queue_depth=0`。四个失败是较大动态程序在受限编译
阶段被杀死；运行时按设计使用 JIT，所有应用结果仍与 JIT 阶段一致。cache 中发布了
4 个模块和对应 `current` 文件。latcd 缺失、编译失败、损坏 `current`、损坏模块和
只读 cache 五种情况均返回与 JIT 金标准一致的 Python 输出，没有遗留测试进程。

同一源码上的本地 `make -C tools/latc test` 退出 0。它包括 100,000 次固定 seed 的
ELF 变异、AOT v2 格式、注册表、模块封装、guest ELF 映射、源码同步、runner 源码
准备和 import 检查。最终产品共同身份保持为
`4836c3f7d266cac658327a93dce8e0b56039ccd029ac9e33cd60eccd68d94464`。
