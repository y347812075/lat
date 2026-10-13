# AOT v2 i386 支持评估与后续规划

## 身份与结论

- 日期：2026-10-13。
- 源码：`1f99be4e52ac8ccaacfa2a577977467d17cd28bd`。
- 分支：`aot-v2-pr-integration-20261010`。
- 方法：源码阅读和架构对照；未构建或运行 i386 AOT v2。
- 状态：规划记录，尚未实施，不代表 32 位功能已通过验收。

达到与当前 x86_64 AOT v2 相同的功能和验收范围，初步估算需要
**10 至 16 人周**。按一名熟悉 LAT 的工程师全职投入，约为 2.5 至
4 个月。这不是工期承诺，应在可行性验证后重新评估。

## 范围与复用

目标是 LoongArch64 Linux 宿主上的 `latx-i386` 和 32 位 Linux ELF，
覆盖静态预编译、运行期收集、增量编译、单 ELF 模块发布、动态库、
TLS、信号恢复、fork、映射失效和无需手动配置的使用方式。
匿名代码等允许回退的边界应与当前 x86_64 验收规则一致。

不包含 Wine/WoW64、PE、旧世界 ABI，也不承诺所有程序零 JIT。
`build32.sh` 能构建翻译器不代表 i386 AOT v2 已受支持。

预计可复用现有 i386 指令翻译能力、daemon 调度/增量/原子发布机制，
以及大部分宿主模块装载基础设施，但须通过真实导出和执行验证。
guest ELF 是 i386，生成的模块和公共 runtime 仍是 LoongArch64 ELF；
不能把全部 `Elf64` 机械替换成 `Elf32`。

## 已确认的代码缺口

以下路径相对仓库根目录，行号对应上述源码。

- `linux-user/meson.build:26`：仅 x86_64 使用真实 runner，i386 使用 stub。
- `tools/latc/cfg/src/elf_image.c:50`、`function_symbols.c`、`got_plt.c`：
  ELF、符号及重定位按 ELF64 实现，需支持 ELF32 和 32 位 PIC/PLT。
- `tools/latc/cfg/src/cfg_decoder.c:5`、`capstone_shadow.c:28`：按 64 位
  模式解码，需适配指令边界和操作数/地址尺寸。例如 `0x40` 至 `0x4f`
  在 32 位模式下是 INC/DEC，不是 REX 前缀。
- `tools/latc/aot-v2/common/tb-key-set.c:38`、`tools/latc/compiler/tbset.c`、
  `tools/latc/aot-v2/compiler/module-pack.c`：固定 `CODE64 | PARALLEL`。
  需定义 i386 TB 语义并贯通生成、校验、合并和查找，不能只删除 CODE64。
- `target/i386/latx/sbt/latc_native_export.c:20`：guest ELF 和 flags 按
  x86_64 实现，需适配导出并验证重定位、出口窗口及 PC map。
- `tools/latc/aot-v2/runtime/guest-elf-map.c:199`、
  `linux-user/latc-aot-v2-runner.c`、`tools/latc/latcd/precompile.c`、
  `linux-user/latc-bundle-loader.c`：映射、依赖发现及 bundle 有 ELF64 假设。
- `tools/latc/aot-v2/runtime/auto-config.c:172` 固定选择 `latx-x86_64`，
  daemon 配置只有一个编译 runner；需支持两种目标的选择和安全隔离。

## 风险与工作量

最大不确定性在 32 位运行语义和 native 导出，而不只是 ELF header：
段状态、CS/SS/FS/GS、TLS、guest CPU 布局、地址/栈宽度及回绕、helper
绑定、出口窗口和信号 PC 恢复均须验证。32/64 位 codegen identity、
缓存、socket 和 daemon 选择必须避免跨目标误用。

| 工作项 | 内容 | 初步估算 |
|---|---|---|
| ELF32 与 CFG | 符号/重定位、32 位解码、PIC/PLT、入口发现 | 2 至 3 人周 |
| 编译与持久格式 | TB 语义、bundle/native、模块打包、身份校验 | 2 至 3 人周 |
| runner 与运行语义 | 调度、地址/栈、段状态、TLS、helper、信号恢复 | 2 至 4 人周 |
| 无感使用与部署 | runner 选择、daemon 配置、缓存隔离、build32 安装路径 | 1 至 2 人周 |
| 验收与回归修复 | ELF32 应用、增量、strict 暖轮、生命周期、性能、x86_64 回归 | 3 至 4 人周 |
| 合计 | 当前 x86_64 AOT v2 同等范围 | 10 至 16 人周 |

- 受限原型约 2 至 4 周：跑通少量静态 ELF32 的收集、生成和暖轮加载。
- 达到旧 32 位 AOT 广泛兼容范围，暂按一人全职 4 至 6 个月或更长预留；
  需先明确旧方案应用矩阵，不能与当前 x86_64 同等范围混为一谈。
- 多人投入可能缩短日历时间，但接口依赖使工期不能按人数简单相除。

## 第一阶段建议

先安排约 1 周可行性验证，计入上述总工作量，不另行叠加：

1. 明确 i386 TB 语义、guest CPU ABI 和 32/64 位身份隔离设计。
2. 选一个静态 ELF32，验证编译、native 导出、模块加载和执行闭环。
3. 选一个带 glibc/TLS 的动态 ELF32，验证 loader、段状态和 helper。
4. 从全新缓存收集，等待 flush 发布，再执行 strict 文件 AOT 暖轮；
   检查实际模块注册和 fallback/submission，不能只看退出成功。
5. 记录故障和可复用范围，重新评估排期。

## 验收与待确认事项

- 保留源码/构建身份、完整命令、退出码、日志、rootfs 和缓存身份。
- 完整 `make -C tools/latc test`、source sync、干净安装树及受影响集成测试。
- 覆盖静态/动态 ELF32、PIE、TLS、IFUNC、dlopen/dlclose、signal、fork、
  映射失效、增量 flush、失败保留旧代和异常输入拒绝。
- 验证无感启动和 32/64 位共存；实际加载正确模块，不能误命中旧缓存。
- 冷轮和暖轮分开，按范围使用 `LATC_STRICT_FILE_AOT=1` 验证文件代码
  零 JIT 回退；匿名代码边界另行说明。
- 性能分别记录预编译、增量 flush、冷启动和暖运行，包含 wall/user/sys、
  RSS 及输出正确性；保留 x86_64 功能和性能回归门槛。
- 32 位 SPEC 测试前确认输入确为 ELF32；已有 x86_64 成绩不是 i386 证据。

用户此前要求暂不修复 `int $0x80` 和 call-next，本记录不撤销该决定。
它们可能涉及 32 位常见系统调用及 PIC 获取地址路径。实施前需确认是否
纳入支持；若继续排除，应保留为已知限制，不能声称所有 32 位路径完整
支持。极罕见边角问题仍须先确认。

本次只记录评估，未授权开始实现、构建测试、提交或推送。
