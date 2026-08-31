# AOT v2 M10 设计

## 诊断顺序

使用现有 `test-aot-v2-dlopen-runner.sh` 作为正式入口。它已经构造 loader 与 libc
AOT、插件 JIT 的混合缓存。先从干净源码和构建目录生成 runner、runtime、latc、
fixture 和模块，再执行四种缓存组合。每次记录模块内容和运行器身份，避免把旧
缓存加载问题误判为运行时缺陷。

若失败，按以下顺序区分原因：

1. 宿主故障 PC 属于 AOT text、JIT code cache、runtime helper 或普通宿主代码；
2. signal 使用的当前实例是否与宿主 PC 所属模块相同，generation 是否仍有效；
3. 插件反复映射和卸载后，访客执行区间及跳转缓存是否已失效；
4. module note 中的 source digest、codegen-id、CPU feature 和 profile 是否与实际
   loader/libc 匹配。

只有当前 HEAD 的正式 fixture 失败才修改运行时代码。测试必须先稳定失败，再进行
修复；调试日志统一使用可搜索前缀，并在提交前删除。

## 运行时状态

保留现有外部 runner hook。内部把已加载模块、guest 实例、host text 范围、
generation 和 PC map 作为同一生命周期记录发布。dispatch、signal 恢复和失效
不得分别构造互不关联的模块身份。fork parent 保留状态；fork child 在 exec 前
停用继承的 AOT 可变状态并只走 JIT；exec 由新进程重新注册。

## 源码唯一来源

保留 `tools/latc` 的最小 imported LAT 树，不复制完整仓库。AOT v2 新增实现指定
一个规范位置，主 LAT 与隔离 runner 通过构建输入或可重复生成步骤使用它。任何
生成副本都必须带来源说明，并由检查脚本比较内容；生成文件不接受手工修改。

## 构建与安装

主 Meson 负责四个匹配产物：`latx-x86_64`、`liblat-aot-runtime.so.2`、`latcd`
和 `latc`。安装测试使用临时 prefix，不引用源码树 build 目录。latcd 启动或调用
编译器时检查 codegen/build 身份，不匹配时返回明确错误，应用继续 JIT。

## 缓存单写者

latcd 打开 cache 后立即取得跨进程独占锁，并在整个服务期持有描述符。锁由内核
在进程退出时自动释放，不用 PID 文件判断进程是否存活。第二个 latcd 获取失败时
在创建临时文件、合并 profile 或清理 cache 前退出。现有临时文件、`rename()`、
文件和目录同步顺序继续保留。

## 测试调度和文档

复杂应用每个阶段使用独立目录和进程组，结果记录命令、整数退出码、stdout 和
stderr。共享设计文档固定 source、module、instance、generation、profile、
current 和 JIT fallback 的含义，并在实现变化后同步更新。

