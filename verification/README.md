本目录是 asyncpg SCRAM-SHA-256-PLUS 首轮冻结后的独立验收材料。实际Windows/Python 3.14.3，新venv从冻结Cython源码重编译，固定pgproto子模块；依赖、工具链路径、实际导入和命令原件齐备，没有使用原模型环境旧pyd代替构建。按verification/reproduction-notes.md复现。无需外部数据库，TLS和PostgreSQL协议对端只使用本机回环和临时证书。不同测试范围分别保存，不相加：协议14过2失败，非SASL5过1失败，证书6过1失败，池acquire2过；基础SCRAM4过、参数8过3跳过62子测试过、模型新增38过。安全缺口及RFC依据见evidence-map.json。录屏中的重复运行不算新测试成绩，错误签名路径额外SSL回调异常保留在录制日志中。原生轨迹与视频各在飞书专用附件字段，公开目录不复制轨迹或视频。

冻结产物提交：https://github.com/9873199/asyncpg-scram-binding/commit/b28954e9c50f81e98ecbaf1bfea46d1a08a8a542
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
