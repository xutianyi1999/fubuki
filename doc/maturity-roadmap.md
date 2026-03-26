# Fubuki 工程成熟化路线图

本文档描述从**当前基线**（以 Docker Compose 多节点 mesh 为主的集成验证）演进为**可长期维护、可发布、可运维**的成熟工程所需的工作包、优先级与验收方式。实现时可按阶段拆 PR；每阶段结束应有**可运行的门禁**（CI 绿灯或明确的手动签收清单）。

---

## 1. 当前基线（事实盘点）

| 能力 | 现状 |
|------|------|
| 集成环境 | `docker/mesh/`：`Dockerfile` 内 `cargo build --release`，`generate_mesh.py` 生成 N 节点 `dc.json` + Compose；`scripts/docker-mesh.sh` 封装 build / up / down / logs |
| 拓扑 | 单 seed（node1 空 bootstrap，其余只连 node1），underlay 172.30.0.0/24，overlay 10.200.1.0/24，关闭 STUN |
| 自动化断言 | **`scripts/docker-mesh-test.sh`**（及 `./scripts/docker-mesh.sh test`）：overlay ICMP、失败打日志、`down -v` |
| 单元 / 集成测试（Rust） | **无**（仓库内未见 `#[test]`） |
| PR 门禁 CI | **Docker E2E**：`.github/workflows/docker-mesh.yml`；Release 仍为 **tag** 触发 `.github/workflows/rust.yml` |
| 发行说明 | 无统一 CHANGELOG 模板 |

**结论**：Docker mesh 已具备**可失败、可进 CI** 的 E2E；成熟化下一步主要是 **Rust 单元测试** 与 **fmt/clippy/test 的常规 PR 门禁**（见阶段 B/C）。

---

## 2. 成熟版本定义（目标态）

满足下列维度即可视为「成熟 v1」（具体指标可在实施时量化到 CI 任务名）：

1. **每次合并主分支前**：`cargo fmt`、`clippy`、**单元/属性测试**通过；**可选** Docker 集成在默认分支上稳定绿或按日/周跑。
2. **集成测试**：至少一条自动化用例验证「N 节点 mesh 上 overlay 互通」（例如 ping 或等价探测），失败时非零退出码。
3. **可运维**：文档说明部署、升级、日志位置、常见故障；关键错误信息可被用户/支持人员检索。
4. **安全与依赖**：`cargo audit`（或等价）进入常规流程；git 依赖有版本/修订说明。
5. **发布**：CHANGELOG 或 Release Notes 与 tag 对齐；破坏性变更有迁移说明。

---

## 3. 总体策略：两层测试金字塔

```
                    ┌─────────────────────┐
                    │  Docker mesh E2E    │  慢、真实 TUN/路由
                    │  (现有环境强化)      │
                    └──────────┬──────────┘
                               │
              ┌────────────────┴────────────────┐
              │  Rust 单元 / 集成（无 Docker）   │  快、编解码/密码/目录
              └─────────────────────────────────┘
```

- **下层**：不启容器即可跑，保证每次 push 成本低、反馈快。  
- **上层**：保留并增强现有 Docker 方案，作为**回归真实环境**的锚点。

---

## 4. 阶段规划

### 阶段 A — 把 Docker mesh 变成「测试」而不是「演示」（P0，约 1–2 周）

**目标**：同一套 compose 可由脚本一键拉起、等待收敛、断言、清理，适合本地与 CI。

| 工作项 | 说明 |
|--------|------|
| A1. 断言脚本 | **已完成**：`scripts/docker-mesh-test.sh` — 等待全容器 Running → node1 ping 全部其他节点 → 末节点 ping node1 → `docker compose down -v`；`MESH_WAIT_SECS` 可调 |
| A2. 超时与稳定性 | **已完成**：容器就绪 90s；overlay 等待默认 180s；失败时 tail compose 日志 |
| A3. CI Job | **已完成**：`.github/workflows/docker-mesh.yml`（`pull_request` + `push`）；托管 runner 需可用 Docker + TUN（与本地验证一致） |
| A4. 文档 | **已完成**：`docker/mesh/README.md` |

**验收**：本地与（若启用）CI 上执行脚本，成功则 0，失败则非 0 且日志可诊断。

---

### 阶段 B — Rust 快速测试层（P0–P1，与 A 并行或紧随）

**目标**：不依赖 Docker 覆盖高价值逻辑，PR 必跑。

| 工作项 | 说明 |
|--------|------|
| B1. `dc::frame` / `dc::msg` | 编解码往返、边界长度、非法输入拒绝 |
| B2. `dc::crypto` | 已知向量或 golden：HKDF 派生、`encrypt`/`decrypt`、错误密钥/篡改密文失败 |
| B3. `dc::directory` | 合并规则、`row_version`、冲突路径（若实现为 warn，可测日志或返回行为） |
| B4. 可选：`tokio` + `UdpSocket` 双任务环回 | 两端口互发 `MEMBER_ANNOUNCE` / 简化 `DATA_IP`，无需 TUN（复杂度较高时可放到 B 后期） |

**验收**：`cargo test` 在 nightly 下全绿；CI 中增加 `cargo test --workspace`（或限定 crate）。

---

### 阶段 C — PR 质量门禁（P0）

| 工作项 | 说明 |
|--------|------|
| C1 | `cargo fmt --check` |
| C2 | `cargo clippy -- -D warnings`（可按模块逐步收紧） |
| C3 | `cargo test`（承接阶段 B） |
| C4 | 与 Release workflow 分离：`ci.yml` 走 PR；`rust.yml` 继续 tag release（避免 PR 触发全矩阵发版） |

---

### 阶段 D — 可观测性与运维文档（P1）

| 工作项 | 说明 |
|--------|------|
| D1 | 统一关键路径日志（启动、bootstrap 解析、TUN/路由、解密失败计数）；文档说明 `RUST_LOG` |
| D2 | 可选：简单 metrics（如 Prometheus 文本导出）或至少文档化「未来指标列表」 |
| D3 | `doc/operations.md`（或等价）：部署检查表、防火墙端口、与系统路由冲突、升级步骤 |

---

### 阶段 E — 安全与供应链（P1–P2）

| 工作项 | 说明 |
|--------|------|
| E1 | CI 定期或每次 PR：`cargo audit`（允许已知豁免列表并注明原因） |
| E2 | `Cargo.lock` 提交策略说明；git 依赖记录 commit 与升级流程 |
| E3 | 简短威胁模型：`doc/security-model.md`（PSK、信任边界、不防什么） |

---

### 阶段 F — 发布与协作（P2）

| 工作项 | 说明 |
|--------|------|
| F1 | `CHANGELOG.md` 或 GitHub Release 模板 |
| F2 | `CONTRIBUTING.md`：nightly 要求、提交规范、如何跑 Docker 测试 |
| F3 | 协议/配置变更时同步 `decentralized-architecture.md` 与 cfg-example |

---

### 阶段 G — Docker 环境扩展（P2，按需）

在 A 稳定后按需增加：

| 工作项 | 说明 |
|--------|------|
| G1 | 第二套拓扑：例如双 bootstrap、或 N>3 全互联抽查 |
| G2 | 可选：启用 STUN 的 compose profile（与当前「关 STUN」对照） |
| G3 | 重启场景：compose restart 指定节点后 overlay 恢复（对应规格 TTL） |

---

## 5. 风险与对策

| 风险 | 对策 |
|------|------|
| GitHub 托管 runner 无法使用 TUN/CAP | 先本地 + self-hosted CI；或 E2E 标记 `continue-on-error` 仅作信息（不推荐长期） |
| Docker 构建过慢 | CI 使用缓存层、`sccache`；或 E2E 用预构建镜像 digest |
| 测试与 nightly 特性耦合 | 在 CI 固定 `RUSTUP_TOOLCHAIN: nightly`，文档写明 |

---

## 6. 建议执行顺序（摘要）

1. **A1–A2**（脚本化 E2E）+ **C1–C3**（fmt/clippy/test 骨架，test 可先极少）  
2. **B1–B3** 填满 `cargo test`  
3. **A3**（Docker E2E 进 CI，若环境允许）  
4. **D、E、F** 并行迭代  
5. **G** 按产品需求扩展拓扑  

---

## 7. 文档维护

本路线图随仓库演进更新：完成某阶段后，在本文档对应小节勾选或链接到实现 PR/issue。

*最后更新：与当前 `docker/mesh`、`scripts/docker-mesh.sh` 布局一致。*
