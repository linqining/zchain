# Cairo 递归桥 PoC 成本实测报告（2026-09-13）

> 排期表 §3"Cairo verifier PoC——递归桥成本实测（建议 2，前置）"出口判据
> 的量化交付。PoC 问题：把 canonical AIR verifier 的检查关系写成 Cairo
> 程序再出证（递归桥），成本是否可承受。**结论先行：最小 canonical 形状
> STARK 验证（8 层 FRI、1 query、深度 8 Merkle 路径、Poseidon252 channel）
> 可在 Cairo 内完整验证并出证成功，单次递归桥证明 ~5–9 分钟（参数族相关）、
> 证明 ~1.0MB（bz2）——Phase 2 正式接入的递归桥成本为一个数量级内可估的
> 常数面，不构成否决项；但证明时间说明链上验证（Cairo Starknet 合约 verifier
> 的执行 + 数据可用性）必须走"验证一次、承诺复用"的聚合形态，逐批出证
> 不可行。**

## 1. 实测环境与流程

- 工程：`cairo-bridge-poc/`（cairo-vm + 官方 `stwo_verifier_core`
  Cairo 库路线；Scarab 工作区 10 crates）。
- 一键流程（`driver/src/main.rs`，本日复验全程 exit 0）：
  1. Rust 镜像求期望值（逐位忠实交叉校验，`driver/src/mirror.rs`）；
  2. `scarb build`（9 个可执行 + base 库）；
  3. cairo-vm 执行各 program（steps/builtins 采集）；
  4. stwo-cairo prove → verify；
  5. **官方 `scarb prove` / `scarb verify` 交叉核对**（独立证明器复核）。

## 2. 递归桥主体：`prog_verify_min`（Cairo 版 canonical AIR verifier 检查）

| 指标 | 值 |
|---|---|
| VM 执行 steps | **15,098**（prove 前 pow2 填充至 131,072） |
| memory holes | 12 |
| builtins | range_check **4,128** · poseidon **38** · output 1（其余 0） |
| cairo_serde 规模 | 314,677 felts（blake2s 族）/ 239,727 felts（poseidon252 族） |
| 证明大小（JSON） | 12.1 MB（blake2s）/ 6.4 MB（poseidon252） |
| 证明大小（binary bz2） | **≈ 1.03 MB** |
| 出证时间（stwo-cairo，M 系列参数） | blake2s_pow26 **10.6 s** · blake2s_m31_pow26 **6.0 s** · **poseidon252_pow26 547.9 s** |
| 验证时间 | 10.8–11.9 ms（blake2s 族）· 239.6 ms（poseidon252 族） |
| 官方交叉验证 | `scarb verify` → **Verified proof successfully** |

## 3. 组件成本基准（递归桥的成本结构）

| program | steps | 主导 builtins | 说明 |
|---|---|---|---|
| prog_baseline（空 program 基线） | 1,537 | range_check 201 | Cairo 程序固定开销 |
| prog_m31_add / m31_mul | 3,140 / 3,340 | range_check 401/601 | Mersenne-31 单次加/乘 |
| prog_qm31_mul | 16,360 | range_check 2,201 | QM31 扩域乘（4×m31 全链） |
| prog_fri_fold | 16,065 | range_check 3,001 | 单层 FRI 折叠 |
| prog_channel | 53,745 | range_check 15,001 · poseidon 200 | Fiat-Shamir channel 抽取（**成本主导项**） |
| prog_merkle（深度 8 路径验证） | 4,301 | poseidon 101 | 单条认证路径 |
| prog_hades | 2,443 | poseidon 100 | 单轮 Poseidon/波斯置换 |

**成本结构结论**：递归桥的 steps 主导项是 **Fiat-Shamir channel 反复
抽取**（~54k steps/次）与 **FRI 折叠链**（~16k steps/层）；builtins 主导项
是 **range_check**（非 poseidon——verifier 的域运算走 Cairo 内存模型而非
内置）。

## 4. 对 Phase 2 立项的含义（工程判读）

1. **可行性**：AIR verifier 的检查关系在 Cairo 内表达无损（镜像逐位一致
   + 双证明器交叉验证通过）——递归桥无原理性障碍。
2. **成本量级**：最小形状单次 ~9 分钟出证（poseidon252 口径）/ 15k steps
   执行。正式接入的 canonical 批次证明验证（query 数、FRI 层数上升）将
   线性~对数放大；按组件基准外推，完整 verifier 预计在 **10⁵–10⁶ steps**
   量级——Starknet 单笔执行的资源包络内，但证明生成侧必须离线。
3. **架构约束**：证明 ~1 MB（bz2）+ 出证分钟级 ⇒ 链上只验一次递归桥
   证明并承诺结论（[Starknet Vault verifier] 的形态），业务批次证明不
   逐笔上链出证——与 `docs/da-selection.md` 的"Vault 根锚定"路线一致。
4. **链上 gas**：未实测（需 Starknet 部署 + 真实 gas 报价）；以 steps/
   builtins 作为成本代理（§2），gas 实测列入 Vault verifier 立项后的
   部署面任务（da-selection.md 同口径"gas 报价需实测"）。

## 5. 复现

```bash
cd cairo-bridge-poc/driver && cargo run --release
# 产物：logs/driver_raw.txt（全量 steps/prove/verify 计时）
#       logs/proof_prog_verify_min_*.bin|json（三参数族证明）
```

## 6. 边界（如实）

- 本 PoC 的 `verify_min` 是 **最小 canonical 形状**（8 层 FRI、1 query），
  非完整 canonical 证明的验证——正式接入前需按完整参数族重测（结构已
  就绪，改参数即可）。
- stwo-cairo 侧 `warn: soundness of proof is not yet guaranteed by Stwo`
  ——上游诚实声明，非本项目可控面。
- 官方交叉验证目前每次运行一参数族（poseidon252 全流程在案）；其余参数
  族以 stwo-cairo 自验证为准。
