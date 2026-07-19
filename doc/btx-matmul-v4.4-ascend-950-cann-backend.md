# Ascend 950 (昇腾) ExactGemm / CANN backend — MatMul v4.4

Bilingual notes for the Huawei Ascend ExactGemm host backend in `src/ascend/`.
Public activation remains inert (`INT32_MAX`). Consensus is still the CPU integer transcript.

---

## 中文摘要

### API 映射（CANN ≥ 9.1，Ascend 950PR/DT，`dav-3510`）

| BTX 入口 | CANN / aclnn |
|---|---|
| `ExactGemmS8S8Ascend` | 两段式 `aclnnMm` → `aclnnMatmul` →（可选）`aclnnMatmulWeightNz`：`GetWorkspaceSize` → execute |
| INT8 权重亲和 | `aclnnCalculateMatmulWeightSize` / `V2` + `aclnnTransMatmulWeight`（头文件存在时） |
| `cubeMathType` | **固定 `0` = KEEP_DTYPE**；禁止 HF32 / FP 降精度（1/2/3） |
| 累加 | 目标 INT8×INT8→INT32，与 `ExactGemmS8S8` 逐字节一致 |
| `ExactGemmS32S8Ascend` | **未证明** → 恒拒绝，回落 CPU `ExactGemmS32S8` |

参考资料：ops-nn `aclnnMm` / `aclnnMatmul` / `aclnnMatmulWeightNz`；ops-math `aclnnTransMatmulWeight`（支持 INT8）；asc-devkit Matmul（`dav-3510`，CANN ≥ 9.1）说明 A/B=`int8_t`、C=`int32_t` 的 Cube 组合。

### 精确性门控

1. 进程内自检对比 CPU `ExactGemmS8S8`，覆盖：
   - 奇数 K / 奇数方阵（奇累加长度）
   - 矩形 MatExpand 式面板
   - 最大 \|entry\| 角点矩阵（±127）
2. 失败则 `IsAscendExactGemmAvailable()=false`。
3. 仅当自检已通过 **且** Cube/aclnn 实际执行后置 `used_cube_path=true`。
4. `ResolveBackend("ascend"|"huawei"|"npu")` 仅在 **已编译 + CANN 可用 + 自检通过** 时选中 ASCEND；否则回落 CPU。
5. 默认 CI **无 CANN SDK** → stub 恒返回 false（fail-closed）。

### 生产资格检查清单（Qualification checklist）

在宣称「Cube ExactGemm 可用」之前，现场必须全部勾选：

- [ ] `BTX_ENABLE_ASCEND=ON` 且 CMake 检测到 `include/acl/acl.h` → `BTX_HAVE_CANN=1`
- [ ] CANN toolkit ≥ 9.1（Ascend 950PR/DT / `dav-3510` 文档基线）
- [ ] NPU 可见（`aclrtGetDeviceCount` > 0）；SoC 为 950 类或文档列出的 Cube INT8 候选
- [ ] 进程启动自检全部 case 与 CPU `ExactGemmS8S8` 逐字节一致
- [ ] `IsAscendExactGemmAvailable()==true` 之后，`ExactGemmS8S8Ascend(..., &used_cube)` 对生产尺寸返回 `used_cube==true`
- [ ] `TryLaunchLtCubeGemmS8S8` 注入 `ExactGemmBackend` 时，挖矿 winner 仍由 CPU 重算密封
- [ ] **禁止** 使用 `cubeMathType∈{1,2,3}`（降精度 / HF32）
- [ ] S32S8 路径未证明前保持拒绝（CPU fallback）

### 已知限制（Known limits）

| 限制 | 说明 |
|---|---|
| 公开 dtype 表偏 FP | ops-nn 文档中 `aclnnMm`/`aclnnMatmul` 列出 BF16/FP16/FP32；INT8 路径依赖工具链实际接纳 + 自检，否则 fail-closed |
| Ascend 950 NZ | `aclnnMatmulWeightNz` 在 950 上文档要求 `aclnnNpuFormatCast`；本实现优先 TransMatmulWeight（A2/A3 亲和），Nz 为可选回退 |
| QuantMatmul | `aclnnQuantMatmulV4` 带 scale，**不**用于 ExactGemm（避免非单位量化破坏整数一致性） |
| Ascend C 内核 | asc-devkit `MatmulType<…, int8_t>`→`int32_t` 是原生 Cube 路径，但需自定义算子；本仓库当前走 host aclnn，不嵌入 Ascend C 内核 |
| S32S8 | 无已证明的 Cube INT32×INT8→INT32 aclnn 路径 → 恒拒绝 |
| 无 CANN CI | 默认构建链接 stub；`IsAscendExactGemmAvailable()==false` |
| 激活 | 公网激活高度仍为 `INT32_MAX`（惰性） |

### 如何用 CANN 构建

```bash
# 安装 Ascend CANN toolkit 后：
export ASCEND_HOME=/usr/local/Ascend/ascend-toolkit/latest   # 或 ASCEND_TOOLKIT_HOME
cmake -S . -B build -DBTX_ENABLE_ASCEND=ON
# 若检测到 include/acl/acl.h → 定义 BTX_HAVE_CANN 并链接真实 TU
# 否则仍编译 stub，并警告 cann_sdk_not_found
```

可选：`BTX_ASCEND_HOME=/path/to/toolkit` 显式指定根目录。

### 运行时行为摘要

| 构建 | 行为 |
|---|---|
| 默认 / 无 CANN | stub：所有入口 false；`ResolveBackend("ascend")` → CPU |
| `BTX_ENABLE_ASCEND` + CANN，自检失败 | 真实 TU 链接，但 `IsAscendExactGemmAvailable()=false`；不设 `used_cube_path` |
| CANN + 自检通过 | Cube S8S8 可用；`MakeResolvedExactGemmBackend` 注入 `TryLaunchLtCubeGemmS8S8` |

---

## English summary

### API mapping (CANN ≥ 9.1, Ascend 950PR/DT, `dav-3510`)

| BTX entry | CANN / aclnn |
|---|---|
| `ExactGemmS8S8Ascend` | Two-phase `aclnnMm` → `aclnnMatmul` → optional `aclnnMatmulWeightNz` |
| INT8 weight affinity | `aclnnCalculateMatmulWeightSize` / `V2` + `aclnnTransMatmulWeight` when headers exist |
| `cubeMathType` | **Always `0` = KEEP_DTYPE**; never HF32 / down-precision |
| Accumulate | INT8×INT8→INT32, byte-identical to `ExactGemmS8S8` |
| `ExactGemmS32S8Ascend` | **Unproven** → always declines → CPU |

Sources: ops-nn Mm/Matmul/MatmulWeightNz; ops-math TransMatmulWeight (INT8); asc-devkit Matmul notes for `dav-3510` int8→int32 Cube.

### Exactness gates

1. Process-local self-qual vs CPU `ExactGemmS8S8`: odd-K / odd squares, rectangular MatExpand-like panels, ±127 corner matrices.
2. Failure keeps `IsAscendExactGemmAvailable()=false`.
3. Set `used_cube_path=true` **only** after self-qual **and** a Cube/aclnn launch.
4. `ResolveBackend("ascend")` selects ASCEND only when **compiled + CANN + self-qual**; else CPU.
5. Default CI has **no CANN SDK** → stub always returns false.

### Production qualification checklist

Before advertising Cube ExactGemm:

- [ ] `BTX_ENABLE_ASCEND=ON` and CMake found `include/acl/acl.h` (`BTX_HAVE_CANN=1`)
- [ ] CANN ≥ 9.1 on Ascend 950PR/DT (`dav-3510`) or documented Cube INT8 candidate
- [ ] NPU present; SoC classified admissible
- [ ] All self-qual cases match CPU `ExactGemmS8S8` byte-for-byte
- [ ] After availability, production shapes set `used_cube_path=true`
- [ ] Mining winners still CPU-resealed
- [ ] Never use `cubeMathType∈{1,2,3}`
- [ ] Keep S32S8 declined until a proven Cube path exists

### Known limits

| Limit | Note |
|---|---|
| Public dtype tables are FP-centric | INT8 on Mm/Matmul is admit-by-self-qual only |
| Ascend 950 NZ | Docs prefer `NpuFormatCast` for WeightNz; we try TransMatmulWeight first |
| QuantMatmul | Not used (scale would break integer ExactGemm) |
| Ascend C kernels | Native int8→int32 Cube exists in asc-devkit; this tree uses host aclnn only |
| S32S8 | Declined |
| No-CANN CI | Stub linked; availability false |
| Activation | Still `INT32_MAX` (inert) |

### Build with CANN

```bash
export ASCEND_HOME=/usr/local/Ascend/ascend-toolkit/latest
cmake -S . -B build -DBTX_ENABLE_ASCEND=ON
# Detects include/acl/acl.h → BTX_HAVE_CANN + real TU; else inert stub.
```

### Sources

- `src/ascend/matmul_v4_lt_accel.h` / `.cpp` / `_stub.cpp`
- Capability string: `"ascend"` (`Kind::ASCEND`); aliases `huawei`, `npu`
- Architecture notes: `doc/btx-matmul-v4.4-multi-vendor-exactgemm-architecture-2026-07-19.md`
