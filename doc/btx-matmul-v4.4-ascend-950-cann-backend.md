# Ascend 950 (昇腾) ExactGemm / CANN backend — MatMul v4.4

Bilingual notes for the Huawei Ascend ExactGemm host scaffolding in `src/ascend/`.
Public activation remains inert (`INT32_MAX`). Consensus is still the CPU integer transcript.

---

## 中文摘要

### API 映射（CANN ≥ 9.1，Ascend 950PR/DT，`dav-3510`）

| BTX 入口 | CANN / aclnn |
|---|---|
| `ExactGemmS8S8Ascend` | `aclnnMm` / `aclnnMatmul` 两段式：`GetWorkspaceSize` → execute |
| INT8 权重亲和 | `aclnnTransMatmulWeight`（若头文件存在则可选调用） |
| `cubeMathType` | **固定 `0` = KEEP_DTYPE**；禁止 HF32 / FP 降精度（1/2/3） |
| 累加 | 目标 INT8×INT8→INT32，与 `ExactGemmS8S8` 逐字节一致 |

### 精确性门控

1. 进程内自检（奇 K、大 \|entry\|）对比 CPU `ExactGemmS8S8`；失败则 `IsAscendExactGemmAvailable()=false`。
2. 仅当 Cube/aclnn 实际执行且匹配后置 `used_cube_path=true`；**禁止**在无自检时声称 Cube。
3. `ResolveBackend("ascend")` 仅在 **已编译 + CANN 可用 + 自检通过** 时选中；否则回落 CPU。
4. 默认 CI **无 CANN SDK** → stub 恒返回 false（fail-closed）。

### 如何用 CANN 构建

```bash
# 安装 Ascend CANN toolkit 后：
export ASCEND_HOME=/usr/local/Ascend/ascend-toolkit/latest   # 或 ASCEND_TOOLKIT_HOME
cmake -S . -B build -DBTX_ENABLE_ASCEND=ON
# 若检测到 include/acl/acl.h → 定义 BTX_HAVE_CANN 并链接真实 TU
# 否则仍编译 stub，并警告 cann_sdk_not_found
```

---

## English summary

### API mapping (CANN ≥ 9.1, Ascend 950PR/DT, `dav-3510`)

| BTX entry | CANN / aclnn |
|---|---|
| `ExactGemmS8S8Ascend` | Two-phase `aclnnMm` / `aclnnMatmul`: `GetWorkspaceSize` then execute |
| INT8 weight affinity | Optional `aclnnTransMatmulWeight` when headers exist |
| `cubeMathType` | **Always `0` = KEEP_DTYPE**; never HF32 / down-precision modes |
| Accumulate | INT8×INT8→INT32, byte-identical to `ExactGemmS8S8` |

### Exactness gates

1. Process-local self-qual (odd-K + max-\|entry\| cases) vs CPU `ExactGemmS8S8`; failure keeps `IsAscendExactGemmAvailable()=false`.
2. Set `used_cube_path=true` **only** after Cube/aclnn ran and matched — never claim Cube without self-qual.
3. `ResolveBackend("ascend")` selects ASCEND only when **compiled + CANN available + self-qual**; else CPU.
4. Default CI has **no CANN SDK** → stub always returns false (fail-closed).

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
