# Huawei Ascend CANN backend — MatMul v4.4 LT ExactGemm

The Ascend backend is experimental and fail-closed. Public activation remains
inert (`INT32_MAX`), and the CPU integer transcript remains authoritative.

## 中文摘要

### 采用的精确整数接口

CANN 9.1 的官方 `aclnnQuantMatmulV5` 文档明确规定：当 `x1`、`x2` 为
`INT8`，输出为 `INT32`，`bias=nullptr` 时，各种 scale 均不参与计算，语义为：

```text
out = x1 @ x2
```

输入组合表仍要求一个 `x2Scale` tensor，因此代码传入 page-locked staging 中的
`FLOAT32(1.0)`；它满足接口类型约束，但按上述官方公式不改变整数结果。本后端只使用
这个 raw INT8→INT32 模式。旧实现尝试通过
`aclnnMm`/`aclnnMatmul` 执行 INT8；公开文档并未把该组合列为受支持类型，因此已经
删除，避免把未文档化的 fallback 误报为 Cube ExactGemm。

`aclnnCalculateMatmulWeightSizeV2` + `aclnnTransMatmulWeight` 将右矩阵转换为
NPU 亲和的 NZ 布局。该转换是本后端的 native-Cube 证明条件，而不只是可选优化：
转换接口或 V5 头文件任一缺失，整个后端恒拒绝。虽然 V5 也支持 ND，但本代码不把
ND-only launch 误报为已经证明的 Cube 路径。

### 性能改进

- Device A/B/C/scale 缓冲、page-locked host staging、stream 和最大 workspace 均为进程级复用。
- `aclrtMemsetAsync`、两个 H2D、V5 GEMM 和 D2H 在同一 stream 中保序，仅末尾同步一次。
- B 的 padding 每次异步清零，避免前一次 NZ 转换留下的数据污染下一次矩阵。
- 第一阶段 `GetWorkspaceSize` 仍按调用执行；CANN opbase 可通过 `ACLNN_CACHE_LIMIT`
  缓存 workspace/executor/tiling 信息。
- 本代码未手工永久缓存 `aclOpExecutor`。官方要求先调用
  `aclSetAclOpExecutorRepeatable`，且 NZ 转换计划未必满足可复用限制；未经现场 CANN
  验证时强行缓存会造成生命周期错误。

### 精确性和诚实性门控

进程首次启用时把 NPU 结果与 CPU `ExactGemmS8S8` 逐字节比较，覆盖：

- 奇数 M/N/K 与非对齐 padding/crop；
- 矩形 panel；
- 对齐的 32×64×48 与 K=256 Cube 形状；
- 密集 `+127/-128` 输入，检查饱和、窄化或错误累加。

只有全部通过后 `IsAscendExactGemmAvailable()` 才返回 true，并且只有成功执行同一
V5 路径后才设置 `used_cube_path=true`。S32×S8 不映射到 V5：CANN 的 `INT32`
输入在该接口中表示 packed INT4，不是语义上的 INT32 乘数，因此继续回落 CPU。

### 构建和上线要求

- 需要 CANN 9.1+，且存在 `aclnnop/aclnn_quant_matmul_v5.h`。
- 链接必须包含 CANN 9.1 对应的 NN 和 Math operator libraries；8.5+ 推荐
  `libopapi_nn.so` + `libopapi_math.so`。若 split libraries 不完整才整体改用
  `libopapi.so`，官方明确禁止同时引用通用库和 split libraries。
- 真机必须记录 SoC、CANN/driver 版本、是否使用 NZ、端到端吞吐和与 CPU golden
  vectors 的结果。
- 能力分类只接受共享 Ascend runtime 初始化后 `aclrtGetSocName()` 返回的真实 SoC；
  不再接受环境变量覆盖，也不会把查询失败默认成 `dav-3510`。
- 公开的 CANN 页面目前主要列出 Atlas A2/A3/350 产品。不能仅凭“Ascend 950”名称
  宣称已验证；950 实机与对应 CANN 发布包必须完成相同自检和性能审核。
- V5 的 x2 format 约束随产品系列变化：部分系列允许或要求 NZ，但 9.1 页面把
  Atlas 350 列为 ND-only。当前代码严格要求 NZ，因此遇到 ND-only 产品会安全拒绝；
  在 Huawei 发布 950/dav-3510 的明确产品映射和 native-Cube 证据前不猜测回退。

## English audit and implementation notes

### Exact operator contract

The backend now requires CANN's documented raw integer mode:

```text
aclnnQuantMatmulV5(x1=INT8, x2=INT8, out=INT32,
                   x1Scale=null, x2Scale=FLOAT32(1),
                   offsets=null, bias=null)
=> out = x1 @ x2
```

CANN 9.1 explicitly says that scales do not participate in this combination.
The documented dtype table nevertheless requires an `x2Scale` tensor, so the
backend supplies a stable FLOAT32 value of 1.0; it is an API-contract input,
not an arithmetic quantization step.
The previous `aclnnMm`/`aclnnMatmul` experiment was removed because released
public dtype tables do not document INT8 inputs with INT32 output for those
ordinary operators. A successful undocumented call is not sufficient evidence
of native Cube execution or stable semantics.

B is transformed from ND to the explicitly AI-processor-affine NZ layout using
`aclnnCalculateMatmulWeightSizeV2` and `aclnnTransMatmulWeight`. This is an
admission requirement, not merely a preference: the backend rejects an ND-only
launch because arithmetic identity alone would not prove the native Cube path.
Missing V5 or either transform API means availability is false.

### Runtime lifecycle

The hot path retains:

- one AscendCL stream;
- grow-only device buffers for A, B, C, scale, and workspace;
- grow-only host-pinned staging buffers for A, B, C, and scale.

Each launch copies into pinned staging, queues padding clear/H2D/operator/D2H
on the same stream, and synchronizes once before returning the host vector.
This removes repeated `aclrtMalloc`, `aclrtMallocHost`, workspace allocation,
and stream setup from repeated LT GEMMs.

The code deliberately does **not** retain a manually repeatable executor.
Huawei documents that phase two cannot normally be called twice and that
`aclSetAclOpExecutorRepeatable` must explicitly admit reuse. The transform may
also make the plan non-repeatable. CANN's own opbase phase-one cache remains
available and is the safe executor/tiling cache until the exact V5+NZ plan has
been qualified on the target toolkit.

### Remaining qualification gaps

- No Ascend hardware or CANN SDK is available in default CI, so only the inert
  stub can be exercised there.
- Capability admission obtains the real `aclrtGetSocName()` through the
  backend-owned one-time runtime initialization. It has no environment override
  and never defaults an unknown device to `dav-3510`.
- V5 layout support is product-specific. The 9.1 page documents ND-only x2 on
  Atlas 350, while other families accept or require the affinity layout. This
  implementation intentionally rejects ND-only execution rather than label it
  native Cube without a target-specific trace; an Atlas 350/dav-3510 mapping
  must not be inferred from a marketing name.
- `msprof`/operator traces should be retained as production evidence that the
  exact V5+NZ path ran on Cube on the target CANN/SoC combination.
- S32×S8 remains CPU-only (radix-256 over Cube S8×S8 when ExactGemm qualifies).
- Exact MX B̂·V is the four Cube ExactGemm scale partition (`e∈{0..3}`, shift,
  sum), self-qualified byte-identical to `ComputeProjectedRightMxBlockScaleLT`.
  MatExpand Extract stays host `ExpandOperandBMatExpandMxComponents` with Cube
  ExactGemm inject for `G*W` / `(G*W)*H`. Provenance:
  `used_cube_path`, `exact_mx_scale_partitioned`, `native_mx_qualified`
  (always false until a documented CANN FP8/MX ExactGemm path is oracle-proven;
  none is admitted today).
- This is host-orchestrated ExactGemm + MX projection, not a fully
  device-resident LT transcript; host round trips between stages will cap
  end-to-end throughput.
- Manual repeatable-executor caching and multi-stream double buffering should
  be enabled only after the selected CANN release proves the V5/NZ executor is
  repeatable and each stream has disjoint buffers/workspace.

## Official sources

- [CANN 9.1 `aclnnQuantMatmulV5`](https://www.hiascend.com/document/detail/zh/CANNCommunityEdition/910beta3/API/aolapi/context/ops-nn/aclnnQuantMatmulV5.md) — raw INT8×INT8→INT32 formula and V5 signature.
- [CANN 8.5 `aclnnMatmul`](https://www.hiascend.com/document/detail/zh/canncommercial/850/API/aolapi/context/ops-nn/aclnnMatmul.md) — ordinary Matmul contract; not used for ExactGemm.
- [CANN 8.5 `aclnnCalculateMatmulWeightSizeV2`](https://www.hiascend.com/document/detail/zh/canncommercial/850/API/aolapi/context/ops-math/aclnnCalculateMatmulWeightSizeV2.md) — INT8 NZ allocation is measured in elements.
- [CANN 8.5 `aclnnTransMatmulWeight`](https://www.hiascend.com/document/detail/zh/canncommercial/850/API/aolapi/context/ops-math/aclnnTransMatmulWeight.md) — INT8 weight-affinity transformation.
- [CANN 8.5 operator-library linkage](https://www.hiascend.com/document/detail/en/canncommercial/850/API/aolapi/operatorlist_00001.html) — split `opapi_nn`/`opapi_math` linkage and the prohibition on mixing them with generic `opapi`.
- [CANN 8.5 `aclrtMemcpyAsync`](https://www.hiascend.com/document/detail/en/canncommercial/850/API/appdevgapi/aclcppdevg_03_0106.html) — page-locked host buffers are required for genuinely asynchronous host transfers.
- [CANN 8.5 `aclrtMemsetAsync`](https://www.hiascend.com/document/detail/en/canncommercial/850/API/appdevgapi/aclcppdevg_03_0104.html) — stream-ordered asynchronous device initialization.
- [`aclSetAclOpExecutorRepeatable`](https://www.hiascend.com/document/detail/en/canncommercial/800/apiref/aolapi/operatorlist_00041.html) — repeatability admission and executor destruction requirements.
- [Ascend C Matmul type contract](https://www.hiascend.com/document/detail/en/canncommercial/850/API/ascendcopapi/atlasascendc_api_07_0614.html) — native int8 matrix inputs accumulate to int32 in the Cube API.
- [Official Ascend custom Matmul kernel invocation sample](https://github.com/Ascend/samples/tree/master/cplusplus/level1_single_api/4_op_dev/6_ascendc_custom_op/kernel_invocation/MatMul) — stream and custom-kernel launch structure.
