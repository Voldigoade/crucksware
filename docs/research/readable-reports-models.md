# Local readable-report model evaluation

This evaluation tests whether a compact local model can turn Crucksware's structured
comparison facts into a short explanation without becoming a source of new facts. The
deterministic report remains authoritative. Model output is not suitable for a trusted
default summary unless it preserves fact identity, evidence references, and important
changes across the test corpus.

## Candidate screening

| Candidate | Card facts and languages | Context | Q4 artifact | Q5 alternative | License and screening |
| --- | --- | ---: | --- | --- | --- |
| Qwen3-0.6B | 0.6B parameters, post-trained, card claims 100+ languages | 32,768 | Upstream GGUF Q4_0, 428,970,080 bytes | Community GGUF Q5_0 listing, approximately 544 MB; not tested | Apache-2.0. Q4_0 empirically tested. |
| Qwen3.5-0.8B | 0.8B parameters, post-trained causal model with vision encoder, card claims 201 languages | 262,144 | Upstream GGUF Q4_0, 563,036,064 bytes | No Q5 artifact in the reviewed upstream GGUF file list; Q8_0 is 834 MB | Apache-2.0. Q4_0 empirically tested. |
| LFM2.5-350M | 350M parameters, post-trained, English, Arabic, Chinese, French, German, Japanese, Korean, Portuguese, Spanish | 32,768 | QAD GGUF Q4_0, 219,312,832 bytes | GGUF Q5_K_M, 260 MB; not tested | LFM Open License v1.0 restricts commercial use by entities at or above USD 10 million annual revenue. QAD Q4_0 empirically tested, but not suitable as Crucksware's default distribution model. |
| Gemma 3 270M IT | 270M parameters, instruction-tuned, card claims over 140 languages | 32,768 | Upstream QAT GGUF Q4_0, 241 MB | Community QAT GGUF Q5_K_M listing, 260 MB; not tested | Google Gemma terms and gated source access. Excluded from download and testing because acceptance of those terms was not part of this evaluation. |
| SmolLM2-360M-Instruct | 360M parameters, instruction-tuned, model card describes primarily English use | Not stated in the reviewed card | Community GGUF Q4_K_M listing, approximately 271 MB | Community GGUF Q5_K_M listing, approximately 290 MB; not tested | Apache-2.0, but screened out because the required French, Spanish, and Simplified Chinese quality is not established by its model card. |

Model cards describe broad training or language coverage, not verified accuracy for
Crucksware reports. The LFM GGUF page lists eight languages while the base model card
lists nine, so the exact supported-language metadata for that quantized artifact is
uncertain. Gemma's source card lists 32K context for the 270M size; its wider 128K
context applies to larger Gemma 3 models. SmolLM2's reviewed card does not state a
maximum context length, so none is asserted here.

The tested artifact identities are pinned by repository revision and SHA-256:

| Artifact | Repository revision | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Qwen3-0.6B Q4_0 | `13ac06624948e4d8589cb4b6f90100837342fcb8` | 428,970,080 | `da2572f16c06133561ce56accaa822216f2391ef4d37fba427801cd6736417d4` |
| Qwen3.5-0.8B Q4_0 | `807dfd9a6fadbf703207aac3bfb0b2b3040d077c` | 563,036,064 | `57d1997790d1744fba5b40a7317df71ea5e2acee28c47e78f0cce39c0703f8cf` |
| LFM2.5-350M QAD Q4_0 | `657e078c94084481950a2d555a941481f715536b` | 219,312,832 | `3d10b6ab8fc91a919534b9558e266255aca0bbc7f6d015963599aa9e74e05b1d` |

## Runtime assessment

`llama.cpp` was used as a temporary measurement runtime because its current source
supports these GGUF models, runs on CPU, and provides optional CUDA, HIP, Vulkan, Metal,
and other backends. Its license is MIT. The measurement used its C API directly, with no
server and no network request. The source came from commit
[`1b29621bacc6a446bd523fc790316a24a06e886f`](https://github.com/ggml-org/llama.cpp/commit/1b29621bacc6a446bd523fc790316a24a06e886f).
This proves neither cross-platform behavior nor a suitable production integration.
Building the runtime required CMake, a C++ toolchain, and a substantial native build.

The current `llama-cpp-2` release (`0.1.159`) offers a direct API but builds the native
runtime and its source uses unsafe FFI operations with assertion and panic paths. Its
documentation also warns that the API can be misused to cause undefined behavior. That
boundary is not accepted for a report pipeline that must handle untrusted evidence
safely. The current Candle project has an official
quantized Qwen3 example and documents Q4_K_M and Q8_0 GGUF paths. Candle remains a
possible Rust-native option, but it was not benchmarked here and Qwen3.5 support was not
established. `mistral.rs` exposes a broader serving and model-format surface than this
small CLI needs. ONNX Runtime is actively released and cross-platform, but the tested
model artifacts are GGUF and would require a different model conversion and packaging
path. No production runtime is selected in this research stage.

## Evaluation method

The temporary corpus contains 14 structured evidence packets derived from Crucksware's
current report model: source additions and removals, signature changes, ELF and PE
facts, mixed trees, rootfs changes, thousands of routine asset changes, malformed or
unsupported facts, no-change results, library changes, and French, Spanish, and
Simplified Chinese outputs. Packets contain facts and evidence identifiers only. No
source tree or arbitrary source text was sent to a model.

Each candidate used the same system instruction, chat formatting, sampling settings,
eight CPU threads, and 140-token output cap. One process loaded each model once, then
handled all 14 cases in sequence. Each packet had one warm inference. The timer measured
prompt processing through the final generated token. A separate timer measured model
file loading. GNU `time` recorded peak process RSS. The filesystem cache was warm; model
load timings therefore are not cold-device measurements. The machine had no usable GPU.
These are one-run screening measurements, not a statistical performance qualification.

The evaluation also tried asking Qwen3 to return only evidence IDs in a JSON selection
object. Across the 14 cases it still emitted prose, malformed or truncated structures,
unrecognized identifiers, and unsupported statements about security motives. Prompt
instructions alone do not provide a safe structured-output boundary.

## Measurements

Machine: AMD Ryzen 7 5700X, 8 cores and 16 logical CPUs; Ubuntu 26.04.1, Linux
7.0.0-38-generic; 31 GiB RAM; no usable GPU. Runtime build reported `llama.cpp`
`0.7.0-dev`; model source was the pinned commit above. Times are milliseconds across
the 14 cases, with average and median shown. Peak RSS is GNU `time` maximum resident
set size.

| Model | Mean / median / max total inference | Median prompt processing | Median first token | Median decode throughput | Model load, cached filesystem | Peak RSS |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Qwen3-0.6B Q4_0 | 1,520 / 1,466 / 2,644 | 330 | 331 | 64.4 tokens/s | 401 ms | 937 MiB |
| Qwen3.5-0.8B Q4_0 | 2,894 / 2,788 / 4,368 | 527 | 527 | 38.1 tokens/s | 556 ms | 970 MiB |
| LFM2.5-350M QAD Q4_0 | 637 / 661 / 994 | 189 | 189 | 127.9 tokens/s | 180 ms | 437 MiB |

Throughput is generated tokens divided by the runtime's measured decode time; it does
not include prompt processing. Model-load timing includes process initialization and
mapping the model after its file was already present in the operating-system cache. It is
not a cold-device load measurement. Artifact sizes are the one-time download-size
measurement; transfer duration was not measured. No model was selected for the product.

The Qwen3 packet outputs were generally readable in English, French, Spanish, and
Simplified Chinese. However, the English corpus exposed two material evidence-reference
errors, an altered identifier, and omissions from high-volume asset and ELF-import
cases. Qwen3.5 produced unsupported explanations about network behavior and security,
and added facts not present in evidence. LFM2.5 was fastest and smallest, but altered or
dropped identifiers and evidence relationships in multiple cases. Those are correctness
failures for this product, regardless of latency.

The concise-summary target of five seconds was met by Qwen3 on these warm packets, with a
2.64 second maximum. The smaller LFM2.5 was under one second but did not meet the
factuality bar. The larger Qwen3.5 was slower and less faithful in this corpus. None is
qualified as a trusted report writer.

## Decision

Do not add model inference or automatic model downloads to the product based on these
results. Use a deterministic, bounded readable-summary layer as the default and keep
the detailed technical report canonical. A future model experiment must use a constrained
output representation that cannot introduce arbitrary prose or unsupported facts, and
must repeat multilingual factuality and latency qualification before becoming a user
feature. No language is advertised as model-qualified from this small screening corpus.

## Primary sources

- [Qwen3-0.6B model card](https://huggingface.co/Qwen/Qwen3-0.6B)
- [Qwen3-0.6B GGUF artifact and checksum](https://huggingface.co/ggml-org/Qwen3-0.6B-GGUF/blob/main/Qwen3-0.6B-Q4_0.gguf)
- [Qwen3-0.6B community Q5 listing](https://huggingface.co/tensorblock/Qwen_Qwen3-0.6B-GGUF)
- [Qwen3.5-0.8B model card](https://huggingface.co/Qwen/Qwen3.5-0.8B)
- [Qwen3.5-0.8B GGUF file list](https://huggingface.co/ggml-org/Qwen3.5-0.8B-GGUF/tree/main)
- [LFM2.5-350M model card](https://huggingface.co/LiquidAI/LFM2.5-350M)
- [LFM2.5 QAD GGUF artifact and checksum](https://huggingface.co/LiquidAI/LFM2.5-350M-GGUF/blob/main/LFM2.5-350M-QAD-Q4_0.gguf)
- [LFM2.5 GGUF quantization sizes](https://huggingface.co/LiquidAI/LFM2.5-350M-GGUF)
- [LFM Open License v1.0](https://www.liquid.ai/lfm-license)
- [SmolLM2-360M-Instruct model card](https://huggingface.co/HuggingFaceTB/SmolLM2-360M-Instruct)
- [SmolLM2 Q4_K_M conversion listing](https://huggingface.co/tensorblock/SmolLM2-360M-Instruct-GGUF)
- [SmolLM2 Q5_K_M conversion size](https://huggingface.co/tensorblock/SmolLM2-360M-Instruct-GGUF)
- [Gemma 3 270M Instruct model card](https://huggingface.co/google/gemma-3-270m-it)
- [Gemma 3 270M Instruct QAT GGUF artifact](https://huggingface.co/ggml-org/gemma-3-270m-it-qat-GGUF/blob/main/gemma-3-270m-it-qat-Q4_0.gguf)
- [Gemma 3 QAT Q5 conversion size](https://huggingface.co/unsloth/gemma-3-270m-it-qat-GGUF/tree/main)
- [Google Gemma terms](https://ai.google.dev/gemma/terms)
- [llama.cpp source and build documentation](https://github.com/ggml-org/llama.cpp)
- [Candle quantized Qwen3 example](https://github.com/huggingface/candle/tree/main/candle-examples/examples/quantized-qwen3)
- [llama-cpp-2 Rust binding documentation](https://docs.rs/llama-cpp-2/latest/llama_cpp_2/)
- [mistral.rs repository](https://github.com/EricLBuehler/mistral.rs)
- [ONNX Runtime release history](https://github.com/microsoft/onnxruntime/releases)
