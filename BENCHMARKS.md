# Benchmarks

What the v0.1 hot path costs on production-representative hardware. Numbers measured 2026-06-23 from the suite in `bench/`; full reproduction instructions in [`bench/README.md`](bench/README.md).

## Reference machine

| CPU | Cores | RAM | Storage | OS | Python |
| --- | --- | --- | --- | --- | --- |
| AMD EPYC Milan (Hetzner CCX13) | 2 dedicated vCPU | 8 GB | local NVMe, ext4, standard `fsync()` | Ubuntu 24.04 (kernel 6.8) | 3.14.6 |

One Linux server-class instance representative of a typical small production deployment. All benches single-threaded; the core count is informational. Local development runs (especially Apple Silicon with `F_FULLFSYNC` plus background OS work) will see different numbers; see [`bench/README.md`](bench/README.md).

## Per-record latency

End-to-end cost of one signed audit record. `InMemorySink` is the crypto + canonicalisation ceiling (sign + chain + RFC 8785 JCS, no I/O). `LocalFileSink` adds JSONL append, manifest rewrite, and per-record `fsync()` × 2.

| Payload | `InMemorySink` (crypto ceiling) | `LocalFileSink` (durable) |
| --- | --- | --- |
| 256 B | 208 µs / record &nbsp;(4 813 rec/sec) | 1.75 ms / record &nbsp;(570 rec/sec) |
| 2 KB  | 285 µs / record &nbsp;(3 512 rec/sec) | 1.73 ms / record &nbsp;(577 rec/sec) |
| 8 KB  | 575 µs / record &nbsp;(1 739 rec/sec) | 2.24 ms / record &nbsp;(446 rec/sec) |

A 2 KB tool-call record adds **~280 µs** of crypto work, or **~1.7 ms** including per-record durable persistence. Payload size matters for the crypto path (JCS canonicalisation scales with size) and is almost noise on the durable path — once you're `fsync`-bound, payload size barely registers.

## Sustained throughput

Records-per-second sustained through `LocalFileSink` over 1 000-record bursts.

| Payload | Throughput |
| --- | --- |
| 256 B | 621 rec/sec |
| 2 KB  | 551 rec/sec |
| 8 KB  | 479 rec/sec |

**One single-core writer sustains ~500 records/sec** with per-record durability — roughly 30 000 tool calls / minute / process. That's well above the call rate of any single agent process and typically enough for a fleet of 5–20 daemon-style agents sharing one writer.

## Verifier throughput

How fast can an auditor re-verify a signed chain? Pre-populated 10 000-record JSONL, no `fsync`, single core.

**6 627 records / second**

Practical translation:

| Chain size | Verification wall time |
| --- | --- |
| 100 K records (~1 light-traffic agent day) | 15 seconds |
| 1 M records (~1 mid-traffic agent week) | 2.5 minutes |
| 10 M records (~6 months audit window) | 25 minutes |

A six-month verification fits in a coffee break on a single 2-vCPU pod. Parallelising by `chain_id` — one process per chain — scales linearly with cores.

## Reference points

Numbers from peer projects for ballpark sanity:

| System | Pattern | Reported throughput |
| --- | --- | --- |
| Sigstore Rekor | Signed transparency log, single-leaf append | ~1–3 K leaves/sec sustained |
| etcd WAL | Append + `fsync`, unsigned | ~10–30 K entries/sec single-node |
| Raw Ed25519 `sign()` (pure crypto, no chaining, no I/O) | — | ~30–60 K sigs/sec single core on commodity x86 |

ai-agent-audit lands in the Sigstore Rekor range for durable writes (~500 rec/sec) and reports a higher verification rate than Rekor's published figures. The gap vs. the raw Ed25519 ceiling is Python orchestration + JCS canonicalisation + `fsync`; the gap vs. etcd is the per-record signature (~50 µs) and the JSON canonical form (~100–300 µs depending on payload).

## Storage caveat

The reference machine uses **local** NVMe. Network-attached storage has dramatically higher `fsync()` latency:

- AWS gp3 EBS: typically 500–2 000 µs per `fsync()`
- GCS persistent disk (standard): similar order
- Azure managed disk (Premium SSD): typically 200–1 000 µs

On the `LocalFileSink` path, expect throughput to drop **5–10×** vs. the table above when running on any of the above. Per-record latency rises to roughly **5–20 ms / record**, throughput to roughly **50–150 rec/sec**.

The v0.2 `S3Sink` is designed to remove synchronous `fsync()` from the hot path: writes buffer to a local WAL, an async coroutine batches them to S3, and S3 Object Lock provides the durability guarantee instead of disk `fsync()`. Throughput target for `S3Sink` on network-attached storage is well above the current `LocalFileSink` numbers; this matrix will be updated when v0.2 ships.

## Reproducing

See [`bench/README.md`](bench/README.md). The numbers in this file reproduce via `bench/run_hetzner.sh`, which creates a fresh CCX13 instance, runs the suite, downloads the output, and deletes the server.
