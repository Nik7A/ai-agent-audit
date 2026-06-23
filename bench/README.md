# Benchmarks

Three benches that answer the questions a sceptical engineering reader brings
when first reading the README:

1. **`test_record_latency.py`** — how much latency does one signed audit
   record add to a tool call? Reported per sink (in-memory ceiling, local
   file with `F_FULLFSYNC`) and across three payload sizes (256B, 2KB, 8KB).
2. **`test_sustained_throughput.py`** — how many records per second can a
   single core push through `LocalFileSink` back-to-back?
3. **`test_verifier_throughput.py`** — how many records per second does the
   verifier chew through? Pre-populated 10 000-record corpus, no fsync.

The bench suite is intentionally NOT collected by the default
`uv run pytest` run (see `testpaths` in `pyproject.toml`). It runs only when
you point pytest at `bench/`.

## Local run (your dev machine)

```bash
uv sync --group dev
uv run pytest bench/ \
    --benchmark-only \
    --benchmark-columns=mean,stddev,ops,rounds \
    --benchmark-sort=mean
```

Total wall time: 2-5 minutes depending on storage subsystem.

**Dev-machine numbers are not directly comparable to `BENCHMARKS.md`.** Two reasons:

- On macOS, the bench uses `F_FULLFSYNC` (true platter sync) rather than the cheaper `fsync()` used on Linux. This is intentional and matches the runtime behaviour of `LocalFileSink` on each platform — but it makes the same workload several times slower on Mac than on Linux for `LocalFileSink` rows.
- Consumer OSes (macOS, desktop Linux) run background services — Spotlight indexing, Apple Intelligence ingest, Time Machine, `mds`, etc. — that contend for the disk and add noticeable variance to `fsync`-bound benches. Expect the `LocalFileSink` and `sustained_throughput` rows to land **2–3× slower** than the cloud reference, with higher run-to-run variance. The `InMemorySink` and `verifier_throughput` rows are CPU-bound and roughly comparable across platforms.

If you want a number you can quote, run the Hetzner reference (next section). Dev-machine runs are for verifying changes don't regress, not for public quoting.

## Cloud run (Hetzner CCX13 reference)

The `BENCHMARKS.md` table at the repo root reports two columns: the author's
dev machine and a Hetzner CCX13 (2 dedicated vCPU AMD EPYC, 80 GB local
NVMe). The cloud column is reproduced via `bench/run_hetzner.sh`, which:

- Creates the server with your uploaded SSH key
- `rsync`s the local working copy (so you don't need to push to a remote)
- Installs `uv` + dev deps on the server
- Runs the bench suite
- Downloads results to the current directory
- Deletes the server on exit (even if anything fails)

### One-time prereqs

```bash
brew install hcloud
hcloud context create ai-agent-audit    # paste API token from Cloud Console
hcloud ssh-key create \
    --name "$(whoami)-mac" \
    --public-key-from-file ~/.ssh/id_ed25519.pub
```

The API token needs Read & Write scope; create it in **Hetzner Cloud
Console → Security → API Tokens**.

### Each run

From the repo root:

```bash
bash bench/run_hetzner.sh
```

End-to-end: 6-8 minutes. Cost: a few euro cents (CCX13 is ~€0.022/hour;
billed by the hour with a monthly cap).

Output files dropped in the current directory:

- `bench-hetzner.txt` — human-readable pytest output
- `bench-hetzner.json` — machine-readable for the `BENCHMARKS.md` matrix
- `bench-fingerprint.txt` — hardware + storage + Python info

The trap in the script deletes the server on any exit (success, failure,
Ctrl-C). If something goes really wrong, `hcloud server list` shows any
leftovers and `hcloud server delete <name>` removes them.

## Reading the output

`pytest-benchmark` prints a table grouped by
`@pytest.mark.benchmark(group=...)`. Each row's `mean` is the wall-clock
seconds for one round; each round writes `records_per_round` records
(printed in the `extra_info` column). Per-record latency is therefore
`mean / records_per_round`. Records per second at single-core saturation is
`records_per_round / mean`.

The `bench-*.json` files are the source of truth that gets folded into the
public `BENCHMARKS.md` matrix.

## Storage caveat

Numbers reflect whatever storage the bench is run on. The Hetzner CCX13
reference uses local NVMe; AWS gp3 EBS, GCS persistent disks, and Azure
managed disks are network-attached and have substantially higher fsync
latency. For fsync-bound workloads (the `record_latency_local_file` group),
expect 5-10x worse numbers on network-attached storage. The `S3Sink`
shipping in v0.2 takes fsync out of the agent's hot path; the matrix in
`BENCHMARKS.md` will reflect that once it ships.
