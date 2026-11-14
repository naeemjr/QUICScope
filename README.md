# QUICScope

QUICScope is dual-use tooling: it can support defensive traffic-analysis
experiments and reproducibility work, while also serving as the artifact for a
future research paper on uncertainty-aware association of encrypted QUIC
observations.

## Novel research question

**When a passive observer cannot uniquely determine whether an encrypted QUIC
observation belongs to an existing connection, can an independent ambiguity
oracle identify when abstention reduces confident association error, and what
coverage cost does that impose?**

The benchmark answers this in a controlled synthetic setting by separating
observable evidence from hidden truth, comparing forced and abstaining
trackers, and measuring risk, coverage, fragmentation, and oracle agreement.
The current repository contains the research artifact and working tooling; the
paper is planned as a future publication.

A fully offline, synthetic benchmark for one question:

> Under partial passive observation of encrypted QUIC traffic, when can a
> monitor safely associate observations with the same underlying
> connection, and when should it abstain because the visible evidence is
> insufficient?

## In 90 seconds

A network monitor that tracks connections has to decide, for each packet it
sees, whether it continues something already tracked. QUIC makes that hard
on purpose: a connection can move to a new address with fresh identifiers,
and identifiers can be absent altogether. QUICScope measures what happens
when a monitor is forced to decide anyway, and what changes when it is
allowed to say "uncertain".

- **Synthetic traces with hidden truth.** A deterministic generator
  produces QUIC-like traffic across ten scenario families. Each event has
  an observable half, which trackers see, and a ground-truth half, which
  only the scorer sees.
- **Three methods.** `strict-tuple` (tuple only), `continuity-forced`
  (scores continuity evidence and always decides), and
  `continuity-abstain` (the same evidence and scores, but declines when the
  best score is below a threshold).
- **An independent ambiguity oracle.** It labels an observation ambiguous
  when two different connection assignments are consistent with everything
  the monitor has seen, under an explicitly declared simulator model. It
  reads no ground truth and shares no code with any tracker.
- **A frozen protocol.** Hypothesis, metrics with denominators, a
  development/held-out seed split, and the threshold-selection rule were
  committed before the held-out evaluation was run.

**Headline result, held-out seeds, synthetic traces only.** Allowing
abstention lowered selective risk (incorrect confident decisions over
confident decisions, at association opportunities) from 18% to 0.87%,
while the abstaining method made a confident decision at 78% of
opportunities. It did not recover continuity: it left 28% of connections
fragmented, against 24% for the forced method. Full results, including
where abstention does not help:
[INDEPENDENT_EVALUATION_AND_APPLICATION_RESULTS.md](INDEPENDENT_EVALUATION_AND_APPLICATION_RESULTS.md).

## Scope, dual-use framing, and synthetic-only limits

QUICScope is **not** a live traffic monitor, an operational sensor, a QUIC
decryption tool, or a way to identify real users or sessions, and it makes
**no claim about real QUIC deployments**.

The implementation is intended for authorized research, defensive
measurement, teaching, and reproducibility. It contains no packet capture,
socket, decryption, or real-user identification capability.

- It captures no packets, opens no sockets, and reads no network
  interface. The source contains no networking code.
- Every address in a trace is from the RFC 5737 documentation ranges.
- Every number it reports describes a simulator whose rules are written
  down in [`src/simmodel.rs`](src/simmodel.rs). How far that is from
  reality is the subject of [docs/VALIDITY_THREATS.md](docs/VALIDITY_THREATS.md)
  and [docs/WHY_THIS_MAY_BE_WRONG.md](docs/WHY_THIS_MAY_BE_WRONG.md).

## Quick start

Requirements: Rust stable with `rustfmt` and `clippy` (developed with
rustc 1.99.0), `make`, and `sha256sum`.

```sh
cd quicscope
cargo fetch --locked        # the only step that uses the network
make check                  # format check, lint, build, unit + integration tests
```

Everything after `cargo fetch` runs offline; the Makefile sets
`CARGO_NET_OFFLINE=true`.

## One experiment command

```sh
make final
```

This runs the frozen held-out evaluation (40 seeds, ten scenario families,
three methods) and the exploratory sweeps, and writes every table and
figure to `results/final/`. It takes a few seconds (about 8 s on the
development machine). To check that your
machine reproduces the committed results byte for byte:

```sh
make verify
```

### Expected outputs

```text
results/final/
  manifest.json                         protocol, seeds, methods, file list
  SHA256SUMS                            checksums of everything below
  heldout/hypothesis.json               the pre-declared rule and its outcome
  heldout/summary.csv                   every metric: mean, SD, min, max, 95% CI
  heldout/per_seed.csv                  primary metrics per seed, with numerators and denominators
  heldout/per_seed_family.csv           all counts per seed x family x method
  heldout/paired_differences.csv        forced minus abstain, per metric
  heldout/risk_coverage.csv             the abstention-threshold curve
  sweeps/sweeps.csv                     exploratory sweeps (separate seeds)
  tables/table_primary_metrics.md
  tables/table_by_family.md
  tables/table5_metric_levels.md        connection / edge / decision / event level
  tables/table6_per_seed.md
  tables/table7_when_abstention_helps.md
  tables/table_sweeps.md                exploratory
  figures/fig1_exact_continuity.svg
  figures/fig2_false_merge_split.svg
  figures/fig3_risk_coverage.svg
  figures/fig4_loss_sweep.svg           exploratory
```

`make final` prints the primary table and the hypothesis outcome:

```text
primary metric (mean [95% CI] over seeds)                  strict-tuple        continuity-forced       continuity-abstain
Connection-level exact continuity rate                   48% [47%, 49%]           66% [65%, 66%]           71% [70%, 71%]
False merge rate (connection pairs)                0.27% [0.26%, 0.29%]     0.41% [0.40%, 0.42%]  0.023% [0.017%, 0.028%]
False split rate (confident)                             41% [41%, 42%]           21% [20%, 21%]     0.80% [0.65%, 0.96%]
Incorrect confident association-edge rate          0.14% [0.13%, 0.15%]     0.26% [0.26%, 0.27%]  0.011% [0.009%, 0.014%]
Decision coverage                                     100% [100%, 100%]        100% [100%, 100%]           78% [78%, 79%]
Selective risk                                           30% [30%, 30%]           18% [18%, 19%]      0.87% [0.72%, 1.0%]
Abstention precision vs the synthetic oracle                        n/a                      n/a          99% [99%, 100%]
Abstention recall vs the synthetic oracle                   0% [0%, 0%]              0% [0%, 0%]           74% [73%, 75%]

primary hypothesis: supported
```

Numerators and denominators for every row are in
[docs/METRICS.md](docs/METRICS.md) and at the foot of each table file.

## Other commands

```sh
make dev                    # development seeds only: the threshold table
make quick                  # one development seed, not a protocol run
cargo run --release -- list                                  # families, methods, metric definitions
cargo run --release -- protocol                              # the frozen constants
cargo run --release -- generate --scenario nat-rebinding --format csv
cargo run --release -- generate --scenario nat-rebinding --format csv --observer-view
cargo run --release -- inspect --scenario migration --tracker continuity-abstain
```

`generate --observer-view` prints only what a tracker is given. `inspect`
prints every decision one method made, with its score, outcome, and the
oracle's label.

## Where to read next

| Question | Document |
|---|---|
| What exactly is being tested, and for whom? | [docs/RESEARCH_QUESTION.md](docs/RESEARCH_QUESTION.md) |
| What can a tracker see, and what is hidden? | [docs/DATA_MODEL.md](docs/DATA_MODEL.md) |
| How do the simulator, oracle, and methods work? | [docs/METHODOLOGY.md](docs/METHODOLOGY.md) |
| What counts as a correct association, a false merge, a false split? | [docs/METRICS.md](docs/METRICS.md) |
| What do the three methods stand for? | [docs/BASELINES.md](docs/BASELINES.md) |
| What was frozen before the final run? | [docs/FROZEN_EVALUATION_PROTOCOL.md](docs/FROZEN_EVALUATION_PROTOCOL.md) |
| How does this differ from the first version? | [docs/PRELIMINARY_VS_FINAL_EVALUATION.md](docs/PRELIMINARY_VS_FINAL_EVALUATION.md) |
| What limits the conclusions? | [docs/VALIDITY_THREATS.md](docs/VALIDITY_THREATS.md) |
| How might the interpretation be wrong? | [docs/WHY_THIS_MAY_BE_WRONG.md](docs/WHY_THIS_MAY_BE_WRONG.md) |
| How do I rerun and verify it? | [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) |
| Results and decision memo | [INDEPENDENT_EVALUATION_AND_APPLICATION_RESULTS.md](INDEPENDENT_EVALUATION_AND_APPLICATION_RESULTS.md) |
| Technical report draft | [paper/technical-report.md](paper/technical-report.md) |

## Layout

```text
src/model.rs            event schema: Observation (visible) and Truth (hidden)
src/simmodel.rs         the declared simulator model, rules M1-M8
src/gen/                wire model, observer model, scenario families
src/oracle.rs           ambiguity oracle and exhaustive enumerator (evaluation only)
src/tracker/            strict-tuple; continuity (one evidence function, two policies)
src/eval.rs             scoring and metric definitions (the only reader of Truth)
src/stats.rs            per-seed summaries and bootstrap intervals
src/protocol.rs         frozen seeds, threshold rule, decision rules
src/experiment.rs       development run, held-out evaluation, sweeps, tables
src/figures.rs          SVG figures
tests/                  model soundness, truth isolation, benchmark suite, CLI
docs/                   protocol, methodology, metrics, threats
paper/                  technical report draft and abstracts
results/preliminary/    the first version's outputs, unmodified
results/dev/            development threshold table
results/final/          held-out results, tables, figures
```

## Status

- 184 tests (150 unit, 34 integration) pass locally.
- A CI workflow is included at the repository root
  (`.github/workflows/quicscope.yml`). It has not been run on GitHub.
- No license has been chosen yet: see [LICENSE-TODO.md](LICENSE-TODO.md).
