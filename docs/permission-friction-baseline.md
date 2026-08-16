# Permission-friction baseline, and why the Phase 1 gate had to be redesigned

Measured 2026-08-16 with `scripts/permission_baseline.py`, over one
machine's local Claude Code artifacts. Raw output:
`docs/baseline-2026-08-16.json`.

Context: [#102](https://github.com/voitta-ai/voitta-yolt/issues/102) gates
Phase 3 on a measurement day after Phase 1
([#98](https://github.com/voitta-ai/voitta-yolt/issues/98)) removed YOLT's
`allow`. The question the gate exists to answer is:

> Once YOLT stops auto-allowing, does the host's own vetting absorb the
> work invisibly, or does daily work get materially more interrupted?

## The finding: the number that question needs does not exist

**Prompt volume is not recoverable from any local artifact.**

A prompt the operator *approved* is indistinguishable from a call that was
never gated at all. The tool simply runs, and the transcript records a
normal result. There is no local counter either — Claude Code's own
`tengu_auto_mode_config` carries `outcomeVisibility: false`, and no
statsig / telemetry / metrics store exists on disk.

So "how often was I interrupted" cannot be counted after the fact, by us
or by anything else on the machine.

What *is* recoverable:

| signal | where | usable? |
| --- | --- | --- |
| tool calls (denominator) | transcripts | yes |
| **rejections** — prompted and declined | transcripts | yes, but far too rare (below) |
| YOLT's own objections | `yolt.log` | yes, but it is the wrong bucket |
| **prompts shown** | — | **nowhere** |

## The numbers

Window 2025-07-08 .. 2026-08-16 — 53 distinct active days, 134 transcripts.

```
tool calls    13,183
rejections        10      (0.076 per 100 calls)
```

By workload, because friction is not uniform and measuring on the wrong
one gives a number that does not transfer:

| class | calls | rejections | per 100 |
| --- | ---: | ---: | ---: |
| infra (clickagy) | 9,229 | 7 | 0.076 |
| other | 3,005 | 3 | 0.100 |
| yolt itself | 949 | 0 | 0.000 |

From `yolt.log`, over 7 active days:

```
safe      5,377      <- newly delegated to the host by #98
unsafe    2,140      <- YOLT's own objections (bucket B)
unknown   1,588
unsafe share: 23.5%
```

## Why the original gate cannot run

Two derived rates settle it:

- **Expected rejections in a one-day window: 0.19.** A measurement day
  produces, on average, *zero* rejections. Two days produce zero. The
  signal is a year's worth of ten events; nothing can be gated on it.
- **~768 calls per day are newly delegated** to the host by #98 (the
  `safe` rate). That is the exposure — large — but the *outcome* on those
  calls is exactly the unmeasurable quantity.

Meanwhile the abundant, easily measured signal — YOLT's 23.5% `unsafe`
rate — is **bucket B**, YOLT's own objections. It is not the thesis. A
gate that reported it would be measuring the wrong thing precisely and the
right thing not at all.

## The redesign

Three components, and the honest labelling of each:

1. **Operator judgment, pre-registered.** Written down *before* the
   window, in advance of any data. This was always the real decision
   criterion; the original design dressed it up as a metric.
2. **Exposure, not outcome.** Report the `safe`-per-day count from
   `yolt.log`. It says how much was newly delegated, which bounds how bad
   a wrong answer could be — without pretending to say what happened.
3. **The one place outcomes surface: `/permissions`.** Claude Code's
   recent-denials view lists commands the auto-mode classifier blocked.
   It is a live UI rather than a file, so it has to be read by hand at the
   end of the window — but it is the only place bucket A appears at all.

Plus a contamination guard: track the `unsafe` rate across the window. A
rise means bucket B grew (new deny rules, or the removal of the
user-allow-pattern upgrade biting), not that the thesis failed.

## What this cost, and the general lesson

The original gate would have consumed two days of deliberately altered
working conditions and produced a number that could not answer its
question. The cheap step that caught it — checking whether the metric was
recoverable *before* running the experiment — took under an hour of
read-only analysis against artifacts that already existed.

Worth generalising: **before instrumenting a behaviour change, confirm the
metric survives the change.** #98's own removal is what made bucket A
invisible — YOLT went silent on exactly the calls the gate needed to
observe. The instrument was disabled by the thing it was built to measure.
