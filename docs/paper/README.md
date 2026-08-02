# Paper: From Benchmark to Live Traffic

## Compiling

No local LaTeX distribution is installed on this machine yet. Two options:

**Option A — Overleaf (recommended for a 6-author paper):**
Upload this whole `docs/paper/` folder (or zip it) to a new Overleaf
project. Overleaf ships IEEEtran and compiles automatically on save —
easiest path for co-author review/comments too.

**Option B — Local compile:**
Install a LaTeX distribution (e.g. MiKTeX for Windows), then from this
directory:
```
pdflatex main.tex
bibtex main
pdflatex main.tex
pdflatex main.tex
```

## Status

See `C:\Users\mtyas\.claude\plans\dapper-scribbling-cloud.md` for the full
plan this paper was built from.

- [x] Base paper chosen (Cantone et al., IEEE Access 2024) via 4-persona debate
- [x] Table 1 (in-distribution 2017) independently re-verified via fresh full-dataset retrain
- [x] Finding 3 / Table IV (17,612-flow capture) independently re-verified via pcap replay
- [x] All citations resolved to real, confirmed sources (9 total, incl. a
      novelty check against IEEE/ACM/arXiv -- no direct collision found)
- [x] main.tex drafted end-to-end with all sections
- [x] Plagiarism-risk rewrite of closely-paraphrased Related Work/Intro passages
- [x] LaTeX compiled -- 5-page clean PDF, zero warnings (MiKTeX installed)
- [x] Table 2/3 (cross-dataset 2017->2018) fresh re-verification attempted --
      Experiment 2 (train-2017, eval-2018) reproduced within ~3pp after fixing
      a real threshold bug (0.55 default vs. the correct 0.35 cross-dataset
      threshold). Experiment 3 (combined training) needed 3 more real fixes
      (train/test leakage, a stale feature-column cache, missing undersampling
      + scale_pos_weight recovered from the project's original May-2026
      combine_and_train.py script) before it stopped producing a broken
      25%-recall model; final fresh result (97.5% recall/97.9% F1/98.4% prec)
      confirms the qualitative finding but doesn't match the documented
      80.83%/89.40%/100% closely enough to cite -- user decided to keep
      Table II's original documented numbers only, no footnote added.
- [ ] Author names/credentials (4 students + guide + HOD) — placeholders in main.tex, need real values
- [ ] Page count / length check against a real target venue once one is chosen
- [ ] Self-review pass (numbers vs. docs/RESEARCH_PAPER_RESULTS_M1-M4.md line-by-line)
