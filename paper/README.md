# Technical report

`paper.tex` (with `references.bib`) is a technical report on the study in this repository:
a defence ablation on a small-model RAG assistant and a validity analysis of the hybrid judge.
`paper.pdf` is the compiled version. Every number comes from `results/` through
`scripts/paper_stats.py` (output in `stats.json`) and the committed `report.md` files.

Build: `pdflatex paper && bibtex paper && pdflatex paper && pdflatex paper`, or upload the folder
to Overleaf.

Status: a workshop-level technical report, not a peer-reviewed paper. The limitations section
lists what a stronger version needs: human labels from at least two annotators, more
applications and target models, adaptive attacks, and a stronger judge. The code, the labels
and the text were produced with substantial AI assistance, which the paper discloses.
