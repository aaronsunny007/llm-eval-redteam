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

## Posting to arXiv

`arxiv-submission.zip` holds what arXiv compiles from (`paper.tex`, `paper.bbl`, `references.bib`);
it was test-compiled from a clean folder (9 pages, no undefined references). arXiv needs the
author's own account, so this step cannot be automated:

1. Register at <https://arxiv.org/user/register> with an institutional or long-standing email.
2. Start a submission, upload the zip, and let arXiv build the PDF; check it.
3. Suggested subject: cs.CR (primary), cross-list cs.CL and cs.LG. First-time authors in a
   subject may need an endorsement from an established author there.
4. Fill in the title, authors (human authors only; the AI assistance is disclosed in the paper),
   abstract and licence, then submit. Moderators review it before it is announced.
