# Paper

`agentshield.tex` is a short paper on the design of AgentShield, the benchmark, the results and their limitations.

- **Built PDF:** `agentshield.pdf`.
- **Tables:** the files in `generated/` are written by `python dataset/eval.py --latex paper/generated`, so every number in them is recomputed from the code.

```sh
sh scripts/build-paper.sh      # regenerates the tables, compiles with tectonic, writes paper/agentshield-arxiv.tar.gz
```

Every reference in `refs.bib` was checked against arXiv or Crossref.
