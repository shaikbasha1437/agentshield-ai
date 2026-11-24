# Paper

`quadward.tex` is a short paper on the design of Quadward, the benchmark, the results and their limitations.

- **Built PDF:** `quadward.pdf`.
- **Tables:** the files in `generated/` are written by `python dataset/eval.py --latex paper/generated`, so every number in them is recomputed from the code.

```sh
sh scripts/build-paper.sh      # regenerates the tables, compiles with tectonic, writes paper/quadward-arxiv.tar.gz
```

Every reference in `refs.bib` was checked against arXiv or Crossref.
