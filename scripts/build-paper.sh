#!/usr/bin/env sh
# Rebuild the paper's tables from the benchmark, compile the PDF with tectonic and make an arXiv source bundle.
# Usage: sh scripts/build-paper.sh   (needs python3 and tectonic; node is optional, for the JS cross-check)
set -eu
cd "$(dirname "$0")/.."
python3 dataset/eval.py --latex paper/generated > /dev/null
cd paper
tectonic -X compile --keep-intermediates quadward.tex
rm -rf arxiv && mkdir -p arxiv/generated
cp quadward.tex refs.bib quadward.bbl arxiv/ && cp generated/*.tex arxiv/generated/
tar -czf quadward-arxiv.tar.gz -C arxiv .
rm -f quadward.aux quadward.log quadward.out quadward.blg
echo "PDF: paper/quadward.pdf  arXiv bundle: paper/quadward-arxiv.tar.gz"
