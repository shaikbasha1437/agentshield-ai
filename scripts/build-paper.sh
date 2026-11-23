#!/usr/bin/env sh
# Rebuild the paper's tables from the benchmark, compile the PDF with tectonic and make an arXiv source bundle.
# Usage: sh scripts/build-paper.sh   (needs python3 and tectonic; node is optional, for the JS cross-check)
set -eu
cd "$(dirname "$0")/.."
python3 dataset/eval.py --latex paper/generated > /dev/null
cd paper
tectonic -X compile --keep-intermediates agentshield.tex
rm -rf arxiv && mkdir -p arxiv/generated
cp agentshield.tex refs.bib agentshield.bbl arxiv/ && cp generated/*.tex arxiv/generated/
tar -czf agentshield-arxiv.tar.gz -C arxiv .
rm -f agentshield.aux agentshield.log agentshield.out agentshield.blg
echo "PDF: paper/agentshield.pdf  arXiv bundle: paper/agentshield-arxiv.tar.gz"
