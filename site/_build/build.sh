#!/bin/sh
# Builds the website into ./_site (run from the repository root). Needs pandoc.
set -eu
OUT="${1:-_site}"
rm -rf "$OUT"
mkdir -p "$OUT/docs" "$OUT/raw"
cp -r site/index.html site/style.css site/site.js site/icon.svg site/install.sh site/img "$OUT/"

page() {
    # page <markdown> <output> <title> <nav-flag>
    pandoc "$1" --from gfm --to html5 --standalone --toc --toc-depth 2 \
        --template site/_build/template.html --lua-filter site/_build/links.lua \
        --highlight-style pygments \
        --metadata pagetitle="$3" --metadata "$4=true" --metadata source="$1" \
        -o "$OUT/docs/$2"
}
page docs/GETTING-STARTED.md index.html "Getting started" nav-start
page docs/PLUGINS.md plugins.html "Writing plugins" nav-plugins
page docs/SECURITY.md security.html "Security model" nav-security
page AGENTS.md agents.html "For coding agents" nav-agents

# Plain copies for agents and tools.
cp docs/PLUGINS.md docs/SECURITY.md docs/GETTING-STARTED.md docs/plugin-template.toml AGENTS.md "$OUT/raw/"
touch "$OUT/.nojekyll"
echo "site built in $OUT"
