#!/bin/sh
set -e
HTMLFILE="../docs/index.html"
HTML="$(cat $HTMLFILE)"
DATE="$(date)"

cat > index_html.go <<EOL
package web

// Code generated on "$DATE" DO NOT EDIT.

const indexSource = \`$HTML\`

EOL