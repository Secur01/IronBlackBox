#!/usr/bin/env bash
#
# package-release.sh - turn a built release tree into the two assets an MSP
# needs to pin a named version, and refuse if they do not verify.
#
# WHY THIS EXISTS. Until v1.1.0 this project pushed a tag and stopped. A tag is
# a mutable pointer: it can be moved, and until a repository ruleset forbids it,
# "v1.0.0" is a name, not an object. An external review put it plainly - a
# reviewer watched HEAD change during the review - and for code an MSP runs as
# SYSTEM the requirement is that they can say "I installed exactly the v1.1.0
# published by Secur01, and here is the immutable object that name refers to".
#
# THE ZIP IS DETERMINISTIC ON PURPOSE. Fixed timestamps, sorted entries, fixed
# permissions: two people building the same tag get byte-identical archives and
# the same SHA-256. GitHub's auto-generated zipball is NOT a substitute - its
# bytes are not contractually stable, so it cannot be pinned.
#
# Usage:
#   tools/package-release.sh <built-release-tree> <tag> [outdir]
#
# Produces, in outdir (default <tree>/../ibb-assets):
#   IronBlackBox-<tag>.zip
#   SHA256SUMS.txt   - every file in the tree, then the zip itself
#
# Then attach both to the GitHub Release.
#
# You can run this yourself against an extracted copy of a published ZIP: the
# archive is byte-reproducible, so rebuilding it must give the digest printed in
# SHA256SUMS.txt. That is the point of publishing this script - a deterministic
# archive nobody else can reproduce proves nothing.

set -euo pipefail

TREE="${1:?usage: tools/package-release.sh <built-release-tree> <tag> [outdir]}"
TAG="${2:?usage: tools/package-release.sh <built-release-tree> <tag> [outdir]}"
OUT="${3:-$(dirname "$TREE")/ibb-assets}"

[[ -d "$TREE" ]] || { echo "no such tree: $TREE" >&2; exit 1; }
[[ -f "$TREE/README.md" ]] || { echo "$TREE does not look like a built release tree" >&2; exit 1; }

ZIP="$OUT/IronBlackBox-$TAG.zip"
SUMS="$OUT/SHA256SUMS.txt"
mkdir -p "$OUT"
rm -f "$ZIP" "$SUMS"

echo "== Hashing $TREE"
( cd "$TREE" && find . -type f -not -path './.git/*' | sed 's|^\./||' \
    | LC_ALL=C sort | xargs sha256sum ) > "$SUMS"
echo "   $(wc -l < "$SUMS") file(s)"

echo "== Building a deterministic archive"
TREE="$TREE" ZIP="$ZIP" python3 - <<'PY'
import os, zipfile
tree = os.environ['TREE']; out = os.environ['ZIP']
files = []
for dp, dn, fn in os.walk(tree):
    dn[:] = [d for d in dn if d != '.git']
    files += [os.path.relpath(os.path.join(dp, f), tree) for f in fn]
files.sort()
with zipfile.ZipFile(out, 'w', zipfile.ZIP_DEFLATED) as z:
    for rel in files:
        zi = zipfile.ZipInfo(filename=rel, date_time=(1980, 1, 1, 0, 0, 0))
        zi.compress_type = zipfile.ZIP_DEFLATED
        zi.external_attr = 0o644 << 16
        with open(os.path.join(tree, rel), 'rb') as fh:
            z.writestr(zi, fh.read())
print('   %d file(s), %d bytes' % (len(files), os.path.getsize(out)))
PY
( cd "$OUT" && sha256sum "$(basename "$ZIP")" >> "$SUMS" )

# A manifest that is not checked against the artifact is decoration. This
# extracts the archive it just wrote and verifies every line against it, so a
# packaging bug fails the build instead of shipping.
echo "== Verifying the archive against the manifest"
VERIFY="$(mktemp -d)"
trap 'rm -rf "$VERIFY"' EXIT
ZIP="$ZIP" VERIFY="$VERIFY" python3 -c "
import os, zipfile
zipfile.ZipFile(os.environ['ZIP']).extractall(os.environ['VERIFY'])"
grep -v "$(basename "$ZIP")" "$SUMS" > "$VERIFY/sums.txt"
( cd "$VERIFY" && sha256sum -c --quiet sums.txt )
echo "   $(grep -c . "$VERIFY/sums.txt") hash(es) match the extracted archive"

echo "== Clean."
echo "   $ZIP"
echo "   $SUMS"
echo "   zip sha256: $(grep "$(basename "$ZIP")" "$SUMS" | cut -d' ' -f1)"
