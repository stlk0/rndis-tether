#!/bin/sh
# Installs or updates rndis-tether from the latest GitHub release:
#   /bin/sh -c "$(curl -fsSL https://raw.githubusercontent.com/stlk0/rndis-tether/main/install.sh)"
# Downloads one archive (the program for Apple silicon and Intel), checks its SHA-256 and
# runs `sudo rndis-tether install`, which asks for your Mac password.
set -eu

REPO=stlk0/rndis-tether
BASE=https://github.com/$REPO/releases/latest/download
ARCHIVE=rndis-tether-macos.tar.gz

major=$(sw_vers -productVersion | cut -d. -f1)
if [ "$major" -lt 13 ]; then
    echo "rndis-tether needs macOS 13 Ventura or newer (this Mac has $(sw_vers -productVersion))." >&2
    exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
echo "Downloading rndis-tether ..."
curl -fsSL "$BASE/$ARCHIVE" -o "$TMP/$ARCHIVE"
curl -fsSL "$BASE/$ARCHIVE.sha256" -o "$TMP/$ARCHIVE.sha256"
(cd "$TMP" && shasum -a 256 -c "$ARCHIVE.sha256" > /dev/null) || {
    echo "The download is damaged (checksum mismatch). Please try again." >&2
    exit 1
}
tar -xzf "$TMP/$ARCHIVE" -C "$TMP"

echo "Installing. macOS asks for your password (the one you use to log in to this Mac):"
sudo "$TMP/rndis-tether" install < /dev/tty
