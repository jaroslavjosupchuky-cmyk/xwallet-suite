#!/bin/bash
set -e

VERSION=$(date +%Y.%m.%d.%H%M)
echo "Building xwallet-suite version: $VERSION"

dch --newversion "$VERSION" "Auto-build version $VERSION"

dpkg-buildpackage -us -uc

echo "Build complete. DEB files:"
ls -lh ../*.deb
