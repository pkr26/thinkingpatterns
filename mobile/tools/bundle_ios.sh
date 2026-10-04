#!/bin/sh
set -eu
# with-environment.sh resolves NODE_BINARY before invoking this wrapper.
# A release must bundle a reviewed HTTPS API origin, not the placeholder.
if [ "${CONFIGURATION:-}" = "Release" ]; then
  # Xcode launches build phases from ios/, while the shared verifier uses
  # paths relative to mobile/. Keep this directory change local to preflight.
  (cd "${PROJECT_DIR}/.." && "${NODE_BINARY:-node}" tools/verify_native_release.mjs --release)
fi
exec "${REACT_NATIVE_PATH}/scripts/react-native-xcode.sh"
