#!/bin/sh
set -eu
# with-environment.sh resolves NODE_BINARY before invoking this wrapper.
# A release must bundle a reviewed HTTPS API origin, not the placeholder.
if [ "${CONFIGURATION:-}" = "Release" ]; then
  "${NODE_BINARY:-node}" "${PROJECT_DIR}/../tools/verify_native_release.mjs" --release
fi
exec "${REACT_NATIVE_PATH}/scripts/react-native-xcode.sh"
