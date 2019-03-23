#!/usr/bin/env bash

# Export global symbols to the file.
# The file is later used by the UNEXPORTED_SYMBOLS_FILE to hide the symbols

BASE_PWD="$PWD"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"
LIBS_DIR=$( realpath ${SCRIPT_DIR}/../../vendor/libs )

xcrun nm -gUj "${LIBS_DIR}/ios/libcrypto.a" | grep -v "^$" | grep "^_" > "${LIBS_DIR}/ios/symbols"
xcrun nm -gUj "${LIBS_DIR}/macosx/libcrypto.a" | grep -v "^$" | grep "^_" > "${LIBS_DIR}/macosx/symbols"