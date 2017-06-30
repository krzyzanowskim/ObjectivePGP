#!/bin/sh

# Export global symbols to the file.
# The file is later used by the UNEXPORTED_SYMBOLS_FILE to hide the symbols

xcrun nm -gUj macosx/libcrypto.a | grep -v "^$" | grep "^_" > macosx/symbols
xcrun nm -gUj ios/libcrypto.a | grep -v "^$" | grep "^_" > ios/symbols