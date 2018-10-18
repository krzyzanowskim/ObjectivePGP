#!/usr/bin/env bash

BASE_PWD="$PWD"
SCRIPT_DIR="$(dirname "$0")"
VENDOR_DIR="${SCRIPT_DIR}/../vendor"
LIBS_DIR="${VENDOR_DIR}/libs"
SRC_DIR="${VENDOR_DIR}/openssl-src"
BUILD_DIR="${VENDOR_DIR}/build"

rm -rf "${BUILD_DIR}"
rm -rf "${SRC_DIR}"

curl -Lk https://www.openssl.org/source/openssl-1.1.1.tar.gz -o "${VENDOR_DIR}/openssl-src.tar.gz"
tar xvzf "${VENDOR_DIR}/openssl-src.tar.gz" -C "${VENDOR_DIR}/"
rm -f "${VENDOR_DIR}/openssl-src.tar.gz"
mv -f "${VENDOR_DIR}/openssl-1.1.1" "${SRC_DIR}"

mkdir -p "${BUILD_DIR}/iphoneos_armv7"
cd "${BUILD_DIR}/iphoneos_armv7"
../../openssl-src/Configure no-shared no-hw no-zlib-dynamic no-asm no-dso no-engine no-hw no-ssl2 no-ssl3 ios-xcrun
make -j 8
cd "${BASE_PWD}"

mkdir -p "${BUILD_DIR}/iphoneos_arm64"
cd "${BUILD_DIR}/iphoneos_arm64"
../../openssl-src/Configure no-shared no-hw no-zlib-dynamic no-asm no-dso no-engine no-hw no-ssl2 no-ssl3 ios64-xcrun
make -j 8

cd "${BASE_PWD}"
mkdir -p "${BUILD_DIR}/iossimulator"
cd "${BUILD_DIR}/iossimulator"
../../openssl-src/Configure no-shared no-hw no-zlib-dynamic no-asm no-dso no-engine no-hw no-ssl2 no-ssl3 iossimulator-xcrun
make -j 8

cd "${BASE_PWD}"
mkdir -p "${BUILD_DIR}/macosx"
cd "${BUILD_DIR}/macosx"
../../openssl-src/Configure no-shared no-hw no-zlib-dynamic no-asm no-dso no-engine no-ssl2 no-ssl3 enable-ec_nistp_64_gcc_128 darwin64-x86_64-cc
make -j 8

cd "${BASE_PWD}"

lipo -create \
     "${BUILD_DIR}/iphoneos_arm64/libcrypto.a" \
     "${BUILD_DIR}/iphoneos_armv7/libcrypto.a" \
     "${BUILD_DIR}/iossimulator/libcrypto.a" \
     -o "${LIBS_DIR}/ios/libcrypto.a"

lipo -create \
     "${BUILD_DIR}/macosx/libcrypto.a" \
     -o "${LIBS_DIR}/macosx/libcrypto.a"

rm -rf "${LIBS_DIR}/ios/openssl/"
mkdir -p "${LIBS_DIR}/ios/openssl"
cp -R "${SRC_DIR}"/include/openssl/*.h "${LIBS_DIR}/ios/openssl/"
cp -R "${BUILD_DIR}"/iphoneos_arm64/include/openssl/*.h "${LIBS_DIR}/ios/openssl"

rm -rf "${LIBS_DIR}/macosx/openssl/"
mkdir -p "${LIBS_DIR}/macosx/openssl"
cp -R "${SRC_DIR}"/include/openssl/*.h "${LIBS_DIR}/macosx/openssl"
cp -R "${BUILD_DIR}"/macosx/include/openssl/*.h "${LIBS_DIR}/macosx/openssl"

# Update list of exported symbols
# The file is later used by the UNEXPORTED_SYMBOLS_FILE to hide the symbols
xcrun nm -gUj "${LIBS_DIR}/ios/libcrypto.a" | grep -v "^$" | grep "^_" > "${LIBS_DIR}/ios/symbols"
xcrun nm -gUj "${LIBS_DIR}/macosx/libcrypto.a" | grep -v "^$" | grep "^_" > "${LIBS_DIR}/macosx/symbols"

rm -rf "${BUILD_DIR}"
rm -rf "${SRC_DIR}"
