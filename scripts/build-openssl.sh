#!/usr/bin/env bash

BASE_PWD="$PWD"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

TMP_DIR=$( mktemp -d )
OPENSSL_SRC_DIR=${TMP_DIR}/src
OPENSSL_BUILD_DIR=${TMP_DIR}/build
LIBS_DIR=$( realpath ${SCRIPT_DIR}/../vendor/libs )

mkdir -p ${OPENSSL_SRC_DIR}
mkdir -p ${OPENSSL_BUILD_DIR}
mkdir -p ${LIBS_DIR}

curl -Lk https://www.openssl.org/source/openssl-3.0.0.tar.gz | tar -xzp --strip-components=1 -C ${OPENSSL_SRC_DIR}

mkdir -p "${OPENSSL_BUILD_DIR}/iphoneos_armv7"
cd "${OPENSSL_BUILD_DIR}/iphoneos_armv7"
${OPENSSL_SRC_DIR}/Configure no-shared no-hw no-zlib-dynamic no-asm no-dso no-engine no-hw no-ssl2 no-ssl3 ios-xcrun
make -j 8
cd "${BASE_PWD}"

mkdir -p "${OPENSSL_BUILD_DIR}/iphoneos_arm64"
cd "${OPENSSL_BUILD_DIR}/iphoneos_arm64"
${OPENSSL_SRC_DIR}/Configure no-shared no-hw no-zlib-dynamic no-asm no-dso no-engine no-hw no-ssl2 no-ssl3 ios64-xcrun
make -j 8

mkdir -p "${OPENSSL_BUILD_DIR}/iossimulator"
cd "${OPENSSL_BUILD_DIR}/iossimulator"
${OPENSSL_SRC_DIR}/Configure no-shared no-hw no-zlib-dynamic no-asm no-dso no-engine no-hw no-ssl2 no-ssl3 iossimulator-xcrun
make -j 8

mkdir -p "${OPENSSL_BUILD_DIR}/macosx"
cd "${OPENSSL_BUILD_DIR}/macosx"
${OPENSSL_SRC_DIR}/Configure no-shared no-hw no-zlib-dynamic no-asm no-dso no-engine no-ssl2 no-ssl3 enable-ec_nistp_64_gcc_128 -mmacosx-version-min=10.9 darwin64-x86_64-cc
make -j 8

lipo -create \
     "${OPENSSL_BUILD_DIR}/iphoneos_arm64/libcrypto.a" \
     "${OPENSSL_BUILD_DIR}/iphoneos_armv7/libcrypto.a" \
     "${OPENSSL_BUILD_DIR}/iossimulator/libcrypto.a" \
     -o "${LIBS_DIR}/ios/libcrypto.a"

lipo -create \
     "${OPENSSL_BUILD_DIR}/macosx/libcrypto.a" \
     -o "${LIBS_DIR}/macosx/libcrypto.a"

rm -rf "${LIBS_DIR}/ios/openssl/"
mkdir -p "${LIBS_DIR}/ios/openssl"
cp -R "${OPENSSL_SRC_DIR}"/include/openssl/*.h "${LIBS_DIR}/ios/openssl/"
cp -R "${OPENSSL_BUILD_DIR}"/iphoneos_arm64/include/openssl/*.h "${LIBS_DIR}/ios/openssl"

rm -rf "${LIBS_DIR}/macosx/openssl/"
mkdir -p "${LIBS_DIR}/macosx/openssl"
cp -R "${OPENSSL_SRC_DIR}"/include/openssl/*.h "${LIBS_DIR}/macosx/openssl"
cp -R "${OPENSSL_BUILD_DIR}"/macosx/include/openssl/*.h "${LIBS_DIR}/macosx/openssl"

# Update list of exported symbols
# The file is later used by the UNEXPORTED_SYMBOLS_FILE to hide the symbols
${LIBS_DIR}/export-symbols.sh

rm -rf ${TMP_DIR}