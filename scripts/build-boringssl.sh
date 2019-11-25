#!/usr/bin/env bash

set -eou pipefail

BASE_PWD="$PWD"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

TMP_DIR=$( mktemp -d )
BORINGSSL_SRC_DIR="${TMP_DIR}/src/boringssl.googlesource.com/boringssl"
BORINGSSL_BUILD_DIR="${TMP_DIR}/build"
LIBS_DIR="${SCRIPT_DIR}/../vendor/libs"
CMAKE_OPTIONS="-GNinja -DCMAKE_BUILD_TYPE=Release -H${BORINGSSL_SRC_DIR} -Wno-dev"
SYMBOLS_PREFIX="pgp_boringssl"
CMAKE_PREFIX_OPTIONS="-DBORINGSSL_PREFIX=${SYMBOLS_PREFIX}"

export GOPATH="${TMP_DIR}"

PGPBORINGSSL_MODULE_HEADERS=("${SYMBOLS_PREFIX}_aes.h"
                             "${SYMBOLS_PREFIX}_arm_arch.h"
                             "${SYMBOLS_PREFIX}_asn1_mac.h"
                             "${SYMBOLS_PREFIX}_asn1t.h"
                             "${SYMBOLS_PREFIX}_base.h"
                             "${SYMBOLS_PREFIX}_bio.h"
                             "${SYMBOLS_PREFIX}_blowfish.h"
                             "${SYMBOLS_PREFIX}_boringssl_prefix_symbols.h"
                             "${SYMBOLS_PREFIX}_boringssl_prefix_symbols_asm.h"
                             "${SYMBOLS_PREFIX}_cast.h"
                             "${SYMBOLS_PREFIX}_chacha.h"
                             "${SYMBOLS_PREFIX}_cmac.h"
                             "${SYMBOLS_PREFIX}_conf.h"
                             "${SYMBOLS_PREFIX}_cpu.h"
                             "${SYMBOLS_PREFIX}_curve25519.h"
                             "${SYMBOLS_PREFIX}_des.h"
                             "${SYMBOLS_PREFIX}_dtls1.h"
                             "${SYMBOLS_PREFIX}_e_os2.h"
                             "${SYMBOLS_PREFIX}_ec.h"
                             "${SYMBOLS_PREFIX}_ec_key.h"
                             "${SYMBOLS_PREFIX}_ecdsa.h"
                             "${SYMBOLS_PREFIX}_err.h"
                             "${SYMBOLS_PREFIX}_evp.h"
                             "${SYMBOLS_PREFIX}_hkdf.h"
                             "${SYMBOLS_PREFIX}_hmac.h"
                             "${SYMBOLS_PREFIX}_hrss.h"
                             "${SYMBOLS_PREFIX}_md4.h"
                             "${SYMBOLS_PREFIX}_md5.h"
                             "${SYMBOLS_PREFIX}_obj_mac.h"
                             "${SYMBOLS_PREFIX}_objects.h"
                             "${SYMBOLS_PREFIX}_opensslv.h"
                             "${SYMBOLS_PREFIX}_ossl_typ.h"
                             "${SYMBOLS_PREFIX}_pkcs12.h"
                             "${SYMBOLS_PREFIX}_poly1305.h"
                             "${SYMBOLS_PREFIX}_rand.h"
                             "${SYMBOLS_PREFIX}_rc4.h"
                             "${SYMBOLS_PREFIX}_ripemd.h"
                             "${SYMBOLS_PREFIX}_rsa.h"
                             "${SYMBOLS_PREFIX}_safestack.h"
                             "${SYMBOLS_PREFIX}_sha.h"
                             "${SYMBOLS_PREFIX}_siphash.h"
                             "${SYMBOLS_PREFIX}_srtp.h"
                             "${SYMBOLS_PREFIX}_ssl.h"
                             "${SYMBOLS_PREFIX}_x509v3.h")

echo $TMP_DIR

if ! hash gsed 2>/dev/null; then
    echo "You need sed \"gsed\" to run this script ..."
    echo
    echo "On macOS: brew install gnu-sed"
    exit 43
fi

mkdir -p ${BORINGSSL_SRC_DIR}
mkdir -p ${BORINGSSL_BUILD_DIR}

rm -rf ${LIBS_DIR}
mkdir -p ${LIBS_DIR}/{ios,macosx}

if [ ! -r /tmp/chromium-stable.zip ]; then
  echo "Downloading..."
  curl -L https://github.com/google/boringssl/archive/chromium-stable.zip > /tmp/chromium-stable.zip
fi

echo "Expanding..."
tar -xzp --strip-components=1 -f /tmp/chromium-stable.zip -C ${BORINGSSL_SRC_DIR}

################## MACOSX ##################

PLATFORM_LIBS_DIR="${LIBS_DIR}/macosx"

# Build generic for macOS
cmake -DCMAKE_OSX_SYSROOT=macosx ${CMAKE_OPTIONS} -DCMAKE_OSX_DEPLOYMENT_TARGET="10.11" -DCMAKE_OSX_ARCHITECTURES=x86_64 -B"${BORINGSSL_BUILD_DIR}/macosx"
ninja -j 4 -C "${BORINGSSL_BUILD_DIR}/macosx" crypto

# Build symbol list to prefix
xcrun nm -gUj "${BORINGSSL_BUILD_DIR}/macosx/crypto/libcrypto.a" | grep -v "^$" | grep "^_" | sed 's/^_//' > "${TMP_DIR}/symbols-macosx.txt"
# go run "${BORINGSSL_SRC_DIR}/util/read_symbols.go" -out "${TMP_DIR}/symbols-macosx.txt" "${BORINGSSL_BUILD_DIR}/macosx/crypto/libcrypto.a"

rm -rf ${BORINGSSL_BUILD_DIR}

# Build prefixed macOS
cmake -DCMAKE_OSX_SYSROOT=macosx ${CMAKE_OPTIONS} ${CMAKE_PREFIX_OPTIONS} -DBORINGSSL_PREFIX_SYMBOLS="${TMP_DIR}/symbols-macosx.txt" -DCMAKE_OSX_DEPLOYMENT_TARGET="10.11" -DCMAKE_OSX_ARCHITECTURES=x86_64 -B"${BORINGSSL_BUILD_DIR}/macosx"
ninja -j 4 -C "${BORINGSSL_BUILD_DIR}/macosx" crypto

lipo -create \
     "${BORINGSSL_BUILD_DIR}/macosx/crypto/libcrypto.a" \
     -o "${PLATFORM_LIBS_DIR}/libcrypto.a"


# Update list of exported symbols
# The file is later used by the UNEXPORTED_SYMBOLS_FILE to hide the symbols
xcrun nm -gUj "${PLATFORM_LIBS_DIR}/libcrypto.a" | grep -v "^$" | grep "^_" > "${PLATFORM_LIBS_DIR}/symbols"

# Prefixed headers
mkdir -p "${PLATFORM_LIBS_DIR}/PGPBoringSSL"
cp ${BORINGSSL_SRC_DIR}/include/openssl/* "${PLATFORM_LIBS_DIR}/PGPBoringSSL"
go run ${BORINGSSL_SRC_DIR}/util/make_prefix_headers.go -out ${PLATFORM_LIBS_DIR}/PGPBoringSSL "${PLATFORM_LIBS_DIR}/symbols"
chmod 444 ${PLATFORM_LIBS_DIR}/PGPBoringSSL/*

pushd ${PLATFORM_LIBS_DIR}/PGPBoringSSL
# Now change the imports from "<PGPBoringSSL/X> to "<SYMBOLS_PREFIX_X>", apply the same prefix to the 'boringssl_prefix_symbols' headers.
find . -name "*.[ch]" -or -name "*.cc" -or -name "*.S" | xargs gsed -i -e 's+include <openssl/+include <'"${SYMBOLS_PREFIX}"'_+' -e 's+include <boringssl_prefix_symbols+include '"<${SYMBOLS_PREFIX}"'_boringssl_prefix_symbols+'
# Okay now we need to rename the headers adding the prefix "${SYMBOLS_PREFIX}_".
find . -name "*.h" | gsed -e "s_./__" | xargs -I {} mv {} "${SYMBOLS_PREFIX}_{}"
# Finally, make sure we refer to them by their prefixed names, and change any includes from angle brackets to quotation marks.
find . -name "*.h" | xargs gsed -i -e 's/include "/include "'"${SYMBOLS_PREFIX}"'_/' -e 's/include <'"${SYMBOLS_PREFIX}"'_\(.*\)>/include "'"${SYMBOLS_PREFIX}"'_\1"/'
# We need BoringSSL to be modularised
echo "MODULARISING BoringSSL"

cat << EOF > "${PLATFORM_LIBS_DIR}/PGPBoringSSL/PGPBoringSSL.h"
//===----------------------------------------------------------------------===//
// This source file is part of the ObjectivePGP project
//===----------------------------------------------------------------------===//
#ifndef PGP_BORINGSSL_H
#define PGP_BORINGSSL_H

EOF

for h in ${PGPBORINGSSL_MODULE_HEADERS[@]}; do
  echo  "#include \"$h\"" >> ${PLATFORM_LIBS_DIR}/PGPBoringSSL/PGPBoringSSL.h
done

echo "#endif  // PGP_BORINGSSL_H" >> "${PLATFORM_LIBS_DIR}/PGPBoringSSL/PGPBoringSSL.h"
popd

rm -rf "${BORINGSSL_BUILD_DIR}"

################## iOS ##################

PLATFORM_LIBS_DIR="${LIBS_DIR}/ios"

# Build generic for iOS
cmake -DCMAKE_OSX_SYSROOT=iphoneos ${CMAKE_OPTIONS} -DCMAKE_OSX_DEPLOYMENT_TARGET="8.0" -DCMAKE_OSX_ARCHITECTURES=arm64 -B"${BORINGSSL_BUILD_DIR}/iphoneos_arm64"
ninja -C "${BORINGSSL_BUILD_DIR}/iphoneos_arm64" crypto

# Build symbol list to prefix
xcrun nm -gUj "${BORINGSSL_BUILD_DIR}/iphoneos_arm64/crypto/libcrypto.a" | grep -v "^$" | grep "^_" | sed 's/^_//' > "${TMP_DIR}/symbols-iphoneos.txt"

rm -rf "${BORINGSSL_BUILD_DIR}"

# Build prefixed iOS

cmake -DCMAKE_OSX_SYSROOT=iphoneos        ${CMAKE_OPTIONS} ${CMAKE_PREFIX_OPTIONS} -DBORINGSSL_PREFIX_SYMBOLS="${TMP_DIR}/symbols-iphoneos.txt" -DCMAKE_OSX_DEPLOYMENT_TARGET="8.0" -DCMAKE_OSX_ARCHITECTURES=arm64 -B"${BORINGSSL_BUILD_DIR}/iphoneos_arm64"
cmake -DCMAKE_OSX_SYSROOT=iphoneos        ${CMAKE_OPTIONS} ${CMAKE_PREFIX_OPTIONS} -DBORINGSSL_PREFIX_SYMBOLS="${TMP_DIR}/symbols-iphoneos.txt" -DCMAKE_OSX_DEPLOYMENT_TARGET="8.0" -DCMAKE_OSX_ARCHITECTURES=armv7 -B"${BORINGSSL_BUILD_DIR}/iphoneos_armv7"
cmake -DCMAKE_OSX_SYSROOT=iphoneos        ${CMAKE_OPTIONS} ${CMAKE_PREFIX_OPTIONS} -DBORINGSSL_PREFIX_SYMBOLS="${TMP_DIR}/symbols-iphoneos.txt" -DCMAKE_OSX_DEPLOYMENT_TARGET="8.0" -DCMAKE_OSX_ARCHITECTURES=armv7s -B"${BORINGSSL_BUILD_DIR}/iphoneos_armv7s"
cmake -DCMAKE_OSX_SYSROOT=iphonesimulator ${CMAKE_OPTIONS} ${CMAKE_PREFIX_OPTIONS} -DBORINGSSL_PREFIX_SYMBOLS="${TMP_DIR}/symbols-iphoneos.txt" -DCMAKE_OSX_DEPLOYMENT_TARGET="8.0" -DCMAKE_OSX_ARCHITECTURES=x86_64 -B"${BORINGSSL_BUILD_DIR}/iphonesimulator_x86_64"

ninja -C "${BORINGSSL_BUILD_DIR}/iphoneos_arm64" crypto
ninja -C "${BORINGSSL_BUILD_DIR}/iphoneos_armv7" crypto
ninja -C "${BORINGSSL_BUILD_DIR}/iphoneos_armv7s" crypto
ninja -C "${BORINGSSL_BUILD_DIR}/iphonesimulator_x86_64" crypto

lipo -create \
     "${BORINGSSL_BUILD_DIR}/iphoneos_arm64/crypto/libcrypto.a" \
     "${BORINGSSL_BUILD_DIR}/iphoneos_armv7/crypto/libcrypto.a" \
     "${BORINGSSL_BUILD_DIR}/iphoneos_armv7s/crypto/libcrypto.a" \
     "${BORINGSSL_BUILD_DIR}/iphonesimulator_x86_64/crypto/libcrypto.a" \
     -o "${PLATFORM_LIBS_DIR}/libcrypto.a"

cp -R "${BORINGSSL_SRC_DIR}/include/" "${PLATFORM_LIBS_DIR}/"

# Update list of exported symbols
# The file is later used by the UNEXPORTED_SYMBOLS_FILE to hide the symbols
xcrun nm -gUj "${PLATFORM_LIBS_DIR}/libcrypto.a" | grep -v "^$" | grep "^_" > "${PLATFORM_LIBS_DIR}/symbols"

# Prefixed headers
mkdir -p "${PLATFORM_LIBS_DIR}/PGPBoringSSL"
cp ${BORINGSSL_SRC_DIR}/include/openssl/* "${PLATFORM_LIBS_DIR}/PGPBoringSSL"
go run ${BORINGSSL_SRC_DIR}/util/make_prefix_headers.go -out ${PLATFORM_LIBS_DIR}/PGPBoringSSL "${PLATFORM_LIBS_DIR}/symbols"
chmod 444 ${PLATFORM_LIBS_DIR}/PGPBoringSSL/*

pushd ${PLATFORM_LIBS_DIR}/PGPBoringSSL
# Now change the imports from "<PGPBoringSSL/X> to "<SYMBOLS_PREFIX_X>", apply the same prefix to the 'boringssl_prefix_symbols' headers.
find . -name "*.[ch]" -or -name "*.cc" -or -name "*.S" | xargs gsed -i -e 's+include <openssl/+include <'"${SYMBOLS_PREFIX}"'_+' -e 's+include <boringssl_prefix_symbols+include '"<${SYMBOLS_PREFIX}"'_boringssl_prefix_symbols+'
# Okay now we need to rename the headers adding the prefix "${SYMBOLS_PREFIX}_".
find . -name "*.h" | gsed -e "s_./__" | xargs -I {} mv {} "${SYMBOLS_PREFIX}_{}"
# Finally, make sure we refer to them by their prefixed names, and change any includes from angle brackets to quotation marks.
find . -name "*.h" | xargs gsed -i -e 's/include "/include "'"${SYMBOLS_PREFIX}"'_/' -e 's/include <'"${SYMBOLS_PREFIX}"'_\(.*\)>/include "'"${SYMBOLS_PREFIX}"'_\1"/'
# We need BoringSSL to be modularised
echo "MODULARISING BoringSSL"

cat << EOF > "${PLATFORM_LIBS_DIR}/PGPBoringSSL/PGPBoringSSL.h"
//===----------------------------------------------------------------------===//
// This source file is part of the ObjectivePGP project
//===----------------------------------------------------------------------===//
#ifndef PGP_BORINGSSL_H
#define PGP_BORINGSSL_H

EOF

for h in ${PGPBORINGSSL_MODULE_HEADERS[@]}; do
  echo "#include \"$h\"" >> ${PLATFORM_LIBS_DIR}/PGPBoringSSL/PGPBoringSSL.h
done

echo  "#endif  // PGP_BORINGSSL_H" >> "${PLATFORM_LIBS_DIR}/PGPBoringSSL/PGPBoringSSL.h"
popd

rm -rf ${TMP_DIR}
