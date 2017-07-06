#!/bin/bash

set -e

PROJECT_NAME="ObjectivePGP"
PROJECT_FILE_PATH="${PROJECT_NAME}.xcodeproj"
TARGET_NAME="${PROJECT_NAME}"
CONFIGURATION="Release"
BUILD_DIR="/tmp/$(uuidgen).${PROJECT_NAME}"
SYMROOT="${BUILD_DIR}"
OBJROOT="${BUILD_DIR}/Intermediates"

PGP_FRAMEWORKS_DIR="Frameworks"
IPHONE_UNIVERSAL_LIB_DIR="${PGP_FRAMEWORKS_DIR}/ios"
IPHONE_UNIVERSAL_FRAMEWORK_DIR="${IPHONE_UNIVERSAL_LIB_DIR}/${TARGET_NAME}.framework"


function make_fat_library () {
    # Will smash 2 static libs together
    #     make_fat_library in1 in2 out
    xcrun lipo -create "${1}" "${2}" -output "${3}"
}

function platform_from_sdk () {
    if [[ "${1}" =~ ([A-Za-z]+) ]]; then
        echo ${BASH_REMATCH[1]}
    fi
}

function build_framework {
    sdk="${1}"
    PLATFORM_NAME=$(platform_from_sdk "${sdk}")

    xcrun xcodebuild -project "${PROJECT_FILE_PATH}" -target "${TARGET_NAME}" -configuration "${CONFIGURATION}" \
        -sdk "${sdk}" \
        ONLY_ACTIVE_ARCH=NO \
        BUILD_DIR="${BUILD_DIR}" \
        SYMROOT="${SYMROOT}" \
        OBJROOT="${OBJROOT}" \
        PLATFORM_NAME="${PLATFORM_NAME}" \
        build
}

# Build frameworks
SDKs=(`xcrun xcodebuild -showsdks | grep -Eo "iphone.*|macos.*"`)
for sdk in "${SDKs[@]}"; do
    build_framework "${sdk}"
done

mkdir -p "${IPHONE_UNIVERSAL_LIB_DIR}"
make_fat_library "${BUILD_DIR}/${CONFIGURATION}-iphoneos/${TARGET_NAME}.framework/${TARGET_NAME}" \
                 "${BUILD_DIR}/${CONFIGURATION}-iphonesimulator/${TARGET_NAME}.framework/${TARGET_NAME}" \
                 "${BUILD_DIR}/${CONFIGURATION}-iphonesimulator/${TARGET_NAME}.framework/${TARGET_NAME}.universal"

rm "${BUILD_DIR}/${CONFIGURATION}-iphonesimulator/${TARGET_NAME}.framework/${TARGET_NAME}"
mv "${BUILD_DIR}/${CONFIGURATION}-iphonesimulator/${TARGET_NAME}.framework/${TARGET_NAME}.universal" \
    "${BUILD_DIR}/${CONFIGURATION}-iphonesimulator/${TARGET_NAME}.framework/${TARGET_NAME}"

ditto "${BUILD_DIR}/${CONFIGURATION}-iphonesimulator/${TARGET_NAME}.framework" "${IPHONE_UNIVERSAL_LIB_DIR}/${TARGET_NAME}.framework"
ditto "${BUILD_DIR}/${CONFIGURATION}/${TARGET_NAME}.framework" "${PGP_FRAMEWORKS_DIR}/macosx/${TARGET_NAME}.framework"

echo "${BUILD_DIR}"
rm -rf "${BUILD_DIR}"