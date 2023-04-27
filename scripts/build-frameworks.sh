#!/usr/bin/env bash

set -e

BASE_PWD="$PWD"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

PROJECT_NAME="ObjectivePGP"
PROJECT_FILE_PATH="${PROJECT_NAME}.xcodeproj"
TARGET_NAME="${PROJECT_NAME}"
CONFIGURATION="Release"
BUILD_DIR=$( mktemp -d )
SYMROOT="${BUILD_DIR}/Debug"
OBJROOT="${BUILD_DIR}/Intermediates"

PGP_FRAMEWORKS_DIR="Frameworks"

function platform_from_sdk () {
    if [[ "${1}" =~ ([A-Za-z]+) ]]; then
        echo ${BASH_REMATCH[1]}
    fi
}

function build_framework {
    sdk="${1}"
    PLATFORM_NAME=$(platform_from_sdk "${sdk}")

    xcrun xcodebuild -jobs 1 \
        -project "${PROJECT_FILE_PATH}" \
        -target "${TARGET_NAME}" \
        -configuration "${CONFIGURATION}" \
        -sdk "${sdk}" \
        ONLY_ACTIVE_ARCH=NO \
        BUILD_DIR="${BUILD_DIR}" \
        SYMROOT="${SYMROOT}.${sdk}" \
        OBJROOT="${OBJROOT}.${sdk}" \
        PLATFORM_NAME="${PLATFORM_NAME}" \
        build
}

# Build frameworks
SDKs=(`xcrun xcodebuild -showsdks | grep -Eo "iphone.*|macosx11.*|macosx12.*|macosx13.*"`)
for sdk in "${SDKs[@]}"; do
    build_framework "${sdk}"
done


# Per platform .framework
mkdir -p "${SCRIPT_DIR}/../Frameworks/iphoneos/"
ditto "${BUILD_DIR}/${CONFIGURATION}-iphoneos/${TARGET_NAME}.framework"      "${SCRIPT_DIR}/../Frameworks/iphoneos/${TARGET_NAME}.xcframework"
ditto "${BUILD_DIR}/${CONFIGURATION}-iphoneos/${TARGET_NAME}.framework.dSYM" "${SCRIPT_DIR}/../Frameworks/iphoneos/${TARGET_NAME}.xcframework.dSYM"
mkdir -p "${SCRIPT_DIR}/../Frameworks/iphonesimulator/"
ditto "${BUILD_DIR}/${CONFIGURATION}-iphonesimulator/${TARGET_NAME}.framework"      "${SCRIPT_DIR}/../Frameworks/iphonesimulator/${TARGET_NAME}.xcframework"
ditto "${BUILD_DIR}/${CONFIGURATION}-iphonesimulator/${TARGET_NAME}.framework.dSYM" "${SCRIPT_DIR}/../Frameworks/iphonesimulator/${TARGET_NAME}.xcframework.dSYM"
mkdir -p "${SCRIPT_DIR}/../Frameworks/macos/"
ditto "${BUILD_DIR}/${CONFIGURATION}/${TARGET_NAME}.framework"      "${SCRIPT_DIR}/../Frameworks/macos/${TARGET_NAME}.xcframework"
ditto "${BUILD_DIR}/${CONFIGURATION}/${TARGET_NAME}.framework.dSYM" "${SCRIPT_DIR}/../Frameworks/macos/${TARGET_NAME}.xcframework.dSYM"

# XCFramework
mkdir -p "${SCRIPT_DIR}/../Frameworks"
rm -rf "${SCRIPT_DIR}/../Frameworks/${TARGET_NAME}.xcframework"
xcrun xcodebuild -quiet -create-xcframework \
	-framework "${BUILD_DIR}/${CONFIGURATION}-iphoneos/${TARGET_NAME}.framework" \
	-framework "${BUILD_DIR}/${CONFIGURATION}-iphonesimulator/${TARGET_NAME}.framework" \
	-framework "${BUILD_DIR}/${CONFIGURATION}/${TARGET_NAME}.framework" \
	-output "${SCRIPT_DIR}/../Frameworks/${TARGET_NAME}.xcframework"

# No need to strip frameworks since no combined platforms in a single framework
# cp "scripts/strip-frameworks.sh" "${IPHONE_UNIVERSAL_LIB_DIR}/${TARGET_NAME}.framework/strip-frameworks.sh"
# cp "scripts/strip-frameworks.sh" "${PGP_FRAMEWORKS_DIR}/macosx/${TARGET_NAME}.framework/Versions/A/Resources/strip-frameworks.sh"

rm -rf "${BUILD_DIR}"
echo "done"