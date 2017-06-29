#!/bin/bash

set -e

PROJECT_NAME="ObjectivePGP"
PROJECT_FILE_PATH="${PROJECT_NAME}.xcodeproj"
TARGET_NAME="${PROJECT_NAME}"
EXECUTABLE_PREFIX="lib"
EXECUTABLE_SUFFIX=".a"
EXECUTABLE_NAME="${EXECUTABLE_PREFIX}${PROJECT_NAME}${EXECUTABLE_SUFFIX}"
CONFIGURATION="Release"
BUILD_DIR="DerivedData/${PROJECT_NAME}/Build/Products"
SYMROOT="${BUILD_DIR}"
OBJROOT="DerivedData/${PROJECT_NAME}/Build/Intermediates.noindex"
PUBLIC_HEADERS_FOLDER_PATH="include/${PROJECT_NAME}"

PGP_FRAMEWORKS_DIR="Frameworks"
IPHONE_UNIVERSAL_LIB_DIR="${PGP_FRAMEWORKS_DIR}/ios"
IPHONE_UNIVERSAL_FRAMEWORK_DIR="${IPHONE_UNIVERSAL_LIB_DIR}/${TARGET_NAME}.framework"

function build_static_library () {
    sdk="${1}"
    PLATFORM_NAME=$(platform_from_sdk "${sdk}")
    
    xcrun xcodebuild -project "${PROJECT_FILE_PATH}" \
    -target "${TARGET_NAME}" \
    -configuration "${CONFIGURATION}" \
    -sdk "${sdk}" \
    ONLY_ACTIVE_ARCH=NO \
    BUILD_DIR="${BUILD_DIR}" \
    OBJROOT="${OBJROOT}" \
    SYMROOT="${SYMROOT}" \
    PLATFORM_NAME="${PLATFORM_NAME}" \
    build
}

function make_fat_library () {
    # Will smash 2 static libs together
    #     make_fat_library in1 in2 out
    xcrun lipo -create "${1}" "${2}" -output "${3}"
}

function create_framework () {
    UNIVERSAL_FRAMEWORK_DIR="${1}"
    LIB_PATH=${2}
    PRODUCT_NAME="${3}"

    # Create the path to the real Headers die
    mkdir -p "${UNIVERSAL_FRAMEWORK_DIR}/Versions/A/Headers"

    # Create the required symlinks
    /bin/ln -sfh "A" "${UNIVERSAL_FRAMEWORK_DIR}/Versions/Current"
    /bin/ln -sfh "Versions/Current/Headers" "${UNIVERSAL_FRAMEWORK_DIR}/Headers"
    /bin/ln -sfh "Versions/Current/${PRODUCT_NAME}" "${UNIVERSAL_FRAMEWORK_DIR}/${PRODUCT_NAME}"

    # Copy the public headers into the framework
    /bin/cp -a "${BUILD_DIR}/${CONFIGURATION}-iphoneos/${PUBLIC_HEADERS_FOLDER_PATH}/" \
               "${UNIVERSAL_FRAMEWORK_DIR}/Versions/A/Headers"

    # Copy lib
    /bin/cp -a "${LIB_PATH}" \
               "${UNIVERSAL_FRAMEWORK_DIR}/Versions/A/${PRODUCT_NAME}"
}

function platform_from_sdk () {
    if [[ "${1}" =~ ([A-Za-z]+) ]]; then
        echo ${BASH_REMATCH[1]}
    fi    
}

# Build libraries
SDKs=(`xcrun xcodebuild -showsdks | grep -Eo "iphone.*|macos.*"`)
for sdk in "${SDKs[@]}"; do
    build_static_library "${sdk}"
done

# macos framework no need to change.
# create universal iphone framework.
# iphoneos + iphonesimulator = iphoneuniversal
mkdir -p "${IPHONE_UNIVERSAL_LIB_DIR}"
make_fat_library "${BUILD_DIR}/${CONFIGURATION}-iphoneos/${EXECUTABLE_NAME}" \
                 "${BUILD_DIR}/${CONFIGURATION}-iphonesimulator/${EXECUTABLE_NAME}" \
                 "${IPHONE_UNIVERSAL_LIB_DIR}/${EXECUTABLE_NAME}"

create_framework "${IPHONE_UNIVERSAL_FRAMEWORK_DIR}" \
                 "${IPHONE_UNIVERSAL_LIB_DIR}/${EXECUTABLE_NAME}" \
                 "${TARGET_NAME}"

rm "${IPHONE_UNIVERSAL_LIB_DIR}/${EXECUTABLE_NAME}"

# copy macos framework
ditto "${BUILD_DIR}/${CONFIGURATION}/${TARGET_NAME}.framework" "${PGP_FRAMEWORKS_DIR}/macOS/${TARGET_NAME}.framework"
