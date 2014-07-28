#!/bin/bash

# Build build/Release fat binary

WORKSPACE="ObjectivePGP.xcworkspace"
CONFIGURATION="Release"
SCHEME="ObjectivePGP"
PLATFORM="ios"
BUILD_DIR=$(PWD)/build-${PLATFORM}
DEST_DIR=${BUILD_DIR}/${CONFIGURATION}

rm -rf ${BUILD_DIR}
mkdir -p ${DEST_DIR}

# # IOS

xcodebuild build -workspace ${WORKSPACE} -scheme ${SCHEME} -configuration ${CONFIGURATION} -sdk iphoneos ONLY_ACTIVE_ARCH=NO SYMROOT=${BUILD_DIR}

xcodebuild build -workspace ${WORKSPACE} -scheme ${SCHEME} -configuration ${CONFIGURATION} -arch i386 -sdk iphonesimulator ONLY_ACTIVE_ARCH=NO SYMROOT=${BUILD_DIR}
mv ${DEST_DIR}-iphonesimulator/libObjectivePGP.a ${DEST_DIR}-iphonesimulator/libObjectivePGP-i386.a
mv ${DEST_DIR}-iphonesimulator/libPods-ObjectivePGP-OpenSSL-Universal.a ${DEST_DIR}-iphonesimulator/libPods-ObjectivePGP-OpenSSL-Universal-i386.a
mv ${DEST_DIR}-iphonesimulator/libPods-ObjectivePGP.a ${DEST_DIR}-iphonesimulator/libPods-ObjectivePGP-i386.a

xcodebuild build -workspace ${WORKSPACE} -scheme ${SCHEME} -configuration ${CONFIGURATION} -arch x86_64 -sdk iphonesimulator ONLY_ACTIVE_ARCH=NO SYMROOT=${BUILD_DIR}
mv ${DEST_DIR}-iphonesimulator/libObjectivePGP.a ${DEST_DIR}-iphonesimulator/libObjectivePGP-x86_64.a
mv ${DEST_DIR}-iphonesimulator/libPods-ObjectivePGP-OpenSSL-Universal.a ${DEST_DIR}-iphonesimulator/libPods-ObjectivePGP-OpenSSL-Universal-x86_64.a
mv ${DEST_DIR}-iphonesimulator/libPods-ObjectivePGP.a ${DEST_DIR}-iphonesimulator/libPods-ObjectivePGP-x86_64.a

lipo -create ${DEST_DIR}-iphoneos/libObjectivePGP.a ${DEST_DIR}-iphonesimulator/libObjectivePGP-i386.a ${DEST_DIR}-iphonesimulator/libObjectivePGP-x86_64.a -output ${DEST_DIR}/libObjectivePGP.a
lipo -create ${DEST_DIR}-iphoneos/libPods-ObjectivePGP-OpenSSL-Universal.a ${DEST_DIR}-iphonesimulator/libPods-ObjectivePGP-OpenSSL-Universal-i386.a ${DEST_DIR}-iphonesimulator/libPods-ObjectivePGP-OpenSSL-Universal-x86_64.a -output ${DEST_DIR}/libPods-ObjectivePGP-OpenSSL-Universal.a
lipo -create ${DEST_DIR}-iphoneos/libPods-ObjectivePGP.a ${DEST_DIR}-iphonesimulator/libPods-ObjectivePGP-i386.a ${DEST_DIR}-iphonesimulator/libPods-ObjectivePGP-x86_64.a -output ${DEST_DIR}/libPods-ObjectivePGP.a
cp -pR ${DEST_DIR}-iphoneos/include ${DEST_DIR}

rm -rf ${BUILD_DIR}/${CONFIGURATION}-iphoneos
rm -rf ${BUILD_DIR}/${CONFIGURATION}-iphonesimulator

#OSX

SCHEME="ObjectivePGPOSX"
PLATFORM="osx"
BUILD_DIR=$(PWD)/build-${PLATFORM}
DEST_DIR=${BUILD_DIR}/${CONFIGURATION}

rm -rf ${BUILD_DIR}
mkdir -p ${DEST_DIR}

xcodebuild build -workspace ${WORKSPACE} -scheme ${SCHEME} -configuration ${CONFIGURATION} -arch x86_64 -sdk macosx10.9 ONLY_ACTIVE_ARCH=NO SYMROOT=${BUILD_DIR}
