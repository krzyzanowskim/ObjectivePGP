# This script strips all non-valid architectures from dynamic libraries in
# the application's `Frameworks` directory.
#
# The following environment variables are required:
#
# BUILT_PRODUCTS_DIR
# FRAMEWORKS_FOLDER_PATH
# VALID_ARCHS
# EXPANDED_CODE_SIGN_IDENTITY


# Signs a framework with the provided identity
code_sign() {
  # Use the current code_sign_identitiy
  echo "Code Signing $1 with Identity ${EXPANDED_CODE_SIGN_IDENTITY_NAME}"
  echo "/usr/bin/codesign --force --sign ${EXPANDED_CODE_SIGN_IDENTITY} --preserve-metadata=identifier,entitlements $1"
  /usr/bin/codesign --force --sign ${EXPANDED_CODE_SIGN_IDENTITY} --preserve-metadata=identifier,entitlements "$1"
}

# Set working directory to product’s embedded frameworks 
cd "${BUILT_PRODUCTS_DIR}/${FRAMEWORKS_FOLDER_PATH}"

if [ "$ACTION" = "install" ]; then
  echo "Copy .bcsymbolmap files to .xcarchive"
  find . -name '*.bcsymbolmap' -type f -exec mv {} "${CONFIGURATION_BUILD_DIR}" \;
else
  # Delete *.bcsymbolmap files from framework bundle unless archiving
  find . -name '*.bcsymbolmap' -type f -exec rm -rf "{}" +\;
fi

echo "Stripping frameworks"

for file in $(find . -type f -perm +111); do
  # Skip non-dynamic libraries
  if ! [[ "$(file "$file")" == *"dynamically linked shared library"* ]]; then
    continue
  fi
  # Get architectures for current file
  archs="$(lipo -info "${file}" | rev | cut -d ':' -f1 | rev)"
  stripped=""
  for arch in $archs; do
    if ! [[ "${VALID_ARCHS}" == *"$arch"* ]]; then
      # Strip non-valid architectures in-place
      lipo -remove "$arch" -output "$file" "$file" || exit 1
      stripped="$stripped $arch"
    fi
  done
  if [[ "$stripped" != "" ]]; then
    echo "Stripped $file of architectures:$stripped"
    if [ "${CODE_SIGNING_REQUIRED}" == "YES" ]; then
      code_sign "${file}"
    fi
  fi
done