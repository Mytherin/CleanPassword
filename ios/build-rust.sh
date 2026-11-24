#!/bin/bash
# Builds CleanPassword's Rust core for iOS (device and simulator) and the
# Mac (Mac Catalyst) into
# ios/build/CleanPasswordCore.xcframework, and generates its Swift bindings
# into ios/Generated/. Run on a Mac with Xcode and rustup:
#
#   ios/build-rust.sh            # release build
#   ios/build-rust.sh --debug    # faster to build, slower to run
#
# The Xcode project runs this before every build (quick when nothing
# changed).
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
OUT="$ROOT/ios/build"
GEN="$ROOT/ios/Generated"

PROFILE=release
FLAG=--release
if [[ "${1:-}" == "--debug" ]]; then
    PROFILE=debug
    FLAG=
fi

# Xcode runs build phases with a minimal PATH.
export PATH="$HOME/.cargo/bin:/opt/homebrew/bin:/usr/local/bin:$PATH"
# Xcode's settings for the app mustn't leak into Rust's builds.
unset SDKROOT PLATFORM_NAME IPHONEOS_DEPLOYMENT_TARGET LLVM_TARGET_TRIPLE_SUFFIX
export IPHONEOS_DEPLOYMENT_TARGET=17.0

DEVICE=aarch64-apple-ios
SIMS=(aarch64-apple-ios-sim x86_64-apple-ios)
CATALYST=(aarch64-apple-ios-macabi x86_64-apple-ios-macabi)

rustup target add "$DEVICE" "${SIMS[@]}" "${CATALYST[@]}" >/dev/null

for target in "$DEVICE" "${SIMS[@]}" "${CATALYST[@]}"; do
    cargo build -p cleanpassword-ffi --lib $FLAG --target "$target"
done

# The Swift bindings come from the library's own metadata (a build for this
# Mac is the simplest to read it from).
MAC_SDK="$(xcrun --sdk macosx --show-sdk-path)"
SDKROOT="$MAC_SDK" cargo build -p cleanpassword-ffi --lib $FLAG
HOST_LIB="$ROOT/target/$PROFILE/libcleanpassword_ffi.dylib"
mkdir -p "$GEN"
SDKROOT="$MAC_SDK" cargo run -q -p cleanpassword-ffi --features bindgen --bin uniffi-bindgen -- \
    generate --library "$HOST_LIB" --language swift --out-dir "$GEN"

rm -rf "$OUT/headers" "$OUT/sim" "$OUT/catalyst" "$OUT/CleanPasswordCore.xcframework"
mkdir -p "$OUT/headers" "$OUT/sim" "$OUT/catalyst"
cp "$GEN/cleanpassword_ffiFFI.h" "$OUT/headers/"
cp "$GEN/cleanpassword_ffiFFI.modulemap" "$OUT/headers/module.modulemap"

# One simulator library for Apple silicon and Intel Macs.
lipo -create \
    "$ROOT/target/${SIMS[0]}/$PROFILE/libcleanpassword_ffi.a" \
    "$ROOT/target/${SIMS[1]}/$PROFILE/libcleanpassword_ffi.a" \
    -output "$OUT/sim/libcleanpassword_ffi.a"

# And one Mac Catalyst library for both.
lipo -create \
    "$ROOT/target/${CATALYST[0]}/$PROFILE/libcleanpassword_ffi.a" \
    "$ROOT/target/${CATALYST[1]}/$PROFILE/libcleanpassword_ffi.a" \
    -output "$OUT/catalyst/libcleanpassword_ffi.a"

xcodebuild -create-xcframework \
    -library "$ROOT/target/$DEVICE/$PROFILE/libcleanpassword_ffi.a" -headers "$OUT/headers" \
    -library "$OUT/sim/libcleanpassword_ffi.a" -headers "$OUT/headers" \
    -library "$OUT/catalyst/libcleanpassword_ffi.a" -headers "$OUT/headers" \
    -output "$OUT/CleanPasswordCore.xcframework" >/dev/null

echo "Built $OUT/CleanPasswordCore.xcframework and $GEN/cleanpassword_ffi.swift"
