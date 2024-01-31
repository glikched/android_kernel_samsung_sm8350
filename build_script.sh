#!/bin/bash

export ARCH=arm64
mkdir out

BUILD_CROSS_COMPILE=~/toolchain/gcc/bin/aarch64-linux-android-
KERNEL_LLVM_BIN=~/toolchain/llvm-arm-toolchain-ship-10.0/bin/clang
CLANG_TRIPLE=aarch64-linux-gnu-
KERNEL_MAKE_ENV=""
BUILD_MODULES_DIR="$(pwd)/out/modules"
MOD_DIR="$ZIP_DIR"/modules/vendor/lib/modules
K_MOD_DIR="$(pwd)/out/modules"

make -j64 -C $(pwd) O=$(pwd)/out $KERNEL_MAKE_ENV ARCH=arm64 CROSS_COMPILE=$BUILD_CROSS_COMPILE REAL_CC=$KERNEL_LLVM_BIN CLANG_TRIPLE=$CLANG_TRIPLE CONFIG_SECTION_MISMATCH_WARN_ONLY=y vendor/r9q_eur_openx_defconfig
make -j64 -C $(pwd) O=$(pwd)/out $KERNEL_MAKE_ENV ARCH=arm64 CROSS_COMPILE=$BUILD_CROSS_COMPILE REAL_CC=$KERNEL_LLVM_BIN CLANG_TRIPLE=$CLANG_TRIPLE CONFIG_SECTION_MISMATCH_WARN_ONLY=y
make -j64 -C $(pwd) O=$(pwd)/out $KERNEL_MAKE_ENV ARCH=arm64 CROSS_COMPILE=$BUILD_CROSS_COMPILE REAL_CC=$KERNEL_LLVM_BIN CLANG_TRIPLE=$CLANG_TRIPLE CONFIG_SECTION_MISMATCH_WARN_ONLY=y INSTALL_MOD_PATH=$BUILD_MODULES_DIR INSTALL_MOD_STRIP=1 modules_install

mkdir modules
find "$(pwd)/out/modules" -type f -iname "*.ko" -exec cp -r {} ./modules/ \;
cp ./out/arch/arm64/boot/Image ./Image
cp ./out/arch/arm64/boot/dtbo.img ./dtbo.img

