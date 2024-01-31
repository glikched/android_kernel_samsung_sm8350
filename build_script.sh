#!/bin/bash

export ARCH=arm64
mkdir out

BUILD_CROSS_COMPILE=~/toolchain/gcc/bin/aarch64-linux-android-
KERNEL_LLVM_BIN=~/toolchain/llvm-arm-toolchain-ship-10.0/bin/clang
CLANG_TRIPLE=aarch64-linux-gnu-
KERNEL_MAKE_ENV=""
ANYKERNEL_DIR="$(pwd)/AnyKernel3"
BUILD_MODULES_DIR="$(pwd)/out/modules"
MOD_DIR="$ANYKERNEL_DIR"/modules/system/lib/modules
K_MOD_DIR="$KERNEL_ROOT_DIR"/out/modules

make -j64 -C $(pwd) O=$(pwd)/out $KERNEL_MAKE_ENV ARCH=arm64 CROSS_COMPILE=$BUILD_CROSS_COMPILE REAL_CC=$KERNEL_LLVM_BIN CLANG_TRIPLE=$CLANG_TRIPLE CONFIG_SECTION_MISMATCH_WARN_ONLY=y vendor/r9q_eur_openx_defconfig
#make -j64 -C $(pwd) O=$(pwd)/out $KERNEL_MAKE_ENV ARCH=arm64 CROSS_COMPILE=$BUILD_CROSS_COMPILE REAL_CC=$KERNEL_LLVM_BIN CLANG_TRIPLE=$CLANG_TRIPLE CONFIG_SECTION_MISMATCH_WARN_ONLY=y
make -j64 -C $(pwd) O=$(pwd)/out $KERNEL_MAKE_ENV ARCH=arm64 CROSS_COMPILE=$BUILD_CROSS_COMPILE REAL_CC=$KERNEL_LLVM_BIN CLANG_TRIPLE=$CLANG_TRIPLE CONFIG_SECTION_MISMATCH_WARN_ONLY=y INSTALL_MOD_PATH=$BUILD_MODULES_DIR INSTALL_MOD_STRIP=1 modules_install

find "$BUILD_MODULES_DIR" -type f -iname "*.ko" -exec cp {} "$MOD_DIR" \;
cp out/arch/arm64/boot/Image $(pwd)/AnyKernel3/Image
cd AnyKernel3
zip -r9 r9q.zip . -x '*.git*' '*patch*' '*ramdisk*' 'LICENSE' 'README.md'
