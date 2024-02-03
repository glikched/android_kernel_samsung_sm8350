#!/bin/bash

SRC_DIR=$(pwd)
TC_DIR=/home/victor/toolchains/clang-r383902b1
JOBS=64
MAKE_PARAMS="-j$JOBS -C $SRC_DIR O=$SRC_DIR/out ARCH=arm64 CC=clang CLANG_TRIPLE=aarch64-linux-gnu- LLVM=1 CROSS_COMPILE=$TC_DIR/bin/llvm-"
export PATH="$TC_DIR/bin:$PATH"
make $MAKE_PARAMS vendor/r9q_eur_openx_defconfig
make $MAKE_PARAMS
make $MAKE_PARAMS INSTALL_MOD_PATH=modules INSTALL_MOD_STRIP=1 modules_install

rm -rf modules
mkdir modules
find "$(pwd)/out/modules" -type f -iname "*.ko" -exec cp -r {} ./AnyKernel3/modules/vendor/lib/modules/ \;

cp ./out/arch/arm64/boot/Image ./AnyKernel3/
cd AnyKernel3
zip -r9 AQUA_Kernel_KSU-v1.0.zip . -x '*.git*' '*patch*' '*ramdisk*' 'LICENSE' 'README.md'
cd ..