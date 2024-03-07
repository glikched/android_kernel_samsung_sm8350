#!/bin/bash

## DEVICE STUFF
DEVICE_HARDWARE="sm8350"
DEVICE_MODEL="$1"
ARGS="$*"
ZIP_DIR="$(pwd)/AnyKernel3"
MOD_DIR="$ZIP_DIR/modules/vendor/lib/modules"
K_MOD_DIR="$(pwd)/out/modules"

# Enviorment Variables
SRC_DIR="$(pwd)"
TC_DIR="$HOME/toolchains/neutron-clang"
JOBS="$(nproc --all)"
MAKE_PARAMS="-j$JOBS -C $SRC_DIR O=$SRC_DIR/out ARCH=arm64 CC=clang CLANG_TRIPLE=$TC_DIR/bin/aarch64-linux-gnu- LLVM=1 CROSS_COMPILE=$TC_DIR/bin/llvm-"
export PATH="$TC_DIR/bin:$PATH"

devicecheck() {
    if [ "$DEVICE_MODEL" == "SM-G990B" ]; then
        DEVICE_NAME="r9q"
        DEFCONFIG=vendor/r9q_eur_openx_defconfig
    elif [ "$DEVICE_MODEL" == "SM-G990B2" ]; then
        DEVICE_NAME="r9q2"
        DEFCONFIG=vendor/r9q_eur_openx2_defconfig
    else
        echo "- Config not found"
        echo " Make sure first argument is DEVICE_MODEL"
        exit
    fi
}

ksu() {
    # Check if KSU flag is provided
    if [[ "$ARGS" == *"--ksu"* ]]; then
        KSU="true"
    else
        KSU="false"
    fi

    # Check the value of KSU
    if [ "$KSU" == "true" ]; then
        ZIP_NAME="AQUA_KSU_"$DEVICE_NAME"_"$DEVICE_MODEL"_"$(date +%d%m%y-%H%M)""
        if [ -d "KernelSU" ]; then
            echo "KernelSU exists"
        else
            echo "KernelSU not found !"
            echo "Fetching ...."
            curl -LSs "https://raw.githubusercontent.com/tiann/KernelSU/main/kernel/setup.sh" | bash -
        fi
    elif [ "$KSU" == "false" ]; then
        echo "KSU disabled"
        ZIP_NAME="AQUA_"$DEVICE_NAME"_"$DEVICE_MODEL"_"$(date +%d%m%y-%H%M)""
        if [ -d "KernelSU" ]; then
            rm -rf drivers/kernelsu
            rm -rf KernelSU
            git reset HEAD --hard
        fi
    fi
}

toolchaincheck() {
    if [ -d "$TC_DIR" ]; then
        echo "Neutron Clang is already there"
        echo "Credits to dakkshesh07"
    else
        echo "Fetching Neutron Clang with antman script"
        echo "Credits to dakkshesh07"
        mkdir -p "$HOME/toolchains/neutron-clang"; cd "$HOME/toolchains/neutron-clang"; curl -LO "https://raw.githubusercontent.com/Neutron-Toolchains/antman/main/antman"; chmod +x antman; ./antman -S
        cd $SRC_DIR
    fi
}

ak3() {
    if [ -d "AnyKernel3" ]; then
        cd AnyKernel3; #git reset HEAD --hard; 
        cd ..
        if [ -d "AnyKernel3/modules" ]; then
            rm -rf AnyKernel3/modules/
            mkdir AnyKernel3/modules/; mkdir AnyKernel3/modules/vendor/; mkdir AnyKernel3/modules/vendor/lib; mkdir AnyKernel3/modules/vendor/lib/modules/
        else
            mkdir AnyKernel3/modules/; mkdir AnyKernel3/modules/vendor/; mkdir AnyKernel3/modules/vendor/lib; mkdir AnyKernel3/modules/vendor/lib/modules/
        fi
    else 
        git clone https://github.com/glikched/AnyKernel3 -b r9q
        if [ -d "AnyKernel3/modules" ]; then
            rm -rf AnyKernel3/modules/
            mkdir AnyKernel3/modules/; mkdir AnyKernel3/modules/vendor/; mkdir AnyKernel3/modules/vendor/lib; mkdir AnyKernel3/modules/vendor/lib/modules/
        else
            mkdir AnyKernel3/modules/; mkdir AnyKernel3/modules/vendor/; mkdir AnyKernel3/modules/vendor/lib; mkdir AnyKernel3/modules/vendor/lib/modules/
        fi
    fi
}

copyoutputtozip() {
    find "$(pwd)/out/modules" -type f -iname "*.ko" -exec cp -r {} ./AnyKernel3/modules/vendor/lib/modules/ \;
    cp ./out/arch/arm64/boot/Image ./AnyKernel3/
    cp ./out/arch/arm64/boot/dtbo.img ./AnyKernel3/
    cd AnyKernel3
    rm -rf AQUA*
    zip -r9 $ZIP_NAME . -x '*.git*' '*patch*' '*ramdisk*' 'LICENSE' 'README.md'
    cd ..
}

help() {
    echo " "
    echo "How to use ?"
    echo " "
    echo " @$ bash ./build_script.sh {DEVICE_MODEL} --only-zip --ksu --help"
    echo " "
    echo "Arguments:"
    echo "         --only-zip: this is for AnyKernel3 Zip testing                    "
    echo "         --ksu     : this pulls latest KernelSU driver and prepares source "
    echo "         --help    : this displays this message                            "
    echo " "
}

    # Check if KSU flag is provided
    if [[ "$ARGS" == *"--only-zip"* ]]; then
        echo "- Skipping Building ..."
        devicecheck
        ksu
        ak3
        copyoutputtozip
        echo "This build was made using these arguments: $ARGS"
    elif [[ "$ARGS" == *"--help"* ]]; then
        help
    else
        echo "- Starting Building ..."
        devicecheck
        ksu
        toolchaincheck
        make $MAKE_PARAMS $DEFCONFIG
        make $MAKE_PARAMS
        make $MAKE_PARAMS INSTALL_MOD_PATH=modules INSTALL_MOD_STRIP=1 modules_install
        ak3
        copyoutputtozip
        echo "This build was made using these arguments: $ARGS"
    fi
