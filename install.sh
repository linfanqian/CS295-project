#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=============================="
echo "[1/5] Downloading libheif"
echo "=============================="
echo "[INFO] Downloading libheif v1.21.2..."
wget https://github.com/strukturag/libheif/releases/download/v1.21.2/libheif-1.21.2.tar.gz

echo "[INFO] Extracting..."
tar -xzf libheif-1.21.2.tar.gz
rm libheif-1.21.2.tar.gz
echo "[INFO] Extraction succeeds"

echo "=============================="
echo "[2/5] Installing AFL++"
echo "=============================="
echo "[INFO] Installing dependencies..."
sudo apt update && sudo apt upgrade -y
sudo apt install -y cmake pkg-config libde265-dev libde265-0 libjpeg-dev libtool build-essential clang-14

echo "[INFO] Installing AFL++..."
sudo apt install -y afl++

echo "=============================="
echo "[3/5] Installing SymCC"
echo "=============================="
echo "[INFO] Installing dependencies..."
sudo apt install -y git cargo g++ libz3-dev llvm-14-dev llvm-14-tools ninja-build python3-pip zlib1g-dev

echo "[INFO] Creating Python venv for lit..."
python3 -m venv ~/symcc-venv
source ~/symcc-venv/bin/activate
python -m pip install --upgrade pip
python -m pip install lit

echo "[INFO] Downloading SymCC..."
rm -rf symcc
git clone https://github.com/AFLplusplus/symcc.git

echo "[INFO] Building SymCC..."
cd symcc
git submodule init
git submodule update
mkdir build && cd build
cmake -G Ninja \
  -DCMAKE_C_COMPILER=clang-14 \
  -DCMAKE_CXX_COMPILER=clang++-14 \
  -DLLVM_DIR=/usr/lib/llvm-14/cmake \
  -DQSYM_BACKEND=ON \
  -DZ3_TRUST_SYSTEM_VERSION=on \
  ..
ninja

echo "[INFO] Building symcc_fuzzing_helper..."
cd util/symcc_fuzzing_helper
cargo build --release
cd ../../.. # now at root directory

echo "=================================="
echo "[4/5] Building libheif with AFL++"
echo "=================================="
export CC=afl-clang-fast
export CXX=afl-clang-fast++
export AFL_USE_ASAN=1
export AFL_USE_UBSAN=1
rm -rf ./libheif-afl-build
cmake -S ./libheif-1.21.2 -B ./libheif-afl-build \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF \
    -DWITH_TESTS=OFF \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX"
cmake --build ./libheif-afl-build
unset CC CXX AFL_USE_ASAN AFL_USE_UBSAN

echo "=================================="
echo "[5/5] Building libheif with SymCC"
echo "=================================="
export CC="$SCRIPT_DIR/symcc/build/symcc"
export CXX="$SCRIPT_DIR/symcc/build/sym++"
export SYMCC_REGULAR_LIBCXX=yes
rm -rf ./libheif-symcc-build
cmake -S ./libheif-1.21.2 -B ./libheif-symcc-build \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_TESTING=OFF \
    -DWITH_TESTS=OFF \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined"
cmake --build ./libheif-symcc-build
unset CC CXX SYMCC_REGULAR_LIBCXX


echo "[INFO] Installation done!"