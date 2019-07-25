#!/bin/bash

# Accept the variables as command line arguments as well
POSITIONAL=()
while [[ $# -gt 0 ]]
do
key="$1"

case $key in
    -v|--version)
    APP_VERSION="$2"
    shift # past argument
    shift # past value
    ;;
    *)    # unknown option
    POSITIONAL+=("$1") # save it in an array for later
    shift # past argument
    ;;
esac
done
set -- "${POSITIONAL[@]}" # restore positional parameters


if [ -z $APP_VERSION ]; then
    echo "APP_VERSION is not set. Please set it to the current release version of the app";
    exit 1;
fi

# This should be set as an environment variable
if [ -z $QT_PATH ]; then 
    echo "QT_PATH is not set. Please set it to the base directory of Qt"; 
    exit 1; 
fi
QT_STATIC=$QT_PATH/clang_64/bin

# Build for MacOS first

# Clean
echo -n "Cleaning..............."
$QT_STATIC/qmake papersapling.pro CONFIG+=release >/dev/null
make distclean >/dev/null 2>&1
rm -rf    artifacts/macOS-yecpaperwallet-v$APP_VERSION
mkdir -p  artifacts/macOS-yecpaperwallet-v$APP_VERSION
echo "[OK]"

echo -n "Testing................"
cd ../lib
if ! cargo test --release; then
    echo "[Test Failed]"
    exit 1;
fi
cd ../ui

echo -n "Configuring............"
# Build
$QT_STATIC/qmake papersapling.pro CONFIG+=release >/dev/null
APP_BUILD_DATE=$(date +%F)
echo "#define APP_VERSION \"$APP_VERSION\"" > src/version.h
echo "#define APP_BUILD_DATE \"$APP_BUILD_DATE\"" >> src/version.h

echo "[OK]"


echo -n "Building..............."
make -j4 >/dev/null
echo "[OK]"

#Qt deploy
echo -n "Deploying.............."
$QT_STATIC/macdeployqt yecpaperwalletui.app 
cp -r yecpaperwalletui.app artifacts/macOS-yecpaperwallet-v$APP_VERSION/
echo "[OK]"

# Run inside docker container
docker run --rm -v ${PWD}/..:/opt/yecpaperwallet zecwallet/compileenv:v0.8 bash -c "cd /opt/yecpaperwallet/ui && ./mkdockerwinlinux.sh -v $APP_VERSION"

# Move to build the cli
cd ../cli

# Clean everything first
cargo clean
echo "pub fn version() -> &'static str { &\"$APP_VERSION\" }" > src/version.rs

# Compile for mac directly, and copy it over first, otherwise it will get overwritten by the docker builds.
cargo build --release 
cp target/release/yecpaperwallet ../ui/artifacts/macOS-yecpaperwallet-v$APP_VERSION/

# For Windows and Linux, build via docker
docker run --rm -v $(pwd)/..:/opt/yecpaperwallet rust/zecpaperwallet:v0.3 bash -c "cd /opt/yecpaperwallet/cli && cargo build --release  && cargo build --release --target x86_64-pc-windows-gnu && cargo build --release --target aarch64-unknown-linux-gnu && cargo build --release --target armv7-unknown-linux-gnueabihf"

# Come back and package everything
cd ../ui

# Now sign and zip the binaries
#macOS
# Was previously copied over
gpg --batch --output artifacts/macOS-yecpaperwallet-v$APP_VERSION/yecpaperwallet.sig --detach-sig artifacts/macOS-yecpaperwallet-v$APP_VERSION/yecpaperwallet 
#gpg --batch --output artifacts/macOS-yecpaperwallet-v$APP_VERSION/yecpaperwallet.app.sig --detach-sig artifacts/macOS-yecpaperwallet-v$APP_VERSION/yecpaperwallet.app 
cd artifacts
cd macOS-yecpaperwallet-v$APP_VERSION
gsha256sum yecpaperwallet > sha256sum.txt
cd ..
zip -r macOS-yecpaperwallet-v$APP_VERSION.zip macOS-yecpaperwallet-v$APP_VERSION 
cd ..


#Linux
cp ../cli/target/release/yecpaperwallet artifacts/linux-yecpaperwallet-v$APP_VERSION/
gpg --batch --output artifacts/linux-yecpaperwallet-v$APP_VERSION/yecpaperwallet.sig --detach-sig artifacts/linux-yecpaperwallet-v$APP_VERSION/yecpaperwallet
gpg --batch --output artifacts/linux-yecpaperwallet-v$APP_VERSION/yecpaperwalletui.sig --detach-sig artifacts/linux-yecpaperwallet-v$APP_VERSION/yecpaperwalletui
cd artifacts
cd linux-yecpaperwallet-v$APP_VERSION
gsha256sum yecpaperwallet yecpaperwalletui > sha256sum.txt
cd ..
zip -r linux-yecpaperwallet-v$APP_VERSION.zip linux-yecpaperwallet-v$APP_VERSION 
cd ..


#Windows
cp ../cli/target/x86_64-pc-windows-gnu/release/yecpaperwallet.exe artifacts/Windows-yecpaperwallet-v$APP_VERSION/
gpg --batch --output artifacts/Windows-yecpaperwallet-v$APP_VERSION/yecpaperwallet.sig --detach-sig artifacts/Windows-yecpaperwallet-v$APP_VERSION/yecpaperwallet.exe
gpg --batch --output artifacts/Windows-yecpaperwallet-v$APP_VERSION/yecpaperwalletui.sig --detach-sig artifacts/Windows-yecpaperwallet-v$APP_VERSION/yecpaperwalletui.exe
cd artifacts
cd Windows-yecpaperwallet-v$APP_VERSION
gsha256sum yecpaperwallet.exe yecpaperwalletui.exe > sha256sum.txt
cd ..
zip -r Windows-yecpaperwallet-v$APP_VERSION.zip Windows-yecpaperwallet-v$APP_VERSION 
cd ..


# aarch64 (armv8)
rm -rf artifacts/aarch64-yecpaperwallet-v$APP_VERSION
mkdir -p artifacts/aarch64-yecpaperwallet-v$APP_VERSION
cp ../cli/target/aarch64-unknown-linux-gnu/release/yecpaperwallet artifacts/aarch64-yecpaperwallet-v$APP_VERSION/
gpg --batch --output artifacts/aarch64-yecpaperwallet-v$APP_VERSION/yecpaperwallet.sig --detach-sig artifacts/aarch64-yecpaperwallet-v$APP_VERSION/yecpaperwallet
cd artifacts
cd aarch64-yecpaperwallet-v$APP_VERSION
gsha256sum yecpaperwallet > sha256sum.txt
cd ..
zip -r aarch64-yecpaperwallet-v$APP_VERSION.zip aarch64-yecpaperwallet-v$APP_VERSION 
cd ..


# ARMv7
rm -rf artifacts/armv7-yecpaperwallet-v$APP_VERSION
mkdir -p artifacts/armv7-yecpaperwallet-v$APP_VERSION
cp ../cli/target/armv7-unknown-linux-gnueabihf/release/yecpaperwallet artifacts/armv7-yecpaperwallet-v$APP_VERSION/
gpg --batch --output artifacts/armv7-yecpaperwallet-v$APP_VERSION/yecpaperwallet.sig --detach-sig artifacts/armv7-yecpaperwallet-v$APP_VERSION/yecpaperwallet
cd artifacts
cd armv7-yecpaperwallet-v$APP_VERSION
gsha256sum yecpaperwallet > sha256sum.txt
cd ..
zip -r armv7-yecpaperwallet-v$APP_VERSION.zip armv7-yecpaperwallet-v$APP_VERSION 
cd ..

