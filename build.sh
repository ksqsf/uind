#!/bin/sh

# This script assumes you are running Linux.  To cross compile uind to
# Windows, you must install Rust toolchain for triple
# 'x86_64-pc-windows-gnu', and have linker set up, e.g. as
# 'x86_64-w64-mingw32-gcc'.

cargo build --release --target-dir target-linux
cargo build --release --target x86_64-pc-windows-gnu --target-dir target-windows
