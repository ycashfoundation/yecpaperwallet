ifeq ($(shell uname),Darwin)
    EXT := dylib
else
    EXT := a
endif

all: release

winrelease: target/x86_64-pc-windows-gnu/release/yecpaperrust.lib

target/x86_64-pc-windows-gnu/release/zecpaperrust.lib: src/lib.rs Cargo.toml
	cargo build --lib --release --target x86_64-pc-windows-gnu

release: target/release/yecpaperrust.$(EXT)
debug: target/debug/yecpaperrust.$(EXT) 

target/release/yecpaperrust.$(EXT): src/lib.rs Cargo.toml
	cargo build --lib --release

target/debug/yecpaperrust.$(EXT): src/lib.rs Cargo.toml
	cargo build --lib

clean:
	rm -rf target
