RUSTFLAGS := -C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt -Zbuild-s threads=12

# Target for building the release version
release:
	cargo +nightly build -Zbuild-std --release

server:
	cargo +nightly build -Zbuild-std --release --bin "skap-server" --features server

tui:
	cargo +nightly build -Zbuild-std --release --bin "skap-tui" --features tui

run-server: server
	./target/release/skap-server

run-tui: tui
	./target/release/skap-tui

only-run-tui:
	./target/release/skap-tui

clean:
	cargo clean
run:
	./target/release/skap

# Default target when just running `make` without any specific target
.PHONY: default
default: release
