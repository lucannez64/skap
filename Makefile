RUSTFLAGS := -C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt -Zbuild-s threads=12

# Target for building the release version
release:
	cargo +nightly build -Zbuild-std --release 

server:
	rm -f target/release/skap && rm -f target/release/skap-server && cargo +nightly build -Zbuild-std --release --features server && mv -f target/release/skap target/release/skap-server

tui:
	rm -f target/release/skap && rm -f target/release/skap-tui && cargo +nightly build -Zbuild-std --release --features tui && mv -f target/release/skap target/release/skap-tui

run-server: server
	./target/release/skap-server

run-tui: tui
	./target/release/skap-tui

clean:
	cargo clean
run:
	./target/release/skap

# Default target when just running `make` without any specific target
.PHONY: default
default: release
