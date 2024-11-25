RUSTFLAGS := -C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt -Zbuild-s threads=12

# Target for building the release version
release:
	cargo +nightly build -Zbuild-std --release 
clean:
	cargo clean
run:
	./target/release/skap

# Default target when just running `make` without any specific target
.PHONY: default
default: release
