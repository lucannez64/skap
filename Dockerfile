FROM lukemathwalker/cargo-chef:latest-rust-slim-bullseye AS chef

WORKDIR /usr/src/skap

FROM chef AS planner

COPY Cargo.toml Cargo.lock ./

RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder

COPY --from=planner /usr/src/skap/recipe.json recipe.json

RUN cargo chef cook --release --recipe-path recipe.json

COPY . .

# Installer les dépendances nécessaires
RUN apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Installer Rust nightly
RUN rustup default nightly && \
    rustup component add rust-src

# Copier les fichiers du projet
COPY Cargo.toml Cargo.lock ./
COPY src ./src/


# Définir les drapeaux Rust pour optimiser la compilation
ENV RUSTFLAGS="-C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt"

# Construire l'application en mode release avec la fonctionnalité "server"
RUN cargo build -Zbuild-std --release --features server --bin skap-server

# Deuxième étape pour une image plus légère
FROM debian:bullseye-slim

WORKDIR /app

# Installer les dépendances d'exécution
RUN apt-get update && \
    apt-get install -y libssl-dev ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copier l'exécutable compilé depuis l'étape de construction
COPY --from=builder /usr/src/skap/target/release/skap-server /app/skap-server

# Exposer le port utilisé par le serveur
EXPOSE 3030

# Définir les variables d'environnement par défaut
ENV DATABASE_URL="postgres://postgres:postgres@postgres:5432/skap"
ENV REDIS_URL="redis://redis:6379"
ENV CA_FILE="/app/ca.pem"
ENV BASE64_KEY="Cnq094AgzRxApmXC5vjCMzVncq42Ihm6fS7diRYhKqQ="

# Commande pour exécuter le serveur
CMD ["/app/skap-server"] 