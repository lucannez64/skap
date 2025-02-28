FROM rustlang/rust:nightly-bullseye-slim as builder

WORKDIR /usr/src/skap

# Installer les dépendances nécessaires en premier pour profiter du cache Docker
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y pkg-config libssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Définir les drapeaux Rust pour optimiser la compilation
ENV RUSTFLAGS="-C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt"

# Ajouter rust-src avant de copier le code
RUN rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu

# Copier d'abord les fichiers de dépendances pour profiter du cache Docker
COPY Cargo.toml Cargo.lock ./
# Créer un répertoire src vide avec un fichier minimal pour tromper cargo
RUN mkdir -p src && \
    echo "fn main() {println!(\"dummy\")}" > src/main.rs

# Précompiler les dépendances pour les mettre en cache
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo fetch

# Maintenant, copier le vrai code source
COPY . .

# Nettoyer les artefacts de build précédents pour s'assurer que tout est recompilé correctement
RUN rm -f target/release/skap-server

# Construire l'application en mode release avec la fonctionnalité "server"
# Utiliser un cache pour le registre Cargo mais pas pour le répertoire target/release
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build -Zbuild-std --release --features server --bin skap-server

# Vérifier que l'exécutable existe et afficher sa date de modification
RUN ls -la /usr/src/skap/target/release/skap-server

# Deuxième étape pour une image plus légère
FROM debian:bullseye-slim

WORKDIR /app

# Installer les dépendances d'exécution
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y libssl-dev ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copier l'exécutable compilé depuis l'étape de construction
COPY --from=builder /usr/src/skap/target/release/skap-server /app/skap-server

# Vérifier que l'exécutable a été correctement copié
RUN ls -la /app/skap-server

# Exposer le port utilisé par le serveur
EXPOSE 3030

# Définir les variables d'environnement par défaut
ENV DATABASE_URL="postgres://postgres:postgres@postgres:5432/skap"
ENV REDIS_URL="redis://redis:6379"
ENV CA_FILE="/app/ca.pem"
ENV BASE64_KEY="Cnq094AgzRxApmXC5vjCMzVncq42Ihm6fS7diRYhKqQ="

# Commande pour exécuter le serveur
CMD ["/app/skap-server"]