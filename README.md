# SKAP

## Migration du système de build de Make vers Zig

Ce projet a migré de Make vers Zig comme système de build. Voici comment utiliser le nouveau système:

### Prérequis

- Zig (dernière version stable)
- Rust avec Cargo et nightly toolchain

### Commandes de build

Les commandes équivalentes à celles de l'ancien Makefile sont:

| Ancienne commande (Make) | Nouvelle commande (Zig) | Description |
|--------------------------|-------------------------|-------------|
| `make` ou `make release` | `zig build` ou `zig build release` | Construire la version release |
| `make server` | `zig build server` | Construire le serveur |
| `make tui` | `zig build tui` | Construire l'interface TUI |
| `make run-server` | `zig build run-server` | Construire et exécuter le serveur |
| `make run-tui` | `zig build run-tui` | Construire et exécuter l'interface TUI |
| `make only-run-tui` | `zig build only-run-tui` | Exécuter l'interface TUI sans reconstruire |
| `make clean` | `zig build clean` | Nettoyer le projet |
| `make run` | `zig build run` | Exécuter l'exécutable principal |

### Configuration

Le fichier `build.zig` contient la configuration de build, notamment les drapeaux Rust. Si vous avez besoin de modifier les options de compilation, veuillez éditer ce fichier.

```zig
// Définir les drapeaux Rust
const rust_flags = "-C target-feature=+aes,+avx2,+sse2,+sse4.1,+bmi2,+popcnt -Zbuild-std --threads=12";
```

### Avantages de l'utilisation de Zig comme système de build

- Système de build plus flexible et puissant que Make
- Syntaxe plus claire et plus facile à maintenir
- Meilleure intégration multi-plateforme
- Possibilité d'extension avec des scripts Zig personnalisés 