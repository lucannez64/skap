# Configuration Docker pour Skap

Ce document explique comment déployer le serveur Skap à l'aide de Docker et Docker Compose.

## Prérequis

- Docker (version 20.10.0 ou supérieure)
- Docker Compose (version 2.0.0 ou supérieure)

## Structure des fichiers

- `Dockerfile` : Configuration pour construire l'image du serveur Skap
- `docker-compose.yml` : Configuration pour orchestrer les services (Skap, PostgreSQL, Redis)
- `init-db.sql` : Script SQL pour initialiser la base de données

## Configuration

### Variables d'environnement

Les variables d'environnement suivantes sont configurées dans le fichier `docker-compose.yml` :

- `DATABASE_URL` : URL de connexion à PostgreSQL
- `REDIS_URL` : URL de connexion à Redis
- `CA_FILE` : Chemin vers le fichier de certificat CA
- `BASE64_KEY` : Clé symétrique encodée en Base64 pour la génération de tokens

Vous pouvez modifier ces valeurs selon vos besoins.

### Certificat CA

Le certificat CA est automatiquement généré lors du premier démarrage des services grâce au service `ca-generator`. Vous n'avez pas besoin de fournir votre propre fichier `ca.pem`.

## Démarrage des services

### Utilisation avec Zig

Si vous utilisez Zig comme gestionnaire de build, vous pouvez utiliser les commandes suivantes :

```bash
# Construire l'image Docker
zig build docker-build

# Démarrer les services Docker
zig build docker-run

# Afficher les logs des services
zig build docker-logs

# Arrêter les services Docker
zig build docker-stop
```

### Utilisation avec Docker Compose

Vous pouvez également utiliser directement Docker Compose :

```bash
# Démarrer tous les services
docker-compose up -d
```

Cette commande va :
1. Générer un certificat CA si nécessaire
2. Construire l'image du serveur Skap
3. Démarrer PostgreSQL et initialiser la base de données
4. Démarrer Redis
5. Démarrer le serveur Skap

## Vérification des services

Pour vérifier que tous les services fonctionnent correctement :

```bash
docker-compose ps
```

## Logs des services

Pour consulter les logs du serveur Skap :

```bash
docker-compose logs -f skap-server
```

Pour consulter les logs du générateur de certificat CA :

```bash
docker-compose logs ca-generator
```

## Arrêt des services

Pour arrêter tous les services :

```bash
docker-compose down
```

Pour arrêter les services et supprimer les volumes (attention, cela supprimera toutes les données, y compris le certificat CA) :

```bash
docker-compose down -v
```

## Sauvegarde des données

Les données de PostgreSQL, Redis et le certificat CA sont stockées dans des volumes Docker. Pour sauvegarder les données de PostgreSQL :

```bash
docker exec -t postgres pg_dump -U postgres skap > skap_backup.sql
```

Pour sauvegarder le certificat CA :

```bash
docker run --rm -v skap_ca-cert:/certs -v $(pwd):/backup alpine sh -c "cp /certs/ca.pem /backup/"
```

## Restauration des données

Pour restaurer les données de PostgreSQL à partir d'une sauvegarde :

```bash
cat skap_backup.sql | docker exec -i postgres psql -U postgres -d skap
```

Pour restaurer un certificat CA sauvegardé :

```bash
docker run --rm -v skap_ca-cert:/certs -v $(pwd):/backup alpine sh -c "cp /backup/ca.pem /certs/"
```

## Optimisations de compilation

Le Dockerfile utilise les mêmes optimisations de compilation que celles définies dans `build.zig` :
- Utilisation de Rust nightly
- Activation des fonctionnalités CPU : AES, AVX2, SSE2, SSE4.1, BMI2, POPCNT
- Utilisation de `-Zbuild-std` pour une compilation optimisée

## Dépannage

### Problème de connexion à PostgreSQL

Si le serveur Skap ne parvient pas à se connecter à PostgreSQL, vérifiez :
- Le certificat CA a été correctement généré (`docker-compose logs ca-generator`)
- L'URL de connexion dans `DATABASE_URL` est correcte
- PostgreSQL est en cours d'exécution (`docker-compose ps`)

### Problème de connexion à Redis

Si le serveur Skap ne parvient pas à se connecter à Redis, vérifiez :
- L'URL de connexion dans `REDIS_URL` est correcte
- Redis est en cours d'exécution (`docker-compose ps`) 