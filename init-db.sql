-- Création des tables pour l'application skap

-- Table des utilisateurs
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    ky_public_key BYTEA NOT NULL,
    di_public_key BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table des mots de passe
CREATE TABLE IF NOT EXISTS passes (
    id UUID NOT NULL,
    user_id UUID NOT NULL,
    data BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Table des mots de passe partagés
CREATE TABLE IF NOT EXISTS shared_passes (
    owner_id UUID NOT NULL,
    pass_id UUID NOT NULL,
    recipient_id UUID NOT NULL,
    data BYTEA NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (owner_id, pass_id, recipient_id),
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Index pour améliorer les performances des requêtes
CREATE INDEX IF NOT EXISTS idx_passes_user_id ON passes(user_id);
CREATE INDEX IF NOT EXISTS idx_shared_passes_recipient_id ON shared_passes(recipient_id);
CREATE INDEX IF NOT EXISTS idx_shared_passes_owner_id ON shared_passes(owner_id);

-- Fonction pour mettre à jour le timestamp 'updated_at'
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger pour mettre à jour automatiquement 'updated_at' lors des mises à jour
CREATE TRIGGER update_passes_updated_at
BEFORE UPDATE ON passes
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column(); 