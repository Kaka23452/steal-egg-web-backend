
-- =========================================================
-- STEAL AN EGG SAAS
-- MySQL Database Schema
-- Requires MySQL 5.7+ compatible SQL features
-- =========================================================

CREATE TABLE IF NOT EXISTS users (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    email VARCHAR(254) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    status ENUM('active', 'disabled') NOT NULL DEFAULT 'active',
    last_login_at DATETIME(3) NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    updated_at DATETIME(3) NOT NULL
        DEFAULT CURRENT_TIMESTAMP(3)
        ON UPDATE CURRENT_TIMESTAMP(3),

    PRIMARY KEY (id),
    UNIQUE KEY uq_users_email (email),
    KEY idx_users_status (status)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- API KEYS
-- Store only SHA-256 hashes, never plaintext API keys.
-- Each key can be revoked independently.
-- =========================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id BIGINT UNSIGNED NOT NULL,
    label VARCHAR(100) NULL,
    key_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    key_prefix VARCHAR(24) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    key_suffix CHAR(4) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    expires_at DATETIME(3) NOT NULL,
    last_used_at DATETIME(3) NULL,
    revoked_at DATETIME(3) NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uq_api_keys_hash (key_hash),
    KEY idx_api_keys_user (user_id),
    KEY idx_api_keys_expiry (expires_at),
    KEY idx_api_keys_revoked (revoked_at),

    CONSTRAINT fk_api_keys_user
        FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- EGG TO PET MAPPING
-- Admin manages egg names and their corresponding pets.
-- =========================================================

CREATE TABLE IF NOT EXISTS egg_pet_map (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    egg_name VARCHAR(191) NOT NULL,
    pet_name VARCHAR(191) NOT NULL,
    updated_at DATETIME(3) NOT NULL
        DEFAULT CURRENT_TIMESTAMP(3)
        ON UPDATE CURRENT_TIMESTAMP(3),

    PRIMARY KEY (id),
    UNIQUE KEY uq_egg_pet_map_egg (egg_name)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- LOCATION ALIASES
-- Example: Demons -> Angels and Demons
-- =========================================================

CREATE TABLE IF NOT EXISTS location_alias (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    from_name VARCHAR(191) NOT NULL,
    to_name VARCHAR(191) NOT NULL,
    updated_at DATETIME(3) NOT NULL
        DEFAULT CURRENT_TIMESTAMP(3)
        ON UPDATE CURRENT_TIMESTAMP(3),

    PRIMARY KEY (id),
    UNIQUE KEY uq_location_alias_from (from_name)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- STOCKS
-- Stores individual egg spawn records for the dashboard
-- and OBS overlay. Expired records are cleaned by the backend.
-- =========================================================

CREATE TABLE IF NOT EXISTS stocks (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    tier VARCHAR(64) NOT NULL,
    egg_name VARCHAR(191) NOT NULL,
    pet_name VARCHAR(191) NOT NULL,
    location VARCHAR(191) NOT NULL,
    spawned_at DATETIME(3) NOT NULL,
    expires_at DATETIME(3) NOT NULL,
    created_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),

    PRIMARY KEY (id),
    KEY idx_stocks_expiry (expires_at),
    KEY idx_stocks_spawned (spawned_at),
    KEY idx_stocks_location (location),
    KEY idx_stocks_tier (tier)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;


-- =========================================================
-- PROCESSED DISCORD MESSAGES
-- Prevents the same Discord message from being ingested twice.
-- Backend cleanup should remove records after their 24-hour TTL.
-- =========================================================

CREATE TABLE IF NOT EXISTS processed_messages (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    message_id VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    processed_at DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    expires_at DATETIME(3) NOT NULL,

    PRIMARY KEY (id),
    UNIQUE KEY uq_processed_messages_message (message_id),
    KEY idx_processed_messages_expiry (expires_at)
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci;
