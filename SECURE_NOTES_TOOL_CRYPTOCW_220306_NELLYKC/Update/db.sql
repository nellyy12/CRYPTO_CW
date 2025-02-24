-- --------------------------------------------------------
-- 📌 Database: `secure_notes`
-- --------------------------------------------------------

CREATE DATABASE IF NOT EXISTS `secure_notes`;
USE `secure_notes`;

-- --------------------------------------------------------
-- 📌 Users Table: Stores User Credentials, Public Key
-- --------------------------------------------------------

CREATE TABLE `users` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `username` VARCHAR(50) NOT NULL UNIQUE,
  `password_hash` VARCHAR(256) NOT NULL,  -- 🔐 Hashed password (SHA-256 + PBKDF2)
  `public_key` BLOB NOT NULL  -- 🔏 Digital signature public key (ECDSA)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------
-- 📌 Notes Table: Stores Encrypted Notes & Signatures
-- --------------------------------------------------------

CREATE TABLE `notes` (
  `note_id` INT AUTO_INCREMENT PRIMARY KEY,
  `user_id` INT NOT NULL,
  `title` VARCHAR(100) NOT NULL,
  `chacha_encrypted` BLOB NOT NULL,  -- 🔐 ChaCha20 encrypted content
  `aes_encrypted` BLOB NOT NULL,  -- 🔐 AES-GCM encrypted content
  `signature` BLOB NOT NULL,  -- ✍️ ECDSA signature for authenticity
  `token` VARCHAR(36) NOT NULL UNIQUE,  -- 🔑 Unique token for shared access
  FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------
-- 📌 Sample Data: Creating Users & Notes
-- --------------------------------------------------------

INSERT INTO `users` (`username`, `password_hash`, `public_key`) VALUES
('user_a', 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3', '...public key data...'),
('user_b', 'ef797c8118f02d4c08e8dfd64b4e0a7b5bc679e543287f27a189d0f0eeb1e123', '...public key data...');

INSERT INTO `notes` (`user_id`, `title`, `chacha_encrypted`, `aes_encrypted`, `signature`, `token`) VALUES
(1, 'Secure Note 1', 0x123456789abcdef, 0xabcdef123456789, 0x112233445566, 'd25d5b5f-3e3c-4f2b-9912-abc123456789'),
(2, 'Secure Note 2', 0xabcdef987654321, 0x654321abcdef98, 0x556677889900, 'f37b5c5d-2a4e-5d6f-9b12-bcd123456789');

-- --------------------------------------------------------
-- 📌 Indexes for Faster Queries
-- --------------------------------------------------------

ALTER TABLE `users`
  ADD UNIQUE INDEX `idx_username` (`username`);

ALTER TABLE `notes`
  ADD INDEX `idx_user_id` (`user_id`);

