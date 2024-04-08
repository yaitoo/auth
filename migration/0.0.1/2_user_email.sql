CREATE TABLE IF NOT EXISTS `<prefix>user_email` (
  `hash` VARCHAR(255) NOT NULL,
  `user_id` BIGINT NOT NULL,
  `mask` VARCHAR(5) NOT NULL,
  `is_verified` BIT(1) NOT NULL DEFAULT 0,
  `verified_at` DATETIME NULL,
  `created_at` DATETIME NOT NULL,
  PRIMARY KEY (`hash`),
  KEY `idx_user` (`user_id`)
);
