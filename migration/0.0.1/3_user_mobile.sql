CREATE TABLE IF NOT EXISTS `<prefix>user_mobile` (
  `hash` VARCHAR(255) NOT NULL,
  `user_id` BIGINT NOT NULL,
  `mask` VARCHAR(125) NOT NULL,
  `is_verified` BIT(1) NOT NULL DEFAULT 0,
  `verified_at` DATETIME NULL,
  `created_at` DATETIME NOT NULL,
  PRIMARY KEY (`hash`),
  KEY `idx_user` (`user_id`)
);
