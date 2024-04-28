CREATE TABLE IF NOT EXISTS `<prefix>user_email` (
  `hash` VARCHAR(255) NOT NULL,
  `user_id` BIGINT NOT NULL,
  `created_at` DATETIME NOT NULL,
  PRIMARY KEY (`hash`),
  KEY `idx_user` (`user_id`)
);