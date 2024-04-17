CREATE TABLE IF NOT EXISTS `<prefix>login_log` (
  `id` bigint NOT NULL,
  `user_id` bigint NOT NULL,
  `method` char(1) NOT NULL COMMENT 'E=email/password/L=password less/T=TOTP/A=oauth',
  `is_ok` bit(1) NOT NULL,
  `ip` varchar(39) NOT NULL,
  `ua` varchar(255) NOT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`,`created_at`)
);
