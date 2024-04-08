CREATE TABLE IF NOT EXISTS `<prefix>login_code` (
  `user_id` bigint NOT NULL,
  `hash` varchar(256) NOT NULL,
  `ip` varchar(39) NOT NULL,
  `is_used` bit(1) NOT NULL DEFAULT b'0',
  `used_at` datetime DEFAULT NULL,
  `expires_on` datetime NOT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`user_id`,`hash`)
);
