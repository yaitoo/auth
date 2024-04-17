CREATE TABLE IF NOT EXISTS `<prefix>login_code` (
  `user_id` bigint NOT NULL,
  `hash` varchar(256) NOT NULL,
  `user_ip` varchar(39) NOT NULL,
  `expires_on` datetime NOT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`user_id`,`hash`)
);
