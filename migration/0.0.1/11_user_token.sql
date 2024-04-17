CREATE TABLE IF NOT EXISTS `<prefix>user_token` (
  `user_id` bigint NOT NULL,
  `hash` varchar(255) NOT NULL,
  `user_ip` varchar(39) NOT NULL,
  `user_agent` varchar(255) NOT NULL,
  `expires_on` datetime NOT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`user_id`,`hash`)
);
