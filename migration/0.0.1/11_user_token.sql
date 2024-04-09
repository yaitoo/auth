CREATE TABLE IF NOT EXISTS `<prefix>user_token` (
  `user_id` bigint NOT NULL,
  `hash` varchar(255) NOT NULL,
  `expires_on` datetime NOT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`user_id`,`hash`)
);
