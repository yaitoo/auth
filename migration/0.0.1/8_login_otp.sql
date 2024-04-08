CREATE TABLE IF NOT EXISTS `<prefix>login_otp` (
  `user_id` bigint NOT NULL,
  `hash` varchar(256) NOT NULL,
  `used_at` datetime NOT NULL,
  PRIMARY KEY (`user_id`,`hash`)
);
