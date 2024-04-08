CREATE TABLE IF NOT EXISTS `<prefix>login_otp` (
  `code` varchar(10) NOT NULL,
  `user_id` bigint NOT NULL,
  `used_at` datetime NOT NULL,
  PRIMARY KEY (`code`,`user_id`)
);
