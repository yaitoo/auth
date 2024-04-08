CREATE TABLE IF NOT EXISTS `<prefix>user_last` (
  `user_id` bigint NOT NULL,
  `is_locked` bit(1) NOT NULL DEFAULT b'0',
  `locked_at` datetime DEFAULT NULL,
  `fails` tinyint NOT NULL DEFAULT '0',
  `last_at` datetime NOT NULL,
  `last_ip` varchar(39) NOT NULL,
  `last_device_name` varchar(45) NOT NULL,
  PRIMARY KEY (`user_id`)
);
