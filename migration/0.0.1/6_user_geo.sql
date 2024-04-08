CREATE TABLE IF NOT EXISTS `<prefix>user_geo` (
  `user_id` bigint NOT NULL,
  `ip` varchar(39) NOT NULL,
  `country` varchar(25) NOT NULL,
  `region` varchar(45) NOT NULL,
  `login_times` int NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`user_id`,`ip`),
  KEY `idx_ip` (`ip`,`user_id`),
  KEY `idx_country` (`country`,`region`,`user_id`)
);
