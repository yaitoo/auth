CREATE TABLE IF NOT EXISTS `<prefix>user_device` (
  `user_id` bigint NOT NULL,
  `ua` varchar(255) NOT NULL,
  `name` varchar(45) NOT NULL,
  `login_times` int NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`user_id`,`ua`),
);
