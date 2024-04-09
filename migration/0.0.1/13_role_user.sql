CREATE TABLE `<prefix>role_user` (
  `role_id` int NOT NULL,
  `user_id` bigint NOT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`role_id`,`user_id`),
  KEY `idx_user` (`user_id`)
);
