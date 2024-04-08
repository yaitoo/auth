CREATE TABLE IF NOT EXISTS `<prefix>user_profile` (
  `user_id` bigint NOT NULL,
  `data` blob NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`user_id`)
);
