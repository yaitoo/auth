CREATE TABLE IF NOT EXISTS `<prefix>user` (
  `id` bigint NOT NULL,
  `status` TINYINT NOT NULL DEFAULT 0,
  `first_name` varchar(255) NOT NULL,
  `last_name` varchar(255) NOT NULL,
  `passwd` varchar(255) NOT NULL,
  `salt` varchar(36) NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`id`)
);
