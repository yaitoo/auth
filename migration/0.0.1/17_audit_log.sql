
CREATE TABLE IF NOT EXISTS `<prefix>audit_log` (
  `id` bigint NOT NULL,
  `user_id` bigint NOT NULL,
  `name` varchar(125) NOT NULL,
  `tag` varchar(50) NOT NULL,
  `metadata` text NOT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_user` (`user_id`)
);
