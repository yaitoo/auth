CREATE TABLE IF NOT EXISTS `<prefix>user` (
  `id` bigint NOT NULL,
  `status` TINYINT NOT NULL DEFAULT 0,
  `first_name` varchar(255) NOT NULL,
  `last_name` varchar(255) NOT NULL,
  `passwd` varchar(255) NOT NULL,
  `salt` varchar(36) NOT NULL,
  
  `email` VARCHAR(125) NOT NULL,
  `email_verified` BIT(1) NOT NULL DEFAULT 0,
  `email_verified_at` DATETIME NULL,

  `mobile` VARCHAR(25) NOT NULL,
  `mobile_verified` BIT(1) NOT NULL DEFAULT 0,
  `mobile_verified_at` DATETIME NULL,

  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`id`)
);
