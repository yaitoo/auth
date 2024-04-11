CREATE TABLE IF NOT EXISTS `<prefix>perm` (
  `code` varchar(255) NOT NULL,
  `tag` varchar(125) NOT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`code`)
);
