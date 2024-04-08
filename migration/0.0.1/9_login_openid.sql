CREATE TABLE IF NOT EXISTS `<prefix>login_openid` (
  `openid_user` varchar(125) NOT NULL,
  `openid_app` varchar(50) NOT NULL,
  `user_id` bigint NOT NULL,
  `created_at` datetime NOT NULL,
  PRIMARY KEY (`openid_user`,`openid_app`),
  KEY `idx_user` (`user_id`)
);
