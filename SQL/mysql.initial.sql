CREATE TABLE IF NOT EXISTS `device_mfa_devices` (
  `id`         int(10) UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`    int(10) UNSIGNED NOT NULL,
  `device_id`  char(48) NOT NULL,
  `public_key` text NOT NULL,
  `label`      varchar(255) NOT NULL DEFAULT '',
  `created`    datetime NOT NULL,
  `created_ip` varchar(45) NOT NULL DEFAULT '',
  `last_used`  datetime NOT NULL,
  `last_ip`    varchar(45) NOT NULL DEFAULT '',
  `revoked`    tinyint(1) NOT NULL DEFAULT 0,
  `status`     varchar(16) NOT NULL DEFAULT 'active',
  `approve_code` varchar(16) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  KEY `user_device` (`user_id`, `device_id`),
  CONSTRAINT `device_mfa_user_id_fk` FOREIGN KEY (`user_id`)
    REFERENCES `users` (`user_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ROW_FORMAT=DYNAMIC ENGINE=INNODB CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
