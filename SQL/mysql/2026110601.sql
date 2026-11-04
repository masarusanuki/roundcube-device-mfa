-- Security keys / Windows Hello (WebAuthn) / セキュリティキー・Windows Hello 用の列
ALTER TABLE `device_mfa_devices`
  MODIFY `device_id` varchar(48) NOT NULL DEFAULT '',
  ADD COLUMN `kind` varchar(16) NOT NULL DEFAULT 'webcrypto' AFTER `device_id`,
  ADD COLUMN `credential_id` varchar(1400) NOT NULL DEFAULT '' AFTER `public_key`,
  ADD COLUMN `sign_count` bigint UNSIGNED NOT NULL DEFAULT 0 AFTER `credential_id`,
  ADD COLUMN `name` varchar(64) NOT NULL DEFAULT '' AFTER `sign_count`;
