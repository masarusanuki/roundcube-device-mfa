-- 強化モード（登録済み端末による承認）用の列を追加
ALTER TABLE `device_mfa_devices`
  ADD COLUMN `status` varchar(16) NOT NULL DEFAULT 'active' AFTER `revoked`,
  ADD COLUMN `approve_code` varchar(16) NOT NULL DEFAULT '' AFTER `status`;
