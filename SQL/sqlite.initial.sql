-- device_mfa (SQLite)
CREATE TABLE device_mfa_devices (
  id integer NOT NULL PRIMARY KEY,
  user_id integer NOT NULL
    REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
  device_id varchar(48) NOT NULL DEFAULT '',
  kind varchar(16) NOT NULL DEFAULT 'webcrypto',
  public_key text NOT NULL,
  credential_id varchar(1400) NOT NULL DEFAULT '',
  sign_count integer NOT NULL DEFAULT 0,
  name varchar(64) NOT NULL DEFAULT '',
  label varchar(255) NOT NULL DEFAULT '',
  created datetime NOT NULL,
  created_ip varchar(45) NOT NULL DEFAULT '',
  last_used datetime NOT NULL,
  last_ip varchar(45) NOT NULL DEFAULT '',
  revoked smallint NOT NULL DEFAULT 0,
  status varchar(16) NOT NULL DEFAULT 'active',
  approve_code varchar(16) NOT NULL DEFAULT ''
);

CREATE INDEX ix_device_mfa_devices_user_device ON device_mfa_devices (user_id, device_id);
