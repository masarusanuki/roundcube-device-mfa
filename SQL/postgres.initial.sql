-- device_mfa (PostgreSQL)
CREATE SEQUENCE device_mfa_devices_seq
    INCREMENT BY 1
    NO MAXVALUE
    NO MINVALUE
    CACHE 1;

CREATE TABLE device_mfa_devices (
    id integer DEFAULT nextval('device_mfa_devices_seq'::text) PRIMARY KEY,
    user_id integer NOT NULL
        REFERENCES users (user_id) ON DELETE CASCADE ON UPDATE CASCADE,
    device_id varchar(48) DEFAULT '' NOT NULL,
    kind varchar(16) DEFAULT 'webcrypto' NOT NULL,
    public_key text NOT NULL,
    credential_id varchar(1400) DEFAULT '' NOT NULL,
    sign_count bigint DEFAULT 0 NOT NULL,
    name varchar(64) DEFAULT '' NOT NULL,
    label varchar(255) DEFAULT '' NOT NULL,
    created timestamp with time zone DEFAULT now() NOT NULL,
    created_ip varchar(45) DEFAULT '' NOT NULL,
    last_used timestamp with time zone DEFAULT now() NOT NULL,
    last_ip varchar(45) DEFAULT '' NOT NULL,
    revoked smallint DEFAULT 0 NOT NULL,
    status varchar(16) DEFAULT 'active' NOT NULL,
    approve_code varchar(16) DEFAULT '' NOT NULL
);

CREATE INDEX device_mfa_devices_user_device_idx ON device_mfa_devices (user_id, device_id);
