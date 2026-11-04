<?php

/**
 * Minimal WebAuthn (FIDO2) server-side verification for device_mfa.
 *
 * - Registration: parses the attestation object (attestation "none"; the attestation
 *   statement itself is not verified), checks clientDataJSON, rpIdHash and flags,
 *   and converts the COSE public key (ES256 / RS256) to PEM.
 * - Authentication: checks clientDataJSON, rpIdHash, flags and the signature counter,
 *   and verifies the signature over authenticatorData || SHA-256(clientDataJSON).
 *
 * WebAuthn（FIDO2）のサーバー側の検証。外部ライブラリなしで、必要な部分だけを実装している。
 */
class device_mfa_webauthn
{
    public const ALG_ES256 = -7;
    public const ALG_RS256 = -257;

    // ------------------------------------------------------------------
    // base64url
    // ------------------------------------------------------------------

    public static function b64u_encode(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    public static function b64u_decode(string $str)
    {
        if (!preg_match('/^[A-Za-z0-9_-]*$/', $str)) {
            return false;
        }
        $str = strtr($str, '-_', '+/');
        if ($pad = strlen($str) % 4) {
            $str .= str_repeat('=', 4 - $pad);
        }

        return base64_decode($str, true);
    }

    // ------------------------------------------------------------------
    // Registration / 登録
    // ------------------------------------------------------------------

    /**
     * @return array{credential_id:string, public_key:string, alg:int, sign_count:int, uv:bool}
     * @throws RuntimeException
     */
    public static function verify_registration(string $client_data_json, string $attestation_object,
        string $challenge, string $origin, string $rp_id): array
    {
        self::check_client_data($client_data_json, 'webauthn.create', $challenge, $origin);

        $offset = 0;
        $att = self::cbor_decode($attestation_object, $offset);
        if (!is_array($att) || !isset($att['authData']) || !is_string($att['authData'])) {
            throw new RuntimeException('invalid attestation object');
        }

        $auth = self::parse_auth_data($att['authData'], $rp_id);
        if (!($auth['flags'] & 0x40)) {
            throw new RuntimeException('no attested credential data');
        }

        $data = $att['authData'];
        if (strlen($data) < 55) {
            throw new RuntimeException('authenticator data too short');
        }
        $cred_len = unpack('n', substr($data, 53, 2))[1];
        if ($cred_len < 16 || $cred_len > 1023 || strlen($data) < 55 + $cred_len + 1) {
            throw new RuntimeException('invalid credential id length');
        }
        $cred_id = substr($data, 55, $cred_len);
        $pos     = 55 + $cred_len;
        $cose    = self::cbor_decode($data, $pos);
        if (!is_array($cose)) {
            throw new RuntimeException('invalid credential public key');
        }

        [$pem, $alg] = self::cose_to_pem($cose);

        return [
            'credential_id' => self::b64u_encode($cred_id),
            'public_key'    => $pem,
            'alg'           => $alg,
            'sign_count'    => $auth['sign_count'],
            'uv'            => (bool) ($auth['flags'] & 0x04),
        ];
    }

    // ------------------------------------------------------------------
    // Authentication / 確認
    // ------------------------------------------------------------------

    /**
     * @return int new signature counter
     * @throws RuntimeException
     */
    public static function verify_assertion(string $client_data_json, string $auth_data, string $signature,
        string $challenge, string $origin, string $rp_id, string $pem, int $stored_count): int
    {
        self::check_client_data($client_data_json, 'webauthn.get', $challenge, $origin);
        $auth = self::parse_auth_data($auth_data, $rp_id);

        // Cloned authenticator detection (counters that do not increase)
        // 複製された認証器の検出（カウンターが増えていない）
        $count = $auth['sign_count'];
        if (($count !== 0 || $stored_count !== 0) && $count <= $stored_count) {
            throw new RuntimeException("signature counter did not increase ({$count} <= {$stored_count})");
        }

        $message = $auth_data . hash('sha256', $client_data_json, true);
        if (openssl_verify($message, $signature, $pem, OPENSSL_ALGO_SHA256) !== 1) {
            throw new RuntimeException('signature verification failed');
        }

        return $count;
    }

    // ------------------------------------------------------------------
    // Common checks
    // ------------------------------------------------------------------

    private static function check_client_data(string $json, string $type, string $challenge, string $origin): void
    {
        $cd = json_decode($json, true);
        if (!is_array($cd)) {
            throw new RuntimeException('invalid clientDataJSON');
        }
        if (($cd['type'] ?? '') !== $type) {
            throw new RuntimeException('unexpected type ' . ($cd['type'] ?? ''));
        }
        if (!is_string($cd['challenge'] ?? null) || !hash_equals($challenge, $cd['challenge'])) {
            throw new RuntimeException('challenge mismatch');
        }
        if (!is_string($cd['origin'] ?? null) || !hash_equals($origin, $cd['origin'])) {
            throw new RuntimeException('origin mismatch: ' . ($cd['origin'] ?? ''));
        }
    }

    private static function parse_auth_data(string $data, string $rp_id): array
    {
        if (strlen($data) < 37) {
            throw new RuntimeException('authenticator data too short');
        }
        if (!hash_equals(hash('sha256', $rp_id, true), substr($data, 0, 32))) {
            throw new RuntimeException('rpIdHash mismatch');
        }
        $flags = ord($data[32]);
        if (!($flags & 0x01)) {
            throw new RuntimeException('user presence flag not set');
        }

        return ['flags' => $flags, 'sign_count' => unpack('N', substr($data, 33, 4))[1]];
    }

    // ------------------------------------------------------------------
    // COSE key → PEM
    // ------------------------------------------------------------------

    /**
     * @return array{0:string, 1:int} [PEM, COSE algorithm]
     */
    public static function cose_to_pem(array $k): array
    {
        $kty = $k[1] ?? null;
        $alg = $k[3] ?? null;

        if ($kty === 2 && $alg === self::ALG_ES256) {
            $x = $k[-2] ?? '';
            $y = $k[-3] ?? '';
            if (($k[-1] ?? null) !== 1 || !is_string($x) || !is_string($y) || strlen($x) !== 32 || strlen($y) !== 32) {
                throw new RuntimeException('unsupported EC key (P-256 only)');
            }
            // SubjectPublicKeyInfo for id-ecPublicKey / prime256v1, uncompressed point
            $der = hex2bin('3059301306072a8648ce3d020106082a8648ce3d030107034200') . "\x04" . $x . $y;
        } elseif ($kty === 3 && $alg === self::ALG_RS256) {
            $n = $k[-1] ?? '';
            $e = $k[-2] ?? '';
            if (!is_string($n) || !is_string($e) || strlen($n) < 256) {
                throw new RuntimeException('unsupported RSA key (2048 bits or more)');
            }
            $rsa = self::der_seq(self::der_int($n) . self::der_int($e));
            $alg_id = self::der_seq(hex2bin('06092a864886f70d010101') . "\x05\x00");
            $der = self::der_seq($alg_id . "\x03" . self::der_len(strlen($rsa) + 1) . "\x00" . $rsa);
        } else {
            throw new RuntimeException("unsupported key type kty={$kty} alg={$alg}");
        }

        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
        if (!openssl_pkey_get_public($pem)) {
            throw new RuntimeException('invalid public key');
        }

        return [$pem, $alg];
    }

    private static function der_len(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = ltrim(pack('N', $len), "\x00");
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function der_int(string $bin): string
    {
        $bin = ltrim($bin, "\x00");
        if ($bin === '' || ord($bin[0]) > 0x7F) {
            $bin = "\x00" . $bin;
        }
        return "\x02" . self::der_len(strlen($bin)) . $bin;
    }

    private static function der_seq(string $content): string
    {
        return "\x30" . self::der_len(strlen($content)) . $content;
    }

    // ------------------------------------------------------------------
    // CBOR (RFC 8949) — the subset used by WebAuthn
    // ------------------------------------------------------------------

    /**
     * Decodes one CBOR item starting at $offset (advanced past the item).
     * Byte strings and text strings are both returned as PHP strings.
     */
    public static function cbor_decode(string $data, int &$offset = 0, int $depth = 0)
    {
        if ($depth > 16) {
            throw new RuntimeException('cbor: nesting too deep');
        }

        $ib = ord(self::take($data, $offset, 1));
        $major = $ib >> 5;
        $info  = $ib & 0x1F;

        if ($major === 7) {
            switch ($info) {
                case 20: return false;
                case 21: return true;
                case 22:
                case 23: return null;
                case 26: return unpack('G', self::take($data, $offset, 4))[1];
                case 27: return unpack('E', self::take($data, $offset, 8))[1];
            }
            throw new RuntimeException('cbor: unsupported simple value ' . $info);
        }

        $len = self::cbor_length($data, $offset, $info);

        switch ($major) {
            case 0:
                return $len;
            case 1:
                return -1 - $len;
            case 2:
            case 3:
                return self::take($data, $offset, $len);
            case 4:
                $list = [];
                for ($i = 0; $i < $len; $i++) {
                    $list[] = self::cbor_decode($data, $offset, $depth + 1);
                }
                return $list;
            case 5:
                $map = [];
                for ($i = 0; $i < $len; $i++) {
                    $key = self::cbor_decode($data, $offset, $depth + 1);
                    if (!is_int($key) && !is_string($key)) {
                        throw new RuntimeException('cbor: unsupported map key');
                    }
                    $map[$key] = self::cbor_decode($data, $offset, $depth + 1);
                }
                return $map;
            case 6: // tag: ignore the tag number, return the tagged item
                return self::cbor_decode($data, $offset, $depth + 1);
        }

        throw new RuntimeException('cbor: unsupported major type');
    }

    private static function cbor_length(string $data, int &$offset, int $info): int
    {
        if ($info < 24) {
            return $info;
        }
        switch ($info) {
            case 24: return ord(self::take($data, $offset, 1));
            case 25: return unpack('n', self::take($data, $offset, 2))[1];
            case 26: return unpack('N', self::take($data, $offset, 4))[1];
            case 27:
                $v = unpack('J', self::take($data, $offset, 8))[1];
                if ($v < 0 || $v > strlen($data)) {
                    throw new RuntimeException('cbor: length out of range');
                }
                return $v;
        }
        throw new RuntimeException('cbor: indefinite or reserved length not supported');
    }

    private static function take(string $data, int &$offset, int $len): string
    {
        if ($len < 0 || $offset + $len > strlen($data)) {
            throw new RuntimeException('cbor: truncated data');
        }
        $out = substr($data, $offset, $len);
        $offset += $len;
        return $out;
    }
}
