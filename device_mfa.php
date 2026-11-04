<?php

/**
 * device_mfa - device-bound second check for Roundcube (no mobile phone needed)
 *
 * After login, the browser proves that it is a device registered for this user:
 *  - "browser key": a non-extractable WebCrypto ECDSA P-256 key in IndexedDB + an HttpOnly cookie
 *  - "security key / Windows Hello": WebAuthn (FIDO2), optional, chosen by the user
 *
 * The check is switched on/off by the client IP (device_mfa_register_networks / device_mfa_outside_mode).
 * Users choose the strength in Settings:
 *  - standard : inside the allowed networks a new device is registered by pressing "Yes"
 *  - strict   : a new device must be approved from an already registered device
 *  - webauthn : every login needs a security key or Windows Hello (inside and outside)
 *
 * ログイン後に、登録済みの端末であることを確認する Roundcube プラグイン（携帯電話は不要）。
 */

require_once __DIR__ . '/lib/device_mfa_webauthn.php';

class device_mfa extends rcube_plugin
{
    public $task = '.*';

    private const SESS_OK        = 'device_mfa_ok';
    private const SESS_CHALLENGE = 'device_mfa_challenge';
    private const SESS_PENDING   = 'device_mfa_pending';
    private const SESS_WA_REG    = 'device_mfa_wa_reg';

    // before the check (確認前)
    private const ACT_VERIFY     = 'plugin.device_mfa_verify';
    private const ACT_REGISTER   = 'plugin.device_mfa_register';
    private const ACT_STATUS     = 'plugin.device_mfa_status';
    private const ACT_WA_VERIFY  = 'plugin.device_mfa_wa_verify';
    // after the check (確認済みのセッションのみ)
    private const ACT_WA_PAGE    = 'plugin.device_mfa_webauthn';
    private const ACT_WA_ADD     = 'plugin.device_mfa_wa_add';

    private const KIND_BROWSER   = 'webcrypto';
    private const KIND_WEBAUTHN  = 'webauthn';
    private const CHALLENGE_TTL  = 300; // seconds
    private const PENDING_TTL    = 900; // seconds, approval wait (承認待ちの有効時間)

    /** @var rcmail */
    private $rc;

    public function init()
    {
        $this->rc = rcmail::get_instance();
        $this->load_config();
        $this->add_texts('localization/');
        $this->add_hook('startup', [$this, 'startup']);
        $this->add_hook('login_after', [$this, 'login_after']);
        $this->add_hook('preferences_sections_list', [$this, 'prefs_sections']);
        $this->add_hook('preferences_list', [$this, 'prefs_list']);
        $this->add_hook('preferences_save', [$this, 'prefs_save']);
    }

    /** Right after login: always start unverified / ログイン直後は必ず未確認から始める */
    public function login_after($args)
    {
        unset($_SESSION[self::SESS_OK], $_SESSION[self::SESS_CHALLENGE], $_SESSION[self::SESS_PENDING], $_SESSION[self::SESS_WA_REG]);
        return $args;
    }

    /**
     * Entry point of every request. Intercepts it until the device check has passed.
     * すべてのリクエストの入口。端末確認が済んでいなければ横取りする。
     */
    public function startup($args)
    {
        if (empty($_SESSION['user_id']) || $args['task'] === 'login' || $args['task'] === 'logout') {
            return $args;
        }

        // Verified session / 確認済みのセッション
        if (!empty($_SESSION[self::SESS_OK]) && hash_equals($this->session_binding(), (string) $_SESSION[self::SESS_OK])) {
            if (in_array($args['action'], [self::ACT_WA_PAGE, self::ACT_WA_ADD], true)
                && !in_array('webauthn', $this->allowed_modes(), true)
            ) {
                return $args; // not offered on this server / このサーバーでは使わない
            }
            if ($args['action'] === self::ACT_WA_PAGE) {
                $this->no_cache_headers();
                $this->render_webauthn_page();
                exit;
            }
            if ($args['action'] === self::ACT_WA_ADD) {
                $this->no_cache_headers();
                $this->api_begin();
                $this->api_webauthn_add();
                exit;
            }
            return $args;
        }

        // Invalid auth cookie (e.g. stolen session id): let Roundcube kill the session
        if (!$this->rc->session->check_auth()) {
            return $args;
        }

        $user_id  = (int) $_SESSION['user_id'];
        $webauthn = $this->webauthn_required($user_id);
        $ip       = rcube_utils::remote_addr();

        // Outside the allowed networks with 'idp': rely on the identity provider's MFA.
        // A user who chose security key / Windows Hello is always checked.
        // 許可ネットワークの外で 'idp' のときだけ、ID プロバイダーの多要素認証に任せる。
        // セキュリティキー・Windows Hello を選んだ利用者は、どこからでも確認する。
        if (!$webauthn && !$this->in_register_networks($ip)
            && $this->rc->config->get('device_mfa_outside_mode', 'deny') === 'idp'
        ) {
            $this->mark_ok();
            $this->log("outside network: device check skipped (IdP MFA) user_id={$user_id} ip={$ip}");
            return $args;
        }

        $this->no_cache_headers();

        $api = [self::ACT_VERIFY, self::ACT_REGISTER, self::ACT_STATUS, self::ACT_WA_VERIFY];
        if (in_array($args['action'], $api, true)) {
            $this->api_begin();
            if ($webauthn !== ($args['action'] === self::ACT_WA_VERIFY)) {
                $this->json_out(403, ['status' => 'retry']); // wrong method for this user's mode
            }
            switch ($args['action']) {
                case self::ACT_STATUS:    $this->api_status(); break;
                case self::ACT_WA_VERIFY: $this->api_webauthn_verify(); break;
                case self::ACT_VERIFY:    $this->api_verify(); break;
                case self::ACT_REGISTER:  $this->api_register(); break;
            }
            exit;
        }

        // Roundcube AJAX / iframe requests are refused (the top page becomes the check page)
        if (!empty($_REQUEST['_remote']) || !empty($_REQUEST['_framed']) || rcube_utils::request_header('X-Roundcube-Request')) {
            http_response_code(401);
            header('Content-Type: text/plain; charset=UTF-8');
            echo 'device verification required';
            exit;
        }

        $this->render_check_page($webauthn);
        exit;
    }

    // ------------------------------------------------------------------
    // API: browser key (WebCrypto) / ブラウザの鍵
    // ------------------------------------------------------------------

    private function api_begin()
    {
        header('Content-Type: application/json; charset=UTF-8');
        if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !$this->rc->check_request()) {
            $this->json_out(403, ['status' => 'error', 'message' => $this->gettext('err_request')]);
        }
    }

    /** Request body (JSON). Protected so that tests can provide it. */
    protected function body()
    {
        $body = json_decode(file_get_contents('php://input'), true);
        return is_array($body) ? $body : [];
    }

    /** One-time challenge of the given purpose / 指定した用途の使い捨てチャレンジを取り出す */
    private function take_challenge($purpose)
    {
        $chal = $_SESSION[self::SESS_CHALLENGE] ?? null;
        unset($_SESSION[self::SESS_CHALLENGE]);

        if (!is_array($chal) || ($chal['purpose'] ?? '') !== $purpose || time() - (int) $chal['ts'] > self::CHALLENGE_TTL) {
            $this->json_out(400, ['status' => 'retry', 'message' => $this->gettext('err_expired')]);
        }

        return $chal['value'];
    }

    private function api_verify()
    {
        $body    = $this->body();
        $chal    = $this->take_challenge('browser');
        $sig     = base64_decode((string) ($body['sig'] ?? ''), true);
        $user_id = (int) $_SESSION['user_id'];
        $ip      = rcube_utils::remote_addr();

        // Device id from the cookie, or — if the cookie was lost — from IndexedDB (the key proves possession)
        // 端末IDは Cookie から。Cookie が消えていれば IndexedDB に保存した値を使う（本人確認は鍵の署名で行う）
        $cookie_id = $this->get_device_cookie();
        $stored_id = $this->valid_device_id($body['device_id'] ?? '');
        $device_id = $cookie_id ?: $stored_id;

        $row = $device_id ? $this->find_browser_device($user_id, $device_id) : null;
        if (!$row) {
            $why = $device_id ? 'no active device for this id' : 'no device cookie and no stored id';
            $this->log("verify UNREGISTERED ({$why}) user_id={$user_id} ip={$ip}");
            $this->json_out(200, ['status' => 'unregistered']);
        }

        if ($sig === false || !$this->verify_browser_sig($chal, $sig, $row['public_key'])) {
            $this->log("verify FAILED user_id={$user_id} device={$row['id']} ip={$ip}");
            $this->json_out(200, ['status' => 'unregistered']);
        }

        if (!$cookie_id) {
            $this->log("cookie RESTORED from IndexedDB user_id={$user_id} device={$row['id']} ip={$ip}");
        }

        $this->maybe_enable_strict($body, $user_id);

        if ($row['status'] === 'pending') {
            $this->set_device_cookie($device_id);
            $_SESSION[self::SESS_PENDING] = (int) $row['id'];
            $this->json_out(200, ['status' => 'pending', 'code' => $row['approve_code'], 'device_id' => $device_id]);
        }

        $db = $this->rc->get_dbh();
        $db->query('UPDATE ' . $this->table() . ' SET last_used = ' . $db->now() . ', last_ip = ? WHERE id = ?', $ip, $row['id']);

        $this->set_device_cookie($device_id); // (re)set and extend / 再設定と期限の延長
        $this->mark_ok();
        $this->log("verify OK user_id={$user_id} device={$row['id']} ip={$ip}");
        $this->json_out(200, ['status' => 'ok', 'redirect' => $this->rc->url(['_task' => 'mail']), 'device_id' => $device_id]);
    }

    private function api_register()
    {
        $body    = $this->body();
        $chal    = $this->take_challenge('browser');
        $sig     = base64_decode((string) ($body['sig'] ?? ''), true);
        $user_id = (int) $_SESSION['user_id'];
        $ip      = rcube_utils::remote_addr();

        // Why the browser registers again (diagnostics) / 登録し直しの理由（原因調査用）
        $reason = preg_replace('/[^a-z_]/', '', (string) ($body['reason'] ?? ''));
        $cookie = $this->get_device_cookie();
        $why    = "reason={$reason} cookie=" . ($cookie ? 'yes' : 'no');

        if (!$this->in_register_networks($ip)) {
            $this->log("register DENIED (network) user_id={$user_id} ip={$ip} {$why}");
            $this->json_out(200, ['status' => 'denied', 'message' => $this->gettext('err_outside')]);
        }

        $pem = $this->spki_to_pem($body['pub'] ?? '');
        if (!$pem || $sig === false || !$this->verify_browser_sig($chal, $sig, $pem)) {
            $this->json_out(400, ['status' => 'error', 'message' => $this->gettext('err_key')]);
        }

        $device_id = $cookie ?: bin2hex(random_bytes(24));
        $label     = mb_substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 250);
        $db        = $this->rc->get_dbh();

        $this->maybe_enable_strict($body, $user_id);

        // Decide on approval before revoking the old key on this device; this device is not an approver.
        // 承認が必要かは、この端末の旧鍵を失効させる前に判定する（この端末自身は承認者に数えない）
        $pending = $this->get_mode() !== 'standard' && $this->count_active($user_id, $device_id) > 0;
        $code    = $pending ? $this->new_approve_code() : '';

        $db->query('UPDATE ' . $this->table() . ' SET revoked = 1 WHERE user_id = ? AND device_id = ? AND kind = ?',
            $user_id, $device_id, self::KIND_BROWSER);

        $db->query('INSERT INTO ' . $this->table()
            . ' (user_id, device_id, kind, public_key, credential_id, sign_count, name, label,'
            . ' created, created_ip, last_used, last_ip, revoked, status, approve_code)'
            . ' VALUES (?, ?, ?, ?, ?, 0, ?, ?, ' . $db->now() . ', ?, ' . $db->now() . ', ?, 0, ?, ?)',
            $user_id, $device_id, self::KIND_BROWSER, $pem, '', '', $label, $ip, $ip,
            $pending ? 'pending' : 'active', $code);

        $this->set_device_cookie($device_id);
        $short = substr($device_id, 0, 8);

        if ($pending) {
            $_SESSION[self::SESS_PENDING] = (int) $db->insert_id('device_mfa_devices');
            $this->log("register PENDING user_id={$user_id} device_id={$short}… code={$code} ip={$ip} {$why}");
            $this->json_out(200, ['status' => 'pending', 'code' => $code, 'device_id' => $device_id]);
        }

        $this->mark_ok();
        $this->log("register OK user_id={$user_id} device_id={$short}… ip={$ip} {$why}");
        $this->json_out(200, ['status' => 'ok', 'redirect' => $this->rc->url(['_task' => 'mail']), 'device_id' => $device_id]);
    }

    /** Polled by a device waiting for approval / 承認待ちの端末からの問い合わせ */
    private function api_status()
    {
        $id        = (int) ($_SESSION[self::SESS_PENDING] ?? 0);
        $user_id   = (int) $_SESSION['user_id'];
        $device_id = $this->get_device_cookie();
        $db        = $this->rc->get_dbh();

        // The expiry is evaluated by the database (its clock may be UTC, e.g. SQLite)
        // 期限の判定はデータベース側で行う（SQLite などは UTC で保存するため）
        $res = $db->query('SELECT id, device_id, revoked, status, approve_code, '
            . 'CASE WHEN created > ' . $db->now(-self::PENDING_TTL) . ' THEN 1 ELSE 0 END AS fresh'
            . ' FROM ' . $this->table() . ' WHERE id = ? AND user_id = ?', $id, $user_id);
        $row = $id ? $db->fetch_assoc($res) : null;

        if (!$row || $row['device_id'] !== $device_id || (int) $row['revoked']) {
            unset($_SESSION[self::SESS_PENDING]);
            $this->json_out(200, ['status' => 'denied', 'message' => $this->gettext('err_not_approved')]);
        }

        if ($row['status'] === 'active') {
            unset($_SESSION[self::SESS_PENDING]);
            $this->mark_ok();
            $this->log("approved device in use user_id={$user_id} device={$row['id']}");
            $this->json_out(200, ['status' => 'ok', 'redirect' => $this->rc->url(['_task' => 'mail'])]);
        }

        if (!(int) $row['fresh']) {
            $db->query('UPDATE ' . $this->table() . ' SET revoked = 1 WHERE id = ?', $row['id']);
            unset($_SESSION[self::SESS_PENDING]);
            $this->json_out(200, ['status' => 'denied', 'message' => $this->gettext('err_pending_expired')]);
        }

        $this->json_out(200, ['status' => 'pending', 'code' => $row['approve_code']]);
    }

    // ------------------------------------------------------------------
    // API: WebAuthn (security key / Windows Hello)
    // ------------------------------------------------------------------

    private function api_webauthn_verify()
    {
        $body    = $this->body();
        $chal    = $this->take_challenge('webauthn');
        $user_id = (int) $_SESSION['user_id'];
        $ip      = rcube_utils::remote_addr();
        $W       = 'device_mfa_webauthn';

        $cred = (string) ($body['id'] ?? '');
        $row  = $cred !== '' ? $this->find_webauthn($user_id, $cred) : null;
        $cdj  = $W::b64u_decode((string) ($body['clientDataJSON'] ?? ''));
        $ad   = $W::b64u_decode((string) ($body['authenticatorData'] ?? ''));
        $sig  = $W::b64u_decode((string) ($body['signature'] ?? ''));

        if (!$row || $cdj === false || $ad === false || $sig === false) {
            $this->log("webauthn verify UNKNOWN credential user_id={$user_id} ip={$ip}");
            $this->json_out(200, ['status' => 'error', 'message' => $this->gettext('err_webauthn')]);
        }

        try {
            $count = $W::verify_assertion($cdj, $ad, $sig, $chal, $this->webauthn_origin(), $this->webauthn_rp_id(),
                $row['public_key'], (int) $row['sign_count']);
        } catch (RuntimeException $e) {
            $this->log("webauthn verify FAILED user_id={$user_id} device={$row['id']} ip={$ip}: " . $e->getMessage());
            $this->json_out(200, ['status' => 'error', 'message' => $this->gettext('err_webauthn')]);
        }

        $db = $this->rc->get_dbh();
        $db->query('UPDATE ' . $this->table() . ' SET sign_count = ?, last_used = ' . $db->now() . ', last_ip = ? WHERE id = ?',
            $count, $ip, $row['id']);

        $this->mark_ok();
        $this->log("webauthn verify OK user_id={$user_id} device={$row['id']} ip={$ip}");
        $this->json_out(200, ['status' => 'ok', 'redirect' => $this->rc->url(['_task' => 'mail'])]);
    }

    /** Register a security key / Windows Hello (verified sessions only) / キーの登録（確認済みのみ） */
    private function api_webauthn_add()
    {
        $body    = $this->body();
        $user_id = (int) $_SESSION['user_id'];
        $ip      = rcube_utils::remote_addr();
        $W       = 'device_mfa_webauthn';

        $chal = $_SESSION[self::SESS_WA_REG] ?? null;
        unset($_SESSION[self::SESS_WA_REG]);
        if (!is_array($chal) || time() - (int) $chal['ts'] > self::CHALLENGE_TTL) {
            $this->json_out(400, ['status' => 'retry', 'message' => $this->gettext('err_expired')]);
        }

        $cdj = $W::b64u_decode((string) ($body['clientDataJSON'] ?? ''));
        $att = $W::b64u_decode((string) ($body['attestationObject'] ?? ''));
        if ($cdj === false || $att === false) {
            $this->json_out(400, ['status' => 'error', 'message' => $this->gettext('err_webauthn_add')]);
        }

        try {
            $reg = $W::verify_registration($cdj, $att, $chal['value'], $this->webauthn_origin(), $this->webauthn_rp_id());
        } catch (RuntimeException $e) {
            $this->log("webauthn add FAILED user_id={$user_id} ip={$ip}: " . $e->getMessage());
            $this->json_out(200, ['status' => 'error', 'message' => $this->gettext('err_webauthn_add')]);
        }

        if ($this->find_webauthn($user_id, $reg['credential_id'])) {
            $this->json_out(200, ['status' => 'error', 'message' => $this->gettext('err_webauthn_dup')]);
        }

        $name  = mb_substr(trim((string) ($body['name'] ?? '')), 0, 60) ?: $this->gettext('kind_webauthn');
        $label = mb_substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 250);
        $db    = $this->rc->get_dbh();

        $db->query('INSERT INTO ' . $this->table()
            . ' (user_id, device_id, kind, public_key, credential_id, sign_count, name, label,'
            . ' created, created_ip, last_used, last_ip, revoked, status, approve_code)'
            . ' VALUES (?, ?, ?, ?, ?, ?, ?, ?, ' . $db->now() . ', ?, ' . $db->now() . ', ?, 0, ?, ?)',
            $user_id, '', self::KIND_WEBAUTHN, $reg['public_key'], $reg['credential_id'], $reg['sign_count'],
            $name, $label, $ip, $ip, 'active', '');

        $this->log("webauthn add OK user_id={$user_id} alg={$reg['alg']} ip={$ip}");
        $this->json_out(200, ['status' => 'ok']);
    }

    // ------------------------------------------------------------------
    // Data access / データ
    // ------------------------------------------------------------------

    /** SQL condition for usable browser keys (not expired) / 期限内のブラウザの鍵 */
    private function browser_alive_sql()
    {
        $days = (int) $this->rc->config->get('device_mfa_expire_days', 180);
        return $days > 0 ? ' AND last_used > ' . $this->rc->get_dbh()->now(-86400 * $days) : '';
    }

    private function find_browser_device($user_id, $device_id)
    {
        $db  = $this->rc->get_dbh();
        $res = $db->query('SELECT * FROM ' . $this->table()
            . ' WHERE user_id = ? AND device_id = ? AND kind = ? AND revoked = 0'
            . " AND ((status = 'active'" . $this->browser_alive_sql() . ')'
            . " OR (status = 'pending' AND created > " . $db->now(-self::PENDING_TTL) . '))'
            . ' ORDER BY id DESC', $user_id, $device_id, self::KIND_BROWSER);

        return $db->fetch_assoc($res) ?: null;
    }

    private function find_webauthn($user_id, $credential_id)
    {
        $db  = $this->rc->get_dbh();
        $res = $db->query('SELECT * FROM ' . $this->table()
            . " WHERE user_id = ? AND kind = ? AND credential_id = ? AND revoked = 0 AND status = 'active'",
            $user_id, self::KIND_WEBAUTHN, (string) $credential_id);

        return $db->fetch_assoc($res) ?: null;
    }

    private function list_webauthn($user_id)
    {
        $db   = $this->rc->get_dbh();
        $res  = $db->query('SELECT * FROM ' . $this->table()
            . " WHERE user_id = ? AND kind = ? AND revoked = 0 AND status = 'active' ORDER BY id",
            $user_id, self::KIND_WEBAUTHN);
        $rows = [];
        while ($r = $db->fetch_assoc($res)) {
            $rows[] = $r;
        }
        return $rows;
    }

    /** Active devices that can approve (all kinds, except the given browser device) */
    private function count_active($user_id, $exclude_device_id = '')
    {
        $db  = $this->rc->get_dbh();
        $res = $db->query('SELECT COUNT(*) AS n FROM ' . $this->table()
            . " WHERE user_id = ? AND revoked = 0 AND status = 'active'"
            . ' AND ((kind = ? AND device_id <> ?' . $this->browser_alive_sql() . ') OR kind = ?)',
            $user_id, self::KIND_BROWSER, (string) $exclude_device_id, self::KIND_WEBAUTHN);
        $row = $db->fetch_assoc($res);

        return (int) ($row['n'] ?? 0);
    }

    /** The user chose WebAuthn and has at least one key / WebAuthn を選び、キーを1つ以上登録している */
    private function webauthn_required($user_id)
    {
        return $this->get_mode() === 'webauthn' && count($this->list_webauthn($user_id)) > 0;
    }

    /** Strengths offered to users (device_mfa_modes); 'standard' is always available */
    private function allowed_modes()
    {
        $modes = array_intersect(['standard', 'strict', 'webauthn'],
            (array) $this->rc->config->get('device_mfa_modes', ['standard', 'strict', 'webauthn']));
        return array_values(array_unique(array_merge(['standard'], $modes)));
    }

    private function get_mode()
    {
        $mode = $this->rc->user ? ($this->rc->user->get_prefs()['device_mfa_mode'] ?? null) : null;
        return in_array($mode, $this->allowed_modes(), true) ? $mode : 'standard';
    }

    /**
     * "Use multi-factor with my own device" on the check page: only standard → strict (never weaker),
     * saved only after a successful check. / 確認画面からは強くする方向だけ受け付ける。
     */
    private function maybe_enable_strict($body, $user_id)
    {
        if (!empty($body['strict']) && $this->get_mode() === 'standard' && in_array('strict', $this->allowed_modes(), true)) {
            $this->rc->user->save_prefs(['device_mfa_mode' => 'strict']);
            $this->log("mode=strict (from check page) user_id={$user_id}");
        }
    }

    private function new_approve_code()
    {
        $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $code  = '';
        for ($i = 0; $i < 8; $i++) {
            $code .= $chars[random_int(0, strlen($chars) - 1)];
        }
        return substr($code, 0, 4) . '-' . substr($code, 4);
    }

    private function in_register_networks($ip)
    {
        $addr = \IPLib\Factory::parseAddressString($ip);
        if (!$addr) {
            return false;
        }
        foreach ((array) $this->rc->config->get('device_mfa_register_networks', []) as $net) {
            $range = \IPLib\Factory::parseRangeString($net);
            if ($range && $range->contains($addr)) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Settings / 設定画面（設定 > 端末確認）
    // ------------------------------------------------------------------

    public function prefs_sections($args)
    {
        $args['list']['device_mfa'] = ['id' => 'device_mfa', 'section' => $this->gettext('section')];
        return $args;
    }

    public function prefs_list($args)
    {
        if ($args['section'] !== 'device_mfa') {
            return $args;
        }

        $h       = fn ($s) => htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
        $t       = fn ($k) => $h($this->gettext($k));
        $user_id = (int) $this->rc->user->ID;
        $mode    = $this->get_mode();
        $db      = $this->rc->get_dbh();
        $mine    = $this->get_device_cookie();
        $keys    = $this->list_webauthn($user_id);

        // --- strength / 認証の強さ
        $radios = '';
        foreach ($this->allowed_modes() as $val) {
            $disabled = $val === 'webauthn' && !$keys ? ' disabled' : '';
            $checked  = $mode === $val ? ' checked' : '';
            $radios  .= '<div style="margin:0 0 12px"><label style="font-weight:bold">'
                . '<input type="radio" name="_dmfa_mode" value="' . $val . '"' . $checked . $disabled . '> '
                . $t("mode_{$val}_title") . '</label>'
                . '<div style="margin:2px 0 0 24px;opacity:.8">' . $t("mode_{$val}_desc")
                . ($disabled ? ' <strong>' . $t('mode_webauthn_need_key') . '</strong>' : '') . '</div></div>';
        }
        $radios .= '<div style="opacity:.8">' . $t('mode_note') . '</div>';

        // --- WebAuthn keys / セキュリティキー・Windows Hello
        $wa_url  = $h($this->rc->url(['_task' => 'settings', '_action' => self::ACT_WA_PAGE]));
        $wa_html = '<p>' . $t('wa_desc') . '</p><p><a class="button" href="' . $wa_url . '" target="_top">'
            . $t('wa_add_button') . '</a></p>';

        // --- pending approvals / 承認待ち
        $res = $db->query('SELECT * FROM ' . $this->table()
            . " WHERE user_id = ? AND revoked = 0 AND status = 'pending' AND created > " . $db->now(-self::PENDING_TTL)
            . ' ORDER BY id DESC', $user_id);
        $pending = '';
        while ($r = $db->fetch_assoc($res)) {
            $pending .= '<tr><td><label><input type="checkbox" name="_dmfa_approve[]" value="' . (int) $r['id'] . '"> '
                . $t('approve') . '</label></td>'
                . '<td style="font-family:monospace;font-size:1.3em;font-weight:bold">' . $h($r['approve_code']) . '</td>'
                . '<td>' . $h($this->browser_name($r['label'])) . '</td>'
                . '<td>' . $h($r['created']) . '</td><td>' . $h($r['created_ip']) . '</td></tr>';
        }

        // --- registered devices and keys / 登録済みの端末とキー
        $res = $db->query('SELECT * FROM ' . $this->table()
            . " WHERE user_id = ? AND revoked = 0 AND status = 'active'"
            . ' AND (kind = ? OR (kind = ?' . $this->browser_alive_sql() . '))'
            . ' ORDER BY last_used DESC', $user_id, self::KIND_WEBAUTHN, self::KIND_BROWSER);
        $devices = '';
        while ($r = $db->fetch_assoc($res)) {
            $is_wa = $r['kind'] === self::KIND_WEBAUTHN;
            $what  = $is_wa ? $t('kind_webauthn') . ': ' . $h($r['name']) : $t('kind_browser') . ': ' . $h($this->browser_name($r['label']));
            $this_one = !$is_wa && $mine && $r['device_id'] === $mine ? ' <strong>' . $t('this_device') . '</strong>' : '';
            $devices .= '<tr><td><label><input type="checkbox" name="_dmfa_revoke[]" value="' . (int) $r['id'] . '"> '
                . $t('delete') . '</label></td>'
                . '<td>' . $what . $this_one . '</td>'
                . '<td>' . $h($r['created']) . '</td><td>' . $h($r['last_used']) . '</td><td>' . $h($r['last_ip']) . '</td></tr>';
        }

        $table = fn ($head, $rows) => '<table class="records-table" style="width:100%"><thead><tr>'
            . implode('', array_map(fn ($c) => '<th>' . $t($c) . '</th>', $head)) . '</tr></thead><tbody>' . $rows . '</tbody></table>';

        $args['blocks']['mode'] = ['name' => $this->gettext('strength'), 'options' => [['content' => $radios]]];
        if (in_array('webauthn', $this->allowed_modes(), true)) {
            $args['blocks']['webauthn'] = ['name' => $this->gettext('wa_title'), 'options' => [['content' => $wa_html]]];
        }
        $args['blocks']['pending'] = [
            'name'    => $this->gettext('pending_title'),
            'options' => [['content' => $pending
                ? '<p>' . $t('pending_desc') . '</p>' . $table(['col_none', 'col_code', 'col_browser', 'col_requested', 'col_ip'], $pending)
                : '<p>' . $t('pending_none') . '</p>']],
        ];
        $args['blocks']['devices'] = [
            'name'    => $this->gettext('devices_title'),
            'options' => [['content' => $devices
                ? '<p>' . $t('devices_desc') . '</p>' . $table(['col_none', 'col_device', 'col_registered', 'col_lastused', 'col_lastip'], $devices)
                : '<p>' . $t('devices_none') . '</p>']],
        ];

        return $args;
    }

    public function prefs_save($args)
    {
        if ($args['section'] !== 'device_mfa') {
            return $args;
        }

        $user_id = (int) $this->rc->user->ID;
        $db      = $this->rc->get_dbh();

        foreach ((array) ($_POST['_dmfa_approve'] ?? []) as $id) {
            $db->query('UPDATE ' . $this->table() . " SET status = 'active', approve_code = ''"
                . " WHERE id = ? AND user_id = ? AND revoked = 0 AND status = 'pending' AND created > "
                . $db->now(-self::PENDING_TTL), (int) $id, $user_id);
            if ($db->affected_rows()) {
                $this->log("approve OK user_id={$user_id} device={$id} by ip=" . rcube_utils::remote_addr());
            }
        }

        foreach ((array) ($_POST['_dmfa_revoke'] ?? []) as $id) {
            $db->query('UPDATE ' . $this->table() . ' SET revoked = 1 WHERE id = ? AND user_id = ?', (int) $id, $user_id);
            if ($db->affected_rows()) {
                $this->log("revoke by user user_id={$user_id} device={$id}");
            }
        }

        // 'webauthn' needs at least one key (checked after deletions above) / キーが残っている場合だけ
        $mode = rcube_utils::get_input_string('_dmfa_mode', rcube_utils::INPUT_POST);
        if ($mode === 'webauthn' && !$this->list_webauthn($user_id)) {
            $mode = 'strict';
        }
        $args['prefs']['device_mfa_mode'] = in_array($mode, $this->allowed_modes(), true) ? $mode : 'standard';
        $this->log("mode={$args['prefs']['device_mfa_mode']} user_id={$user_id}");

        return $args;
    }

    /** "Firefox / macOS" from a User-Agent */
    private function browser_name($ua)
    {
        $b = preg_match('/Edg\//', $ua) ? 'Edge' : (preg_match('/Firefox\//', $ua) ? 'Firefox'
            : (preg_match('/Chrome\//', $ua) ? 'Chrome' : (preg_match('/Safari\//', $ua) ? 'Safari' : 'Browser')));
        $o = preg_match('/Windows/', $ua) ? 'Windows' : (preg_match('/iPhone|iPad/', $ua) ? 'iOS'
            : (preg_match('/Mac OS X|Macintosh/', $ua) ? 'macOS' : (preg_match('/Android/', $ua) ? 'Android'
            : (preg_match('/Linux/', $ua) ? 'Linux' : '?'))));
        return "{$b} / {$o}";
    }

    // ------------------------------------------------------------------
    // Crypto: browser key / ブラウザの鍵の検証
    // ------------------------------------------------------------------

    /** WebCrypto ECDSA signature (r||s, 64 bytes) over the challenge string */
    private function verify_browser_sig($message, $raw_sig, $pem)
    {
        if (strlen($raw_sig) !== 64) {
            return false;
        }
        $int = function ($bin) {
            $bin = ltrim($bin, "\x00");
            if ($bin === '' || ord($bin[0]) > 0x7F) {
                $bin = "\x00" . $bin;
            }
            return "\x02" . chr(strlen($bin)) . $bin;
        };
        $seq = $int(substr($raw_sig, 0, 32)) . $int(substr($raw_sig, 32, 32));
        $der = "\x30" . chr(strlen($seq)) . $seq;

        return openssl_verify($message, $der, $pem, OPENSSL_ALGO_SHA256) === 1;
    }

    private function spki_to_pem($b64)
    {
        $der = base64_decode((string) $b64, true);
        if ($der === false || strlen($der) < 80 || strlen($der) > 200) {
            return null;
        }
        $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
        $key = openssl_pkey_get_public($pem);
        if (!$key) {
            return null;
        }
        $d = openssl_pkey_get_details($key);
        if (($d['type'] ?? null) !== OPENSSL_KEYTYPE_EC || ($d['ec']['curve_name'] ?? '') !== 'prime256v1') {
            return null;
        }
        return $pem;
    }

    // ------------------------------------------------------------------
    // Session / Cookie / WebAuthn parameters
    // ------------------------------------------------------------------

    /** The "verified" flag is bound to this session / 確認済みフラグをこのセッションに結び付ける */
    private function session_binding()
    {
        return hash_hmac('sha256', session_id() . '|' . $_SESSION['user_id'], $this->rc->config->get('des_key'));
    }

    private function mark_ok()
    {
        $_SESSION[self::SESS_OK] = $this->session_binding();
    }

    private function cookie_name()
    {
        return $this->rc->config->get('device_mfa_cookie_name', 'rc_device_mfa');
    }

    private function valid_device_id($v)
    {
        return is_string($v) && preg_match('/^[0-9a-f]{48}$/', $v) ? $v : null;
    }

    private function get_device_cookie()
    {
        return $this->valid_device_id($_COOKIE[$this->cookie_name()] ?? '');
    }

    private function set_device_cookie($device_id)
    {
        setcookie($this->cookie_name(), $device_id, [
            'expires'  => time() + 86400 * 400, // browser maximum / ブラウザの上限
            'path'     => '/',
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    /** IndexedDB key name: HMAC, so that no e-mail address is stored in clear on the device */
    private function key_ref()
    {
        return substr(hash_hmac('sha256', 'keyref|' . $_SESSION['user_id'] . '|' . $this->rc->get_user_name(),
            $this->rc->config->get('des_key')), 0, 32);
    }

    private function webauthn_rp_id()
    {
        if ($id = $this->rc->config->get('device_mfa_webauthn_rp_id')) {
            return $id;
        }
        return strtolower(preg_replace('/:\d+$/', '', (string) ($_SERVER['HTTP_HOST'] ?? '')));
    }

    private function webauthn_origin()
    {
        if ($origin = $this->rc->config->get('device_mfa_webauthn_origin')) {
            return rtrim($origin, '/');
        }
        return (rcube_utils::https_check() ? 'https' : 'http') . '://' . strtolower((string) ($_SERVER['HTTP_HOST'] ?? ''));
    }

    /** WebAuthn user handle (opaque, 16 bytes) */
    private function webauthn_user_handle()
    {
        return substr(hash_hmac('sha256', 'wa-user|' . $_SESSION['user_id'], $this->rc->config->get('des_key'), true), 0, 16);
    }

    private function new_challenge($purpose)
    {
        $value = device_mfa_webauthn::b64u_encode(random_bytes(32));
        $_SESSION[self::SESS_CHALLENGE] = ['value' => $value, 'ts' => time(), 'purpose' => $purpose];
        return $value;
    }

    // ------------------------------------------------------------------
    // Pages / 画面
    // ------------------------------------------------------------------

    private function render_check_page($webauthn)
    {
        $user_id = (int) $_SESSION['user_id'];
        $h       = fn ($s) => htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');

        $cfg = [
            'mode'      => $webauthn ? 'webauthn' : 'browser',
            'challenge' => $this->new_challenge($webauthn ? 'webauthn' : 'browser'),
            'token'     => $this->rc->get_request_token(),
            'keyRef'    => $this->key_ref(),
            'verifyUrl'   => $this->rc->url(['_task' => 'mail', '_action' => self::ACT_VERIFY]),
            'registerUrl' => $this->rc->url(['_task' => 'mail', '_action' => self::ACT_REGISTER]),
            'statusUrl'   => $this->rc->url(['_task' => 'mail', '_action' => self::ACT_STATUS]),
            'waVerifyUrl' => $this->rc->url(['_task' => 'mail', '_action' => self::ACT_WA_VERIFY]),
            'reloadUrl'   => $this->rc->url(['_task' => 'mail']),
            't'         => $this->js_texts(['ask_verify', 'ask_register', 'verifying', 'registering', 'ok_redirect',
                'wait_approval', 'waiting', 'unsupported', 'failed', 'wa_ask', 'wa_waiting', 'wa_failed', 'wa_unsupported']),
        ];

        if ($webauthn) {
            $cfg['rpId']  = $this->webauthn_rp_id();
            $cfg['allow'] = array_map(fn ($r) => $r['credential_id'], $this->list_webauthn($user_id));
            $extra = '<p class="note">' . $h($this->gettext('wa_note')) . '</p>';
            $yes   = $this->gettext('wa_button');
        } else {
            if (!in_array('strict', $this->allowed_modes(), true)) {
                $extra = '';
            } elseif ($this->get_mode() === 'standard') {
                $extra = '<label class="opt"><input type="checkbox" id="mfa"> <strong>' . $h($this->gettext('optin_title'))
                    . '</strong><br><span>' . $h($this->gettext('optin_desc')) . '</span></label>';
            } else {
                $extra = '<div class="opt on"><strong>' . $h($this->gettext('optin_on_title')) . '</strong><br>'
                    . $h($this->gettext('optin_on_desc')) . '</div>';
            }
            $extra .= '<p class="note">' . $h($this->gettext('note')) . '</p>';
            $yes    = $this->gettext('yes');
        }

        $this->output_page($this->gettext('title'), $cfg, 'device_mfa_client.inc', $h($yes), $extra);
    }

    /** Page to register a security key / Windows Hello (verified sessions only) */
    private function render_webauthn_page()
    {
        $h    = fn ($s) => htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
        $chal = device_mfa_webauthn::b64u_encode(random_bytes(32));
        $_SESSION[self::SESS_WA_REG] = ['value' => $chal, 'ts' => time()];

        $cfg = [
            'mode'       => 'webauthn_add',
            'challenge'  => $chal,
            'token'      => $this->rc->get_request_token(),
            'rpId'       => $this->webauthn_rp_id(),
            'rpName'     => $this->rc->config->get('product_name', 'Roundcube'),
            'userId'     => device_mfa_webauthn::b64u_encode($this->webauthn_user_handle()),
            'userName'   => $this->rc->get_user_name(),
            'exclude'    => array_map(fn ($r) => $r['credential_id'], $this->list_webauthn((int) $_SESSION['user_id'])),
            'addUrl'     => $this->rc->url(['_task' => 'settings', '_action' => self::ACT_WA_ADD]),
            'reloadUrl'  => $this->rc->url(['_task' => 'settings', '_action' => self::ACT_WA_PAGE]),
            'backUrl'    => $this->rc->url(['_task' => 'settings', '_action' => 'preferences']),
            't'          => $this->js_texts(['wa_add_waiting', 'wa_add_ok', 'wa_add_failed', 'wa_unsupported']),
        ];

        $extra = '<p><label for="waname">' . $h($this->gettext('wa_name_label')) . '</label><br>'
            . '<input type="text" id="waname" maxlength="60" placeholder="' . $h($this->gettext('wa_name_placeholder')) . '"></p>'
            . '<p class="note">' . $h($this->gettext('wa_add_note')) . '</p>'
            . '<p><a class="btn" id="back" href="' . $h($cfg['backUrl']) . '">' . $h($this->gettext('back_to_settings')) . '</a></p>';

        $this->output_page($this->gettext('wa_add_title'), $cfg, 'device_mfa_webauthn.inc', $h($this->gettext('wa_add_start')), $extra);
    }

    private function js_texts(array $keys)
    {
        $out = [];
        foreach ($keys as $k) {
            $out[$k] = $this->gettext($k);
        }
        return $out;
    }

    private function output_page($title, array $cfg, $script, $yes_label, $extra_html)
    {
        $h       = fn ($s) => htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
        $title   = $h($title);
        $user    = $h($this->rc->get_user_name());
        $logout  = $h($this->rc->url(['_task' => 'logout', '_token' => $this->rc->get_request_token()]));
        $product = $h($this->rc->config->get('product_name', 'Roundcube'));
        $lang    = $h(substr((string) ($_SESSION['language'] ?? 'en'), 0, 2));
        $json    = json_encode($cfg, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
        $js      = file_get_contents(__DIR__ . '/' . $script);
        $l_check = $h($this->gettext('checking'));
        $l_retry = $h($this->gettext('retry'));
        $l_out   = $h($this->gettext('logout'));

        header('Content-Type: text/html; charset=UTF-8');
        header('X-Frame-Options: DENY');

        echo <<<HTML
<!doctype html>
<html lang="{$lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{$title} - {$product}</title>
<style>
  :root { color-scheme: light dark; --bg:#f4f6f8; --fg:#1f2933; --card:#fff; --muted:#5f6b7a; --accent:#37beff; --err:#c0392b; --ok:#1e8449; }
  @media (prefers-color-scheme: dark) { :root { --bg:#161b22; --fg:#e6edf3; --card:#21262d; --muted:#9aa5b1; --err:#ff7b72; --ok:#56d364; } }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px;
         background:var(--bg); color:var(--fg); font-family: system-ui, "Hiragino Sans", "Yu Gothic UI", Meiryo, sans-serif; }
  .card { background:var(--card); max-width:460px; width:100%; padding:32px 28px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,.08); }
  h1 { font-size:1.25rem; margin:0 0 4px; }
  .user { color:var(--muted); font-size:.9rem; margin-bottom:24px; word-break:break-all; }
  #msg { min-height:3em; line-height:1.6; }
  #msg.err { color:var(--err); } #msg.ok { color:var(--ok); }
  .code { display:block; margin:12px 0; font:700 2rem/1.2 ui-monospace, Menlo, Consolas, monospace; letter-spacing:.1em; text-align:center;
          padding:12px; border-radius:8px; background:rgba(55,190,255,.12); color:var(--fg); }
  .spin { display:inline-block; width:1em; height:1em; border:2px solid var(--muted); border-top-color:var(--accent);
          border-radius:50%; animation:s 0.8s linear infinite; vertical-align:-2px; margin-right:6px; }
  @keyframes s { to { transform:rotate(360deg); } }
  .actions { margin-top:24px; display:flex; gap:12px; flex-wrap:wrap; }
  a.btn, button { font:inherit; padding:8px 16px; border-radius:6px; border:1px solid var(--muted); background:transparent; color:var(--fg); text-decoration:none; cursor:pointer; }
  button.primary { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; min-width:96px; }
  input[type=text] { font:inherit; width:100%; padding:8px; border:1px solid var(--muted); border-radius:6px; background:transparent; color:var(--fg); }
  .opt { display:block; margin-top:20px; padding:12px 14px; border:1px solid rgba(55,190,255,.5); border-radius:8px; font-size:.85rem; line-height:1.6; cursor:pointer; }
  .opt.on { cursor:default; background:rgba(55,190,255,.10); }
  .opt input { width:1.1em; height:1.1em; vertical-align:-2px; margin:0 4px 0 0; }
  .opt span { color:var(--muted); }
  .note { margin-top:20px; font-size:.8rem; color:var(--muted); line-height:1.5; }
</style>
</head>
<body>
<main class="card">
  <h1>{$title}</h1>
  <div class="user">{$user}</div>
  <div id="msg"><span class="spin"></span>{$l_check}</div>
  <div class="actions">
    <button type="button" id="yes" class="primary" hidden>{$yes_label}</button>
    <button type="button" id="retry" hidden>{$l_retry}</button>
    <a class="btn" href="{$logout}">{$l_out}</a>
  </div>
  {$extra_html}
</main>
<script>window.DEVICE_MFA = {$json};</script>
<script>{$js}</script>
</body>
</html>
HTML;
    }

    // ------------------------------------------------------------------
    // Utilities
    // ------------------------------------------------------------------

    private function table()
    {
        return $this->rc->get_dbh()->table_name('device_mfa_devices', true);
    }

    /** Sends a JSON response and ends the request. Protected so that tests can capture it. */
    protected function json_out($code, $data)
    {
        http_response_code($code);
        echo json_encode($data, JSON_UNESCAPED_UNICODE);
        exit;
    }

    private function no_cache_headers()
    {
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');
    }

    private function log($msg)
    {
        rcube::write_log('device_mfa', $msg);
    }
}
