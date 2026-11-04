<?php

/**
 * device_mfa - 端末束縛による第2要素認証 (Roundcube plugin)
 *
 * Office365(OAuth) でログインした後、ブラウザ内に保存された
 * 取り出し不可(non-extractable)の ECDSA P-256 秘密鍵でサーバのチャレンジに署名させ、
 * 「登録済みの同じ端末・同じブラウザ」であることを確認する。
 *
 *  - 端末識別: HttpOnly Cookie (device_id) + IndexedDB 内の秘密鍵 の両方が必要
 *  - 初回登録: device_mfa_register_networks に含まれる IP (院内) からのみ自動登録
 *  - 確認が済むまで、ログアウト以外のすべてのリクエストを遮断
 *  - 利用者は 設定 > 端末確認 で強さを選べる
 *      standard : 院内IPなら「はい」で新しい端末を登録（IPアドレスを認証要素とみなす）
 *      strict   : 新しい端末の登録に、本人の登録済み端末での承認が必要（多要素）
 */
class device_mfa extends rcube_plugin
{
    public $task = '.*';

    private const SESS_OK        = 'device_mfa_ok';
    private const SESS_CHALLENGE = 'device_mfa_challenge';
    private const ACT_VERIFY     = 'plugin.device_mfa_verify';
    private const ACT_REGISTER   = 'plugin.device_mfa_register';
    private const ACT_STATUS     = 'plugin.device_mfa_status';
    private const SESS_PENDING   = 'device_mfa_pending';
    private const PENDING_TTL    = 900; // 承認待ちの有効時間(秒)

    /** @var rcmail */
    private $rc;

    public function init()
    {
        $this->rc = rcmail::get_instance();
        $this->load_config();
        $this->add_hook('startup', [$this, 'startup']);
        $this->add_hook('login_after', [$this, 'login_after']);
        $this->add_hook('preferences_sections_list', [$this, 'prefs_sections']);
        $this->add_hook('preferences_list', [$this, 'prefs_list']);
        $this->add_hook('preferences_save', [$this, 'prefs_save']);
    }

    /**
     * ログイン直後: 必ず未確認状態から始める
     */
    public function login_after($args)
    {
        unset($_SESSION[self::SESS_OK], $_SESSION[self::SESS_CHALLENGE], $_SESSION[self::SESS_PENDING]);
        return $args;
    }

    /**
     * すべてのリクエストの入口。端末確認が済んでいなければ横取りする。
     */
    public function startup($args)
    {
        // 未ログイン・ログイン処理中・ログアウトは素通し
        if (empty($_SESSION['user_id']) || $args['task'] === 'login' || $args['task'] === 'logout') {
            return $args;
        }

        if (!empty($_SESSION[self::SESS_OK]) && $_SESSION[self::SESS_OK] === $this->session_binding()) {
            return $args;
        }

        // 盗まれたセッションIDなど、認証クッキーが不正なら Roundcube 本体に処理させる(セッション破棄)
        if (!$this->rc->session->check_auth()) {
            return $args;
        }

        // 登録許可ネットワークの外からのアクセスで、device_mfa_outside_mode が 'idp' のときだけ、
        // 端末確認を行わず ID プロバイダー（例：Entra ID の条件付きアクセス）の多要素認証に任せる。
        // 既定の 'deny' では、外からも端末確認を行う（登録済みの端末だけ通す）
        $ip = rcube_utils::remote_addr();
        if (!$this->registration_allowed($ip)
            && $this->rc->config->get('device_mfa_outside_mode', 'deny') === 'idp'
        ) {
            $this->mark_ok();
            $this->log("outside network: device check skipped (IdP MFA) user_id={$_SESSION['user_id']} ip={$ip}");
            return $args;
        }

        $this->no_cache_headers();

        if (in_array($args['action'], [self::ACT_VERIFY, self::ACT_REGISTER, self::ACT_STATUS], true)) {
            $this->handle_api($args['action']);
            exit;
        }

        // Roundcube の AJAX / iframe 呼び出しは拒否 (トップページが確認画面に置き換わる)
        if (!empty($_REQUEST['_remote']) || !empty($_REQUEST['_framed'])
            || rcube_utils::request_header('X-Roundcube-Request')
        ) {
            http_response_code(401);
            header('Content-Type: text/plain; charset=UTF-8');
            echo 'device verification required';
            exit;
        }

        $this->render_challenge_page();
        exit;
    }

    // ------------------------------------------------------------------
    // API
    // ------------------------------------------------------------------

    private function handle_api($action)
    {
        header('Content-Type: application/json; charset=UTF-8');

        if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !$this->rc->check_request()) {
            $this->json_out(403, ['status' => 'error', 'message' => '不正なリクエストです。画面を再読み込みしてください。']);
        }

        if ($action === self::ACT_STATUS) {
            $this->handle_status();
        }

        $body = json_decode(file_get_contents('php://input'), true);
        $sig  = is_array($body) && isset($body['sig']) ? base64_decode((string) $body['sig'], true) : false;

        $chal = $_SESSION[self::SESS_CHALLENGE] ?? null;
        unset($_SESSION[self::SESS_CHALLENGE]); // 1回限り

        if (!$chal || !is_array($chal) || time() - $chal['ts'] > 300 || $sig === false) {
            $this->json_out(400, ['status' => 'retry', 'message' => 'チャレンジの有効期限切れです。']);
        }

        $user_id   = (int) $_SESSION['user_id'];
        $device_id = $this->get_device_cookie();
        $ip        = rcube_utils::remote_addr();

        if ($action === self::ACT_VERIFY) {
            $row = $device_id ? $this->find_device($user_id, $device_id) : null;

            if (!$row) {
                $why = $device_id ? 'no active device for cookie' : 'no device cookie';
                $this->log("verify UNREGISTERED ({$why}) user_id={$user_id} ip={$ip}");
                $this->json_out(200, ['status' => 'unregistered']);
            }

            if (!$this->verify_sig($chal['value'], $sig, $row['public_key'])) {
                $this->log("verify FAILED user_id={$user_id} device={$row['id']} ip={$ip}");
                $this->json_out(200, ['status' => 'unregistered']);
            }

            $this->maybe_enable_strict($body, $user_id);

            if ($row['status'] === 'pending') {
                $_SESSION[self::SESS_PENDING] = (int) $row['id'];
                $this->json_out(200, ['status' => 'pending', 'code' => $row['approve_code']]);
            }

            $this->rc->get_dbh()->query(
                'UPDATE ' . $this->table() . ' SET `last_used` = ' . $this->rc->get_dbh()->now()
                . ', `last_ip` = ? WHERE `id` = ?',
                $ip, $row['id']
            );

            $this->set_device_cookie($device_id); // 有効期限を延長
            $this->mark_ok();
            $this->log("verify OK user_id={$user_id} device={$row['id']} ip={$ip}");
            $this->json_out(200, ['status' => 'ok', 'redirect' => $this->rc->url(['_task' => 'mail'])]);
        }

        // ---- 登録 ----
        if (!$this->registration_allowed($ip)) {
            $this->log("register DENIED (network) user_id={$user_id} ip={$ip}");
            $this->json_out(200, [
                'status'  => 'denied',
                'message' => 'この端末は未登録です。院内ネットワークに接続した端末から一度ログインして登録してください。',
            ]);
        }

        $pem = $this->spki_to_pem($body['pub'] ?? '');
        if (!$pem || !$this->verify_sig($chal['value'], $sig, $pem)) {
            $this->json_out(400, ['status' => 'error', 'message' => '鍵の検証に失敗しました。']);
        }

        if (!$device_id) {
            $device_id = bin2hex(random_bytes(24));
        }

        $label = mb_substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 250);
        $db    = $this->rc->get_dbh();

        $this->maybe_enable_strict($body, $user_id);

        // 承認が必要かどうかは、旧鍵を失効させる前に判定する
        // 強化モードで、承認できる登録済み端末が1台以上あれば「承認待ち」で登録する
        // （同じ端末で鍵を作り直す場合、その端末自身は承認者に数えない）
        $pending = $this->get_mode() === 'strict' && $this->count_active($user_id, $device_id) > 0;
        $code    = $pending ? $this->new_approve_code() : '';

        // 同一端末(Cookie)で鍵を作り直した場合は旧鍵を失効させる
        $db->query('UPDATE ' . $this->table() . ' SET `revoked` = 1 WHERE `user_id` = ? AND `device_id` = ?',
            $user_id, $device_id);

        $db->query(
            'INSERT INTO ' . $this->table()
            . ' (`user_id`, `device_id`, `public_key`, `label`, `created`, `created_ip`, `last_used`, `last_ip`, `revoked`, `status`, `approve_code`)'
            . ' VALUES (?, ?, ?, ?, ' . $db->now() . ', ?, ' . $db->now() . ', ?, 0, ?, ?)',
            $user_id, $device_id, $pem, $label, $ip, $ip, $pending ? 'pending' : 'active', $code
        );

        $this->set_device_cookie($device_id);

        if ($pending) {
            $_SESSION[self::SESS_PENDING] = (int) $db->insert_id('device_mfa_devices');
            $this->log("register PENDING user_id={$user_id} device_id=" . substr($device_id, 0, 8) . "… code={$code} ip={$ip}");
            $this->json_out(200, ['status' => 'pending', 'code' => $code]);
        }

        $this->mark_ok();
        $this->log("register OK user_id={$user_id} device_id=" . substr($device_id, 0, 8) . "… ip={$ip}");
        $this->json_out(200, ['status' => 'ok', 'redirect' => $this->rc->url(['_task' => 'mail'])]);
    }

    private function find_device($user_id, $device_id)
    {
        $db   = $this->rc->get_dbh();
        $days = (int) $this->rc->config->get('device_mfa_expire_days', 180);
        $sql  = 'SELECT * FROM ' . $this->table() . ' WHERE `user_id` = ? AND `device_id` = ? AND `revoked` = 0'
            . " AND (`status` = 'active'" . ($days > 0 ? ' AND `last_used` > ' . $db->now(-86400 * $days) : '')
            . " OR `status` = 'pending' AND `created` > " . $db->now(-self::PENDING_TTL) . ')';

        $res = $db->query($sql . ' ORDER BY `id` DESC LIMIT 1', $user_id, $device_id);
        $row = $db->fetch_assoc($res);

        return $row ?: null;
    }

    /**
     * 承認待ちの端末が承認されたかを返す（承認待ち画面からのポーリング）
     */
    private function handle_status()
    {
        $id        = (int) ($_SESSION[self::SESS_PENDING] ?? 0);
        $user_id   = (int) $_SESSION['user_id'];
        $device_id = $this->get_device_cookie();
        $db        = $this->rc->get_dbh();

        $res = $db->query('SELECT * FROM ' . $this->table() . ' WHERE `id` = ? AND `user_id` = ?', $id, $user_id);
        $row = $id ? $db->fetch_assoc($res) : null;

        if (!$row || $row['device_id'] !== $device_id || $row['revoked']) {
            unset($_SESSION[self::SESS_PENDING]);
            $this->json_out(200, ['status' => 'denied', 'message' => 'この端末の登録は承認されませんでした。']);
        }

        if ($row['status'] === 'active') {
            unset($_SESSION[self::SESS_PENDING]);
            $this->mark_ok();
            $this->log("approved device in use user_id={$user_id} device={$row['id']}");
            $this->json_out(200, ['status' => 'ok', 'redirect' => $this->rc->url(['_task' => 'mail'])]);
        }

        if (strtotime($row['created']) < time() - self::PENDING_TTL) {
            $db->query('UPDATE ' . $this->table() . ' SET `revoked` = 1 WHERE `id` = ?', $row['id']);
            unset($_SESSION[self::SESS_PENDING]);
            $this->json_out(200, ['status' => 'denied', 'message' => '承認の有効期限（15分）が切れました。もう一度ログインしてください。']);
        }

        $this->json_out(200, ['status' => 'pending', 'code' => $row['approve_code']]);
    }

    /**
     * 確認画面で「自分の端末での多要素認証を使う」が選ばれたら強化モードにする。
     * 確認前の画面なので、強くする方向（standard → strict）の変更だけを受け付ける。
     */
    private function maybe_enable_strict($body, $user_id)
    {
        if (!empty($body['strict']) && $this->get_mode() !== 'strict') {
            $this->rc->user->save_prefs(['device_mfa_mode' => 'strict']);
            $this->log("mode=strict (from confirmation page) user_id={$user_id}");
        }
    }

    private function get_mode()
    {
        $mode = $this->rc->user ? ($this->rc->user->get_prefs()['device_mfa_mode'] ?? null) : null;
        return $mode === 'strict' ? 'strict' : 'standard';
    }

    private function count_active($user_id, $exclude_device_id = null)
    {
        $db   = $this->rc->get_dbh();
        $days = (int) $this->rc->config->get('device_mfa_expire_days', 180);
        $res  = $db->query('SELECT COUNT(*) AS n FROM ' . $this->table()
            . " WHERE `user_id` = ? AND `revoked` = 0 AND `status` = 'active'"
            . ($days > 0 ? ' AND `last_used` > ' . $db->now(-86400 * $days) : '')
            . ' AND `device_id` <> ?', $user_id, (string) $exclude_device_id);
        $row  = $db->fetch_assoc($res);

        return (int) ($row['n'] ?? 0);
    }

    /** 承認コード（紛らわしい文字を除いた 4+4 文字） */
    private function new_approve_code()
    {
        $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
        $code  = '';
        for ($i = 0; $i < 8; $i++) {
            $code .= $chars[random_int(0, strlen($chars) - 1)];
        }
        return substr($code, 0, 4) . '-' . substr($code, 4);
    }

    // ------------------------------------------------------------------
    // 設定画面（設定 > 端末確認）
    // ------------------------------------------------------------------

    public function prefs_sections($args)
    {
        $args['list']['device_mfa'] = ['id' => 'device_mfa', 'section' => '端末確認'];
        return $args;
    }

    public function prefs_list($args)
    {
        if ($args['section'] !== 'device_mfa') {
            return $args;
        }

        $h       = fn ($s) => htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
        $user_id = (int) $this->rc->user->ID;
        $mode    = $this->get_mode();
        $db      = $this->rc->get_dbh();
        $mine    = $this->get_device_cookie();

        // --- 認証の強さ ---
        $radios = '';
        foreach ([
            'standard' => ['標準（院内のIPアドレスで認証）',
                '院内のネットワークからなら、新しい端末も「はい」を押すだけで登録できます。'],
            'strict'   => ['強化（多要素）',
                '新しい端末を登録するとき、すでに登録済みの自分の端末での承認が必要になります。パスワードが漏れても、院内から勝手に端末を登録されることを防げます。'],
        ] as $val => [$title, $desc]) {
            $checked = $mode === $val ? ' checked' : '';
            $radios .= '<div style="margin:0 0 12px"><label style="font-weight:bold">'
                . '<input type="radio" name="_dmfa_mode" value="' . $val . '"' . $checked . '> ' . $h($title) . '</label>'
                . '<div style="margin:2px 0 0 24px;opacity:.8">' . $h($desc) . '</div></div>';
        }
        $radios .= '<div style="opacity:.8">院外からのアクセスは、どちらの場合も Microsoft の多要素認証で確認します。'
            . '「強化」でも、承認できる登録済みの端末が1台もないときは「標準」と同じ方法で登録されます。</div>';

        // --- 承認待ち ---
        $res = $db->query('SELECT * FROM ' . $this->table()
            . " WHERE `user_id` = ? AND `revoked` = 0 AND `status` = 'pending' AND `created` > " . $db->now(-self::PENDING_TTL)
            . ' ORDER BY `id` DESC', $user_id);
        $pending = '';
        while ($r = $db->fetch_assoc($res)) {
            $pending .= '<tr><td><label><input type="checkbox" name="_dmfa_approve[]" value="' . (int) $r['id'] . '"> 承認する</label></td>'
                . '<td style="font-family:monospace;font-size:1.3em;font-weight:bold">' . $h($r['approve_code']) . '</td>'
                . '<td>' . $h($this->browser_name($r['label'])) . '</td>'
                . '<td>' . $h($r['created']) . '</td><td>' . $h($r['created_ip']) . '</td></tr>';
        }

        // --- 登録済みの端末 ---
        $days = (int) $this->rc->config->get('device_mfa_expire_days', 180);
        $res  = $db->query('SELECT * FROM ' . $this->table()
            . " WHERE `user_id` = ? AND `revoked` = 0 AND `status` = 'active'"
            . ($days > 0 ? ' AND `last_used` > ' . $db->now(-86400 * $days) : '')
            . ' ORDER BY `last_used` DESC', $user_id);
        $devices = '';
        while ($r = $db->fetch_assoc($res)) {
            $this_one = $mine && $r['device_id'] === $mine ? ' <strong>（この端末）</strong>' : '';
            $devices .= '<tr><td><label><input type="checkbox" name="_dmfa_revoke[]" value="' . (int) $r['id'] . '"> 削除</label></td>'
                . '<td>' . $h($this->browser_name($r['label'])) . $this_one . '</td>'
                . '<td>' . $h($r['created']) . '</td><td>' . $h($r['last_used']) . '</td><td>' . $h($r['last_ip']) . '</td></tr>';
        }

        $table = fn ($head, $rows) => '<table class="records-table" style="width:100%"><thead><tr>'
            . implode('', array_map(fn ($c) => '<th>' . $h($c) . '</th>', $head)) . '</tr></thead><tbody>' . $rows . '</tbody></table>';

        $args['blocks']['mode'] = [
            'name'    => '認証の強さ',
            'options' => [['content' => $radios]],
        ];
        $args['blocks']['pending'] = [
            'name'    => '承認待ちの端末',
            'options' => [['content' => $pending
                ? '<p>新しい端末に表示されているコードと同じであることを確かめてから、「承認する」にチェックを入れて保存してください。心当たりのない端末は承認しないでください（15分で自動的に無効になります）。</p>'
                  . $table(['', 'コード', 'ブラウザ', '登録要求日時', 'IPアドレス'], $pending)
                : '<p>承認待ちの端末はありません。</p>']],
        ];
        $args['blocks']['devices'] = [
            'name'    => '登録済みの端末',
            'options' => [['content' => $devices
                ? '<p>使わなくなった端末や心当たりのない端末は、「削除」にチェックを入れて保存してください。</p>'
                  . $table(['', 'ブラウザ', '登録日時', '最終利用日時', '最終利用IP'], $devices)
                : '<p>登録済みの端末はありません。</p>']],
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
        $mode    = rcube_utils::get_input_string('_dmfa_mode', rcube_utils::INPUT_POST);
        $args['prefs']['device_mfa_mode'] = $mode === 'strict' ? 'strict' : 'standard';

        foreach ((array) ($_POST['_dmfa_approve'] ?? []) as $id) {
            $db->query('UPDATE ' . $this->table() . " SET `status` = 'active', `approve_code` = ''"
                . " WHERE `id` = ? AND `user_id` = ? AND `revoked` = 0 AND `status` = 'pending' AND `created` > "
                . $db->now(-self::PENDING_TTL), (int) $id, $user_id);
            if ($db->affected_rows()) {
                $this->log("approve OK user_id={$user_id} device={$id} by ip=" . rcube_utils::remote_addr());
            }
        }

        foreach ((array) ($_POST['_dmfa_revoke'] ?? []) as $id) {
            $db->query('UPDATE ' . $this->table() . ' SET `revoked` = 1 WHERE `id` = ? AND `user_id` = ?', (int) $id, $user_id);
            if ($db->affected_rows()) {
                $this->log("revoke by user user_id={$user_id} device={$id}");
            }
        }

        $this->log("mode={$args['prefs']['device_mfa_mode']} user_id={$user_id}");

        return $args;
    }

    /** User-Agent を「Firefox / macOS」のような表記にする */
    private function browser_name($ua)
    {
        $b = preg_match('/Edg\//', $ua) ? 'Edge' : (preg_match('/Firefox\//', $ua) ? 'Firefox'
            : (preg_match('/Chrome\//', $ua) ? 'Chrome' : (preg_match('/Safari\//', $ua) ? 'Safari' : 'ブラウザ')));
        $o = preg_match('/Windows/', $ua) ? 'Windows' : (preg_match('/iPhone|iPad/', $ua) ? 'iOS'
            : (preg_match('/Mac OS X|Macintosh/', $ua) ? 'macOS' : (preg_match('/Android/', $ua) ? 'Android'
            : (preg_match('/Linux/', $ua) ? 'Linux' : '不明'))));
        return "{$b} / {$o}";
    }

    private function registration_allowed($ip)
    {
        $nets = (array) $this->rc->config->get('device_mfa_register_networks', []);
        $addr = \IPLib\Factory::parseAddressString($ip);

        if (!$addr) {
            return false;
        }

        foreach ($nets as $net) {
            $range = \IPLib\Factory::parseRangeString($net);
            if ($range && $range->contains($addr)) {
                return true;
            }
        }

        return false;
    }

    // ------------------------------------------------------------------
    // 暗号処理
    // ------------------------------------------------------------------

    /**
     * WebCrypto の ECDSA 署名 (r||s 64byte) を検証する
     */
    private function verify_sig($message, $raw_sig, $pem)
    {
        if (strlen($raw_sig) !== 64) {
            return false;
        }

        $der = $this->raw_to_der($raw_sig);

        return openssl_verify($message, $der, $pem, OPENSSL_ALGO_SHA256) === 1;
    }

    private function raw_to_der($raw)
    {
        $int = function ($bin) {
            $bin = ltrim($bin, "\x00");
            if ($bin === '' || ord($bin[0]) > 0x7F) {
                $bin = "\x00" . $bin;
            }
            return "\x02" . chr(strlen($bin)) . $bin;
        };

        $seq = $int(substr($raw, 0, 32)) . $int(substr($raw, 32, 32));

        return "\x30" . chr(strlen($seq)) . $seq;
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
    // セッション / Cookie
    // ------------------------------------------------------------------

    /** 確認済みフラグを、このセッションの認証Cookieに結び付ける */
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

    private function get_device_cookie()
    {
        $v = $_COOKIE[$this->cookie_name()] ?? '';
        return preg_match('/^[0-9a-f]{48}$/', $v) ? $v : null;
    }

    private function set_device_cookie($device_id)
    {
        setcookie($this->cookie_name(), $device_id, [
            'expires'  => time() + 86400 * 400, // ブラウザ上限(400日)
            'path'     => '/',
            'secure'   => true,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    /** IndexedDB 上の鍵名 (ユーザー名を端末に平文で残さないよう HMAC 化) */
    private function key_ref()
    {
        return substr(hash_hmac('sha256', 'keyref|' . $_SESSION['user_id'] . '|' . $this->rc->get_user_name(),
            $this->rc->config->get('des_key')), 0, 32);
    }

    // ------------------------------------------------------------------
    // 画面
    // ------------------------------------------------------------------

    private function render_challenge_page()
    {
        $challenge = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $_SESSION[self::SESS_CHALLENGE] = ['value' => $challenge, 'ts' => time()];

        $cfg = [
            'challenge'   => $challenge,
            'token'       => $this->rc->get_request_token(),
            'keyRef'      => $this->key_ref(),
            'verifyUrl'   => $this->rc->url(['_task' => 'mail', '_action' => self::ACT_VERIFY]),
            'registerUrl' => $this->rc->url(['_task' => 'mail', '_action' => self::ACT_REGISTER]),
            'statusUrl'   => $this->rc->url(['_task' => 'mail', '_action' => self::ACT_STATUS]),
            'reloadUrl'   => $this->rc->url(['_task' => 'mail']),
        ];

        $h       = fn ($s) => htmlspecialchars((string) $s, ENT_QUOTES, 'UTF-8');
        $user    = $h($this->rc->get_user_name());
        $logout  = $h($this->rc->url(['_task' => 'logout', '_token' => $this->rc->get_request_token()]));
        $product = $h($this->rc->config->get('product_name', 'Roundcube'));
        $json    = json_encode($cfg, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
        $js      = file_get_contents(__DIR__ . '/device_mfa_client.inc');

        if ($this->get_mode() === 'strict') {
            $mfa = '<div class="opt on"><strong>自分の端末での多要素認証：オン</strong><br>'
                . '新しい端末を登録するときは、自分の登録済み端末での承認が必要です。'
                . '変更は、ログイン後の「設定 &gt; 端末確認」で行えます。</div>';
        } else {
            $mfa = '<label class="opt"><input type="checkbox" id="mfa"> <strong>自分の端末での多要素認証を使う</strong><br>'
                . '<span>オンにすると、これから新しい端末を登録するときに、自分の登録済み端末での承認が必要になります。'
                . 'パスワードが漏れても、院内から勝手に端末を登録されることを防げます。'
                . '（あとから「設定 &gt; 端末確認」で変更できます）</span></label>';
        }

        header('Content-Type: text/html; charset=UTF-8');
        header('X-Frame-Options: DENY');

        echo <<<HTML
<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>端末の確認 - {$product}</title>
<style>
  :root { color-scheme: light dark; --bg:#f4f6f8; --fg:#1f2933; --card:#fff; --muted:#5f6b7a; --accent:#37beff; --err:#c0392b; --ok:#1e8449; }
  @media (prefers-color-scheme: dark) { :root { --bg:#161b22; --fg:#e6edf3; --card:#21262d; --muted:#9aa5b1; --err:#ff7b72; --ok:#56d364; } }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; align-items:center; justify-content:center; padding:16px;
         background:var(--bg); color:var(--fg); font-family: system-ui, "Hiragino Sans", "Yu Gothic UI", Meiryo, sans-serif; }
  .card { background:var(--card); max-width:440px; width:100%; padding:32px 28px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,.08); }
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
  .opt { display:block; margin-top:20px; padding:12px 14px; border:1px solid rgba(55,190,255,.5); border-radius:8px;
         font-size:.85rem; line-height:1.6; cursor:pointer; }
  .opt.on { cursor:default; background:rgba(55,190,255,.10); }
  .opt input { width:1.1em; height:1.1em; vertical-align:-2px; margin:0 4px 0 0; }
  .opt span { color:var(--muted); }
  .note { margin-top:20px; font-size:.8rem; color:var(--muted); line-height:1.5; }
</style>
</head>
<body>
<main class="card">
  <h1>端末の確認</h1>
  <div class="user">{$user}</div>
  <div id="msg"><span class="spin"></span>この端末が登録済みか確認しています…</div>
  <div class="actions">
    <button type="button" id="yes" class="primary" hidden>はい</button>
    <button type="button" id="retry" hidden>再試行</button>
    <a class="btn" href="{$logout}">ログアウト</a>
  </div>
  {$mfa}
  <p class="note">この確認では、接続元のIPアドレスに加えて、ブラウザのキャッシュ（ブラウザ内に保存されたデータ）を利用して、登録済みの同じ端末・同じブラウザであることを確かめています。<br>ブラウザのキャッシュや閲覧データを消去した場合、別のブラウザやプライベートブラウズを使った場合は、端末の再登録が必要になります。</p>
</main>
<script>window.DEVICE_MFA = {$json};</script>
<script>{$js}</script>
</body>
</html>
HTML;
    }

    // ------------------------------------------------------------------
    // util
    // ------------------------------------------------------------------

    private function table()
    {
        return $this->rc->get_dbh()->table_name('device_mfa_devices', true);
    }

    private function json_out($code, $data)
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
