#!/usr/bin/env php
<?php
/**
 * device_mfa admin CLI / 登録端末の管理
 *
 *   list [user]          list devices and keys / 登録端末とキーの一覧
 *   revoke <id>          revoke one device or key / 端末・キーを1つ失効
 *   revoke-user <user>   revoke all devices and keys of a user / 利用者の全端末・キーを失効
 *   reset-user <user>    revoke all and set the strength back to "standard"
 *                        (e.g. the user lost the security key) / 全失効して強さを「標準」に戻す（キーの紛失など）
 *
 * Roundcube in another place: RC_DIR=/var/www/roundcube bin/device_mfa_admin.php list
 */
define('INSTALL_PATH', rtrim(getenv('RC_DIR') ?: '/usr/share/roundcubemail', '/') . '/');
require_once INSTALL_PATH . 'program/include/clisetup.php';

$rc  = rcube::get_instance();
$db  = $rc->get_dbh();
$t   = $db->table_name('device_mfa_devices', true);
$u   = $db->table_name('users', true);
$cmd = $argv[1] ?? 'list';
$arg = $argv[2] ?? null;

function user_ids($db, $u, $username)
{
    $ids = [];
    $res = $db->query("SELECT user_id FROM $u WHERE username = ?", $username);
    while ($r = $db->fetch_assoc($res)) {
        $ids[] = (int) $r['user_id'];
    }
    return $ids;
}

switch ($cmd) {
case 'list':
    $sql = "SELECT d.*, u.username FROM $t d JOIN $u u ON u.user_id = d.user_id";
    $res = $arg ? $db->query("$sql WHERE u.username = ? ORDER BY d.id", $arg) : $db->query("$sql ORDER BY d.id");
    printf("%-5s %-32s %-8s %-9s %-19s %-19s %-15s %s\n", 'ID', 'USER', 'STATE', 'KIND', 'CREATED', 'LAST_USED', 'LAST_IP', 'NAME / BROWSER');
    while ($r = $db->fetch_assoc($res)) {
        $kind = ($r['kind'] ?? 'webcrypto') === 'webauthn' ? 'webauthn' : 'browser';
        $what = $kind === 'webauthn' ? $r['name'] : $r['label'];
        printf("%-5d %-32s %-8s %-9s %-19s %-19s %-15s %s\n", $r['id'], $r['username'],
            (int) $r['revoked'] ? 'revoked' : $r['status'], $kind, substr($r['created'], 0, 19),
            substr($r['last_used'], 0, 19), $r['last_ip'], mb_substr((string) $what, 0, 50));
    }
    break;

case 'revoke':
    $db->query("UPDATE $t SET revoked = 1 WHERE id = ?", (int) $arg);
    echo $db->affected_rows() . " device(s) revoked\n";
    break;

case 'revoke-user':
case 'reset-user':
    $ids = $arg ? user_ids($db, $u, $arg) : [];
    if (!$ids) {
        fwrite(STDERR, "user not found: {$arg}\n");
        exit(1);
    }
    $n = 0;
    foreach ($ids as $id) {
        $db->query("UPDATE $t SET revoked = 1 WHERE user_id = ? AND revoked = 0", $id);
        $n += $db->affected_rows();
        if ($cmd === 'reset-user') {
            $user = new rcube_user($id);
            $user->save_prefs(['device_mfa_mode' => 'standard']);
        }
    }
    echo "{$n} device(s) revoked" . ($cmd === 'reset-user' ? ", strength reset to standard" : '') . "\n";
    break;

default:
    fwrite(STDERR, "usage: {$argv[0]} list [user] | revoke <id> | revoke-user <user> | reset-user <user>\n");
    exit(1);
}
