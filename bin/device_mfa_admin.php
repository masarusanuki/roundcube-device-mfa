#!/usr/bin/env php
<?php
/**
 * 登録端末の管理
 *   list [ユーザー名]        登録端末一覧
 *   revoke <ID>              端末を失効
 *   revoke-user <ユーザー名>  ユーザーの全端末を失効
 */
define('INSTALL_PATH', rtrim(getenv('RC_DIR') ?: '/usr/share/roundcubemail', '/') . '/');
require_once INSTALL_PATH . 'program/include/clisetup.php';

$rc  = rcube::get_instance();
$db  = $rc->get_dbh();
$t   = $db->table_name('device_mfa_devices', true);
$u   = $db->table_name('users', true);
$cmd = $argv[1] ?? 'list';
$arg = $argv[2] ?? null;

switch ($cmd) {
case 'list':
    $sql = "SELECT d.*, u.username FROM $t d JOIN $u u ON u.user_id = d.user_id";
    $res = $arg ? $db->query("$sql WHERE u.username = ? ORDER BY d.id", $arg) : $db->query("$sql ORDER BY d.id");
    printf("%-5s %-35s %-7s %-19s %-15s %-19s %-15s %s\n", 'ID', 'USER', 'STATE', 'CREATED', 'CREATED_IP', 'LAST_USED', 'LAST_IP', 'BROWSER');
    while ($r = $db->fetch_assoc($res)) {
        printf("%-5d %-35s %-7s %-19s %-15s %-19s %-15s %s\n", $r['id'], $r['username'],
            $r['revoked'] ? 'revoked' : ($r['status'] ?? 'active'), $r['created'], $r['created_ip'], $r['last_used'], $r['last_ip'],
            mb_substr($r['label'], 0, 60));
    }
    break;
case 'revoke':
    $db->query("UPDATE $t SET revoked = 1 WHERE id = ?", (int) $arg);
    echo $db->affected_rows() . " device(s) revoked\n";
    break;
case 'revoke-user':
    $db->query("UPDATE $t SET revoked = 1 WHERE user_id IN (SELECT user_id FROM $u WHERE username = ?)", $arg);
    echo $db->affected_rows() . " device(s) revoked\n";
    break;
default:
    fwrite(STDERR, "usage: {$argv[0]} list [user] | revoke <id> | revoke-user <user>\n");
    exit(1);
}
