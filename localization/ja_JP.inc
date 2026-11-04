<?php

/*
 +-----------------------------------------------------------------------+
 | Localization file of the device_mfa plugin                            |
 |                                                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version.                                                    |
 +-----------------------------------------------------------------------+
*/

$labels = [];
$labels['title'] = '端末の確認';
$labels['checking'] = 'この端末が登録済みか確認しています…';
$labels['yes'] = 'はい';
$labels['retry'] = '再試行';
$labels['logout'] = 'ログアウト';
$labels['note'] = 'この確認では、接続元のIPアドレスに加えて、ブラウザのキャッシュ（ブラウザ内に保存されたデータ）を利用して、登録済みの同じ端末・同じブラウザであることを確かめています。ブラウザのキャッシュや閲覧データを消去した場合、別のブラウザやプライベートブラウズを使った場合は、端末の再登録が必要になります。';
$labels['ask_verify'] = '接続元のIPアドレスに加えて、ブラウザのキャッシュに保存された情報で、登録済みの端末であることを確認します。この端末でログインしますか？';
$labels['ask_register'] = 'この端末はまだ登録されていません。接続元のIPアドレスに加えて、このブラウザのキャッシュに端末確認用の情報を保存して、この端末を登録しますか？';
$labels['verifying'] = '確認しています…';
$labels['registering'] = 'この端末を登録しています…';
$labels['ok_redirect'] = '確認できました。メール画面に移動します…';
$labels['wait_approval'] = 'この端末を使うには、本人の登録済みの端末での承認が必要です。登録済みの端末で「設定 > 端末確認」を開き、次のコードと同じものを承認してください。';
$labels['waiting'] = '承認を待っています（15分で無効になります）…';
$labels['unsupported'] = 'このブラウザは端末確認に対応していません（HTTPS接続と最新のブラウザが必要です）。';
$labels['failed'] = '端末確認に失敗しました: ';
$labels['optin_title'] = '自分の端末での多要素認証を使う';
$labels['optin_desc'] = 'オンにすると、これから新しい端末を登録するときに、自分の登録済み端末での承認が必要になります。パスワードが漏れても、院内から勝手に端末を登録されることを防げます。（あとから「設定 > 端末確認」で変更できます）';
$labels['optin_on_title'] = '自分の端末での多要素認証：オン';
$labels['optin_on_desc'] = '新しい端末を登録するときは、自分の登録済み端末での承認が必要です。変更は、ログイン後の「設定 > 端末確認」で行えます。';
$labels['wa_button'] = 'セキュリティキー・Windows Hello で確認';
$labels['wa_ask'] = 'セキュリティキーまたは Windows Hello で確認します。';
$labels['wa_waiting'] = 'ブラウザの案内に従ってください（キーに触れる、PIN を入力する、指紋を使うなど）…';
$labels['wa_failed'] = 'セキュリティキー・Windows Hello で確認できませんでした: ';
$labels['wa_unsupported'] = 'このブラウザはセキュリティキー・Windows Hello（WebAuthn）に対応していません。';
$labels['wa_note'] = 'ログインのたびにセキュリティキーまたは Windows Hello で確認する設定になっています。キーをなくした場合は、管理者にリセットを依頼してください。';
$labels['section'] = '端末確認';
$labels['strength'] = '認証の強さ';
$labels['mode_standard_title'] = '標準（院内のIPアドレスで認証）';
$labels['mode_standard_desc'] = '院内のネットワークからなら、新しい端末も「はい」を押すだけで登録できます。';
$labels['mode_strict_title'] = '強化（多要素）';
$labels['mode_strict_desc'] = '新しい端末を登録するとき、すでに登録済みの自分の端末での承認が必要になります。パスワードが漏れても、院内から勝手に端末を登録されることを防げます。';
$labels['mode_webauthn_title'] = 'セキュリティキー・Windows Hello（最も強い）';
$labels['mode_webauthn_desc'] = '院内・院外を問わず、ログインのたびに登録したセキュリティキーまたは Windows Hello での確認が必要になります。パスワード＋持っているもので、正式な二要素認証になります。';
$labels['mode_webauthn_need_key'] = '先に下でキーを登録してください。';
$labels['mode_note'] = '標準と強化では、院外からのアクセスは管理者の設定（登録済み端末のみ、または ID プロバイダーの多要素認証）に従います。最も強い設定を選んでも、登録したキーが1つもない場合は「強化」として扱います。';
$labels['wa_title'] = 'セキュリティキー・Windows Hello';
$labels['wa_desc'] = 'USB・NFC のセキュリティキー（FIDO2）や、この PC の Windows Hello を登録できます。登録したキーは「登録済みの端末」に表示されます。';
$labels['wa_add_button'] = 'セキュリティキー・Windows Hello を登録する';
$labels['pending_title'] = '承認待ちの端末';
$labels['pending_desc'] = '新しい端末に表示されているコードと同じであることを確かめてから、「承認する」にチェックを入れて保存してください。心当たりのない端末は承認しないでください（15分で自動的に無効になります）。';
$labels['pending_none'] = '承認待ちの端末はありません。';
$labels['devices_title'] = '登録済みの端末';
$labels['devices_desc'] = '使わなくなった端末や心当たりのない端末は、「削除」にチェックを入れて保存してください。';
$labels['devices_none'] = '登録済みの端末はありません。';
$labels['approve'] = '承認する';
$labels['delete'] = '削除';
$labels['this_device'] = '（この端末）';
$labels['kind_browser'] = 'ブラウザ';
$labels['kind_webauthn'] = 'セキュリティキー・Windows Hello';
$labels['col_none'] = '';
$labels['col_code'] = 'コード';
$labels['col_browser'] = 'ブラウザ';
$labels['col_requested'] = '登録要求日時';
$labels['col_ip'] = 'IPアドレス';
$labels['col_device'] = '端末';
$labels['col_registered'] = '登録日時';
$labels['col_lastused'] = '最終利用日時';
$labels['col_lastip'] = '最終利用IP';
$labels['wa_add_title'] = 'セキュリティキー・Windows Hello の登録';
$labels['wa_add_start'] = '登録する';
$labels['wa_name_label'] = '名前（キーを見分けるため）';
$labels['wa_name_placeholder'] = '例：青い USB キー、病棟 PC の Windows Hello';
$labels['wa_add_note'] = 'ブラウザが、セキュリティキーに触れるか、Windows Hello（PIN・指紋・顔）を使うよう案内します。';
$labels['wa_add_waiting'] = 'ブラウザの案内に従ってください…';
$labels['wa_add_ok'] = '登録しました。「設定 > 端末確認」で「セキュリティキー・Windows Hello」を選べるようになりました。';
$labels['wa_add_failed'] = '登録できませんでした: ';
$labels['back_to_settings'] = '設定に戻る';
$labels['err_request'] = '不正なリクエストです。画面を再読み込みしてください。';
$labels['err_expired'] = '確認の有効期限が切れました。';
$labels['err_outside'] = 'この端末は未登録です。院内ネットワークに接続した端末から一度ログインして登録してください。';
$labels['err_key'] = '鍵の検証に失敗しました。';
$labels['err_not_approved'] = 'この端末の登録は承認されませんでした。';
$labels['err_pending_expired'] = '承認の有効期限（15分）が切れました。もう一度ログインしてください。';
$labels['err_webauthn'] = 'セキュリティキー・Windows Hello を確認できませんでした。';
$labels['err_webauthn_add'] = 'セキュリティキー・Windows Hello を登録できませんでした。';
$labels['err_webauthn_dup'] = 'このキーはすでに登録されています。';
