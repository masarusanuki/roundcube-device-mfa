# device_mfa — device-bound second check for Roundcube (no phone needed)

A Roundcube plugin that adds a **device check after login**. Designed for places where
**mobile phones cannot be used** (e.g. hospitals), so app/SMS based MFA is not an option.
Users choose one of three strengths:

| Strength | What is checked after the password | |
|---|---|---|
| **Standard** | the network (IP address) + a key stored in this browser | default |
| **Strict** | as Standard, but a new device must be approved on an already registered device | |
| **Security key / Windows Hello** | a FIDO2 security key or Windows Hello (WebAuthn) on every login | **real two-factor authentication** |

Administrators decide which strengths are offered with `device_mfa_modes` — e.g. `['standard']` for
"network + confirmation page only" with no choice shown to users.

*日本語の説明は下にあります。*

> **What Standard and Strict are, and what they are not.** They check *the network the user is on* and
> *the browser profile they use*, in addition to the password. That is **not a formal multi-factor
> authentication** (network and browser are not "something you have" in the strict sense, and a browser
> profile could be copied). The **Security key / Windows Hello** strength is. Read [Security model](#security-model).

## On/off by IP address

The device check (Standard / Strict) is switched **on or off by the client's IP address**:

| Client IP | Device check | Second check done by |
|---|---|---|
| inside `device_mfa_register_networks` (e.g. the hospital LAN) | **ON** — confirmation page, register / verify the device | this plugin (network + browser key) |
| outside, `device_mfa_outside_mode = 'deny'` (default) | **ON** — only registered devices; new registration refused | this plugin (browser key) |
| outside, `device_mfa_outside_mode = 'idp'` | **OFF** — no confirmation page | the identity provider's MFA (e.g. Entra ID Conditional Access) |

Users who chose **Security key / Windows Hello** are always checked, inside and outside.
The client IP is `REMOTE_ADDR`, or `X-Forwarded-For` only when the request comes from a proxy listed in `proxy_whitelist`.

## Do I need Office 365?

**No.** This plugin does not use Office 365 at all. It runs after any Roundcube login — a normal
IMAP password login (Dovecot, Postfix, …) works the same way. It was developed on a Roundcube that
signs in with Office 365, which is the only reason Office 365 is mentioned here.

Choose `device_mfa_outside_mode` by how your users sign in:

| How users sign in | `device_mfa_outside_mode` | Result outside the allowed networks |
|---|---|---|
| Normal password (no identity provider) — **most installations** | **`'deny'`** (default) | only devices registered inside can log in; password alone is not enough |
| Office 365 / another identity provider that **enforces MFA outside** your network (e.g. Entra ID Conditional Access) | `'idp'` | no device check; the identity provider's MFA is the second check |

> With `'idp'` but **no MFA at the identity provider**, access from outside is protected by the password only.
> Roundcube cannot see whether the identity provider performed MFA, so only use `'idp'` when you are sure it does.

Typical flow for a password-only installation:
1. Set `device_mfa_register_networks` to your internal network (and its NAT address if Roundcube sees that).
2. Users log in once **from inside** and press "Yes" — the browser is registered.
3. From then on that browser can also log in from outside; other browsers cannot, unless registered inside first.

## What it can do

- After login (any login method), a confirmation page asks "Log in on this device?" — the user presses **Yes**
- **Browser key**: the browser signs a one-time server challenge with an **ECDSA P-256 key** created by WebCrypto
  with `extractable: false` and stored in IndexedDB; the server keeps only the public key.
  The device id is kept in an HttpOnly cookie **and** next to the key, so a lost cookie is restored automatically
  (the key's signature is still required)
- **Security key / Windows Hello (WebAuthn)**: users register FIDO2 security keys (USB/NFC) or Windows Hello in Settings
  and then confirm every login with them. ES256 and RS256 keys are supported; the signature counter is checked
- New browsers can be registered only from **configured networks** (`device_mfa_register_networks`)
- Until the check passes, every request except logout is blocked (AJAX/iframe requests get 401)
- **Settings → Device check**: choose the strength, register security keys, approve waiting devices (Strict), list and delete devices
- On the confirmation page, "Use multi-factor with my own device" switches Standard → Strict (never weaker)
- **Languages**: English and Japanese (follows the user's language; others fall back to English)
- **Databases**: MySQL/MariaDB, PostgreSQL, SQLite
- Admin CLI: list, revoke, reset a user who lost a key

## Requirements

- Roundcube 1.7 (tested with 1.7.5, PHP 8.4)
- MySQL/MariaDB, PostgreSQL or SQLite
- HTTPS (WebCrypto, WebAuthn and `Secure` cookies require it)
- If a reverse proxy is in front of Roundcube, add it to `proxy_whitelist`, otherwise the network check sees the proxy address

## Installation

```bash
cd /usr/share/roundcubemail/plugins
git clone https://github.com/masarusanuki/roundcube-device-mfa.git device_mfa
# create the table (choose your database)
mysql roundcubemail < device_mfa/SQL/mysql.initial.sql
#   psql roundcubemail < device_mfa/SQL/postgres.initial.sql
#   sqlite3 /path/to/roundcube.db < device_mfa/SQL/sqlite.initial.sql
cp device_mfa/config.inc.php.dist /etc/roundcubemail/device_mfa.inc.php    # edit device_mfa_register_networks
chown root:apache /etc/roundcubemail/device_mfa.inc.php && chmod 640 /etc/roundcubemail/device_mfa.inc.php
```
Add `'device_mfa'` to `$config['plugins']`.

> **Set `device_mfa_register_networks` before enabling the plugin.** If it is empty (with the default `'deny'`),
> nobody can register a device and nobody can log in.

**Upgrading (MySQL)**: from v1.0 run `SQL/mysql/2026110501.sql` (if not yet) and `SQL/mysql/2026110601.sql`.

Web server examples (nginx / Apache, with PATH_INFO for the OAuth callback): [`examples/`](examples/).
Behind a reverse proxy that changes the host name, set `device_mfa_webauthn_rp_id` / `device_mfa_webauthn_origin`.

### Admin CLI
```bash
bin/device_mfa_admin.php list [username]
bin/device_mfa_admin.php revoke <id>
bin/device_mfa_admin.php revoke-user <username>
bin/device_mfa_admin.php reset-user <username>    # lost security key: revoke all, strength back to Standard
# Roundcube in another place: RC_DIR=/var/www/roundcube bin/device_mfa_admin.php list
```
Log: `logs/device_mfa.log` (`/var/log/roundcubemail/device_mfa.log` with the RPM). Re-registrations are logged
with the reason (`reason=no_key|server_unregistered cookie=yes|no`), and restored cookies as `cookie RESTORED`.

## How it works

```
login (any) ──▶ login_after: reset "verified" flag
              ─▶ startup hook: not verified?
                   ├─ strength = security key → WebAuthn page (inside and outside)
                   ├─ outside register networks and mode 'idp' → verified (IdP MFA)
                   └─ otherwise → confirmation page with a 32-byte challenge (5 min, single use)
browser key:  key in IndexedDB?
                   ├─ yes → sign → POST verify (sig + cookie or stored device id) → check with stored public key
                   └─ no  → generate key (non-extractable) → POST register (public key + sig)
                             ├─ Standard (or no other device) → active
                             └─ Strict → pending + approval code → approved on a registered device → active
WebAuthn:     navigator.credentials.get (allowCredentials) → POST → verify clientData, rpIdHash, flags,
              counter and signature over authenticatorData ‖ SHA-256(clientDataJSON)
```

| Part | Implementation |
|---|---|
| Gate | `startup` hook; the "verified" flag is an HMAC bound to the session id and user id |
| Challenge | 32 random bytes, valid 5 minutes, removed from the session before verification (replay protection) |
| Browser key | WebCrypto ECDSA P-256/SHA-256 (`r‖s`) → DER → `openssl_verify`; SPKI must be `prime256v1`; registration requires a signature |
| WebAuthn | `lib/device_mfa_webauthn.php`: small CBOR decoder, COSE (ES256/RS256) → PEM, attestation `none` (statement not verified), origin / rpId / UP flag / counter checks |
| Cookie | `Secure`, `HttpOnly`, `SameSite=Lax`, 400 days, extended on each successful check |
| IndexedDB key name | HMAC of the user id (no e-mail address stored in clear on the device) |
| API | `POST` only, Roundcube request token in `X-Roundcube-Request` (CSRF) |
| Page | `X-Frame-Options: DENY`, `Cache-Control: no-store` |
| Data | table `device_mfa_devices` (kind, public key, credential id, counter, name, browser, created/last used time and IP, status, revoked) |
| Pending expiry | evaluated by the database (`created > now - 15 min`), so it works with any database clock / time zone |

## Security model

What it helps against:
- A stolen **cookie alone** is useless without the private key
- **Replay** of a captured response (one-time, short-lived challenge; WebAuthn signature counter)
- A leaked **database** (only public keys are stored)
- In Strict: a stolen password used **from inside** the allowed network cannot register a new device
- With **Security key / Windows Hello**: a stolen password is useless without the key, from anywhere; phishing sites
  cannot use the key (WebAuthn is bound to the origin); a personal USB key also works on **shared PCs**

What it does **not** guarantee:
- In Standard, anyone with the password **inside the allowed network** can register a browser
- Browser keys identify a **browser profile**, not hardware; copying the whole profile may copy the key
- On **shared PCs**, browser keys identify the PC, not the person (use personal security keys there)
- PCs that wipe browser data at logoff (or private windows) lose the browser key every time
- Outside the allowed network with `'idp'`, security depends on the identity provider's MFA (Roundcube cannot verify it was performed)
- The WebAuthn attestation statement is not verified (any FIDO2 authenticator is accepted)

## Limitations

- WebAuthn and PostgreSQL were tested with generated test data and a schema review only:
  please report results with real security keys / Windows Hello and real PostgreSQL servers
- Approval by a registered device (Strict) needs the user to have another registered device

## License

GPL-3.0-or-later

---

## 日本語

Roundcube のログイン後に**端末の確認**を追加するプラグインです。病院など**携帯電話を使えない場所**で、アプリや SMS による多要素認証の代わりに使うことを想定しています。
利用者は3つの強さから選べます。

| 強さ | パスワードに加えて確認するもの | |
|---|---|---|
| **標準** | ネットワーク（IP アドレス）＋このブラウザに保存した鍵 | 既定 |
| **強化** | 標準と同じ。ただし新しい端末は、登録済みの端末での承認が必要 | |
| **セキュリティキー・Windows Hello** | ログインのたびに FIDO2 のセキュリティキーか Windows Hello（WebAuthn） | **正式な二要素認証** |

管理者は `device_mfa_modes` で、利用者に見せる強さを絞れます。たとえば `['standard']` にすると「IP アドレス＋確認画面」だけになり、選択肢は表示されません。

> **標準と強化について**：パスワードに加えて「どのネットワークから」「どのブラウザで」使っているかを確認します。これは**正式な多要素認証ではありません**（ネットワークやブラウザは、厳密な意味での「持っているもの」ではなく、ブラウザのプロファイルは複製できる可能性があります）。「セキュリティキー・Windows Hello」は正式な二要素認証です。

### IP アドレスで ON/OFF
端末確認（標準・強化）は、**接続元の IP アドレスで ON/OFF が切り替わります**。

| 接続元の IP | 端末確認 | 第2の確認を行うもの |
|---|---|---|
| `device_mfa_register_networks` の中（例：院内 LAN） | **ON**：確認画面を表示し、端末を登録・確認する | このプラグイン（ネットワーク＋ブラウザの鍵） |
| 外側で、`device_mfa_outside_mode = 'deny'`（既定） | **ON**：登録済み端末だけ許可し、新しい登録は拒否 | このプラグイン（ブラウザの鍵） |
| 外側で、`device_mfa_outside_mode = 'idp'` | **OFF**：確認画面を出さない | ID プロバイダーの多要素認証（例：Entra ID の条件付きアクセス） |

「セキュリティキー・Windows Hello」を選んだ利用者は、院内・院外を問わず毎回確認します。
接続元の IP は `REMOTE_ADDR` を使います。`X-Forwarded-For` は、`proxy_whitelist` に入っているプロキシ経由のときだけ信用します。

### Office 365 は必要？
**不要です。** このプラグインは Office 365 を一切使いません。Roundcube にログインした後に動くので、普通のパスワードでのログイン（Dovecot や Postfix などのメールサーバー）でも同じように使えます。Office 365 の名前が出てくるのは、Office 365 でログインする Roundcube で開発したためです。

`device_mfa_outside_mode` は、利用者のログイン方法に合わせて選んでください。

| ログイン方法 | `device_mfa_outside_mode` | 許可ネットワークの外からのアクセス |
|---|---|---|
| 普通のパスワード（ID プロバイダーなし）— **ほとんどの環境** | **`'deny'`**（既定） | 院内で登録した端末だけがログインできる。パスワードだけでは入れない |
| Office 365 など、**外からは多要素認証を求める** ID プロバイダー（例：Entra ID の条件付きアクセス） | `'idp'` | 端末確認をせず、ID プロバイダーの多要素認証を第2の確認とする |

> ID プロバイダー側で多要素認証をしていないのに `'idp'` にすると、外からはパスワードだけで入れてしまいます。Roundcube からは ID プロバイダーが多要素認証をしたかどうかを確認できないので、確実に設定されている場合だけ `'idp'` を使ってください。

パスワードでログインする環境での、典型的な使い方：
1. `device_mfa_register_networks` に院内（社内）のネットワークを設定する（Roundcube から見える NAT のアドレスも）
2. 利用者は一度**院内から**ログインし、「はい」を押す。これでそのブラウザが登録される
3. 以後、そのブラウザは院外からもログインできる。ほかのブラウザは、院内で登録しない限りログインできない

### できること
- ログイン後に「この端末でログインしますか？」と表示し、利用者が「はい」を押す
- **ブラウザの鍵**：WebCrypto で作った ECDSA P-256 の鍵（`extractable: false`、IndexedDB に保存）で、サーバーの使い捨てコードに署名する。サーバーは公開鍵だけを保存する。端末IDは HttpOnly の Cookie と、鍵の隣の両方に保存するので、Cookie だけが消えても自動で戻る（鍵の署名は必ず必要）
- **セキュリティキー・Windows Hello（WebAuthn）**：利用者が設定画面で FIDO2 のセキュリティキー（USB・NFC）や Windows Hello を登録し、ログインのたびにそれで確認する。ES256 と RS256 に対応し、署名カウンターも確認する
- 新しいブラウザを登録できるのは、設定したネットワーク（`device_mfa_register_networks`）からだけ
- 確認が済むまで、ログアウト以外の操作はすべて遮断する
- **設定 > 端末確認**：強さの選択、セキュリティキーの登録、承認待ちの端末の承認（強化）、端末の一覧表示と削除
- 確認画面の「自分の端末での多要素認証を使う」で、標準 → 強化に切り替えられる（弱める方向は不可）
- **言語**：英語・日本語（利用者の言語設定に合わせる。その他の言語は英語）
- **データベース**：MySQL/MariaDB、PostgreSQL、SQLite
- 管理者向けのコマンド：一覧、失効、キーをなくした利用者のリセット

### 導入
上の Installation を参照してください。**有効にする前に `device_mfa_register_networks` を設定してください。** 空のままだと（既定の `'deny'` では）、誰も端末を登録できず、ログインできなくなります。
MySQL で以前の版から更新する場合は、`SQL/mysql/2026110501.sql`（未実行なら）と `SQL/mysql/2026110601.sql` を実行してください。
キーをなくした利用者は、管理者が `bin/device_mfa_admin.php reset-user <利用者>` で全端末を失効させ、強さを「標準」に戻せます。

### 防げること
- **Cookie だけ**を盗まれても、秘密鍵がないと使えない
- 通信を記録して**再送**されても、使い捨てで短時間しか有効でないコード（WebAuthn では署名カウンターも）なので通らない
- **データベース**が漏れても、保存しているのは公開鍵だけなので、端末になりすませない
- 強化では、パスワードを盗まれても、**許可したネットワークの中から**新しい端末を登録されない
- **セキュリティキー・Windows Hello** では、どこからでも、キーがなければパスワードだけでは入れない。偽サイトではキーが使えない（WebAuthn はサイトのアドレスに結び付く）。個人の USB キーなら**共用 PC**でも本人の確認になる

### 保証できないこと
- 標準では、許可したネットワークの中にいれば、パスワードを知っている人は誰でもブラウザを登録できる
- ブラウザの鍵で確認できるのはブラウザのプロファイルで、ハードウェアではない（プロファイルを丸ごと複製すると鍵も移る可能性がある）
- 共用 PC では、ブラウザの鍵は「人」ではなく「PC」の確認になる（共用 PC では個人のセキュリティキーを使う）
- ログオフ時にブラウザのデータを消す PC やプライベートウィンドウでは、毎回ブラウザの鍵が消える
- ネットワークの外で `'idp'` の場合、安全性は ID プロバイダーの多要素認証に依存する（Roundcube からは実施されたかを確認できない）
- WebAuthn の構成証明（attestation）は検証しない（どの FIDO2 の認証器でも受け付ける）

### 制限
- WebAuthn と PostgreSQL は、テスト用に作ったデータとテーブル定義の確認でしか試していません。実際のセキュリティキー・Windows Hello や PostgreSQL での結果を教えていただけると助かります
- 強化での承認には、ほかに登録済みの端末が必要です
