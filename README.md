# device_mfa — device-bound second check for Roundcube (no phone needed)

A Roundcube plugin that adds a **device check after login**: the browser proves, with a non-extractable
key created on first use, that it is a device registered for this user. Designed for places where
**mobile phones cannot be used** (e.g. hospitals), so app/SMS based MFA is not an option.

*日本語の説明は下にあります。*

> **What this is, and what it is not.** Inside the allowed network, this plugin checks
> *the network the user is on* and *the browser profile they use*, in addition to the password.
> That is **not a formal multi-factor authentication** (network and device are not "something you have"
> in the strict sense, and the browser profile could be copied). Read [Security model](#security-model) before using it.

## On/off by IP address

The device check is switched **on or off by the client's IP address**:

| Client IP | Device check | Second check done by |
|---|---|---|
| inside `device_mfa_register_networks` (e.g. the hospital LAN) | **ON** — confirmation page, register / verify the device | this plugin (network + device key) |
| outside, `device_mfa_outside_mode = 'idp'` (default) | **OFF** — no confirmation page | the identity provider's MFA (e.g. Entra ID Conditional Access) |
| outside, `device_mfa_outside_mode = 'deny'` | **ON** — only registered devices; new registration refused | this plugin (device key) |

The client IP is `REMOTE_ADDR`, or `X-Forwarded-For` only when the request comes from a proxy listed in `proxy_whitelist`.

## What it can do


- After login (tested with Office 365 OAuth), a confirmation page asks "Log in on this device?" — the user presses **Yes**
- The browser signs a one-time server challenge with an **ECDSA P-256 key** created by WebCrypto
  with `extractable: false` and stored in IndexedDB; the server keeps only the public key
- A device is recognized only when **both** the HttpOnly cookie (device id) **and** the key in IndexedDB are present
- New devices can be registered only from **configured networks** (`device_mfa_register_networks`)
- Outside those networks: either rely on the identity provider's MFA (`'idp'`, default) or allow registered devices only (`'deny'`)
- Until the check passes, every request except logout is blocked (AJAX/iframe requests get 401)
- Each user can choose the strength in **Settings → 端末確認 (Device check)**:
  - **Standard**: inside the allowed network, a new device is registered by pressing Yes
  - **Strict (multi-factor)**: a new device shows an approval code (e.g. `9JB6-J34Q`) and must be approved
    from one of the user's already registered devices within 15 minutes
- Users can list and delete their own devices; admins have a CLI (`bin/device_mfa_admin.php`)

## Requirements

- Roundcube 1.7 (tested with 1.7.5, PHP 8.4), MySQL/MariaDB
- HTTPS (WebCrypto and `Secure` cookies require it)
- If a reverse proxy is in front of Roundcube, add it to `proxy_whitelist`, otherwise the network check sees the proxy address

## Installation

```bash
cd /usr/share/roundcubemail/plugins
git clone https://github.com/masarusanuki/roundcube-device-mfa.git device_mfa
mysql roundcubemail < device_mfa/SQL/mysql.initial.sql
cp device_mfa/config.inc.php.dist /etc/roundcubemail/device_mfa.inc.php    # edit device_mfa_register_networks
chown root:apache /etc/roundcubemail/device_mfa.inc.php && chmod 640 /etc/roundcubemail/device_mfa.inc.php
```
Add `'device_mfa'` to `$config['plugins']`.

> **Set `device_mfa_register_networks` before enabling the plugin.** If it is empty and
> `device_mfa_outside_mode` is `'deny'`, nobody can register a device.

Upgrading from a version without the strict mode: run `SQL/mysql/2026110501.sql`.

Web server examples (nginx / Apache, with PATH_INFO for the OAuth callback): [`examples/`](examples/).

### Admin CLI
```bash
bin/device_mfa_admin.php list [username]
bin/device_mfa_admin.php revoke <id>
bin/device_mfa_admin.php revoke-user <username>
# Roundcube in another place: RC_DIR=/var/www/roundcube bin/device_mfa_admin.php list
```
Log: `logs/device_mfa.log` (`/var/log/roundcubemail/device_mfa.log` with the RPM).

## How it works

```
login (OAuth) ─▶ login_after: reset "verified" flag
               ─▶ startup hook: not verified?
                    ├─ outside register networks and mode 'idp' → verified (IdP MFA)
                    └─ otherwise → confirmation page with a 32-byte challenge (5 min, single use)
browser: "Yes" ─▶ key in IndexedDB?
                    ├─ yes → sign challenge → POST verify (sig + cookie) → server checks with stored public key
                    └─ no  → generate key (non-extractable) → POST register (public key + sig)
                              ├─ standard (or no other device) → active
                              └─ strict → pending + approval code → approved on a registered device → active
```

| Part | Implementation |
|---|---|
| Gate | `startup` hook; the "verified" flag is an HMAC bound to the session id and user id |
| Challenge | 32 random bytes, valid 5 minutes, removed from the session before verification (replay protection) |
| Signature | WebCrypto ECDSA P-256/SHA-256 (`r‖s`) converted to DER and checked with `openssl_verify` |
| Public key | SPKI from the browser, curve must be `prime256v1`; registration requires a signature (proof of possession) |
| Cookie | `Secure`, `HttpOnly`, `SameSite=Lax`, 400 days, extended on each successful check |
| IndexedDB key name | HMAC of the user id (no e-mail address stored in clear on the device) |
| API | `POST` only, Roundcube request token in `X-Roundcube-Request` (CSRF) |
| Page | `X-Frame-Options: DENY`, `Cache-Control: no-store` |
| Data | table `device_mfa_devices` (public key, browser, created/last used time and IP, status, revoked) |

## Security model

What it helps against:
- A stolen **cookie alone** is useless without the private key, and vice versa
- **Replay** of a captured response (one-time, short-lived challenge)
- A leaked **database** (only public keys are stored)
- In strict mode: a stolen password used **from inside** the allowed network cannot register a new device

What it does **not** guarantee:
- In standard mode, anyone with the password **inside the allowed network** can register a device
- It identifies a **browser profile**, not hardware; copying the whole profile may copy the key
- On **shared PCs** it identifies the PC, not the person
- PCs that wipe browser data at logoff (or private windows) lose the key every time, so the check degrades to a network check
- Outside the allowed network with `'idp'`, security depends on the identity provider's MFA (Roundcube cannot verify it was performed)

## Limitations / TODO

- UI strings are Japanese only (no localization files yet)
- MySQL/MariaDB only (no PostgreSQL/SQLite schema yet)
- Under investigation: one report of the device cookie not being kept between logins (the same browser was registered several times)

## License

GPL-3.0-or-later

---

## 日本語

Roundcube のログイン後に**端末の確認**を追加するプラグインです。初回にブラウザ内で作った「取り出し不可」の鍵で、登録済みの端末であることを確かめます。
病院など**携帯電話を使えない場所**で、アプリや SMS による多要素認証の代わりに使うことを想定しています。

> **このプラグインでできること・できないこと**：許可したネットワークの中では、パスワードに加えて「どのネットワークから」「どのブラウザで」使っているかを確認します。これは**正式な多要素認証ではありません**（ネットワークや端末は、厳密な意味での「持っているもの」ではなく、ブラウザのプロファイルは複製できる可能性があります）。使う前に上の「Security model」を確認してください。

### IP アドレスで ON/OFF
端末確認は、**接続元の IP アドレスで ON/OFF が切り替わります**。

| 接続元の IP | 端末確認 | 第2の確認を行うもの |
|---|---|---|
| `device_mfa_register_networks` の中（例：院内 LAN） | **ON**：確認画面を表示し、端末を登録・確認する | このプラグイン（ネットワーク＋端末の鍵） |
| 外側で、`device_mfa_outside_mode = 'idp'`（既定） | **OFF**：確認画面を出さない | ID プロバイダーの多要素認証（例：Entra ID の条件付きアクセス） |
| 外側で、`device_mfa_outside_mode = 'deny'` | **ON**：登録済み端末だけ許可し、新しい登録は拒否 | このプラグイン（端末の鍵） |

接続元の IP は `REMOTE_ADDR` を使います。`X-Forwarded-For` は、`proxy_whitelist` に入っているプロキシ経由のときだけ信用します。

### できること
- ログイン後に「この端末でログインしますか？」と表示し、利用者が「はい」を押す
- ブラウザが WebCrypto で作った ECDSA P-256 の鍵（`extractable: false`、IndexedDB に保存）で、サーバーの使い捨てコードに署名する。サーバーは公開鍵だけを保存する
- HttpOnly の Cookie（端末ID）と IndexedDB の鍵が**両方そろったとき**だけ、登録済みの端末とみなす
- 新しい端末を登録できるのは、設定したネットワーク（`device_mfa_register_networks`）からだけ
- それ以外のネットワークからは、ID プロバイダーの多要素認証に任せる（`'idp'`、既定）か、登録済み端末だけを許可する（`'deny'`）
- 確認が済むまで、ログアウト以外の操作はすべて遮断する
- 利用者は「設定 > 端末確認」で強さを選べる
  - **標準**：許可したネットワークの中なら、「はい」で新しい端末を登録
  - **強化（多要素）**：新しい端末に承認コードを表示し、本人の登録済み端末で15分以内に承認する
- 利用者は自分の端末の一覧表示と削除ができる。管理者向けにはコマンド（`bin/device_mfa_admin.php`）がある

### 導入
上の Installation を参照してください。**有効にする前に `device_mfa_register_networks` を設定してください。** 空のままで `device_mfa_outside_mode` が `'deny'` だと、誰も端末を登録できません。

### 防げること
- **Cookie だけ**を盗まれても、秘密鍵がないと使えない（逆も同じ）
- 通信を記録して**再送**されても、使い捨てで短時間しか有効でないコードなので通らない
- **データベース**が漏れても、保存しているのは公開鍵だけなので、端末になりすませない
- 強化モードでは、パスワードを盗まれても、**許可したネットワークの中から**新しい端末を登録されない

### 保証できないこと
- 標準モードでは、許可したネットワークの中にいれば、パスワードを知っている人は誰でも端末を登録できる
- 確認できるのはブラウザのプロファイルで、ハードウェアではない（プロファイルを丸ごと複製すると鍵も移る可能性がある）
- 共用 PC では「人」ではなく「PC」の確認になる
- ログオフ時にブラウザのデータを消す PC やプライベートウィンドウでは、毎回鍵が消えるため、実質的にネットワークの確認だけになる
- ネットワークの外で `'idp'` の場合、安全性は ID プロバイダーの多要素認証に依存する（Roundcube からは実施されたかを確認できない）
