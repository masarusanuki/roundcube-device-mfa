/* device_mfa: check page (browser key or WebAuthn). Inlined into the page by device_mfa.php.
   The file extension is .inc because some mail systems reject archives that contain .js files. */
(function () {
  'use strict';

  var C = window.DEVICE_MFA;
  var T = C.t || {};
  var DB_NAME = 'roundcube_device_mfa';
  var STORE = 'keys';
  var msg = document.getElementById('msg');
  var retry = document.getElementById('retry');
  var yes = document.getElementById('yes');
  var mfa = document.getElementById('mfa');

  function show(text, cls, busy) {
    msg.className = cls || '';
    msg.textContent = '';
    if (busy) {
      var s = document.createElement('span');
      s.className = 'spin';
      msg.appendChild(s);
    }
    msg.appendChild(document.createTextNode(text));
  }

  function fail(text) {
    show(text, 'err');
    yes.hidden = true;
    retry.hidden = false;
  }

  retry.addEventListener('click', function () { location.href = C.reloadUrl; });

  // Wait until "Yes" is pressed / 「はい」が押されるまで待つ
  function ask(text) {
    show(text);
    yes.hidden = false;
    yes.focus();
    return new Promise(function (resolve) {
      yes.addEventListener('click', function () {
        yes.hidden = true;
        resolve();
      }, { once: true });
    });
  }

  // "Use multi-factor with my own device" survives the reload of the re-registration flow
  function strictFlag() { return !!(mfa && mfa.checked); }
  try {
    if (mfa && sessionStorage.getItem('device_mfa_strict') === '1') mfa.checked = true;
    if (mfa) mfa.addEventListener('change', function () {
      try { sessionStorage.setItem('device_mfa_strict', mfa.checked ? '1' : '0'); } catch (e) {}
    });
  } catch (e) {}

  function post(url, body) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Roundcube-Request': C.token },
      body: JSON.stringify(body)
    }).then(function (r) { return r.json(); });
  }

  // ---- base64 helpers
  function b64(buf) {
    var bin = '', bytes = new Uint8Array(buf);
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }
  function b64u(buf) { return b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
  function fromB64u(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // ---- IndexedDB
  function openDb() {
    return new Promise(function (resolve, reject) {
      var req = indexedDB.open(DB_NAME, 1);
      req.onupgradeneeded = function () { req.result.createObjectStore(STORE); };
      req.onsuccess = function () { resolve(req.result); };
      req.onerror = function () { reject(req.error); };
    });
  }
  function idb(mode, fn) {
    return openDb().then(function (db) {
      return new Promise(function (resolve, reject) {
        var tx = db.transaction(STORE, mode);
        var req = fn(tx.objectStore(STORE));
        tx.oncomplete = function () { db.close(); resolve(req && req.result); };
        tx.onerror = function () { db.close(); reject(tx.error); };
      });
    });
  }
  var getKey = function () { return idb('readonly', function (s) { return s.get(C.keyRef); }); };
  var putKey = function (v) { return idb('readwrite', function (s) { return s.put(v, C.keyRef); }); };
  var delKey = function () { return idb('readwrite', function (s) { return s.delete(C.keyRef); }); };

  // Keep the device id next to the key, so that a lost cookie can be restored
  // 端末IDも鍵と一緒に保存し、Cookie が消えたときに戻せるようにする
  function rememberDeviceId(rec, res) {
    if (rec && res && res.device_id && rec.deviceId !== res.device_id) {
      rec.deviceId = res.device_id;
      return putKey(rec).catch(function () {});
    }
    return Promise.resolve();
  }

  function sign(privateKey) {
    return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, new TextEncoder().encode(C.challenge));
  }

  function done(res) {
    if (res.status === 'ok') {
      show(T.ok_redirect, 'ok', true);
      location.replace(res.redirect);
      return true;
    }
    if (res.status === 'retry') {
      location.href = C.reloadUrl; // new challenge / 新しいチャレンジで再実行
      return true;
    }
    if (res.status === 'pending') {
      waitApproval(res.code);
      return true;
    }
    if (res.status === 'denied' || res.status === 'error') {
      fail(res.message || T.failed);
      return true;
    }
    return false;
  }

  // Strict mode: wait until a registered device approves / 登録済み端末で承認されるまで待つ
  function waitApproval(code) {
    msg.className = '';
    msg.textContent = '';
    msg.appendChild(document.createTextNode(T.wait_approval));
    var c = document.createElement('span');
    c.className = 'code';
    c.textContent = code;
    msg.appendChild(c);
    var s = document.createElement('span');
    s.className = 'spin';
    msg.appendChild(s);
    msg.appendChild(document.createTextNode(T.waiting));

    var timer = setInterval(function () {
      post(C.statusUrl, {}).then(function (res) {
        if (res.status === 'pending') return;
        clearInterval(timer);
        done(res);
      }).catch(function () {});
    }, 3000);
  }

  // Reason of a re-registration after a reload (diagnostics) / 再登録の理由（原因調査用）
  var regReason = 'no_key';
  try {
    regReason = sessionStorage.getItem('device_mfa_reason') || 'no_key';
    sessionStorage.removeItem('device_mfa_reason');
  } catch (e) {}

  // ---- browser key flow / ブラウザの鍵
  function register() {
    show(T.registering, '', true);
    var keyPair;
    return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])
      .then(function (kp) {
        keyPair = kp;
        return Promise.all([crypto.subtle.exportKey('spki', kp.publicKey), sign(kp.privateKey)]);
      })
      .then(function (r) {
        return post(C.registerUrl, { pub: b64(r[0]), sig: b64(r[1]), strict: strictFlag(), reason: regReason });
      })
      .then(function (res) {
        if (res.status !== 'ok' && res.status !== 'pending') return done(res);
        // The private key stays non-extractable inside the stored CryptoKey object
        // 秘密鍵は取り出し不可のまま CryptoKey として保存する（承認待ちでも保存しておく）
        return putKey({ privateKey: keyPair.privateKey, deviceId: res.device_id || '', created: Date.now() })
          .then(function () { done(res); });
      });
  }

  function browserFlow() {
    if (!window.crypto || !crypto.subtle || !window.indexedDB) {
      fail(T.unsupported);
      return;
    }
    if (navigator.storage && navigator.storage.persist) {
      navigator.storage.persist().catch(function () {});
    }

    getKey()
      .then(function (rec) {
        if (!rec || !rec.privateKey) {
          return ask(T.ask_register).then(register);
        }
        return ask(T.ask_verify)
          .then(function () {
            show(T.verifying, '', true);
            return sign(rec.privateKey);
          })
          .then(function (sig) {
            return post(C.verifyUrl, { sig: b64(sig), device_id: rec.deviceId || '', strict: strictFlag() });
          })
          .then(function (res) {
            return rememberDeviceId(rec, res).then(function () {
              if (done(res)) return;
              // Unregistered on the server (revoked / expired / unknown): drop the key and register again
              // with a new challenge / サーバー側で未登録 → 鍵を捨て、新しいチャレンジで登録し直す
              try { sessionStorage.setItem('device_mfa_reason', 'server_unregistered'); } catch (e) {}
              return delKey().then(function () { location.href = C.reloadUrl; });
            });
          });
      })
      .catch(function (e) {
        fail(T.failed + (e && e.message ? e.message : e));
      });
  }

  // ---- WebAuthn flow / セキュリティキー・Windows Hello
  function webauthnFlow() {
    if (!window.PublicKeyCredential || !navigator.credentials) {
      fail(T.wa_unsupported);
      return;
    }
    ask(T.wa_ask)
      .then(function () {
        show(T.wa_waiting, '', true);
        return navigator.credentials.get({
          publicKey: {
            challenge: fromB64u(C.challenge),
            rpId: C.rpId,
            allowCredentials: C.allow.map(function (id) { return { type: 'public-key', id: fromB64u(id) }; }),
            userVerification: 'preferred',
            timeout: 120000
          }
        });
      })
      .then(function (cred) {
        return post(C.waVerifyUrl, {
          id: cred.id,
          clientDataJSON: b64u(cred.response.clientDataJSON),
          authenticatorData: b64u(cred.response.authenticatorData),
          signature: b64u(cred.response.signature)
        });
      })
      .then(function (res) { done(res); })
      .catch(function (e) {
        fail(T.wa_failed + (e && e.message ? e.message : e));
      });
  }

  if (C.mode === 'webauthn') {
    webauthnFlow();
  } else {
    browserFlow();
  }
})();
