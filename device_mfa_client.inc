(function () {
  'use strict';

  var C = window.DEVICE_MFA;
  var DB_NAME = 'roundcube_device_mfa';
  var STORE = 'keys';
  var msg = document.getElementById('msg');
  var retry = document.getElementById('retry');

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
    retry.hidden = false;
  }

  var yes = document.getElementById('yes');
  var mfa = document.getElementById('mfa');

  // 「自分の端末での多要素認証を使う」のチェック状態（オンにする方向のみ送信）
  function strictFlag() { return !!(mfa && mfa.checked); }

  // 再読み込み（再登録の流れ）でもチェック状態を引き継ぐ
  try {
    if (mfa && sessionStorage.getItem('device_mfa_strict') === '1') mfa.checked = true;
    if (mfa) mfa.addEventListener('change', function () {
      try { sessionStorage.setItem('device_mfa_strict', mfa.checked ? '1' : '0'); } catch (e) {}
    });
  } catch (e) {}

  retry.addEventListener('click', function () { location.href = C.reloadUrl; });

  // 「はい」が押されるまで待つ
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

  // ---- IndexedDB ----
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

  // ---- 署名・通信 ----
  function b64(buf) {
    var bin = '', bytes = new Uint8Array(buf);
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function sign(privateKey) {
    return crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey,
      new TextEncoder().encode(C.challenge));
  }

  function post(url, body) {
    return fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-Roundcube-Request': C.token },
      body: JSON.stringify(body)
    }).then(function (r) { return r.json(); });
  }

  function done(res) {
    if (res.status === 'ok') {
      show('確認できました。メール画面に移動します…', 'ok', true);
      location.replace(res.redirect);
      return true;
    }
    if (res.status === 'retry') {
      location.href = C.reloadUrl; // 新しいチャレンジで再実行
      return true;
    }
    if (res.status === 'pending') {
      waitApproval(res.code);
      return true;
    }
    if (res.status === 'denied' || res.status === 'error') {
      fail(res.message || 'エラーが発生しました。');
      return true;
    }
    return false;
  }

  // 強化モード: 登録済みの端末で承認されるまで待つ
  function waitApproval(code) {
    msg.className = '';
    msg.textContent = '';
    msg.appendChild(document.createTextNode(
      'この端末を使うには、本人の登録済みの端末での承認が必要です。登録済みの端末で「設定 > 端末確認」を開き、次のコードと同じものを承認してください。'));
    var c = document.createElement('span');
    c.className = 'code';
    c.textContent = code;
    msg.appendChild(c);
    var s = document.createElement('span');
    s.className = 'spin';
    msg.appendChild(s);
    msg.appendChild(document.createTextNode('承認を待っています（15分で無効になります）…'));

    var timer = setInterval(function () {
      post(C.statusUrl, {}).then(function (res) {
        if (res.status === 'pending') return;
        clearInterval(timer);
        done(res);
      }).catch(function () {});
    }, 3000);
  }

  function register() {
    show('この端末を登録しています…', '', true);
    var keyPair;
    return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])
      .then(function (kp) {
        keyPair = kp;
        return Promise.all([crypto.subtle.exportKey('spki', kp.publicKey), sign(kp.privateKey)]);
      })
      .then(function (r) { return post(C.registerUrl, { pub: b64(r[0]), sig: b64(r[1]), strict: strictFlag() }); })
      .then(function (res) {
        if (res.status !== 'ok' && res.status !== 'pending') return done(res);
        // 秘密鍵は取り出し不可のまま CryptoKey オブジェクトとして保存（承認待ちでも保存しておく）
        return putKey({ privateKey: keyPair.privateKey, created: Date.now() })
          .then(function () { done(res); });
      });
  }

  function start() {
    if (!window.crypto || !crypto.subtle || !window.indexedDB) {
      fail('このブラウザは端末確認に対応していません（HTTPS接続と最新のブラウザが必要です）。');
      return;
    }

    if (navigator.storage && navigator.storage.persist) {
      navigator.storage.persist().catch(function () {});
    }

    getKey()
      .then(function (rec) {
        if (!rec || !rec.privateKey) {
          return ask('この端末はまだ登録されていません。接続元のIPアドレスに加えて、このブラウザのキャッシュに端末確認用の情報を保存して、この端末を登録しますか？')
            .then(register);
        }
        return ask('接続元のIPアドレスに加えて、ブラウザのキャッシュに保存された情報で、登録済みの端末であることを確認します。この端末でログインしますか？')
          .then(function () {
            show('確認しています…', '', true);
            return sign(rec.privateKey);
          })
          .then(function (sig) { return post(C.verifyUrl, { sig: b64(sig), strict: strictFlag() }); })
          .then(function (res) {
            if (done(res)) return;
            // unregistered: サーバ側で失効/期限切れ/Cookie消失 → 古い鍵を捨てて再登録を試みる
            // (チャレンジは使い捨てのため、ページを読み直して新しいチャレンジで登録)
            return delKey().then(function () { location.href = C.reloadUrl; });
          });
      })
      .catch(function (e) {
        fail('端末確認に失敗しました: ' + (e && e.message ? e.message : e));
      });
  }

  start();
})();
