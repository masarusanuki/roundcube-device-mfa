/* device_mfa: registration of a security key / Windows Hello (WebAuthn). Inlined by device_mfa.php. */
(function () {
  'use strict';

  var C = window.DEVICE_MFA;
  var T = C.t || {};
  var msg = document.getElementById('msg');
  var retry = document.getElementById('retry');
  var yes = document.getElementById('yes');
  var nameInput = document.getElementById('waname');

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

  function b64u(buf) {
    var bin = '', bytes = new Uint8Array(buf);
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function fromB64u(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  retry.addEventListener('click', function () { location.href = C.reloadUrl; });

  if (!window.PublicKeyCredential || !navigator.credentials) {
    show(T.wa_unsupported, 'err');
    return;
  }

  msg.textContent = '';
  yes.hidden = false;

  yes.addEventListener('click', function () {
    yes.hidden = true;
    show(T.wa_add_waiting, '', true);

    navigator.credentials.create({
      publicKey: {
        rp: { id: C.rpId, name: C.rpName },
        user: { id: fromB64u(C.userId), name: C.userName, displayName: C.userName },
        challenge: fromB64u(C.challenge),
        pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
        authenticatorSelection: { userVerification: 'preferred', residentKey: 'discouraged' },
        excludeCredentials: C.exclude.map(function (id) { return { type: 'public-key', id: fromB64u(id) }; }),
        attestation: 'none',
        timeout: 120000
      }
    })
      .then(function (cred) {
        return fetch(C.addUrl, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json', 'X-Roundcube-Request': C.token },
          body: JSON.stringify({
            name: nameInput ? nameInput.value : '',
            clientDataJSON: b64u(cred.response.clientDataJSON),
            attestationObject: b64u(cred.response.attestationObject)
          })
        }).then(function (r) { return r.json(); });
      })
      .then(function (res) {
        if (res.status === 'ok') {
          show(T.wa_add_ok, 'ok');
          return;
        }
        if (res.status === 'retry') {
          location.href = C.reloadUrl;
          return;
        }
        show(res.message || T.wa_add_failed, 'err');
        retry.hidden = false;
      })
      .catch(function (e) {
        show(T.wa_add_failed + (e && e.message ? e.message : e), 'err');
        retry.hidden = false;
      });
  });
})();
