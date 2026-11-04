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
$labels['title'] = 'Device check';
$labels['checking'] = 'Checking whether this device is registered…';
$labels['yes'] = 'Yes';
$labels['retry'] = 'Retry';
$labels['logout'] = 'Log out';
$labels['note'] = 'This check uses your IP address and data stored in this browser (its cache) to confirm that this is a registered device and browser. If you clear the browser\'s cache or browsing data, use another browser, or use a private window, the device has to be registered again.';
$labels['ask_verify'] = 'Your IP address and the information stored in this browser\'s cache are used to confirm that this is a registered device. Log in on this device?';
$labels['ask_register'] = 'This device is not registered yet. Store device check information in this browser\'s cache (in addition to your IP address) and register this device?';
$labels['verifying'] = 'Checking…';
$labels['registering'] = 'Registering this device…';
$labels['ok_redirect'] = 'Confirmed. Opening your mailbox…';
$labels['wait_approval'] = 'This device must be approved on one of your registered devices. On a registered device, open Settings > Device check and approve the same code:';
$labels['waiting'] = 'Waiting for approval (expires in 15 minutes)…';
$labels['unsupported'] = 'This browser does not support the device check (HTTPS and an up-to-date browser are required).';
$labels['failed'] = 'Device check failed: ';
$labels['optin_title'] = 'Use multi-factor with my own device';
$labels['optin_desc'] = 'When turned on, registering a new device will require approval on one of your registered devices. Even if your password leaks, nobody can register a device from inside the network. (You can change this later in Settings > Device check.)';
$labels['optin_on_title'] = 'Multi-factor with your own device: on';
$labels['optin_on_desc'] = 'Registering a new device requires approval on one of your registered devices. You can change this after login in Settings > Device check.';
$labels['wa_button'] = 'Use security key / Windows Hello';
$labels['wa_ask'] = 'Confirm with your security key or Windows Hello.';
$labels['wa_waiting'] = 'Follow your browser\'s instructions (touch the key, or enter your PIN / use your fingerprint)…';
$labels['wa_failed'] = 'Could not confirm with the security key / Windows Hello: ';
$labels['wa_unsupported'] = 'This browser does not support security keys / Windows Hello (WebAuthn).';
$labels['wa_note'] = 'You chose to confirm every login with a security key or Windows Hello. If you lost your key, ask your administrator to reset it.';
$labels['section'] = 'Device check';
$labels['strength'] = 'Strength';
$labels['mode_standard_title'] = 'Standard (authenticated by the internal IP address)';
$labels['mode_standard_desc'] = 'From the internal network, a new device is registered by just pressing "Yes".';
$labels['mode_strict_title'] = 'Strict (multi-factor)';
$labels['mode_strict_desc'] = 'Registering a new device requires approval on one of your already registered devices. Even if your password leaks, nobody can register a device from inside the network.';
$labels['mode_webauthn_title'] = 'Security key / Windows Hello (strongest)';
$labels['mode_webauthn_desc'] = 'Every login, inside and outside the network, must be confirmed with a registered security key or Windows Hello. Password + something you have: real two-factor authentication.';
$labels['mode_webauthn_need_key'] = 'Register a key first (below).';
$labels['mode_note'] = 'With Standard and Strict, access from outside the network follows the administrator\'s setting (registered devices only, or the identity provider\'s multi-factor authentication). If you choose the strongest setting but have no key left, Strict is used.';
$labels['wa_title'] = 'Security keys / Windows Hello';
$labels['wa_desc'] = 'Register a USB/NFC security key (FIDO2) or Windows Hello on this PC. Registered keys are listed under "Registered devices".';
$labels['wa_add_button'] = 'Register a security key / Windows Hello';
$labels['pending_title'] = 'Devices waiting for approval';
$labels['pending_desc'] = 'Check that the code is the same as the one shown on the new device, tick "Approve" and save. Do not approve devices you do not recognize (requests expire after 15 minutes).';
$labels['pending_none'] = 'No devices are waiting for approval.';
$labels['devices_title'] = 'Registered devices';
$labels['devices_desc'] = 'Tick "Delete" and save to remove devices you no longer use or do not recognize.';
$labels['devices_none'] = 'No registered devices.';
$labels['approve'] = 'Approve';
$labels['delete'] = 'Delete';
$labels['this_device'] = '(this device)';
$labels['kind_browser'] = 'Browser';
$labels['kind_webauthn'] = 'Security key / Windows Hello';
$labels['col_none'] = '';
$labels['col_code'] = 'Code';
$labels['col_browser'] = 'Browser';
$labels['col_requested'] = 'Requested';
$labels['col_ip'] = 'IP address';
$labels['col_device'] = 'Device';
$labels['col_registered'] = 'Registered';
$labels['col_lastused'] = 'Last used';
$labels['col_lastip'] = 'Last IP';
$labels['wa_add_title'] = 'Register a security key / Windows Hello';
$labels['wa_add_start'] = 'Register';
$labels['wa_name_label'] = 'Name (to tell your keys apart)';
$labels['wa_name_placeholder'] = 'e.g. Blue USB key, Ward PC Windows Hello';
$labels['wa_add_note'] = 'Your browser will ask you to touch the security key or to use Windows Hello (PIN, fingerprint, face).';
$labels['wa_add_waiting'] = 'Follow your browser\'s instructions…';
$labels['wa_add_ok'] = 'Registered. You can now choose "Security key / Windows Hello" in Settings > Device check.';
$labels['wa_add_failed'] = 'Could not register: ';
$labels['back_to_settings'] = 'Back to settings';
$labels['err_request'] = 'Invalid request. Please reload the page.';
$labels['err_expired'] = 'The check has expired.';
$labels['err_outside'] = 'This device is not registered. Log in once from a device connected to the internal network to register it.';
$labels['err_key'] = 'The key could not be verified.';
$labels['err_not_approved'] = 'Registration of this device was not approved.';
$labels['err_pending_expired'] = 'The approval request expired (15 minutes). Please log in again.';
$labels['err_webauthn'] = 'The security key / Windows Hello could not be verified.';
$labels['err_webauthn_add'] = 'The security key / Windows Hello could not be registered.';
$labels['err_webauthn_dup'] = 'This key is already registered.';
