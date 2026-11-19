// capy-auth: feedback for the passkey buttons that allauth's webauthn.js runs.
// allauth only writes a failed attempt (no passkey on this device, the person
// cancelled, a timeout, an old browser) to the browser console, so the button looks
// dead. This shows a message in the page's status line (capy_auth/passkeys/status.html,
// which holds the words, so they can be translated), hides the buttons on a browser
// that can't use passkeys, and stops a second press while one attempt is running.
(function () {
  'use strict'

  const BUTTON_IDS = [
    'passkey_login',
    'mfa_webauthn_add',
    'mfa_webauthn_authenticate',
    'mfa_webauthn_reauthenticate'
  ]
  const STATUS_ID = 'capy_auth_passkey_status'

  function passkeyButtons () {
    return BUTTON_IDS.map((id) => document.getElementById(id)).filter(Boolean)
  }

  function say (key) {
    const status = document.getElementById(STATUS_ID)
    if (status) {
      status.textContent = status.dataset[key]
    }
  }

  document.addEventListener('allauth.error', function () {
    passkeyButtons().forEach((button) => { button.disabled = false })
    say('failed')
  })

  document.addEventListener('DOMContentLoaded', function () {
    const buttons = passkeyButtons()
    if (!window.PublicKeyCredential) {
      buttons.forEach((button) => { button.hidden = true })
      if (buttons.length) {
        say('unsupported')
      }
      return
    }
    buttons.forEach((button) => {
      // Runs after allauth's own click handler, which starts the attempt.
      button.addEventListener('click', function () {
        say('working')
        setTimeout(() => { button.disabled = true })
      })
    })
  })
})()
