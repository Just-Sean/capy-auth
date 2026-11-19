# Capy Auth

User accounts for Django projects: signup, login, MFA, passkeys, social login and an API, built on django-allauth.

A self-contained Django app (`capy_auth`) that any project can install, built
for projects from the capy-project template (v1; called django-starter up to v1.0.1)
and working in any Django project. It has no project of its own: its tests run against
a tiny stand-in project in `tests/`.

**Works with:** Python 3.14+, Django 6.1 or a later 6.x, and PostgreSQL 18 (what
projects made from capy-project run) or SQLite. CI tests both databases with the versions in
`uv.lock` (the newest 6.x), and SQLite once more with the lowest versions allowed
(Django 6.1).

## Architecture

- **The app** (`src/capy_auth/`) is what projects install. Its main parts are
  described here as they're added (models, views, templates, background jobs): what
  each one does, how they connect, and why each major choice was made.
- **Built on django-allauth** (65.22.1 or a later 65.x): allauth does the account
  work (signup, login, email verification, password reset, MFA, passkeys, social
  login, the API). capy-auth is a thin, opinionated layer on top: settings, pages that
  fit a capy project, and the checks a project needs. Why: authentication is too risky
  to write by hand, and allauth is the most complete, best maintained option for
  Django. capy-auth defines no user model; it uses the project's
  (`settings.AUTH_USER_MODEL`). allauth brings its own dependencies into the project
  (cryptography, fido2, PyJWT, oauthlib, requests, qrcode); the project's pip-audit and
  Dependabot check them along with its other packages.
- **Made for capy projects:** a project made from capy-project, styled with
  capy-theme. Its pages extend the project's `layout.html` and use daisyUI 5 classes,
  so capy-theme's active theme styles them; it never imports capy-theme.
- **Settings admins change** live in one database record (`config/`), shown in the
  Django admin as the "capy-auth settings" page. capy-auth's account adapter
  (`account/adapter.py`) reads it when allauth asks how to behave, and Django's checks
  (`config/checks.py`) stop a project that forgot to use that adapter or gave a bad
  starting value. The record is read once per request (kept on the request). Why the
  database, not only the project's settings: admins change
  these while the site runs, without a deploy. Secrets and anything that must not
  change while running stay in the project's settings. The record holds single
  choices (on/off, a level); lists get their own tables in their own sections: the ban
  list, and social-login providers, whose secrets capy-auth stores encrypted (allauth's
  own provider table keeps them in plain text).
- **Accounts** are allauth's, set up by the settings in
  [Add it to a project](#add-it-to-a-project): signup with email and password, login by
  email, email verified by a code before the first login (with "send a new code"),
  password reset links that work once for an hour, notification emails, and the same
  answers for known and unknown addresses.
  - **Email addresses:** people manage theirs on the email page, linked from "Your
    account". A completed password reset confirms the account's address when it's the
    account's only one and its own email (the link went there, as allauth's reset by
    code already does). This relies on two allauth defaults, checked on each allauth
    upgrade: resets go only by email, and a reset link stops working when the
    account's addresses change, so a project mustn't replace
    `ACCOUNT_PASSWORD_RESET_TOKEN_GENERATOR`. `account/services.py` and
    `account/receivers.py` do that, confirm an address by hand (`mark_email_verified`)
    and send the "choose your password" email for accounts staff create; migration
    0004 adds existing users' emails to allauth's list. Why a signal for the staff
    email: capy-auth never changes the project's user admin, so it notices an account
    saved on the admin's "add user" page instead.

  capy-auth's adapter (`account/adapter.py`)
  names people by their email, words the "too many attempts" message for both logins
  and codes, and hashes a password when someone signs up with a taken email, so that
  answer takes as long as a new account's. Django's checks (`config/checks.py`) warn
  when a project weakens one of these settings. `urls.py` mounts allauth's pages with
  capy-auth's "Your account" page, where people land after logging in, and
  `templates/429.html` puts allauth's "too many attempts" page inside the layout.
- **MFA** (`mfa/`): allauth's MFA app with capy-auth's adapter (`adapter.py`), which
  encrypts every secret allauth stores (`crypto.py`: Fernet from `cryptography`, keys
  from `CAPY_AUTH_ENCRYPTION_KEYS`; why Fernet: a hard-to-misuse recipe with built-in
  key changes, and the library comes with allauth's MFA anyway; why a key of its own,
  not one made from `SECRET_KEY`: a `SECRET_KEY` leak or change would then expose or
  break everyone's MFA too). `services.py` re-encrypts everything with the first key
  (`manage.py capy_auth_reencrypt`) and emails an owner after repeated wrong codes
  (`receivers.py`, on allauth's signals); a secret no key can read raises an error the
  middleware (`limits/middleware.py`) turns into a clear page. `staff.py` is the
  middleware that requires two-step sign-in for staff and superusers (allauth has no
  switch for it): it reads allauth's record of how this session signed in (plus
  setting it up, which capy-auth records), and what a staff member can open depends
  on whether they have it set up yet, so a password alone never gets past it.
  `checks.py` holds E007 to E012, W005 and W006. `forms.py` has capy-auth's forms for adding and renaming a
  passkey (plain words, "sign in without my password" ticked, names up to 100
  characters), which `MFA_FORMS` points at. The MFA pages are rewritten from allauth's in capy-auth's words
  (`templates/mfa/`): the overview, setting up an authenticator app (the QR code on
  white, a key you can copy), the code step (which code to enter), turning it off (what
  it removes), recovery codes (what they're for, where to keep them, download or copy)
  and making new ones, and the passkey pages (the list as cards, adding one, renaming,
  removing, confirming with one), each with a way back; so are their confirmation
  messages. Confirming it's you with a code stays allauth's, inside the layout.
  Passkeys are allauth's WebAuthn support (fido2); its scripts are static files, so
  they work under the strict policy. capy-auth adds one small static script of its own
  (`static/capy_auth/js/passkeys.js`): allauth only writes a failed passkey attempt to
  the browser's console, so this shows a message next to the button, hides passkey
  buttons on browsers that can't use them, and stops a second press while one attempt
  runs. Changes ask you to confirm it's you again (password or passkey).
- **Sessions** (`sessions/`, `templates/usersessions/`):
  - **Asking again:** allauth asks for the password again, on its "Confirm it's you"
    page (rewritten by capy-auth), before sensitive changes: adding, removing or
    choosing the main email address, setting a password, and later MFA. After you
    confirm it there, it doesn't ask again for 5 minutes
    (`ACCOUNT_REAUTHENTICATION_TIMEOUT`, allauth's default; Django's checks warn,
    with `capy_auth.W001`, if a project makes it longer). Typing the password to sign
    in doesn't count, so the first such change after signing in always asks. Changing
    the password asks for the current one on its own form instead.
  - **Signed-in devices** (`/accounts/sessions/`): allauth's user sessions app records
    each sign-in through capy-auth's pages; `recording.py` also records Django's own
    logins (another app's login page) and, when someone opens the page from a session
    nobody recorded, that session, so this device is always listed and "Sign out
    everywhere else" reaches every recorded session. `views.py` is allauth's page with
    that step first; the template (rewritten from allauth's) shows cards that wrap on
    phones. It shows when each session started, not when it was last used: allauth's
    `USERSESSIONS_TRACK_ACTIVITY` would write to the database on every signed-in
    request, so it's left off (a project that turns it on gets a "Last seen" line on
    each device). The page doesn't ask for the password again: someone with a stolen
    session could see the other devices and sign them out, but they just sign in
    again, and changing the password signs out everyone else, the thief included.
  - **What's stored:** each session's IP address and browser description (personal
    data), until the session ends and the person next signs in or opens the page;
    staff can see all of them in allauth's "User sessions" admin. `checks.py` holds
    the startup checks E006 (the app or middleware missing) and W004 (cookie-only
    sessions, which the server can't end).
- **Emails** are sent by the project's background worker (`emails/`). capy-auth's
  adapter builds each email as allauth does, keeps the finished email in the cache
  under a random key for up to an hour, and enqueues a job (Django's Tasks API) that
  carries only that key. The job sends the email, then removes it from the cache; a
  short "being sent" marker stops two runs of the job sending it twice. Why: sending
  can take seconds, and a job that carried the email would keep verification codes
  and reset links in the database's job table until finished jobs are pruned
  (capy-project's daily `prune_db_task_results` deletes them after 14 days). This is
  how well-run services do it too: retries with growing waits, sending at least once,
  short-lived codes and a "send a new code" button. When something goes wrong:
  - **The mail server fails:** the email stays in the cache and the job tries again
    after 1, 2, 5, 10 and 15 minutes; after the last try it's dropped (an error is
    logged and the job is marked failed). Where jobs run straight away (development,
    tests), there's no waiting, so it's dropped at the first failure.
  - **The cache is down, or the job queue is:** the email is sent during the request
    instead (a warning is logged), so signup and resets keep working.
  - **The email is gone from the cache** (the worker wasn't running for over an hour,
    or Redis was restarted, cleared or full): it isn't sent (an error is logged) and
    the person asks for a new code or reset link.
  - Emails with attachments (allauth's have none) are sent during the request.
- **Limits** (`limits/`): `axes.py` tells django-axes to count failed logins under the
  account's main email, however it was typed (another of its addresses, or its
  username), so one person's typos lock out only that account;
  `templates/capy_auth/locked_out.html` is axes' lockout page, inside the layout;
  `middleware.py` turns the cache (Redis) being down on account pages into a 503 page
  instead of an error, never skipping the limits; `checks.py` stops a production site
  whose email can't be sent (`capy_auth.E004`). The proxy setting for allauth's own
  limits is in the install steps.
- **Bans** (`bans/`): the ban list (`models.py`: banned email addresses, banned social
  accounts, and attempts to use a banned address), its admin pages (`admin.py`),
  reading it (`selectors.py`) and changes it makes (`services.py`: suspending and
  reactivating accounts, recording attempts). allauth's signup forms build on
  `forms.py`'s `BanCheck` (the project's `ACCOUNT_SIGNUP_FORM_CLASS`), which treats a
  banned address as one that already has an account, so the page never shows the ban.
  The account adapter records signup attempts, refuses to confirm a banned address and
  sends a banned address only the ban notice; `receivers.py` records add-email attempts
  (allauth's internal `_add_email` signal) and makes sure no banned address is ever
  stored as confirmed, whatever confirms it. `checks.py` is the startup check E005. Why this
  way: refusing a banned address on the page would let anyone test which addresses are
  banned; only the address's owner is told, by email. Social accounts are checked by
  capy-auth's social login support (a later release).
- **Passwords** (`passwords/breached.py`): a Django password validator the project adds
  to `AUTH_PASSWORD_VALIDATORS`, which reads who to check from the settings record.
  Why it works this way: Have I Been Pwned's range API with padding, so only a
  5-character hash prefix leaves the server; it fails closed (Sean's decision), so a
  breached password can't get in during an outage, and remembers a failure for a minute
  so an outage costs milliseconds, not a stuck web worker; Python's own HTTPS client,
  so no new dependency (it ignores proxy settings: see install step 4).
- **Pages** come from allauth. capy-auth overrides mainly allauth's page frame and its
  small building blocks, under allauth's own template names:
  `templates/allauth/layouts/base.html` puts every allauth page inside the project's
  `layout.html` (title, head and content blocks; allauth's scripts go in the head, and
  its own menu and messages list are left out; a later feature adds a menu), and
  `templates/allauth/elements/` draws every allauth building block it changes (buttons,
  fields, forms, alerts, badges, panels, collapsible details, tables, headings and
  social-login buttons) with daisyUI classes. `templates/capy_auth/fields/widget.html`
  picks daisyUI's class for each kind of form input, and the `daisy_widget` filter
  (`templatetags/capy_auth_forms.py`) adds it to the input. Every form field gets a
  visible label (even where allauth asks for none), and its help text and errors carry
  the ids Django points the input at, so screen readers read them. Two allauth pages,
  `account/email_change.html` and `account/phone_change.html`, are copied with their
  inline style (which the Content Security Policy blocks) replaced by the `hidden`
  attribute; a test fails if allauth's originals change, and another if allauth gives
  an element something the override doesn't show. More are rewritten rather than
  copied: `account/email.html` (addresses wrap on narrow screens, the choices are
  grouped under a legend, the buttons say they act on the chosen address, capy-auth's
  wording), `account/password_reset_from_key.html` and `_done.html` ("Choose a
  password", then a "Sign in" button), `usersessions/usersession_list.html` (see
  Sessions), `account/reauthenticate.html` and `base_reauthenticate.html` ("Confirm
  it's you", why it asks, a way back), and the two-step sign-in pages in `mfa/` (see
  MFA). `account/login.html` is allauth's copied with capy-auth's passkey parts
  (`templates/capy_auth/passkeys/`): the hidden form the passkey button submits is in
  the page's content, not with the scripts in the head; the button does nothing without
  JavaScript (a notice says so); and a status line says when an attempt fails.
  allauth's own passkey snippets are left alone, so a project's own sign-in page that
  includes them still works. A test fails when allauth's original of any of these
  changes.
  `account/account_inactive.html` replaces allauth's inactive-account page with an
  "Account suspended" page inside the layout (written for capy-auth, not copied).
- **The stand-in project** (`tests/settings.py`, `tests/urls.py`) is the smallest
  Django project that runs the app, so the tests prove it works outside any one
  project. It has allauth, capy-project's strict Content Security Policy (enforced),
  copies of capy-project's `base.html` and `layout.html` (`tests/templates/`), and
  either Django's own user model or a copy of capy-project's (`tests/email_users/`,
  with `TEST_USER_MODEL=email`). It runs django-axes as capy-project does (a
  development-only dependency); capy-project's own per-address limit is capy-project's
  code, so it isn't here. `tests/` also checks the rules below.
- **Released as git tags** (`vX.Y.Z`) that projects install from GitHub, never on the
  public PyPI (`pyproject.toml` refuses an upload). Built with uv's own build backend,
  kept up to date with capy-module by Copier (see
  [Updating from the starter](#updating-from-the-starter)).

## Add it to a project

These are the exact lines for a project made from capy-project. allauth's options are
set the way capy-auth's pages, tests and security choices expect; the comments say why.

In a project made from capy-project, with its database running
(`docker compose up -d`):

1. Install a released version (a tag) from GitHub; the module's first one is `v0.1.0`:

   ```bash
   uv add git+https://github.com/Just-Sean/capy-auth --tag vX.Y.Z
   ```

   If the repository is private, your machine needs a GitHub login for git (for
   example `gh auth setup-git`), and the project's production image needs one while it
   builds: see "Adding a reusable app" in the project's README (a Docker build
   secret; never a token in the URL). While developing the module next to a project,
   `uv add --editable ../capy-auth` uses your working copy instead. Before
   deploying, run the `uv add … --tag vX.Y.Z` line again: a folder outside the project
   can't be built into its image.

2. In `config/settings/core.py`, add `"capy_auth"` to `INSTALLED_APPS` after
   `"accounts"`, and allauth's apps after `"django.contrib.messages"`. `capy_auth`
   must come before allauth's apps, so its versions of allauth's page templates are
   the ones Django uses. In `MIDDLEWARE`, add allauth's and capy-auth's right after
   Django's messages middleware (django-axes' stays last). capy-auth's first one shows
   a "temporarily unavailable" page (503) on account pages (signing in, signing up,
   passwords, email addresses) when one fails because the cache (Redis) is down,
   instead of a server error; nothing gets through, and the pages work again by
   themselves once the cache is back. Its second one requires two-step sign-in for
   staff and superusers (see "Staff need two-step sign-in" under step 4's "Two-step
   sign-in (MFA)"); it goes after allauth's `AccountMiddleware`, or Django's checks
   stop the site (`capy_auth.E010`):

   ```python
   INSTALLED_APPS = [
       "accounts",
       "capy_auth",
       ...,
       "django.contrib.messages",
       "allauth",
       "allauth.account",
       "allauth.usersessions",  # the "Signed-in devices" page
       "allauth.mfa",  # two-step sign-in
       ...,
   ]
   MIDDLEWARE = [
       ...,
       "django.contrib.messages.middleware.MessageMiddleware",
       "allauth.account.middleware.AccountMiddleware",
       "allauth.usersessions.middleware.UserSessionsMiddleware",
       "capy_auth.limits.middleware.CacheDownMiddleware",
       "capy_auth.mfa.staff.StaffTwoStepMiddleware",
       ...,
   ]
   ```

   allauth's user sessions app records each sign-in in its own table (created by
   `migrate` in step 8) for the "Signed-in devices" page. Its middleware is part of
   allauth's setup and only does work if `USERSESSIONS_TRACK_ACTIVITY` is on. Without
   either one, Django's checks stop the site (`capy_auth.E006`). Sessions that were
   already signed in before you add it are listed only after they sign in again (or
   open the page themselves), so "Sign out everywhere else" can't reach them until
   then. To sign everyone out once at rollout (with database sessions, as capy-project
   has), run after deploying:

   ```bash
   uv run python manage.py shell -c "from django.contrib.sessions.models import Session; Session.objects.all().delete()"   # development
   docker compose -f compose.yaml -f compose.prod.yaml exec web python manage.py shell -c "from django.contrib.sessions.models import Session; Session.objects.all().delete()"   # production
   ```

3. In `config/urls.py` (change its import to `from django.urls import include, path`),
   add to `urlpatterns`, and send the admin's login to capy-auth's sign-in page with
   allauth's `secure_admin_login`, so staff sign in where the limits, the ban list and
   two-step sign-in apply (without it, Django's checks stop the site,
   `capy_auth.E011`):

   ```python
   from allauth.account.decorators import secure_admin_login

   admin.site.login = secure_admin_login(admin.site.login)  # before urlpatterns

   urlpatterns = [
       ...,
       path("accounts/", include("capy_auth.urls")),
   ]
   ```

   The admin's own login page then sends visitors to capy-auth's sign-in page and
   back to the admin afterwards. Signed-in people who aren't staff get "403
   Forbidden" there, as Django's admin does for them.

   Mounted there, Django's default `LOGIN_URL` (`/accounts/login/`) and
   `LOGIN_REDIRECT_URL` (`/accounts/profile/`, capy-auth's "Your account" page) already
   point at capy-auth's pages, so leave both unset.

4. In `config/settings/users.py`, where capy-project keeps its login settings:
   - **Login backends:** replace Django's `ModelBackend` with allauth's backend (which
     also gives staff their admin permissions, as `ModelBackend` did): every sign-in,
     the admin's included, now goes through capy-auth's sign-in page (step 3).
     capy-project's two login-limit backends stay first. Update the comment above the
     list too: `ModelBackend` is no longer "the real login".

     ```python
     AUTHENTICATION_BACKENDS = [
         "config.login_limits.IPLoginLimitBackend",
         "axes.backends.AxesStandaloneBackend",
         "allauth.account.auth_backends.AuthenticationBackend",  # every sign-in, by email
     ]
     ```

   - **django-axes counts by email:** add these next to capy-project's other `AXES_`
     settings. allauth logs in by email and axes counts by username, so without the
     first one every failed email login from one address counts under one empty name,
     and 5 wrong passwords from a shared office would lock out everyone there. With
     it, axes counts each account under its main email, whichever of its addresses
     was typed, in any capitals (axes' reset after a successful login too), so 5
     failures lock out that account from that address and
     nobody else. The second shows the lockout (status 429) as a page inside the
     layout, saying how long to wait, with a "Forgot your password?" link, instead of
     axes' bare text.

     ```python
     AXES_USERNAME_CALLABLE = "capy_auth.limits.axes.login_name"
     AXES_LOCKOUT_TEMPLATE = "capy_auth/locked_out.html"
     ```

     In the comment above `AUTHENTICATION_BACKENDS`, "username" now means the
     account's email (for example "failed logins for one account (by its email) from
     one address").

     How the limits add up:
     - **django-axes** (capy-project's settings): 5 failures for one account from one
       address lock that pair out for 15 minutes. It finds the visitor's address with
       capy-project's `AXES_CLIENT_IP_CALLABLE` (`config.login_limits.client_ip`),
       which behind the proxy trusts only the address the proxy adds, so changing a
       made-up `X-Forwarded-For` doesn't reset the count. Keep that setting.
     - **capy-project's per-address limit** (`IPLoginLimitBackend`, 30 failures from
       one address) works as it is.
     - **allauth's own limit:** 5 failures for one email in 5 minutes, from any
       address. Anyone who knows a person's email can therefore stop that person
       logging in for up to 5 minutes at a time. That's the usual trade-off (NIST SP
       800-63B asks for limits per account): it stops password guessing against one
       account from many addresses, and a password reset still works meanwhile.
     - People who are locked out see the "Too many attempts" page, with a link to reset
       their password; a reset doesn't count as a login and isn't blocked.

     To unlock someone before the 15 minutes are up (allauth's limit clears itself
     after 5 minutes), use their main email in lowercase; `axes_reset` unlocks
     everyone:

     ```bash
     uv run python manage.py axes_reset_username ada@example.com   # development
     uv run python manage.py axes_reset
     docker compose -f compose.yaml -f compose.prod.yaml exec web python manage.py axes_reset_username ada@example.com   # production
     docker compose -f compose.yaml -f compose.prod.yaml exec web python manage.py axes_reset
     ```

   - **allauth, as capy-auth sets it up** (Django's checks warn, with
     `capy_auth.W001`, about any security choice here that a project weakens):

     ```python
     # capy-auth's account adapter: applies the capy-auth settings page's choices.
     # Without it, Django's checks stop with capy_auth.E001. A project with its own
     # adapter makes it a subclass of this one instead.
     ACCOUNT_ADAPTER = "capy_auth.account.adapter.AccountAdapter"
     # Name people by their email in messages and emails, not the username allauth
     # makes up for them.
     ACCOUNT_USER_DISPLAY = "capy_auth.account.adapter.user_display"
     # Checks the ban list at signup without showing the ban on the page. Without it,
     # Django's checks stop with capy_auth.E005. A project with its own signup form
     # makes it a subclass of this one instead, and calls super().clean() from its own
     # clean().
     ACCOUNT_SIGNUP_FORM_CLASS = "capy_auth.bans.forms.BanCheck"
     # Log in with an email address; sign up with just email and password (allauth
     # fills in the username).
     ACCOUNT_LOGIN_METHODS = {"email"}
     ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
     # The email must be confirmed before the first login, with a code from an email
     # (no confirmation links: a code works on any device and puts no token in a URL).
     # The code page offers a new code. It doesn't offer "use a different email": that
     # would show only for new accounts, giving away which emails already have one, and
     # it would skip the ban list. Leave ACCOUNT_EMAIL_VERIFICATION_SUPPORTS_CHANGE off.
     ACCOUNT_EMAIL_VERIFICATION = "mandatory"
     ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = True
     ACCOUNT_EMAIL_VERIFICATION_SUPPORTS_RESEND = True
     # Logins last for the session's lifetime (Django's 2 weeks), not only until the
     # browser closes, with no "remember me" box.
     ACCOUNT_SESSION_REMEMBER = True
     # Ask for the password again before changing email addresses or setting a
     # password (changing it asks for the current one anyway). For 5 minutes after
     # it's confirmed, it doesn't ask again (allauth's ACCOUNT_REAUTHENTICATION_TIMEOUT,
     # 300 seconds by default; leave it unset).
     ACCOUNT_REAUTHENTICATION_REQUIRED = True
     # Tell people by email when their password or email address changes.
     ACCOUNT_EMAIL_NOTIFICATIONS = True
     # Password reset links work once and expire after 1 hour (Django's default: 3 days).
     PASSWORD_RESET_TIMEOUT = 60 * 60
     # Behind capy-project's Caddy proxy, count each visitor by their own address (the
     # last X-Forwarded-For entry), not everyone as the proxy's: otherwise one person
     # could use up the login and signup limits for the whole site.
     ALLAUTH_TRUSTED_PROXY_COUNT = 1 if env.bool("DJANGO_BEHIND_PROXY", default=False) else 0
     ```

   - **Two-step sign-in (MFA):** authenticator apps, passkeys or security keys, and
     recovery codes: optional for most people, required for staff and superusers (see
     "Staff need two-step sign-in" below). capy-auth's MFA adapter encrypts every
     secret before allauth stores it; without the adapter or allauth's MFA app, Django's
     checks stop the site (`capy_auth.E008`). `DEBUG` comes from `core.py` in a project
     made from capy-project, so import it at the top of `users.py`:

     ```python
     from .core import DEBUG  # at the top of users.py, with the other imports

     MFA_ADAPTER = "capy_auth.mfa.adapter.MFAAdapter"
     # capy-auth's forms for adding and renaming a passkey: plain words, "sign in
     # without my password" ticked, names up to 100 characters. Without them the site
     # works with allauth's wording, and Django's checks warn (capy_auth.W006).
     MFA_FORMS = {
         "add_webauthn": "capy_auth.mfa.forms.AddPasskeyForm",
         "edit_webauthn": "capy_auth.mfa.forms.EditPasskeyForm",
     }
     # Authenticator apps, recovery codes, and passkeys or security keys (WebAuthn).
     MFA_SUPPORTED_TYPES = ["totp", "recovery_codes", "webauthn"]
     # "Sign in with a passkey" on the sign-in page. Signing up with only a passkey
     # stays off (allauth's MFA_PASSKEY_SIGNUP_ENABLED, False by default).
     MFA_PASSKEY_LOGIN_ENABLED = True
     # Passkeys over plain http, for development only: in production it would stop
     # allauth checking which site a passkey sign-in came from, so Django's checks
     # stop the site if it's on there (capy_auth.E009).
     MFA_WEBAUTHN_ALLOW_INSECURE_ORIGIN = DEBUG
     # A code from the previous 30 seconds still works (a code read at second 29 and
     # typed at second 31; the standard, RFC 6238, recommends it). A used code never
     # works twice.
     MFA_TOTP_TOLERANCE = 1
     # The key that encrypts MFA secrets (see below). env.list reads a comma-separated
     # value; the first key encrypts, every key decrypts.
     CAPY_AUTH_ENCRYPTION_KEYS = env.list("CAPY_AUTH_ENCRYPTION_KEYS", default=[])
     ```

     **Passkeys** are tied to the site's domain (the address people sign in at): moving
     the site to another domain (including switching between `www.` and the bare
     domain, or from a staging address) means everyone adds their passkeys again. So
     pick one address and redirect the others to it, host nothing untrusted on its
     subdomains (their pages could ask for the site's passkeys), and have the proxy pass
     the real `Host` header (capy-project's Caddy does). They need https in production
     (Caddy provides it); in development, `http://localhost` works with the setting
     above. E009 is a startup check: it runs with `manage.py check` and `migrate`, not
     when gunicorn starts, so keep running one of those when you deploy (capy-project's
     deploy runs `migrate`).

     **Every passkey or security key can sign in on its own** (without the password)
     when the device allows it. allauth doesn't store whether "sign in without my
     password" was ticked, and phones and computers often save a key as a passkey
     anyway, so capy-auth's pages don't promise otherwise; the box is ticked by
     default and only matters for an older security key with no PIN or fingerprint,
     which then works only after the password. Signing in with only a key always needs
     its fingerprint, face or PIN. Two more choices, made on purpose:
     - **Passkey sign-ins aren't counted by django-axes** (it counts wrong passwords,
       and its lockout doesn't block a passkey). A passkey can't be guessed, each
       attempt answers a one-time challenge, and allauth limits passkey sign-in
       attempts itself (10 a minute from one address).
     - **A copied security key isn't detected.** Keys report a counter that a copy
       could reveal by going backwards; allauth doesn't store it, and synced passkeys
       (phones, password managers) always report 0, so capy-auth doesn't check it.

     Recovery codes can be seen and downloaded again later, after the password is
     typed again (as GitHub and Google do). After 5 wrong codes in an hour at the code
     step, the account's owner gets an email saying someone has their password (once;
     allauth already refuses more than 5 wrong codes in 5 minutes). Only superusers
     should get allauth's "Can change authenticator" and "Can add authenticator"
     permissions: whoever has them could move one person's secret onto another's
     account.

     **A project that used allauth's MFA before installing capy-auth** has its
     secrets stored unencrypted; capy-auth can't read them, so those people get the
     "can't be checked" page below until their authenticators are removed (see "If
     it's lost" below: staff are among them) and they set up two-step sign-in again.

     **Staff need two-step sign-in.** Staff and superusers who haven't used two-step
     sign-in in this session (the code after the password, a passkey sign-in,
     "Confirm it's you" with either, or setting it up) are sent from every page, the
     admin's included:
     - **With none set up,** to "Two-step sign-in" to set up an app or a passkey; until
       then they can only do that (confirming it's them first, with their password or
       an emailed code, as setting it up asks) or sign out. Afterwards a "Continue"
       button takes them where they were going.
     - **With it set up but not used in this session** (a session from before they
       were made staff, or from another app's login page), to "Confirm it's you" with
       their app, a recovery code or their passkey; until then they can only do that
       or sign out. Their password or an emailed code doesn't count, so those aren't
       offered, and the pages that manage two-step sign-in (recovery codes, adding or
       turning off a method) stay closed: a password alone can't get past it.

     Both pages say why they're there and offer "Sign out". There's no grace period: a
     new superuser from `createsuperuser` sets it up at their first sign-in, and
     someone made staff while signed in is asked at their next page. **Until a staff
     member sets it up, their password alone can get in and set it up** (as with any
     account that adds two-step sign-in), so set it up for a new superuser right after
     `createsuperuser`, before the site is public. allauth's "trust this browser"
     (`MFA_TRUST_ENABLED`, off by default) doesn't skip it for staff: a trusted
     browser's sign-in isn't a two-step sign-in, so they confirm it anyway. Staff also
     need `"mfa"` in allauth's `ACCOUNT_REAUTHENTICATION_METHODS` (its default; Django's
     checks stop the site without it, `capy_auth.E012`).

     **Other ways to sign in skip capy-auth's sign-in page:** allauth's backend
     accepts a password from any Django login form (`django.contrib.auth.urls`'
     `LoginView`, another app's login page, a second `AdminSite`, which needs the same
     `secure_admin_login` line), and an API that signs people in with its own tokens or
     a password on each request (Django REST framework's Token or Basic
     authentication) never meets this middleware. Those skip capy-auth's limits, the
     ban list's email and the second step for everyone. capy-auth's middleware still
     asks staff for two-step sign-in on pages (not on such APIs), but keep the site's
     only sign-in page capy-auth's: don't add another login page or a password- or
     token-based API login.

     A staff member who loses their phone or key signs in with a recovery code. If
     they've lost those too, another superuser removes their authenticators in the
     admin (**MFA › Authenticators**, after checking it's really them); they then sign
     in with their password and set it up again. With no other superuser, remove them
     on the server, with the email on their account (their main one; `(0, {})` means
     no account matched):

     ```bash
     uv run python manage.py shell -c "from allauth.mfa.models import Authenticator; print(Authenticator.objects.filter(user__email__iexact='ada@example.com').delete())"   # development
     docker compose -f compose.yaml -f compose.prod.yaml exec web python manage.py shell -c "from allauth.mfa.models import Authenticator; print(Authenticator.objects.filter(user__email__iexact='ada@example.com').delete())"   # production
     ```

     **Passwords are checked against breached passwords only when they're set**,
     never at sign-in, for anyone, staff included (see "Breached passwords" below).
     For staff that's safe enough: with two-step sign-in required, a breached password
     alone can't get in (once they've set it up). A check at sign-in would also fail
     closed, so an outage of the breach service would lock every admin out.

   - **The encryption key (whoever sets up the server does this once).** MFA secrets
     (the key each authenticator app shares with the site, and the seed of recovery
     codes) are stored encrypted, so a copy of the database alone (a dump, a backup, a
     stolen disk) doesn't give them away. It doesn't protect against someone who has
     the server itself, where the key and the database both are. Generate a key:

     ```bash
     uv run python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # development, or any machine with the project
     docker compose -f compose.yaml -f compose.prod.yaml run --rm --no-deps web python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"   # production
     ```

     Put it in `.env.production` as `CAPY_AUTH_ENCRYPTION_KEYS=<the key>` and deploy.
     In `.env.example`, in capy-project's style:

     ```bash
     # Key that encrypts MFA secrets (capy-auth README, "The encryption key").
     # Development can leave it out (a stand-in is used); production needs a real one.
     # Back it up with the other secrets, not with the database backup.
     # CAPY_AUTH_ENCRYPTION_KEYS=
     ```

     **Back it up with the project's other secrets** (for example in a password
     manager), **not with the database backup**: the two together would undo the
     encryption. Nobody else ever sees or types it.
     - **In development**, without it, a stand-in key made from `SECRET_KEY` is used,
       and Django's checks say so every time the site starts (`capy_auth.W005`), with
       the commands above. (Changing `SECRET_KEY` in development then makes existing
       development MFA setups unreadable.)
     - **In production**, without it or with a malformed one, the site doesn't start
       (`capy_auth.E007`), and the message says how to fix it. In a project made from
       capy-project, the deploy's `up --wait` fails: the message is in
       `docker compose -f compose.yaml -f compose.prod.yaml logs migrate`. `check --deploy` also stops with E007 if `DEBUG` was left
       on by mistake. Add the key, then deploy again so the site picks it up.
     - **The project's own tests** run with `DEBUG` off, so they need a throwaway key
       too (any generated key, e.g. in the test settings or the tests' environment).
     - The capy-auth settings page in the admin shows whether it's set (never the key).
     - **Changing it** (routinely, or after a leak): generate a new key and put it
       first, keeping the old one after it (`CAPY_AUTH_ENCRYPTION_KEYS=<new>,<old>`),
       deploy, then re-encrypt every stored secret with the new key:

       ```bash
       uv run python manage.py capy_auth_reencrypt   # development
       docker compose -f compose.yaml -f compose.prod.yaml exec web python manage.py capy_auth_reencrypt   # production
       ```

       It says how many it did and whether any couldn't be read. Then drop the old key
       and deploy again. After a leak, the secrets the old key protected must be
       treated as exposed: also ask people to set up their authenticator apps again.
     - **If it's lost**, the stored secrets can't be read. Everyone with two-step
       sign-in then gets a page at the code step saying it can't be checked right now
       and to contact the site's staff; nobody gets in without a working code, and the
       server logs an error naming the setting. Staff are locked out of the admin too
       (they need two-step sign-in), so whoever runs the server removes every
       authenticator there, and everyone signs in with their password and sets
       two-step sign-in up again (staff at once, as they're asked):

       ```bash
       uv run python manage.py shell -c "from allauth.mfa.models import Authenticator; print(Authenticator.objects.all().delete())"   # development
       docker compose -f compose.yaml -f compose.prod.yaml exec web python manage.py shell -c "from allauth.mfa.models import Authenticator; print(Authenticator.objects.all().delete())"   # production
       ```

   - **Breached passwords:** add capy-auth's check to the end of capy-project's
     `AUTH_PASSWORD_VALIDATORS` (12 characters minimum, no common or all-digit
     passwords, no composition rules: those stay as they are):

     ```python
     AUTH_PASSWORD_VALIDATORS = [
         ...,
         {"NAME": "capy_auth.passwords.breached.BreachedPasswordValidator"},
     ]
     ```

     It checks each new password (signup, change, reset, the admin's password forms,
     `createsuperuser`) against Have I Been Pwned's list of breached passwords (NIST SP
     800-63B). Only the first 5 characters of the password's SHA-1 hash are sent, over
     HTTPS, to `api.pwnedpasswords.com`; each check has 3 seconds in all. When the check
     applies and the service can't be reached or answers badly, the password is refused
     with a message to try again in a few minutes (it fails closed), and for the next
     minute new passwords are refused at once instead of each waiting on the service.
     Admins choose who is checked on the capy-auth settings page (Django's checks warn,
     `capy_auth.W003`, when this line is missing, since the option then does nothing).
   - **Who is checked:** "everyone" (the default, and recommended) checks every new
     password. "Staff and superusers" checks only passwords set while the account is
     already staff or a superuser: a new superuser from `createsuperuser`, staff created
     in the admin, and users made staff later are **not** checked at that level. Django
     itself skips password rules in a few places, at any level:
     `createsuperuser --noinput` (with `DJANGO_SUPERUSER_PASSWORD`), answering "y" to
     `createsuperuser`'s "bypass password validation" question, and `set_password()` in
     code.
   - **Network:** capy-project's web container can already reach
     `api.pwnedpasswords.com` (only the database and Redis are cut off from the
     internet). The check doesn't use proxy settings (`HTTPS_PROXY`): behind a
     firewall, allow direct HTTPS to `api.pwnedpasswords.com:443`, or every new
     password is refused.
   - **When Have I Been Pwned is down:** logins still work, but signup, password
     changes and resets are refused with "try again in a few minutes", and the web
     log shows "Have I Been Pwned couldn't be reached or answered badly" (once a
     minute) (`docker compose -f compose.yaml -f compose.prod.yaml logs web`). For a
     long outage, open the admin's capy-auth settings page, set "Check breached
     passwords" to **nobody**, and set it back to **everyone** once it's over. Alert
     on that log line in production.

     allauth already answers signup, login and reset the same way for known and unknown
     addresses (`ACCOUNT_PREVENT_ENUMERATION`, on by default). To keep that, the reset
     form emails any address typed in (an address with no account is told so), so
     someone could send a stranger a few of these emails; allauth's limits keep it to a
     few a minute per address.

   - **Optional:** the `CAPY_AUTH_` settings in [Settings](#settings) only set starting
     values. Set one (as the type its row gives: `True`/`False` or one of the choices,
     e.g. `env.bool(...)` or `env.str(...)` when read from the environment, and listed
     in `.env.example`) only to start differently from its default.

   **Existing users** (such as a superuser made with `createsuperuser`) are asked for an
   emailed code the first time they log in (the admin's login goes through capy-auth's
   pages too). Migration 0004 (run by `migrate` in step 8, and by
   production's migrate step) adds their email to allauth's list as unconfirmed.
   Resetting their password with "Forgot your password?" also confirms it. Someone who
   can't receive the code yet (a superuser on a new server before email is set up) can
   be confirmed by hand, with their email:

   ```bash
   uv run python manage.py mark_email_verified you@example.com   # development
   docker compose -f compose.yaml -f compose.prod.yaml exec web python manage.py mark_email_verified you@example.com   # production
   ```

   It confirms the address, adding it to the account's addresses if it isn't there
   yet, and makes it the account's main address when the account has no confirmed one.
   It says which account it confirmed, or why it couldn't: no account uses the address,
   more than one does (for example the same email in different capitals: confirm it on
   the right account in the admin's email address list instead), or it's on the ban
   list.

   **Accounts staff create** on the admin's "add user" page get an email with a
   one-time link to choose their password ("An account was created for you"); choosing
   it confirms their address, and the page then offers "Sign in". The link works once,
   for 1 hour (`PASSWORD_RESET_TIMEOUT` above); after that, they use "Forgot your
   password?" on the sign-in page. The password staff type on the form isn't sent: the
   person replaces it with the link, and until they do, logging in with it asks for an
   emailed code, like any unconfirmed address. The admin says whether the link was
   sent. Nothing is sent when another account already has the address confirmed, when
   the add form has no email (capy-project's user admin asks for one; Django's own
   doesn't), or for accounts made any other way (signup, the shell, `createsuperuser`,
   other admin pages, a login system that creates users). So the add-user permission
   also means "can email a set-password link to an address".

5. **Email.** Signup, verification codes and password resets all send email.
   - **Development** needs nothing: capy-project prints emails, codes included, where
     `runserver` runs.
   - **Production** needs `EMAIL_URL` (`smtp+tls://` or `smtp+ssl://`) and
     `DJANGO_DEFAULT_FROM_EMAIL` in `.env.production` (the project README's "Email"
     section). Without them, Django's checks stop the site (`capy_auth.E004`), since
     signup and password resets can't work. The check reads Django 6.1's `MAILERS`
     (as capy-project sets it) and, outside development, stops a default mailer that
     delivers nothing or writes emails where they shouldn't be (dummy, console, file,
     or capy-project's stand-in when `EMAIL_URL` is missing), or a missing default.
   - **The worker and the cache:** capy-auth's emails are sent by the project's
     background worker (its `worker` service in production; development and tests run
     jobs straight away) and wait for it in the cache (Redis). capy-project already has
     both; Django's checks warn (`capy_auth.W002`) when jobs run in a separate worker
     with a cache it can't share. Redis must stay private (password-protected, and in
     production not published on a port), since queued emails hold codes and reset
     links for up to an hour. If people say no code arrives, check the worker is
     running and read its log (capy-project's README, "Background jobs"):

     ```bash
     docker compose -f compose.yaml -f compose.prod.yaml ps worker
     docker compose -f compose.yaml -f compose.prod.yaml logs worker
     ```

     A job that gave up is also listed, as failed, in the admin's background jobs.
   - **For reliable delivery,** point `EMAIL_URL` at a transactional email service
     (such as Postmark, Amazon SES or Mailgun): it accepts each email in a moment and
     keeps trying the recipient's mail server for hours.

6. The module's pages extend the project's `templates/layout.html` (see
   [Pages](#pages)), which shows Django's messages ("Saved.") in a `role="status"`
   region that modules rely on.
   - **A project made from capy-project v1.1.0 or later** already has it: nothing to
     do.
   - **A project made from v1.0.x** (when it was called django-starter): run
     `copier update` to capy-project v1.1.0 or later, which adds `layout.html`, and
     follow the "New in v1.1.0" update notes in capy-project's own README (on its
     GitHub page; a project's README doesn't have them). If you can't update yet, add
     this `templates/layout.html` (your nav bar goes where the comment is; add a
     `footer` block with a `<footer>` once there's something to put in it):

     ```html
     {% extends "base.html" %}
     {% block header %}
     <header>
       {# Your nav bar. #}
       <div role="status">
         {% for message in messages %}<p>{{ message }}</p>{% endfor %}
       </div>
     </header>
     {% endblock %}
     ```

     A theme that sets attributes on `<html>` also needs that project's `base.html`
     to have the `html_attrs` block, as in v1.1.0: change its `<html lang="en">` line
     to `<html lang="en"{% block html_attrs %}{% endblock %}>`.
     Without it, the theme's line is silently ignored. If you added this README's
     earlier `layout.html`, delete its empty `footer` block: an empty `<footer>` is
     announced by screen readers as a landmark with nothing in it.

   If this module is a theme or an app shell, also add the line this README gives to
   the project's `layout.html`, where its comments say (see [Pages](#pages)).
7. capy-auth's pages use daisyUI classes, which capy-theme styles. The project needs
   Tailwind CSS 4 and daisyUI 5 set up as capy-theme's README says ("Tailwind and
   daisyUI for a new project"). Tailwind only includes classes it finds in the files
   it scans, so add capy-auth's templates to the project's `tailwind/source.css`, next
   to capy-theme's line, with a path relative to `tailwind/`. This prints where the
   templates are installed:

   ```bash
   uv run python -c "import capy_auth, pathlib; print(pathlib.Path(capy_auth.__file__).parent / 'templates')"
   ```

   For example (the Python version in the path is the project's):

   ```css
   @source "../.venv/lib/python3.14/site-packages/capy_auth/templates";
   ```

   Then rebuild the stylesheet:

   ```bash
   uv run python manage.py tailwind build       # once, or for production
   uv run python manage.py tailwind runserver   # while developing: rebuilds on changes
   ```

8. Create capy-auth's and allauth's tables, then run the project's tests:

   ```bash
   uv run python manage.py migrate      # production's migrate step does this by itself
   uv run pytest
   ```

   **capy-project's own tests of the admin's login need changing**, since the admin's
   login now goes through capy-auth's sign-in page and staff need two-step sign-in:
   - the login-limit tests (`tests/test_login_rate_limit.py`) post an email and
     password (`login` and `password`) to `/accounts/login/` instead of a username to
     the admin's login page;
   - the security-header tests (`tests/test_security_headers.py`) fetch
     `/accounts/login/` instead of the admin's login page;
   - tests that use pytest-django's `admin_client` (a superuser signed in without
     two-step sign-in, who is now sent to set it up) sign the superuser in with two-step
     sign-in first, as capy-auth's own `tests/staff.py` does.

9. Check it by hand: start the site (`uv run python manage.py runserver`), open
   http://localhost:8000/accounts/signup/, sign up, copy the code from the email printed
   in the `runserver` output, and you land on "Your account". Sign out, then sign in
   again with the same email and password. Open "Email addresses" from "Your account"
   and add a second address: it first asks for your password (signing in doesn't
   count); add or remove another within 5 minutes and it doesn't ask again. Sign in to
   the same account from a second browser, then in the first open "Signed-in devices"
   from "Your account": both are listed, this one marked "This device". Choose "Sign
   out everywhere else" and reload the second browser: it's signed out. Open "Two-step
   sign-in", set up an authenticator app with its QR code, save the recovery codes,
   then sign out and in: it asks for a code (the app's, or a recovery code, which works
   only once). Setting up or turning off the authenticator app first asks you to confirm
   it's you. In Chrome and in Firefox, add a passkey from "Two-step sign-in", sign out,
   and choose "Sign in with a passkey": it signs you in, with no Content-Security-Policy
   errors in the browser's console. Then cancel the browser's passkey prompt: a message
   appears under the button. You need somewhere to keep the passkey: your phone (scan
   the QR code the browser shows), a security key, or the browser's own passkey
   storage. In Chrome you can also use DevTools > More tools > WebAuthn > "Enable
   virtual authenticator environment"; Firefox on Linux needs a phone or a security
   key. Use `http://localhost:8000` throughout, not `127.0.0.1`: a passkey only works
   at the address it was added on.
   `runserver` prints `capy_auth.W005` until `CAPY_AUTH_ENCRYPTION_KEYS` is set, and
   the capy-auth settings page shows "MFA secrets encryption". To see that only
   encrypted text is stored (it starts with `gAAAA`, never the key the app showed):

   ```bash
   uv run python manage.py shell -c "from allauth.mfa.models import Authenticator; print(list(Authenticator.objects.values_list('type', 'data')))"
   ```

   To check staff two-step sign-in, make a superuser and confirm their email:

   ```bash
   uv run python manage.py createsuperuser
   uv run python manage.py mark_email_verified you@example.com
   ```

   Open http://localhost:8000/admin/ (or your `DJANGO_ADMIN_URL`): it sends you to
   capy-auth's sign-in page, then to "Two-step sign-in", which says why, until you set
   up an app or a passkey. After saving the recovery codes, "Continue" opens the
   admin. Sign out and in again: after the code, the admin opens straight away.
   Signed in as someone who isn't staff, the admin says "403 Forbidden".

   To check the staff email, add a user in the admin, open the "An account was created
   for you" email in the `runserver` output, choose a password with its link, and sign
   in without another code.

## Settings

Admins change capy-auth's settings in the Django admin, on the **capy-auth settings**
page: superusers, and staff with "Can change capy-auth settings" (or "Can view
capy-auth settings" to see them read-only). They're kept as one record in the
database; the admin's history shows who changed what. They only take effect when the
project uses capy-auth's account adapter (install step 4).

The record is created the first time it's needed (the first visit to the signup page
or the settings page, or the first password check), with
its starting values from the project's settings below. After that, what admins set
wins: changing the project's setting no longer has an effect, so change it on the
settings page instead. An option added in a later release starts from the project's
setting too: its migration copies the setting into the existing record (and the
CHANGELOG names it).
| Setting | Default | Starting value of |
| --- | --- | --- |
| `CAPY_AUTH_SIGNUP_OPEN` | `True` | **Signup open:** anyone can create an account. When off, the signup page says signup is closed and creates no accounts. allauth's own `ACCOUNT_SIGNUP_ENABLED = False` also closes it. |
| `CAPY_AUTH_BREACHED_PASSWORD_CHECK` | `"everyone"` | **Check breached passwords:** `"everyone"` (shown as "everyone"), `"staff"` ("staff and superusers") or `"off"` ("nobody"). New passwords that have appeared in a data breach are refused. While it applies and Have I Been Pwned can't be reached, new passwords are refused too. Needs the validator in `AUTH_PASSWORD_VALIDATORS` (install step 4, which also says who each level covers). |

Settings that must not change while the site runs (secrets, the site's domain, the
email server) stay in the project's settings and environment. `CAPY_AUTH_ENCRYPTION_KEYS`
(the key for MFA secrets; "The encryption key" in install step 4) is one of these: the
settings page only shows whether it's set, never the key. Each starting value must
be `True` or `False` (or one of the option's choices); Django's checks stop the
project otherwise (`capy_auth.E002`).

**Adding an option** (for developers): add the field to `config/models.py` with a
`db_default`, its starting value to `starting_values()` in `config/selectors.py`, a
check in `config/checks.py`, and, in the same migration, a `RunPython` step that copies
`getattr(settings, "CAPY_AUTH_…", default)` into the existing record (using
`apps.get_model`, with `migrations.RunPython.noop` as the reverse).

## Ban list

Staff ban people in the Django admin, under **Capy Auth**. Banning and lifting bans
change accounts, so the ban pages need the account permissions too (superusers have
them all):

- **Adding or deleting bans:** the ban list's own permission plus "Can change user".
- **Lifting bans** (the action below): "Can delete banned email address" plus "Can
  change user".
- **Looking at bans or attempts:** their "view" permission plus "Can view user" (or
  "Can change user"). Deleting attempts needs "Can change user" too.

What happens:

- **Banned email addresses:** add an address (capitals, and spaces before or after it,
  don't matter; an international domain matches its punycode form) and an optional
  reason (staff only). Adding it suspends every account whose own email, or one of
  whose confirmed addresses, is that address: the account is deactivated, never
  deleted, its password is removed, and its main email address gets a "your account
  has been suspended" email. Removing the password signs it out everywhere: Django
  checks every session against a fingerprint of the account's password, so all its
  sessions stop working, on every device and in any session store, even ones nothing
  recorded, and lifting the ban later signs nobody back in. Its two-step sign-in
  (authenticator app, passkeys, security keys, recovery codes) is removed too, so a
  passkey can't sign it straight back in when the ban is lifted, even one someone else
  added; the "restored" email asks the person to set it up again. Signing in then fails as
  for a wrong password (the email told them why). The ban page lists the accounts it
  suspended. Editing a ban later (its reason) changes no account; its address can't
  be changed (lift the ban and add a new one). You can't ban one of your own
  addresses.
- **Only the exact address is banned:** `mallory+anything@example.com` is a different
  address. Some providers deliver it to `mallory@example.com` and some don't, so
  capy-auth doesn't guess.
- **What a banned address can't do:** sign up (the page looks like any signup; no
  account is made) or be confirmed on an account (adding it looks normal, but no code
  is sent and it's never stored as confirmed, whatever tries to confirm it). Instead of
  any code, link or other email, the address gets one notice: "This address can't be
  used for an account". Each real signup or add-email try is recorded under **Banned
  address attempts** (the address, what was tried, the account if signed in, the IP
  address, the time) and logged as a warning; a password reset isn't recorded. Nothing
  happens to the account automatically: staff look and decide, and may delete old
  entries (they hold IP addresses, which are personal data).
- **Reversing a ban:** select bans in the list and choose **Lift the selected bans and
  reactivate the accounts they suspended**. An account another ban still holds stays
  suspended. Each reactivated account gets a "your account has been restored" email
  with a one-time link to choose a new password (its old one was removed; after the
  link expires, "Forgot your password?" works too). The admin's history records the
  lifted bans and each reactivated account. Deleting a ban lifts it without
  reactivating anyone; reactivate an account by hand by checking the **Active** box
  on its user page (the person then uses "Forgot your password?"). A suspended account
  asking for a password reset is told no account was found, as for any inactive
  account.
- **Deactivating an account by hand** (unchecking **Active** on its user page) keeps
  its password: signing in with it shows "Account suspended", and checking **Active**
  again signs its old sessions back in. Use a ban to cut a person off completely.
- **Bans come from the admin:** a ban created another way (the shell, fixtures, a data
  migration) blocks the address but suspends no one; to suspend, call
  `capy_auth.bans.services.suspend_accounts(ban)` too.
- **Deleting accounts:** staff with Django's "delete user" permission can delete an
  account on its user page as usual. The ban is on the address, so it still applies.
- **Banned social accounts:** a provider (allauth's provider ID, e.g. `google`) and the
  person's ID there. They're stored now and checked once capy-auth's social login
  support arrives.

To try it: ban an address in the admin, then sign up with it. The page looks like any
signup, the `runserver` output shows only the ban notice, and the attempt appears under
**Banned address attempts**.

## Upgrading

Install the new tag (the same `uv add … --tag vX.Y.Z` line), then run
`uv run python manage.py migrate`, rebuild the Tailwind stylesheet
(`uv run python manage.py tailwind build`; a new version may use daisyUI classes the
old one didn't), and in production deploy as usual (the image runs `collectstatic`; the
migrate step migrates). Read `CHANGELOG.md` first: each version
says what a project must do, if anything. When it says "deploy vX.Y.Z first", install
and deploy that version before going further, even when jumping several versions:
skipping it can remove a column the running code still uses (see
[Database](#database)).

## Logging

The module logs through its own logger, never `print()`, and never sets up handlers
(the project decides where logs go):

```python
import logging

logger = logging.getLogger("capy_auth")
```

Never log secrets, passwords, tokens or personal data; log IDs instead.

What capy-auth logs (never an email's content or address): a warning when an email is
sent during the request instead of by the worker (the cache or job queue is down, or it
has attachments) and each time a send fails and will be tried again; an error when a
queued email is gone from the cache, can't be read, or couldn't be sent after the last
try. An error, with the cache's own error, for each request that gets the "temporarily
unavailable" page because the cache is down. A warning when a banned address is tried,
with what was tried and the recorded attempt's ID (the address is in the admin, not the
log). An error when a stored MFA secret can't be decrypted with any key in
`CAPY_AUTH_ENCRYPTION_KEYS` (never the key or the secret). An error, too, when Have I Been Pwned can't be reached or answers badly (at most
once a minute, while new passwords are refused; never the password or who it was for).

## Rules that keep it pluggable

- Never import from a project or from another module (another capy module, such as
  capy-theme). Its own dependencies, such as django-allauth, are fine.
- Link to users with `settings.AUTH_USER_MODEL`, never a project's `User` class.
- Keep templates in `src/capy_auth/templates/capy_auth/` and static
  files in `src/capy_auth/static/capy_auth/`, so names never clash.
  **Exception:** templates that replace allauth's keep allauth's names
  (`templates/allauth/…`, `templates/account/…`), since that's how Django picks
  capy-auth's version over allauth's; so does `templates/429.html`, the page allauth
  shows when a rate limit is hit. Any other template capy-auth adds goes in
  `templates/capy_auth/`.
- Read settings with the `CAPY_AUTH_` prefix and a default (see
  Settings), when they're used (in forms, views, validation), never in a model field's
  definition (`choices`, `max_length`, `default`, `upload_to`): a project that changed
  the setting would get migrations of its own for the module.
- **Never add a `check --deploy` warning** to a project (`tests/test_host_rules.py`
  checks this).
- **URLs:** name them inside `app_name = "capy_auth"` in `urls.py`
  (`{% url "capy_auth:detail" … %}`), so
  they never clash with a project's. Models expose a `public_id` (a UUID) in URLs and
  APIs, never the database `id`, as projects made from capy-project do.
  **Exception:** `capy_auth.urls` includes allauth's pages, whose names
  (`account_login`, `account_signup`, …) allauth's own code relies on, so it has no
  `app_name`; capy-auth's own page names start with `capy_auth_` instead
  (`capy_auth_account`).
- **Business logic** lives in plain functions (`services.py` for changes, `selectors.py`
  for reads) that views, the admin and background jobs share.
- **Slow work** (emails, file processing, calls to other services) goes to a
  background job with Django's Tasks API, in the module's `tasks.py`: enqueue it with
  `transaction.on_commit(lambda: my_job.enqueue(obj.id))` when saving something, keep
  each job well under 60 seconds (a deploy waits that long for running jobs), and when
  a job's arguments change, keep accepting the old ones until queued jobs have run. A
  project needs its `worker` running for them. **Email** goes through
  `django.core.mail`. A job's arguments never hold a secret (a code, a link with a
  token, a password): capy-auth's emails wait in the cache and the job carries only a
  random key (`emails/`).
- **The cache** is Redis in projects made from capy-project, and Django raises an error when
  Redis is down: code that must keep working then catches cache errors and falls back
  to the database. Clear a cached value when its data is saved; don't rely on a
  timeout alone.

### Pages

- **Every page extends `layout.html`**, the project's own layout (its nav bar, theme
  and any footer), and fills only:
  - `{% block title %}`: always, with what the page is ("Edit
    invoice"), translated like other text. Without it the tab says "Untitled page",
    which screen readers announce.
  - `{% block head %}{{ block.super }}…{% endblock %}`: the page's
    stylesheets and scripts, starting with `{{ block.super }}`.
  - `{% block content %}`: the page itself.

  Leave `header` and `footer` to the project, and never ship a `layout.html` of your
  own. A module whose job is the layout itself (a nav menu, a theme) provides template
  tags instead, and its README says which line a project adds to its `layout.html`:
  in its `head` block, in the nav in its `<header>`, or, for attributes on `<html>`,
  in its `html_attrs` block, starting with a space
  (`{% block html_attrs %} data-theme="dark"{% endblock %}`), since
  it follows `lang="en"`.
  Modules rely only on the name `layout.html`, these three blocks, and the layout
  showing Django's messages in a `role="status"` region. Template tags that
  read the database belong in `layout.html`, never in `base.html`, so the project's
  error pages keep working when the database is down; a tag shown on every page runs a
  fixed, small number of queries.
- **Accessible** (WCAG 2.2 AA):
  - the content starts with one `<h1>`, headings in order;
  - no page-level `<main>`, `<header>` or `<footer>` of the module's own (the layout
    has them; a `<header>` inside an `<article>` is fine);
  - forms rendered by Django (labels, help text and errors linked to their fields) or,
    when written by hand, a visible `<label for>` and `aria-describedby` for help and
    errors on every field; after a failed submit, the errors are near the top of the
    page or the first wrong field gets the focus;
  - **form help text is shown as HTML** (as Django's own forms do, for lists such as
    the password rules), so it must be fixed text or built with `format_html`, never
    from user or database data;
  - real `<button>` and `<a>` elements, never clickable `<div>`s; buttons and
    standalone links (not links inside a sentence) at least 24 by 24 CSS
    pixels, with a visible focus outline (never `outline: none` without a replacement);
  - every `<img>` has `alt` (empty, `alt=""`, for decoration) and its `width` and
    `height`, so the page doesn't jump while it loads;
  - the module's CSS uses the page's colors (`currentColor`, inherited colors or the
    theme's CSS variables) rather than fixed ones, and any color it does set has enough
    contrast (4.5:1 for text, 3:1 for icons and borders) in both light and dark mode;
  - sizes in `rem`, and the page works at 320 px wide and zoomed to 200% without
    scrolling sideways;
  - animations and transitions stop under `@media (prefers-reduced-motion: reduce)`.
- **Static files** always through `{% load static %}{% static "capy_auth/…" %}`,
  never `/static/…` (projects give files cache-busting names). `url()` paths in CSS
  are relative and must exist (the project's `collectstatic` fails otherwise). Scripts
  get `defer`; no web fonts of the module's own.
- **Text people see** is marked for translation: `gettext_lazy as _` in Python
  (models' `verbose_name`, form labels, messages) and
  `{% load i18n %}{% translate "…" %}` in templates
  (`{% blocktranslate %}…{{ name }}…{% endblocktranslate %}` for text
  with values in it).
- **Confirm actions** with Django's messages framework
  (`messages.success(request, _("Saved."))`); the project's `layout.html` shows them.
- **No inline code**: projects enforce a strict Content Security Policy (a
  project made from capy-project only reports problems while you develop, and blocks them in
  production). Put CSS and JavaScript in static files; if inline code is unavoidable,
  give the tag `nonce="{{ csp_nonce }}"` or
  `{% csp_nonce_attr %}`. Never `style="…"`, `onclick=` or
  `javascript:` links, and no code that needs `eval` (htmx's `hx-on`, or Alpine's
  standard build: use its CSP build). Load nothing from other sites (CDNs, web fonts, images too) and don't post
  forms to them; `data:` URLs only for images and icons. No frames, video, audio,
  embedded objects or manifests: the policy of projects made from capy-project blocks them all.
- **`tests/test_csp.py` checks** the module's HTML, SVG, XML and Jinja templates under
  `templates/` and `jinja2/` against that policy. It's a safety net that reads
  template source, not a browser: it can't see CSS or JavaScript files, what inline
  code loads, what template variables hold (a URL from a setting or the database), a
  block a project's template fills in, HTML built in Python (`format_html`), or
  markup opened in one `{% if %}` branch and closed in another, so
  keep the same rules there. It reports a full URL to the project's own site as another
  site (use a path, `/x/`, or `{% url %}`), and a nonce'd script
  whose code contains the text `<script` or `<style`. To comment code out, use
  `{% comment %}`, a one-line `{# #}` or an
  HTML comment: Django prints a `{# #}` that spans lines as text,
  and the check reads Jinja templates the same way, so keep `{# #}`
  on one line in Jinja templates too.
- **HTML emails** go in `templates/capy_auth/emails/` (or
  `jinja2/capy_auth/emails/`): they need inline styles and full image URLs,
  and the site's policy doesn't apply to them, so the check skips that folder. Nothing
  else goes there.
- **Testing pages:** the stand-in project already has copies of capy-project v1.1.0's
  `base.html` and `layout.html` in `tests/templates/`, under its enforced Content
  Security Policy, so a test that requests one of the module's pages gets the same page
  frame and policy as in a real project. Keep those copies in step with capy-project's.

## Security

Rules for the module's code. The project trusts whatever the module does, so:

- **Views:** every view checks login and permission (or ownership), so nobody can see
  or change someone else's data by changing an ID in the URL. Test it for anonymous
  users and for other users.
- **Forms and input:** validate all input with Django forms;
  `{% csrf_token %}` in every POST form; never `csrf_exempt`.
- **Database:** the ORM or parameterized queries only, never SQL built from strings.
- **Changes only on POST:** a view that changes anything refuses GET
  (`@require_POST`), so a link or an image on another site can't trigger it. Check
  redirect targets such as `next` with `url_has_allowed_host_and_scheme` (no open
  redirects).
- **Logins:** never check passwords or tokens yourself; use
  `django.contrib.auth.authenticate(request, ...)`, so the project's login rate
  limiting (django-axes) counts every attempt. The one exception is allauth's passkey
  sign-in, which has its own limit (see "Every passkey or security key can sign in on
  its own").
- **Output:** keep auto-escaping; never `|safe` or `mark_safe` on anything a user
  typed. Auto-escaping only makes text safe inside HTML, not inside CSS, JavaScript or
  a URL, so:
  - a value that ends up in CSS, JavaScript or a URL (a color, a name, a link) is
    checked against a strict pattern or a list of choices when it's saved, not only
    when it's shown;
  - data for JavaScript goes through `{{ data|json_script:"id" }}`,
    never `{{ }}` inside a script;
  - never build a `Template(...)` from text a user typed;
  - a URL a user gives is saved and put in a link (`href`) only if it starts with
    `https://` (or `http://`): this stops `javascript:` links. Never redirect to one;
    redirects go only to pages on the project's own site (see `next` above).
- **Uploads:** check the size, and the type from the file's content, never from its
  name or the browser's word. For images, during the request, keeping Pillow's
  `MAX_IMAGE_PIXELS` limit and treating its `DecompressionBombWarning` as an error
  (only around this check, not for the whole server):

  ```python
  import warnings

  from PIL import Image

  with warnings.catch_warnings():
      warnings.simplefilter("error", Image.DecompressionBombWarning)
      with Image.open(upload) as img:
          img.verify()  # raises for a broken or oversized image: refuse the upload
          kind = img.format  # e.g. "PNG": check it's one the module allows
  ```

  Fully decoding, resizing or converting an image happens later, in a background job
  (see below).
  Name the stored file's extension after the format Pillow found (`img.format`), not
  the uploaded name. `ImageField` needs Pillow (`uv add pillow`). Store each file
  under a `capy_auth/` folder with a random part, from a function of the
  module's own (projects' helpers can't be imported):

  ```python
  from uuid import uuid4

  from django.utils.text import get_valid_filename


  def random_folder(instance, filename):
      # Each file in its own unguessable folder; a top-level function keeps migrations stable.
      return f"capy_auth/{uuid4().hex}/{get_valid_filename(filename)}"
  ```

  In projects made from capy-project the default storage is **private**: its files are served
  only through the project's own view, to whoever the project's `can_download()`
  allows (by default, active staff). So a module that keeps private files either says
  in this README what projects should allow in `can_download()`, or serves them
  through its own view that checks permission. Such a view sends each file with
  `FileResponse(…, as_attachment=True)` and the headers
  `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`
  and `Cache-Control: private, no-store`, always as a download, as the project's own
  view does (an `<img>` tag still shows an image sent this way). With S3 storage
  (`DJANGO_MEDIA_STORAGE=s3`), a file's `.url` is a signed link that works for an hour
  for whoever has it: show it only to people allowed to see the file, and never save
  or email it. Files anyone may see (pictures on public pages) go in the project's
  "public" storage, chosen without importing project code (a function keeps the
  module's migrations the same in every project):

  ```python
  from django.conf import settings
  from django.core.files.storage import default_storage, storages


  def public_storage():
      # The project's public storage (capy-project's projects have one), else the default.
      return storages["public"] if "public" in settings.STORAGES else default_storage
  ```

  and `models.ImageField(storage=public_storage, upload_to=random_folder, ...)`.
  Unpacking archives, decoding images or reading fonts is capped in size and runs in a
  background job, never in the request.
- **URLs a user gives** (webhooks, "import from a link", remote images): otherwise a
  user can make the server reach its own database, Redis, cloud metadata or other
  internal services. Fetch them in a background job, and:
  - only `https://` on port 443;
  - resolve the host, and go on only if **every** address it gives is public
    (`ipaddress.ip_address(a).is_global`; for an IPv6 address, check its
    `ipv4_mapped` address too);
  - connect to the address you checked, not the name again: a second lookup can give
    a different, internal address (DNS rebinding). Keep certificate checks on, checked
    against the original host name (the client library's way of pinning the address
    while keeping the name, never `verify=False`);
  - don't follow redirects, or check each one the same way;
  - cap the response size and the time.
- **Background jobs:** pass IDs, never secrets, tokens or personal data, as arguments:
  they're stored in the database and shown in the admin.
- **Secrets:** never in code. A secret the module needs comes from a project setting
  (read from the environment there); fail with a clear error if it's missing.
- **Calls to other services:** HTTPS only, certificate checks on, and a timeout.
- **Logs:** see [Logging](#logging).

## Database

- **Supported:** PostgreSQL 18 and SQLite (both tested on every pull request). CI's
  Postgres tests log in as a role like the app login of a project made from capy-project (not a
  superuser), as projects migrate with.
- **Every migration keeps working with the previous release's code.** Projects
  migrate while the old code still runs, and a rollback keeps the new database with
  the old code, so:
  - a new field is `null=True` or has `db_default=…`, never only `default=` (which
    exists only in Python: the old code's inserts would fail);
  - a new constraint accepts every row the previous release can write;
  - a model gets its `public_id` in the migration that creates it: adding a unique
    field to a table that already has rows rewrites and locks the whole table (it then
    takes a nullable field, filled in batches, and a unique index made as below);
  - **removing a field takes three releases:**
    1. stop using it, and make it nullable or give it a `db_default`;
    2. remove it from the model with a migration that changes only Django's state
       (`migrations.SeparateDatabaseAndState(state_operations=[migrations.RemoveField(…)])`,
       no database operations);
    3. drop the column. Django's `RemoveField` can't (the field is no longer in the
       model), so use
       `migrations.RunSQL('ALTER TABLE "capy_auth_thing" DROP COLUMN "old_name"', migrations.RunSQL.noop)`
       (on SQLite, the column's index or constraint must go first), or `DROP TABLE`
       for a whole model.
  - **renaming a field** the same way, or its data is lost (the old code keeps writing
    only the old column, during the deploy and after a rollback):
    1. add the new field (nullable or with a `db_default`), write to both fields, and
       copy the old values across in a data migration;
    2. copy again the rows the old code wrote meanwhile, make the old field nullable
       (or give it a `db_default`), read and write only the new field, and remove the
       old one from the model (state only);
    3. drop the old column.

    If the new field must be required, make it so in a later release, after step 2's
    copy. Each of these releases can be rolled back only to the one before it, and the
    column drop can't be undone.

    To rename it only in Python, keep the column instead:
    `new_name = models.CharField(…, db_column="old_name")` changes nothing in the
    database.
- **A release that finishes such a change** says "deploy vX.Y.Z first" in
  `CHANGELOG.md`, naming the release before it, so a project that skips versions
  doesn't drop a column its running code still uses (see [Upgrading](#upgrading)).
- **Big tables:** on Postgres, a plain `AddIndex`, a field type change and a new
  unique, check or foreign-key constraint lock the table for as long as they take,
  while the old code is serving; a new foreign key locks the table it points to (often
  the users table) too, and every query that comes after a waiting migration waits
  as well. Build indexes with `CONCURRENTLY`, which doesn't lock. Django's
  `AddIndexConcurrently` crashes on SQLite, so a module that supports both uses a
  migration like this one:

  ```python
  from django.db import migrations, models

  # The name is unique in the whole database, 30 characters at most.
  INDEX = models.Index(fields=["created"], name="capy_auth_created_idx")


  def add_index(apps, schema_editor):
      model = apps.get_model("capy_auth", "Thing")
      if schema_editor.connection.vendor == "postgresql":
          schema_editor.add_index(model, INDEX, concurrently=True)
      else:
          schema_editor.add_index(model, INDEX)


  def remove_index(apps, schema_editor):
      model = apps.get_model("capy_auth", "Thing")
      if schema_editor.connection.vendor == "postgresql":
          schema_editor.remove_index(model, INDEX, concurrently=True)
      else:
          schema_editor.remove_index(model, INDEX)


  class Migration(migrations.Migration):
      atomic = False  # CONCURRENTLY can't run inside a transaction

      dependencies = [("capy_auth", "0002_previous")]

      operations = [
          migrations.SeparateDatabaseAndState(
              database_operations=[migrations.RunPython(add_index, remove_index)],
              state_operations=[migrations.AddIndex("thing", INDEX)],
          ),
      ]
  ```

  Add the same index to the model's `Meta.indexes`. If the migration fails on
  Postgres, it leaves an INVALID index behind: drop it (`DROP INDEX CONCURRENTLY …`)
  before running `migrate` again.
- **Data migrations** that change many rows go in a migration of their own (never with
  schema changes), with `atomic = False`, saving each batch (say 1,000 rows) in its own
  `transaction.atomic()`, so no single transaction holds the table for long.
- **Nothing that needs a superuser** (e.g. `CREATE EXTENSION` of an untrusted
  extension; trusted ones such as `pg_trgm` work): projects made from capy-project migrate
  with a login that isn't one, and so does CI. If the module needs such an extension,
  say so here and in the CHANGELOG, so the project adds it first.
- **Never edit or delete a released migration**; add a new one. Data migrations use
  `apps.get_model` and have a reverse (or `migrations.RunPython.noop`).
- **Queries:** no query per row (`select_related` and `prefetch_related`); an index for
  the filters and orderings the module runs often on tables that grow (each index slows
  every write, so not on every field); pagination on any list that grows; and in the
  admin, `raw_id_fields` for links to users (`autocomplete_fields` only works if the
  project's user admin has `search_fields`) or other big tables, since a plain one
  puts every user in the page. pytest-django's `django_assert_max_num_queries` keeps a
  page's query count in check in its tests.
- **Say in the CHANGELOG** when a migration deletes data or is slow on big tables.

Create migrations after changing models (`tests/test_app.py` fails until you do):

```bash
uv run django-admin makemigrations capy_auth --settings=tests.settings --pythonpath=.
```

After updating the copy of capy-project's user model (`tests/email_users/models.py`),
make its migration the same way, with that user model switched on:

```bash
TEST_USER_MODEL=email uv run django-admin makemigrations email_users --settings=tests.settings --pythonpath=.
```

## Develop it

You need git, Docker (for Postgres tests and full secret scans) and uv 0.12: the
module requires that version line, the same one CI uses, so `uv.lock` is always
written the way CI reads it. If uv came from its standalone installer,
`uv self update 0.12.24` switches to it (down from a newer uv too); otherwise install
0.12.24 the way you installed uv. Once, after cloning the repository:

```bash
git clone https://github.com/Just-Sean/capy-auth.git && cd capy-auth
uv sync                    # installs Python, Django, allauth, django-axes and the test tools
uv run pre-commit install  # turns on the checks that run on every commit
```

The repository already exists on GitHub (public, MIT); the starter's steps for
creating it are done. In the repository's Settings:

- **Code security** (called "Advanced Security" on some accounts): turn on
  "Dependabot alerts" and "Dependabot security updates"; for a public repository, also
  secret scanning with push protection, and code scanning.
- **Branches:** protect `main` so a pull request needs CI to pass before it's merged:
  require the checks "Lint (ruff)", "Tests (sqlite, locked versions)", "Tests
  (postgres, locked versions)", "Tests (sqlite, lowest versions)", "Tests (sqlite,
  locked versions, capy-project users)", "Tests (postgres, locked versions, capy-project
  users)", "Dependency
  vulnerabilities (pip-audit)", "Package (only the module ships)" and "Secrets
  (gitleaks, whole history)". GitHub lists them to pick from only after CI has run
  once, so open your first pull request, then come back. On a free GitHub account,
  a private repository can't protect branches: there, check that CI passed before you
  merge.

Every day:

```bash
uv run pytest                      # runs the tests on SQLite, no setup needed
TEST_USER_MODEL=email uv run pytest  # the same, with a copy of capy-project's user model
uv run pytest --cov                # the same, with coverage (fails below 80%)
uv run ruff check .                # finds problems
uv run ruff format .               # formats the code
uv run pre-commit run --all-files  # the commit checks, on every file
```

Before every pull request, check the dependencies for known vulnerabilities:

```bash
(f=$(mktemp) && trap 'rm -f "$f"' EXIT && uv export --locked --format requirements-txt --no-emit-project --quiet -o "$f" && uv run pip-audit --disable-pip --require-hashes -r "$f")
```

**On GitHub,** every pull request runs `.github/workflows/ci.yml`: ruff; the tests
with coverage on SQLite and on PostgreSQL 18 (logged in as a role that isn't a
superuser, like a project's) with the versions in `uv.lock`, once more on SQLite
with the lowest versions `pyproject.toml` allows, and on both databases again with a
copy of capy-project's user model (`TEST_USER_MODEL=email`); pip-audit; a scan of the whole
history for secrets (gitleaks); and a check that the built package holds only the
module. A newer push to a pull request cancels the older run. Dependabot
(`.github/dependabot.yml`) opens pull requests for updates every week, once a release
is a week old.

The commit check only scans what's being committed. To scan every file and the whole
history for secrets (the every-file scan also reads files git ignores, like a local
`.env`, so a finding there may never have been committed):

```bash
docker run --rm -v "$PWD:/repo:ro" ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f dir /repo --redact   # every file
docker run --rm -v "$PWD:/repo:ro" ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f git /repo --redact   # the whole history
```

**Updated by hand** (Dependabot doesn't touch these), keeping each pair in step:

- **uv:** `UV_VERSION` in `.github/workflows/ci.yml`, and in `pyproject.toml` both
  `required-version` and the `uv_build` range (`>=0.12,<0.13` goes with uv 0.12),
  plus the `uv self update` command under Develop it.
- **gitleaks:** `rev` in `.pre-commit-config.yaml` (`uv run pre-commit autoupdate --freeze`)
  and `GITLEAKS_IMAGE` in `.github/workflows/ci.yml`, plus the two commands above.

To run the tests on Postgres here too, with a login like CI's (port 5433, so it never
clashes with a project's database on 5432):

```bash
docker run -d --rm --name capy-auth-postgres -p 127.0.0.1:5433:5432 -e POSTGRES_USER=app -e POSTGRES_PASSWORD=app -e POSTGRES_DB=module_tests postgres:18-trixie
docker exec capy-auth-postgres pg_isready -U app -h 127.0.0.1   # repeat until "accepting connections"
docker exec capy-auth-postgres psql -U app -d module_tests -c "CREATE ROLE module LOGIN PASSWORD 'module' NOSUPERUSER CREATEDB"
DATABASE_URL=postgres://module:module@localhost:5433/module_tests uv run pytest
TEST_USER_MODEL=email DATABASE_URL=postgres://module:module@localhost:5433/module_tests uv run pytest
docker stop capy-auth-postgres   # stops it and deletes it, data included
```

To check what the package will ship (CI does this too): `rm -rf dist && uv build
--wheel`, then `uv run python -m zipfile -l dist/*.whl` should list only
`capy_auth/` and its metadata.

## Release a version

After the first push, nothing is pushed straight to `main`: every change goes
through a pull request. Each tag is `v` plus `version` from `pyproject.toml`.

**The first release** is `v0.1.0`: `pyproject.toml` and `CHANGELOG.md` already say
0.1.0. If the CHANGELOG's 0.1.0 entry needs more, follow steps 1 to 4 without changing
the version. If not, there's nothing for a pull request: check that CI passed on
`main`, try `main` in a project as step 2 says (with `--branch main`), then tag `v0.1.0` (step 4).

1. Open an issue for the release and a branch for it. Change `version` in
   `pyproject.toml`, run `uv lock` (CI refuses a lock file that doesn't match), and add
   the version at the top of `CHANGELOG.md`: what changed, and what a project must do
   when it upgrades (newest version first). Commit `pyproject.toml`, `uv.lock` and
   `CHANGELOG.md`.
2. Try the branch in a project made from capy-project:
   - **While developing:** install your working copy
     (`uv add --editable ../capy-auth`) and run the project's tests (they
     include `check --deploy` with production settings).
   - **In production form:** push the branch, install it with
     `uv add git+https://github.com/Just-Sean/capy-auth --branch BRANCH`,
     and try it in the project's local production run (its README, "Production (the
     real image, run locally)").

   Afterwards, put the project back on its previous tag (the `uv add … --tag` line),
   or `uv remove capy-auth` before the module's first release.
3. Open a pull request; CI must pass (both databases, both user models, the lowest
   versions, the package check). Merge it.
4. Tag the merged `main` and push only the tag:

   ```bash
   git switch main && git pull
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

5. In each project, install the new tag when you want it (see [Upgrading](#upgrading)).

## Updating from the starter

When capy-module improves (its release notes on GitHub say what changed and
what to do):

1. Commit everything, and make a branch.
2. Run `copier update`. Copier asks its questions again: press Enter to keep each
   answer.
3. Where the starter and your module both changed a file, Copier writes both versions
   into it between `<<<<<<<` and `>>>>>>>` lines: search for `<<<<<<<` (`git status`
   lists the changed files) and keep the right lines, your own changes and the newer
   of two pinned versions.
4. Run `uv lock`, `uv run pytest --cov`, `TEST_USER_MODEL=email uv run pytest` and
   `uv run ruff check .`.
5. Commit, open a pull request, and merge it once CI passes. If CI's check names
   changed, update the required checks under Settings > Branches.

To change the GitHub owner (or the license or copyright year) the module was made
with, which also brings in the starter's newest release as `copier update` always
does:

```bash
copier update --defaults --data github_owner=NEW-OWNER
```

If the repository itself moved, also point git at it:
`git remote set-url origin https://github.com/NEW-OWNER/capy-auth.git`.

## Files

| Path | Purpose |
| --- | --- |
| `src/capy_auth/` | The Django app that projects install |
| `src/capy_auth/apps.py` | The app's name, label and admin title |
| `src/capy_auth/models.py` | Lists the module's database models for Django (each lives in its section) |
| `src/capy_auth/admin.py` | Lists the module's admin pages for Django (each lives in its section) |
| `src/capy_auth/config/` | The settings record (`models.py`), reading it (`selectors.py`), its admin page (`admin.py`, which also shows whether the MFA key is set) and Django's checks for the project's setup (`checks.py`: errors E001–E003, warnings W001 for weakened security settings, W002 for a cache the worker can't share, W003 for a missing breached-password check) |
| `src/capy_auth/urls.py` | capy-auth's URLs (mounted at `accounts/`): the "Your account" page, where people land after logging in, the "Signed-in devices" page (`sessions/`), and allauth's pages |
| `src/capy_auth/mfa/` | Encrypting MFA secrets (`crypto.py`), the MFA adapter that does it (`adapter.py`), re-encrypting and the wrong-code warning (`services.py`, `receivers.py`), the passkey forms (`forms.py`), two-step sign-in required for staff (`staff.py`), and the startup checks E007 to E012, W005 and W006 (`checks.py`) |
| `src/capy_auth/templates/capy_auth/staff/` | What the two-step pages show staff who must use it: why they're there (`notice.html`), and "Sign out" or "Continue" (`way_on.html`) |
| `src/capy_auth/management/commands/capy_auth_reencrypt.py` | `manage.py capy_auth_reencrypt`: re-encrypts every MFA secret with the first key |
| `src/capy_auth/templates/mfa/` | The two-step sign-in pages (rewritten from allauth's): the overview, setting up and turning off an authenticator app, the sign-in code step, recovery codes, passkeys and security keys (`webauthn/`), and their confirmation messages |
| `src/capy_auth/templates/capy_auth/mfa_unavailable.html` | The page shown when a stored MFA secret can't be decrypted |
| `src/capy_auth/templates/capy_auth/passkeys/` | The passkey parts of capy-auth's pages: the sign-in page's form and scripts, the second step's passkey form, allauth's scripts plus capy-auth's, and the status line with the no-JavaScript notice |
| `src/capy_auth/static/capy_auth/js/passkeys.js` | Shows a message when a passkey attempt fails, hides passkey buttons on browsers without passkeys, and stops a second press while one runs |
| `src/capy_auth/sessions/` | Recording every sign-in (`recording.py`), the "Signed-in devices" page's view (`views.py`), and the startup checks E006 and W004 (`checks.py`) |
| `src/capy_auth/templates/usersessions/` | The "Signed-in devices" page at `accounts/sessions/` and its message (rewritten from allauth's; compare with allauth's when upgrading it, as for `account/`) |
| `src/capy_auth/templates/capy_auth/account.html` | The "Your account" page |
| `src/capy_auth/templates/429.html` | allauth's "too many attempts" page, inside the layout |
| `src/capy_auth/account/adapter.py` | capy-auth's account adapter (allauth asks it how to behave: whether signup is open, its messages, equal timing for taken emails, sending emails through the worker) and `user_display` |
| `src/capy_auth/emails/` | Emails sent by the background worker: the finished email waits in the cache (`sending.py`), the job sends it and retries (`tasks.py`) |
| `src/capy_auth/templates/allauth/layouts/base.html` | Puts every allauth page inside the project's `layout.html` |
| `src/capy_auth/templates/allauth/elements/` | allauth's building blocks (buttons, fields, forms, …) with daisyUI classes |
| `src/capy_auth/templates/account/` | allauth pages capy-auth replaces: `email_change.html` and `phone_change.html`, copied with their inline style removed (compare with allauth's when upgrading it; likewise `send_mail` in `account/adapter.py`, copied from allauth's); `email.html`, `password_reset_from_key*.html` and `reauthenticate.html`, rewritten (see Pages); `login.html`, copied with capy-auth's passkey parts; and the suspended page (below) |
| `src/capy_auth/templates/capy_auth/fields/widget.html` | daisyUI's class for each kind of form input |
| `src/capy_auth/limits/` | django-axes counting by the account's main email (`axes.py`), the "temporarily unavailable" page while the cache is down (`middleware.py`, `templates/capy_auth/unavailable.html`), the email check E004 (`checks.py`) |
| `src/capy_auth/bans/` | The ban list: its tables (`models.py`), admin pages (`admin.py`), reading it (`selectors.py`), suspending, reactivating and recording attempts (`services.py`), the signup check (`forms.py`), the add-email record and "never confirmed" safeguard (`receivers.py`) and the startup check E005 (`checks.py`) |
| `src/capy_auth/templates/capy_auth/email/` | The ban notice, "your account has been suspended" and "your account has been restored" emails, and "an account was created for you" (plain text; not the `emails/` Python package) |
| `src/capy_auth/templates/account/account_inactive.html` | allauth's inactive-account page, saying the account is suspended |
| `src/capy_auth/templates/capy_auth/locked_out.html` | django-axes' "too many attempts" lockout page, inside the layout (`AXES_LOCKOUT_TEMPLATE`) |
| `tests/client_ip.py` | A small copy of capy-project's `client_ip`, so the tests find the visitor's address as capy-project does behind its proxy |
| `src/capy_auth/passwords/breached.py` | The breached-password check: asks Have I Been Pwned with a 5-character hash prefix, refuses breached passwords, fails closed |
| `src/capy_auth/templatetags/capy_auth_forms.py` | The `daisy_widget` filter: adds the classes `widget.html` picks to an input |
| `src/capy_auth/account/services.py`, `account/receivers.py` | Confirming an address by hand, the "choose your password" email for accounts staff create, confirming the address on a completed reset |
| `src/capy_auth/management/commands/mark_email_verified.py` | `manage.py mark_email_verified <email>` |
| `src/capy_auth/templates/capy_auth/email/account_created_*.txt` | The "An account was created for you" email |
| `src/capy_auth/migrations/` | Database migrations (see Database); 0004 adds existing users' emails to allauth's list |
| `tests/settings.py` | A tiny stand-in project for the tests, with allauth, capy-project's Content Security Policy, django-axes as capy-project runs it, jobs run straight away (as in capy-project's development and tests) and a choice of user model (`TEST_USER_MODEL`) |
| `tests/urls.py` | The stand-in project's URLs: capy-auth's (its own page and allauth's) under `accounts/`, the admin with its login sent through allauth, a page in the layout, and another app's login page (Django's own login) |
| `tests/templates/` | Copies of capy-project's `base.html` and `layout.html`, which the module's pages extend |
| `tests/email_users/` | A copy of capy-project's user model, used with `TEST_USER_MODEL=email` |
| `tests/test_stand_in_project.py` | Checks the stand-in project gives the module what a capy project does |
| `tests/test_pages.py` | Checks allauth's pages render inside the layout under the strict policy, with daisyUI inputs, visible labels, linked help text and errors, and that the overrides keep up with allauth |
| `tests/test_settings_store.py` | Checks the settings record, its admin page, Django's checks and closing signup |
| `tests/test_email_password.py` | Checks signup, verification by code, login, logout, password reset and change, end to end |
| `tests/test_email_password_edges.py` | Edge cases and security: email case and spaces, code limits, rate limits behind a proxy, timing, redirects, reset tokens |
| `tests/test_background_email.py` | Checks emails go through the job with only a key in it, arrive as allauth built them, are sent once, retried after a mail server failure, and sent at once when the cache or job queue is down |
| `tests/test_limits.py` | Checks axes locks out one account (under its main email, however typed), not everyone at an address, and a forged forwarded address doesn't escape; the lockout page; the cache-down page; the email check |
| `tests/test_email_addresses.py` | Checks the email page (add with a code, make primary, remove), the existing-users migration, `mark_email_verified` and the email for accounts staff create |
| `tests/test_email_addresses_edges.py` | Edge cases: blank and shared addresses, the migration on real migration history, the email page's limits, the real admin "add user" page, when a reset does and doesn't confirm |
| `tests/test_sessions.py` | Checks asking for the password again (the 5-minute window), the "Signed-in devices" page, signing out everywhere else, and E006/W004 |
| `tests/test_sessions_edges.py` | Edge cases: every action that asks again, the 5-minute edge, sessions from Django's own login and from before the install, password changes, other users, hostile or long browser descriptions, IPv6 |
| `tests/test_mfa.py` | Checks setting up an authenticator app, signing in with its code, recovery codes, encrypted storage, changing keys and re-encrypting, the wrong-code warning, each MFA page's hints, wording and way back, the checks and the settings page's status line |
| `tests/test_mfa_edges.py` | Edge cases: codes at time-step edges, spaces, reuse, the wrong-code limit, recovery codes made again and downloaded, a lost or malformed key, bans and password resets |
| `tests/test_passkeys.py` | Checks adding a passkey or security key, signing in with it on its own and as the second step (refusing forged answers and other sites), confirming a change with it, renaming and removing it, E009 and W006 |
| `tests/test_passkey_pages.py` | Checks the passkey pages' wording, the second step worded for the person's ways of signing in, and that every passkey page has what its scripts need |
| `tests/test_passkeys_edges.py` | Tries to break passkeys: bans, unconfirmed emails, replayed answers, another person's key, keys without a PIN, rate limits, the cache going down, sessions, names |
| `tests/test_staff_two_step.py` | Checks staff and superusers must use two-step sign-in (setting it up counts, then "Continue"; or confirm with it, offered only its ways; a passkey counts), what the pages say and allow meanwhile, the admin's login going to capy-auth's sign-in page, E010 to E012 |
| `tests/test_staff_two_step_edges.py` | Tries to break it (from the QA review): a password alone reaching recovery codes or managing two-step sign-in, a project page named like a two-step page, the admin's Log out, POSTs and AJAX, people who stop being staff, another person's second step, where "next" leads |
| `tests/staff.py` | Signs staff in with two-step sign-in, for the tests of the admin pages, and helpers for the staff tests |
| `tests/webauthn.py` | A software passkey (fido2 and cryptography), so the tests prove a real passkey works with the server |
| `tests/totp.py` | Authenticator-app codes worked out as the apps do (RFC 6238), so the tests prove a real app works |
| `tests/test_bans.py` | Checks a banned address can't sign up or be added without the page showing it, gets only the ban notice, and is recorded; banning suspends, removes the password (signing every session out, recorded or not, in any store) and emails; lifting reactivates and emails a link to choose a new password; the admin permissions; the check E005 |
| `tests/test_breached_passwords.py` | Checks the breached-password check: what leaves the server, answers good and bad, failing closed and the minute after a failure, who is checked, the setting, its migration and checks |
| `tests/test_breached_password_pages.py` | Checks it on every page and command that sets a password (signup, change, reset, the admin, `createsuperuser`), and that the settings record is read once per request |
| `tests/hibp.py` | A stand-in for Have I Been Pwned (padded answers), so no test goes over the network |
| `tests/test_security_settings_check.py` | Checks the warnings W001 (weakened allauth settings) and W002 (a cache the worker can't share) |
| `tests/accounts.py` | Shared by the account tests: signing up, logging in, codes and reset links |
| `tests/conftest.py` | Clears allauth's rate-limit counts before each test, puts the Have I Been Pwned stand-in in place of the real connection, and the `ada` user |
| `tests/helpers.py` | `check_page()`, shared by the tests that request pages: in the layout, under the policy, accessible |
| `tests/test_app.py` | Checks the app loads from its own package and its migrations are complete |
| `tests/test_host_rules.py` | Checks the module adds no `check --deploy` warning to a project |
| `tests/test_csp.py` | Checks the module's templates have nothing a strict Content Security Policy blocks |
| `LICENSE` | The module's license (MIT) |
| `pyproject.toml` | Package name, version, Django versions supported, tool settings |
| `CHANGELOG.md` | What changed in each version, and what projects must do |
| `uv.lock` | The exact version of every package, so tests and CI install the same thing (commit it) |
| `.pre-commit-config.yaml` | The checks on every commit: gitleaks (secrets) and ruff |
| `.github/workflows/ci.yml` | The checks on every pull request (see Develop it) |
| `.github/dependabot.yml` | Weekly pull requests for package and CI updates |
| `.gitignore` | Keeps secrets, keys, local databases and test output out of git |
| `.python-version` | The Python version uv installs |
| `.copier-answers.yml` | Lets `copier update` find the template; don't edit |

## License

MIT: see `LICENSE`.
