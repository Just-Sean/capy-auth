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
  starting value. Why the database, not only the project's settings: admins change
  these while the site runs, without a deploy. Secrets and anything that must not
  change while running stay in the project's settings. The record holds single
  choices (on/off, a level); lists get their own tables in their own sections: the ban
  list, and social-login providers, whose secrets capy-auth stores encrypted (allauth's
  own provider table keeps them in plain text).
- **Accounts** are allauth's, set up by the settings in
  [Add it to a project](#add-it-to-a-project): signup with email and password, login by
  email, email verified by a code before the first login (with "send a new code"),
  password reset links that work once for an hour, notification emails, and the same
  answers for known and unknown addresses. capy-auth's adapter (`account/adapter.py`)
  names people by their email, words the "too many attempts" message for both logins
  and codes, and hashes a password when someone signs up with a taken email, so that
  answer takes as long as a new account's. Django's checks (`config/checks.py`) warn
  when a project weakens one of these settings. `urls.py` mounts allauth's pages with
  capy-auth's "Your account" page, where people land after logging in, and
  `templates/429.html` puts allauth's "too many attempts" page inside the layout.
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
- **Pages** come from allauth. capy-auth overrides only allauth's page frame and its
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
  an element something the override doesn't show.
- **The stand-in project** (`tests/settings.py`, `tests/urls.py`) is the smallest
  Django project that runs the app, so the tests prove it works outside any one
  project. It has allauth, capy-project's strict Content Security Policy (enforced),
  copies of capy-project's `base.html` and `layout.html` (`tests/templates/`), and
  either Django's own user model or a copy of capy-project's (`tests/email_users/`,
  with `TEST_USER_MODEL=email`). It doesn't have capy-project's login limits
  (django-axes and the per-address limit) yet: the feature that makes capy-auth work
  with them adds them here. `tests/` also checks the rules below.
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
   the ones Django uses. In `MIDDLEWARE`, add allauth's right after Django's messages
   middleware (django-axes' stays last):

   ```python
   INSTALLED_APPS = [
       "accounts",
       "capy_auth",
       ...,
       "django.contrib.messages",
       "allauth",
       "allauth.account",
       ...,
   ]
   MIDDLEWARE = [
       ...,
       "django.contrib.messages.middleware.MessageMiddleware",
       "allauth.account.middleware.AccountMiddleware",
       ...,
   ]
   ```

3. In `config/urls.py` (change its import to `from django.urls import include, path`),
   add to `urlpatterns`:

   ```python
   urlpatterns = [
       ...,
       path("accounts/", include("capy_auth.urls")),
   ]
   ```

   Mounted there, Django's default `LOGIN_URL` (`/accounts/login/`) and
   `LOGIN_REDIRECT_URL` (`/accounts/profile/`, capy-auth's "Your account" page) already
   point at capy-auth's pages, so leave both unset.

4. In `config/settings/users.py`, where capy-project keeps its login settings:
   - **Login backends:** put allauth's backend where Django's `ModelBackend` is, and
     keep `ModelBackend` after it for the admin's own login page (a later capy-auth
     feature sends that through allauth too). capy-project's two login-limit backends
     stay first. Update the comment above the list too: `ModelBackend` is no longer
     "the real login". Until capy-auth's rate-limit feature, django-axes probably
     counts every failed email login from one address together (allauth logs in by
     email, axes by username), so 5 wrong passwords from a shared office address may
     briefly lock out email logins from that address.

     ```python
     AUTHENTICATION_BACKENDS = [
         "config.login_limits.IPLoginLimitBackend",
         "axes.backends.AxesStandaloneBackend",
         "allauth.account.auth_backends.AuthenticationBackend",  # logins by email
         "django.contrib.auth.backends.ModelBackend",  # the admin's login page
     ]
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
     # Log in with an email address; sign up with just email and password (allauth
     # fills in the username).
     ACCOUNT_LOGIN_METHODS = {"email"}
     ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*", "password2*"]
     # The email must be confirmed before the first login, with a code from an email
     # (no confirmation links: a code works on any device and puts no token in a URL).
     # The code page offers a new code. It doesn't offer "use a different email": that
     # would show only for new accounts, giving away which emails already have one.
     ACCOUNT_EMAIL_VERIFICATION = "mandatory"
     ACCOUNT_EMAIL_VERIFICATION_BY_CODE_ENABLED = True
     ACCOUNT_EMAIL_VERIFICATION_SUPPORTS_RESEND = True
     # Logins last for the session's lifetime (Django's 2 weeks), not only until the
     # browser closes, with no "remember me" box.
     ACCOUNT_SESSION_REMEMBER = True
     # Ask for the password again before changing the password or email addresses.
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

     capy-project's password rules (`AUTH_PASSWORD_VALIDATORS`: 12 characters minimum,
     no common or all-digit passwords, no composition rules) stay as they are, and
     allauth already answers signup, login and reset the same way for known and unknown
     addresses (`ACCOUNT_PREVENT_ENUMERATION`, on by default). To keep that, the reset
     form emails any address typed in (an address with no account is told so), so
     someone could send a stranger a few of these emails; allauth's limits keep it to a
     few a minute per address.

   - **Optional:** the `CAPY_AUTH_` settings in [Settings](#settings) only set starting
     values. Set one (as `True` or `False`, e.g. `env.bool(...)` when read from the
     environment, and listed in `.env.example`) only to start differently from its
     default.

   **Existing users** (such as a superuser made with `createsuperuser`) are asked for an
   emailed code the first time they log in through capy-auth's pages; the admin's own
   login page doesn't ask.

5. **Email.** Signup, verification codes and password resets all send email.
   - **Development** needs nothing: capy-project prints emails, codes included, where
     `runserver` runs.
   - **Production** needs `EMAIL_URL` (`smtp+tls://` or `smtp+ssl://`) and
     `DJANGO_DEFAULT_FROM_EMAIL` in `.env.production` (the project README's "Email"
     section). Without them, no email is sent: the worker's job fails with "Email
     isn't set up".
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

9. Check it by hand: start the site (`uv run python manage.py runserver`), open
   http://localhost:8000/accounts/signup/, sign up, copy the code from the email printed
   in the `runserver` output, and you land on "Your account". Sign out, then sign in
   again with the same email and password.

## Settings

Admins change capy-auth's settings in the Django admin, on the **capy-auth settings**
page: superusers, and staff with "Can change capy-auth settings" (or "Can view
capy-auth settings" to see them read-only). They're kept as one record in the
database; the admin's history shows who changed what. They only take effect when the
project uses capy-auth's account adapter (install step 4).

The record is created on the first visit to the signup page or the settings page, with
its starting values from the project's settings below. After that, what admins set
wins: changing the project's setting no longer has an effect, so change it on the
settings page instead. An option added in a later release starts from the project's
setting too: its migration copies the setting into the existing record (and the
CHANGELOG names it).
| Setting | Default | Starting value of |
| --- | --- | --- |
| `CAPY_AUTH_SIGNUP_OPEN` | `True` | **Signup open:** anyone can create an account. When off, the signup page says signup is closed and creates no accounts. allauth's own `ACCOUNT_SIGNUP_ENABLED = False` also closes it. |

Settings that must not change while the site runs (secrets, the site's domain, the
email server) stay in the project's settings and environment. Each starting value must
be `True` or `False` (or one of the option's choices); Django's checks stop the
project otherwise (`capy_auth.E002`).

**Adding an option** (for developers): add the field to `config/models.py` with a
`db_default`, its starting value to `starting_values()` in `config/selectors.py`, a
check in `config/checks.py`, and, in the same migration, a `RunPython` step that copies
`getattr(settings, "CAPY_AUTH_…", default)` into the existing record (using
`apps.get_model`, with `migrations.RunPython.noop` as the reverse).

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
try.

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
  limiting (django-axes) counts every attempt.
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
uv sync                    # installs Python, Django, allauth and the test tools
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
| `src/capy_auth/config/` | The settings record (`models.py`), reading it (`selectors.py`), its admin page (`admin.py`) and Django's checks for the project's setup (`checks.py`: errors E001–E002, warnings W001 for weakened security settings and W002 for a cache the worker can't share) |
| `src/capy_auth/urls.py` | capy-auth's URLs (mounted at `accounts/`): the "Your account" page, where people land after logging in, and allauth's pages |
| `src/capy_auth/templates/capy_auth/account.html` | The "Your account" page |
| `src/capy_auth/templates/429.html` | allauth's "too many attempts" page, inside the layout |
| `src/capy_auth/account/adapter.py` | capy-auth's account adapter (allauth asks it how to behave: whether signup is open, its messages, equal timing for taken emails, sending emails through the worker) and `user_display` |
| `src/capy_auth/emails/` | Emails sent by the background worker: the finished email waits in the cache (`sending.py`), the job sends it and retries (`tasks.py`) |
| `src/capy_auth/templates/allauth/layouts/base.html` | Puts every allauth page inside the project's `layout.html` |
| `src/capy_auth/templates/allauth/elements/` | allauth's building blocks (buttons, fields, forms, …) with daisyUI classes |
| `src/capy_auth/templates/account/` | allauth pages copied with their inline style removed (compare with allauth's when upgrading it; likewise `send_mail` in `account/adapter.py`, copied from allauth's) |
| `src/capy_auth/templates/capy_auth/fields/widget.html` | daisyUI's class for each kind of form input |
| `src/capy_auth/templatetags/capy_auth_forms.py` | The `daisy_widget` filter: adds the classes `widget.html` picks to an input |
| `src/capy_auth/migrations/` | Database migrations (see Database) |
| `tests/settings.py` | A tiny stand-in project for the tests, with allauth, capy-project's Content Security Policy, jobs run straight away (as in capy-project's development and tests) and a choice of user model (`TEST_USER_MODEL`) |
| `tests/urls.py` | The stand-in project's URLs: capy-auth's (its own page and allauth's) under `accounts/`, and a page its own tests use |
| `tests/templates/` | Copies of capy-project's `base.html` and `layout.html`, which the module's pages extend |
| `tests/email_users/` | A copy of capy-project's user model, used with `TEST_USER_MODEL=email` |
| `tests/test_stand_in_project.py` | Checks the stand-in project gives the module what a capy project does |
| `tests/test_pages.py` | Checks allauth's pages render inside the layout under the strict policy, with daisyUI inputs, visible labels, linked help text and errors, and that the overrides keep up with allauth |
| `tests/test_settings_store.py` | Checks the settings record, its admin page, Django's checks and closing signup |
| `tests/test_email_password.py` | Checks signup, verification by code, login, logout, password reset and change, end to end |
| `tests/test_email_password_edges.py` | Edge cases and security: email case and spaces, code limits, rate limits behind a proxy, timing, redirects, reset tokens |
| `tests/test_background_email.py` | Checks emails go through the job with only a key in it, arrive as allauth built them, are sent once, retried after a mail server failure, and sent at once when the cache or job queue is down |
| `tests/test_security_settings_check.py` | Checks the warnings W001 (weakened allauth settings) and W002 (a cache the worker can't share) |
| `tests/accounts.py` | Shared by the account tests: signing up, logging in, codes and reset links |
| `tests/conftest.py` | Clears allauth's rate-limit counts before each test; the `ada` user |
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
