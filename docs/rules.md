# Rules

The rules of this package for CakePHP 2 applications, what each one finds, and how to fix it. Each rule is
written for Semgrep ([resources/semgrep/cakephp2.yml](../resources/semgrep/cakephp2.yml)) and PHPStan
([src/PHPStan/](../src/PHPStan/)), and finds the same places with both engines. Semgrep also runs the PHP rules
of the Semgrep Registry (`p/php` by default), which are described on [semgrep.dev](https://semgrep.dev/p/php).

| Rule | Risk | PHPStan identifier | CWE | OWASP Top 10 (2021) |
| --- | --- | --- | --- | --- |
| [`cakephp2-query-concatenation`](#cakephp2-query-concatenation) | High | `securitySast.queryConcatenation` | CWE-89 | A03 Injection |
| [`cakephp2-conditions-string`](#cakephp2-conditions-string) | High | `securitySast.conditionsString` | CWE-89 | A03 Injection |
| [`cakephp2-render-request`](#cakephp2-render-request) | High | `securitySast.renderRequest` | CWE-22 | A01 Broken Access Control |
| [`cakephp2-unserialize-request`](#cakephp2-unserialize-request) | High | `securitySast.unserializeRequest` | CWE-502 | A08 Software and Data Integrity Failures |
| [`cakephp2-redirect-request`](#cakephp2-redirect-request) | Medium | `securitySast.redirectRequest` | CWE-601 | A01 Broken Access Control |
| [`cakephp2-xml-build-variable`](#cakephp2-xml-build-variable) | Medium | `securitySast.xmlBuildVariable` | CWE-918 | A10 Server-Side Request Forgery |
| [`cakephp2-security-csrf-disabled`](#cakephp2-security-csrf-disabled) | Medium | `securitySast.securityCsrfDisabled` | CWE-352 | A01 Broken Access Control |
| [`cakephp2-view-unescaped-output`](#cakephp2-view-unescaped-output) | Medium | `securitySast.viewUnescapedOutput` | CWE-79 | A03 Injection |

The rules look at the code, not at where the values come from, so a finding is a place to check, not always a
vulnerability. A value "of the request" is `$this->request` (its `query()`, `data()`, `params`, ...) or
`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` and `$_FILES`. See [Fixing the Findings](fixing.md) for the way
through a report, and [The Configuration](#the-configuration) for the rules of the settings.

## cakephp2-query-concatenation

SQL built from a string with a variable, by concatenation or in a double-quoted string, passed to
`Model::query()`.

**Why it matters.** The value goes into the SQL as it is. When it comes from the request, or from data that a
user saved earlier, a quote in it ends the string of the SQL, and the rest is SQL of the attacker: reading other
tables (the passwords), changing or deleting records, or logging in as anyone (SQL injection).

```php
// Found
$this->Post->query("SELECT * FROM posts WHERE title LIKE '%" . $q . "%'");
$this->Post->query("SELECT * FROM posts WHERE id = $id");

// Fixed: the values of query() are escaped by the database driver
$this->Post->query('SELECT * FROM posts WHERE title LIKE ?', ['%' . $q . '%']);
$this->Post->query('SELECT * FROM posts WHERE id = ?', [$id]);

// Better: find() with a conditions array, which also applies the behaviors and the callbacks of the model
$this->Post->find('all', ['conditions' => ['Post.title LIKE' => '%' . $q . '%']]);
```

**Values that cannot be placeholders.** The names of the tables and of the columns, `ORDER BY` and the
direction cannot be values of `?`. Map them to a list of allowed names, never put the value of the request in
the SQL:

```php
$columns = ['title' => 'Post.title', 'created' => 'Post.created'];
$sort = $columns[$this->request->query('sort')] ?? 'Post.created';
$direction = $this->request->query('direction') === 'asc' ? 'ASC' : 'DESC';
$posts = $this->Post->find('all', ['order' => [$sort => $direction]]);
```

For a list of values (`IN`), give an array to the conditions: `['Post.id' => $ids]`. In `LIKE`, `%` and `_` of
the value are wildcards: escape them when the user searches them as text.

**When it is safe.** The variable is a constant of the code, or an integer cast with `(int)` just before. Prefer
the placeholders anyway; [suppress](README.md#suppressing-a-finding) the finding with the reason otherwise.

**Check the fix.** Run the check again; a test of the action with a quote in the value (`O'Brien`) shows that
the query still works; the full scan of [pieceofcake2/security-dast](https://pieceofcake2.github.io/security-dast/)
sends SQL to the parameters of the pages.

## cakephp2-conditions-string

A conditions string with a variable, as `'conditions' => "..."` or as an item of a conditions array without a
key, e.g. in the options of `find()`, of `paginate`, of `updateAll()` or `deleteAll()`.

**Why it matters.** CakePHP escapes the values of a conditions array, `['Post.title' => $title]`, but takes a
string as SQL: the same SQL injection as with `query()`.

```php
// Found
$this->Post->find('all', ['conditions' => "Post.title = '$title'"]);
$this->Post->find('all', ['conditions' => ['Post.published' => 1, "Post.title = '" . $title . "'"]]);
$this->Post->deleteAll("Post.user_id = $userId");

// Fixed: every value as a value of the array
$this->Post->find('all', ['conditions' => ['Post.title' => $title]]);
$this->Post->find('all', ['conditions' => ['Post.published' => 1, 'Post.title' => $title]]);
$this->Post->deleteAll(['Post.user_id' => $userId]);
```

The operators go in the key, the value in the value: `['Post.created >=' => $from]`,
`['Post.title LIKE' => '%' . $q . '%']`, `['NOT' => ['Post.id' => $ids]]`, `['OR' => [...]]`. For the
`paginate` settings of a controller, the same arrays apply.

**When it is safe.** The string has no variable of the request, e.g. a constant SQL fragment. Keep the
variables out of the string: put them in the values of the array.

## cakephp2-render-request

A value of the request passed to `$this->render()` or `$this->element()`.

**Why it matters.** The value names the view. With `../` in it, any template of the application is rendered,
e.g. an element of the administration, with the variables of the action: information that the page should not
show, or a template that runs code with values it does not expect (path traversal).

```php
// Found
$this->render($this->request->query('page'));
echo $this->element($this->request->params['pass'][0]);

// Fixed: map the value to the allowed views
$pages = ['terms' => 'terms', 'privacy' => 'privacy'];
$page = $pages[$this->request->query('page')] ?? null;
if ($page === null) {
    throw new NotFoundException();
}
$this->render($page);
```

For static pages, the `PagesController` of pieceofcake2/app refuses `..` in the path: use it, and keep the pages
in `templates/Pages/`. Never build the path of a file to read or include from the request either:
`file_get_contents()`, `include`, `readfile()` and `$this->response->file()` have the same problem.

## cakephp2-unserialize-request

A value of the request passed to `unserialize()`.

**Why it matters.** `unserialize()` creates objects of any class that the application can load, and their
methods (`__wakeup()`, `__destruct()`, ...) then run with the values of the attacker. With the classes of the
application and of its packages, it can delete files or run code (object injection).

```php
// Found
$data = unserialize($this->request->data('payload'));
$cart = unserialize($_COOKIE['cart']);

// Fixed: JSON, which only makes arrays and scalars
$data = json_decode((string)$this->request->data('payload'), true);
$cart = $this->Cookie->read('cart');
```

`CookieComponent` encrypts its values (`aes`, see [cakephp2-config-cookie-cipher](#cakephp2-config-cookie-cipher))
and writes arrays as JSON: keep the data of the user there, or in the session. When a format must stay
`unserialize()`, e.g. a cache of the server, give `['allowed_classes' => false]` and never a value that a user
can change.

## cakephp2-redirect-request

A value of the request passed to `$this->redirect()`.

**Why it matters.** An attacker sends a link of your site, `https://example.com/users/login?redirect=https://evil.example`:
the user sees your domain, logs in, and lands on the page of the attacker, e.g. a copy of the login that asks for
the password again (open redirect, phishing).

```php
// Found
return $this->redirect($this->request->query('url'));

// Fixed: a path of the application only
$url = (string)$this->request->query('url');
if (!str_starts_with($url, '/') || str_starts_with($url, '//') || str_starts_with($url, '/\\')) {
    $url = '/';
}
return $this->redirect($url);
```

`//evil.example` and `/\evil.example` are URLs of another site for the browsers: check for them as above. Better,
redirect to a route array chosen by a key: `['controller' => 'orders', 'action' => 'index']`.

`AuthComponent::redirectUrl()` keeps the redirect after the login on the site (pieceofcake2/cakephp 2.12.5 and
later, [GHSA-x4p9-p4cx-gxwx](https://github.com/pieceofcake2/cakephp/security/advisories/GHSA-x4p9-p4cx-gxwx)):
update when the application uses an older version.

## cakephp2-xml-build-variable

`Xml::build()` with a variable, without `['readFile' => false]`.

**Why it matters.** `readFile` is `true` by default: a string that is a path or a URL (`http://`, `https://`)
is read. With a value of the request, the server fetches a URL of the attacker, e.g. an address of the internal
network or of the metadata of the cloud (SSRF), or reads a local file.

```php
// Found
$xml = Xml::build($this->request->data('xml'));

// Fixed: a string of XML only
$xml = Xml::build((string)$this->request->data('xml'), ['readFile' => false]);
```

Before 2.12.3, pieceofcake2/cakephp also fetched URLs with `['readFile' => false]`
([GHSA-wgww-24w3-wfqp](https://github.com/pieceofcake2/cakephp/security/advisories/GHSA-wgww-24w3-wfqp)):
update to 2.12.3 or later. An array of data passed to `Xml::build()` is converted, not read: suppress the finding
of such a call, with the reason.

## cakephp2-security-csrf-disabled

`$this->Security->csrfCheck = false` or `$this->Security->validatePost = false`.

**Why it matters.** The CSRF tokens of `SecurityComponent` make sure that a form was sent from a page of the
site. Without them, another site can make the browser of a logged-in user send the form: change the email or the
password of the account, place an order, delete data (CSRF). `validatePost` also checks that the fields of the
form were not added or changed (form tampering). Turning them off in `beforeFilter()` often turns them off for
every action of the controller.

```php
// Found
public function beforeFilter()
{
    parent::beforeFilter();
    $this->Security->csrfCheck = false;
}

// Fixed: only the actions that receive requests of other sites, e.g. a webhook
public function beforeFilter()
{
    parent::beforeFilter();
    $this->Security->unlockedActions = ['webhook'];
}
```

- An action of `unlockedActions` must check the request itself, e.g. the signature of the webhook.
- For a field that JavaScript adds or changes, unlock that field only: `$this->Security->unlockedFields = ['Order.coupon'];`,
  or `$this->Form->unlockField('Order.coupon')` in the view.
- For requests of JavaScript (Ajax), send the token: read it from the form (`data[_Token][key]`) and post it with
  the data, instead of turning the check off.

## cakephp2-view-unescaped-output

A variable printed in a view without `h()`, as `<?= $var ?>` or `<?php echo $var; ?>`. The views are the files of
the extensions of the views in `templates/` and `View/` (see [What is Scanned](README.md#what-is-scanned)).

**Why it matters.** A value that contains HTML is run by the browser: a `<script>` in a name, a comment or a
parameter runs with the session of each user who opens the page, and can read the page, send forms in the name of
the user, or act as them (XSS). The values saved by users (persistent XSS) reach every user, the administrators
too.

```php
<!-- Found -->
<div><?= $post['Post']['body'] ?></div>
<a href="<?= $url ?>">Next</a>

<!-- Fixed -->
<div><?= h($post['Post']['body']) ?></div>
<?= $this->Html->link('Next', $url) ?>
```

- `h()` escapes for the text and the attributes of HTML (with quotes around the attribute). The helpers
  (`$this->Html->link()`, `$this->Form->input()`, ...) escape their values.
- In a URL attribute, also check the scheme: `h()` does not stop `javascript:`. Build URLs with routes or
  `$this->Html->url()`, and accept only `http`/`https` URLs of users.
- In JavaScript, write values with `json_encode()`: `var name = <?= json_encode($name, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;`.
- HTML that users write (e.g. Markdown) must be sanitized with a library that removes scripts and event
  attributes before it is printed.

To keep the number of findings small, these are not reported:

- the output of a helper or of a function call
- a variable set in the view, before it is printed, to the output of a helper, to `h()`, to `count()`, or to
  a number with `(int)` or `(float)`
- `$content_for_layout` and `$scripts_for_layout`, the HTML of the layouts
- the variables of `--safe-view-variables`, e.g. variables that hold sanitized HTML

```php
<?php $link = $this->Html->link('Back', '/'); ?>
<?= $link ?>            <!-- not reported: a helper -->
<?php $count = count($posts); ?>
<?= $count ?>           <!-- not reported: a number -->
<?= $content_for_layout ?>  <!-- not reported: the layout -->
<?= $post['Post']['body'] ?>  <!-- reported -->
```

A variable that holds sanitized HTML on purpose is set safe for all the views with `--safe-view-variables` or
the settings file, by its name without `$` (its keys and properties are included):

```php
// config/security.php
return [
    'sast' => ['safeViewVariables' => ['body_html']],
];
```

Or suppress one place with a comment (see [Suppressing a Finding](README.md#suppressing-a-finding)). The
confidence of the rule is low: the variables set by the controller are not followed, so a variable that the
controller already escaped is reported too. Escape in the view anyway: it is where the context (HTML, attribute,
JavaScript) is known.

## The Configuration

The rules of the configuration check the values of `Configure` of the application, as they are with
`APP_ENV=prod` (see [The Configuration](README.md#the-configuration)). They are run by both engines, and are
turned off with `--config-check=0`. They are placed at the line of the setting in `core.php`.

| Rule | Risk | CWE | OWASP Top 10 (2021) |
| --- | --- | --- | --- |
| [`cakephp2-config-debug`](#cakephp2-config-debug) | High | CWE-489 | A05 Security Misconfiguration |
| [`cakephp2-config-salt`](#cakephp2-config-salt) | High | CWE-1188, CWE-330 | A02 Cryptographic Failures |
| [`cakephp2-config-cipher-seed`](#cakephp2-config-cipher-seed) | Medium (Low with `aes` cookies) | CWE-1188 | A02 Cryptographic Failures |
| [`cakephp2-config-cookie-cipher`](#cakephp2-config-cookie-cipher) | Medium | CWE-327 | A02 Cryptographic Failures |
| [`cakephp2-config-cookie-key`](#cakephp2-config-cookie-key) | Medium | CWE-321, CWE-326 | A02 Cryptographic Failures |
| [`cakephp2-config-session-cookie`](#cakephp2-config-session-cookie) | Medium | CWE-1004, CWE-614 | A05 Security Misconfiguration |
| [`cakephp2-config-openssl`](#cakephp2-config-openssl) | Low | CWE-1104 | A06 Vulnerable and Outdated Components |

The secrets are compared with the values of the distributions of CakePHP 2 and pieceofcake2 and the samples of
their documentation, as their SHA-256 and length; they are not written to the report.

Set the secrets in the environment of production (the variables of the server, or a `config/.env.prod.local`
that is not committed), never in a committed file, and generate them:

```bash
php -r 'echo bin2hex(random_bytes(32)), PHP_EOL;'   # a key of 32 bytes, as 64 hexadecimal characters
```

**Change a secret with care.** A secret that is in use already signs or encrypts data: the passwords, the
cookies, the forms of the open pages. The sections below say what each change breaks, and how to move.

### cakephp2-config-debug

`debug` is not 0 in production. Error pages show the code, the SQL, the paths and the configuration, and
`DebugKit` may be loaded: everything an attacker needs.

Set `APP_DEBUG=0` in the environment of production, or leave it unset (`debug` is 0 by default in
pieceofcake2/app). Load `DebugKit` only when `debug` is not 0. Check the error pages of production after the
change: CakePHP then shows `templates/Errors/error400.ctp` and `error500.ctp` (`app/View/Errors/` in the legacy
layout).

### cakephp2-config-salt

`Security.salt` is the default of the distribution, a sample of the documentation, or shorter than 32
characters. Everyone knows these values: the hashes and the signed values, e.g. the tokens of the forms of
`SecurityComponent`, can be forged, and the passwords hashed with the salt are easier to crack.

Set `SECURITY_SALT` in the environment of production to a random value of 32 bytes or more. What the change
breaks:

- **The passwords of the `Simple` hasher of `AuthComponent`** (the default): it hashes `salt . password`, so
  no user can log in with the new salt. Move to the `Blowfish` hasher first (below).
- **The values of `Security::encrypt()`**, the `aes` cookies of `CookieComponent` too: their HMAC uses the salt
  (and their key is the salt when `Cookie.key` is not set). They can no longer be read: the users lose these
  cookies once, and the data encrypted in the database must be decrypted and encrypted again.
- **The forms open at the time of the change** are black-holed once; the users send them again.

To move the passwords, use a hasher that checks the old hashes and makes new ones with Blowfish, and keep the
old salt as `Security.previousSalt` until every user has logged in once:

```php
// src/Controller/Component/Auth/MigratingPasswordHasher.php (app/Controller/Component/Auth/ in the legacy layout)
App::uses('BlowfishPasswordHasher', 'Controller/Component/Auth');
App::uses('Security', 'Utility');

class MigratingPasswordHasher extends BlowfishPasswordHasher
{
    public function check($password, $hashedPassword)
    {
        if (str_starts_with((string)$hashedPassword, '$2')) {
            return parent::check($password, $hashedPassword);
        }

        // An old hash of the Simple hasher: the old salt and the password, with Security::$hashType (sha1)
        return $hashedPassword === Security::hash($password, null, (string)Configure::read('Security.previousSalt'));
    }
}
```

```php
// AppController: the Migrating hasher for the Form authentication
public $components = ['Auth' => ['authenticate' => ['Form' => ['passwordHasher' => 'Migrating']]]];
```

Then, after a successful `$this->Auth->login()`, save a new hash of the password with the hasher when the stored
one does not start with `$2` (and not a second time through a `beforeSave()` of the model that hashes too). New
passwords (registration, reset) are hashed with Blowfish by `hash()`. When all users have moved, or the others
must reset their password, remove `Security.previousSalt` and the old branch of `check()`.

### cakephp2-config-cipher-seed

`Security.cipherSeed` is the default of the distribution or a sample of the documentation. It is the key of the
`cipher` cookies of `CookieComponent` and of `Security::cipher()`, which are weak by design. Move the cookies to
`aes` ([cakephp2-config-cookie-cipher](#cakephp2-config-cookie-cipher)): the seed then matters no more, and the
risk of this rule is low. Until then, set `SECURITY_CIPHER_SEED` to a random number; the `cipher` cookies written
with the old seed can no longer be read (the users lose them once).

### cakephp2-config-cookie-cipher

`CookieComponent` encrypts with `cipher` (`Cookie.type` is not set, or is `cipher`): an XOR with a stream of
`mt_rand()`, which can be broken from a few cookies.

Set in `config/core.php` (`app/Config/core.php`), and the key in the environment of production:

```php
Configure::write('Cookie.type', 'aes');
Configure::write('Cookie.key', env('COOKIE_KEY') ?: null);
Configure::write('Security.useOpenSsl', true);
```

The `cipher` cookies cannot be read after the switch: the values in them are lost once (e.g. "remember me"
logs out, a cart is emptied). Plan the switch with a release.

### cakephp2-config-cookie-key

`Cookie.key`, the key of the `aes` cookies, is a sample of the documentation or shorter than 32 bytes. Anyone
who knows the key can read and forge the cookies, e.g. a "remember me" cookie with the id of another user.

Set `COOKIE_KEY` in the environment of production to a random value of 32 bytes or more. The cookies encrypted
with the old key can no longer be read: the users lose them once (and log in again for "remember me").

### cakephp2-config-session-cookie

The session cookie is set without `HttpOnly` or `Secure`: `session.cookie_httponly` or
`session.cookie_secure` is false in `Session.ini`. Without `HttpOnly`, a script of an XSS reads the session
cookie; without `Secure`, the cookie is sent over HTTP too, where the network can read it.

CakePHP sets both by default (`Secure` on HTTPS): remove the settings that turn them off. Add `SameSite` for
the requests of other sites:

```php
Configure::write('Session', [
    'defaults' => 'php',
    'ini' => ['session.cookie_samesite' => 'Lax'],
]);
```

Behind a proxy that ends HTTPS, CakePHP sets `Secure` only when it sees the request as HTTPS: set
`'session.cookie_secure' => 1` in the `ini` of production then.

### cakephp2-config-openssl

`Security.useOpenSsl` is not `true`: `Security::encrypt()` and the `aes` cookies use mcrypt, which is not
maintained and not bundled with PHP 7.2+. Set `Security.useOpenSsl` to `true`. The OpenSSL implementation of
CakePHP is compatible with the one of mcrypt (AES-128-CBC): the values encrypted before the switch are read
after it.
