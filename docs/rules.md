# Rules

The rules of this package for CakePHP 2 applications. Each one is written for Semgrep
([resources/semgrep/cakephp2.yml](../resources/semgrep/cakephp2.yml)) and PHPStan
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
`$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` and `$_FILES`.

## cakephp2-query-concatenation

SQL built from a string with a variable, by concatenation or in a double-quoted string, passed to
`Model::query()`. The value goes into the SQL as it is: an SQL injection when it comes from the request.

```php
// Found
$this->Post->query("SELECT * FROM posts WHERE title LIKE '%" . $q . "%'");
$this->Post->query("SELECT * FROM posts WHERE id = $id");

// Fixed: the values array of query(), or find()
$this->Post->query('SELECT * FROM posts WHERE title LIKE ?', ['%' . $q . '%']);
$this->Post->find('all', ['conditions' => ['Post.title LIKE' => '%' . $q . '%']]);
```

## cakephp2-conditions-string

A conditions string with a variable, as `'conditions' => "..."` or as an item of a conditions array without a
key, e.g. in the options of `find()` or `paginate`. CakePHP escapes the values of a
conditions array, but not a string.

```php
// Found
$this->Post->find('all', ['conditions' => "Post.title = '$title'"]);
$this->Post->find('all', ['conditions' => ['Post.published' => 1, "Post.title = '" . $title . "'"]]);

// Fixed
$this->Post->find('all', ['conditions' => ['Post.title' => $title]]);
```

## cakephp2-render-request

A value of the request passed to `$this->render()` or `$this->element()`. A path in it (`../`) renders any
template, possibly with variables that the page should not show.

```php
// Found
$this->render($this->request->query('page'));

// Fixed: map the value to the allowed views
$pages = ['terms' => 'terms', 'privacy' => 'privacy'];
$page = $pages[$this->request->query('page')] ?? null;
if ($page === null) {
    throw new NotFoundException();
}
$this->render($page);
```

## cakephp2-unserialize-request

A value of the request passed to `unserialize()`. It can create objects of any class of the application, whose
methods (e.g. `__destruct()`) then run: a remote code execution in the worst case.

```php
// Found
$data = unserialize($this->request->data('payload'));

// Fixed
$data = json_decode((string)$this->request->data('payload'), true);
```

## cakephp2-redirect-request

A value of the request passed to `$this->redirect()`. An attacker can send a link of your site that redirects to
another one (open redirect), e.g. a phishing page after the login.

```php
// Found
return $this->redirect($this->request->query('url'));

// Fixed: a path of the application only
$url = (string)$this->request->query('url');
if (!str_starts_with($url, '/') || str_starts_with($url, '//')) {
    $url = '/';
}
return $this->redirect($url);
```

`AuthComponent::redirectUrl()` keeps the redirect after the login on the site (pieceofcake2/cakephp 2.12.5 and
later, [GHSA-x4p9-p4cx-gxwx](https://github.com/pieceofcake2/cakephp/security/advisories/GHSA-x4p9-p4cx-gxwx)).

## cakephp2-xml-build-variable

`Xml::build()` with a variable, without `['readFile' => false]`. `readFile` is `true` by default: a string that
is a path or a URL (`http://`, `https://`) is read. With a value of the request, the server fetches a URL of the
attacker (SSRF) or reads a local file.

```php
// Found
$xml = Xml::build($this->request->data('xml'));

// Fixed: a string of XML only
$xml = Xml::build((string)$this->request->data('xml'), ['readFile' => false]);
```

Before 2.12.3, pieceofcake2/cakephp also fetched URLs with `['readFile' => false]`
([GHSA-wgww-24w3-wfqp](https://github.com/pieceofcake2/cakephp/security/advisories/GHSA-wgww-24w3-wfqp)):
update to 2.12.3 or later. An array of data passed to `Xml::build()` is converted, not read; suppress the
finding of such a call.

## cakephp2-security-csrf-disabled

`$this->Security->csrfCheck = false` or `$this->Security->validatePost = false`: the CSRF tokens or the form
tampering protection of `SecurityComponent` are turned off, often for every action of a controller.

```php
// Found
public function beforeFilter()
{
    parent::beforeFilter();
    $this->Security->csrfCheck = false;
}

// Fixed: only the actions that need it, e.g. a webhook
public function beforeFilter()
{
    parent::beforeFilter();
    $this->Security->unlockedActions = ['webhook'];
}
```

## cakephp2-view-unescaped-output

A variable printed in a view without `h()`, as `<?= $var ?>` or `<?php echo $var; ?>`. A value that contains
HTML is run by the browser (XSS). The views are the `.ctp` files, and the files of the other extensions of the
views in `templates/` and `View/` (see [What is Scanned](README.md#what-is-scanned)).

```php
<!-- Found -->
<div><?= $post['Post']['body'] ?></div>

<!-- Fixed -->
<div><?= h($post['Post']['body']) ?></div>
```

To keep the number of findings small, these are not reported:

- the output of a helper (`$this->Html->link()`, `$this->Form->input()`, ...) or of a function call: the
  helpers escape the values
- a variable set in the view, before it is printed, to the output of a helper, to `h()`, to `count()`, or to
  a number with `(int)` or `(float)`
- `$content_for_layout` and `$scripts_for_layout`, the HTML of the layouts
- the variables of `--safe-view-variables`, e.g. variables that hold HTML on purpose

```php
<?php $link = $this->Html->link('Back', '/'); ?>
<?= $link ?>            <!-- not reported: a helper -->
<?php $count = count($posts); ?>
<?= $count ?>           <!-- not reported: a number -->
<?= $content_for_layout ?>  <!-- not reported: the layout -->
<?= $post['Post']['body'] ?>  <!-- reported -->
```

A variable that holds HTML on purpose, e.g. the result of a Markdown parser that sanitizes it, is set safe for
all the views with `--safe-view-variables` or the settings file, by its name without `$` (its keys and
properties are included):

```php
// config/security.php
return [
    'sast' => ['safeViewVariables' => ['body_html']],
];
```

Or suppress one place with a comment (see [Suppressing a Finding](README.md#suppressing-a-finding)). The
confidence of the rule is low: the variables set by the controller are not followed.

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

### cakephp2-config-debug

`debug` is not 0. Error pages show the code, the SQL and the configuration. Set `APP_DEBUG` to 0 in
production, or leave it unset.

### cakephp2-config-salt

`Security.salt` is the default of the distribution, a sample of the documentation, or shorter than 32
characters. The hashes and the signed values, e.g. the tokens of the forms, can be forged. Set
`SECURITY_SALT` to a random value of 32 bytes or more:

```bash
php -r 'echo bin2hex(random_bytes(32)), PHP_EOL;'
```

### cakephp2-config-cipher-seed

`Security.cipherSeed` is the default of the distribution or a sample of the documentation. It is the key of the
`cipher` cookies of `CookieComponent`. Set `SECURITY_CIPHER_SEED` to a random number, and move the cookies to
`aes`. Its risk is low when the cookies are `aes`.

### cakephp2-config-cookie-cipher

`CookieComponent` encrypts with `cipher` (`Cookie.type` is not set, or is `cipher`), which is not secure.
Set `Cookie.type` to `aes`, `Cookie.key` to a random value of 32 bytes or more, and `Security.useOpenSsl` to
`true`.

### cakephp2-config-cookie-key

`Cookie.key`, the key of the `aes` cookies, is a sample of the documentation or shorter than 32 bytes. Set
`COOKIE_KEY` to a random value of 32 bytes or more.

### cakephp2-config-session-cookie

The session cookie is set without `HttpOnly` or `Secure`: `session.cookie_httponly` or
`session.cookie_secure` is false in `Session.ini`. CakePHP sets both by default (`Secure` on HTTPS); remove
the settings that turn them off.

### cakephp2-config-openssl

`Security.useOpenSsl` is not `true`: `Security::encrypt()` and the `aes` cookies use mcrypt, which is not
maintained and not bundled with PHP 7.2+. Set `Security.useOpenSsl` to `true`.
