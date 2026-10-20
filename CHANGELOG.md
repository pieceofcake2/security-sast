# CHANGELOG

## 1.2.1

- Semgrep reads every view as PHP, checked on the same code with Semgrep 1.180.0 in Docker: the views were given
  to Semgrep one by one with `--scan-unknown-extensions`, which reads a file of an extension that it does not know
  with the rules of every language, and one that it knows with those of its language only:
  - A view of an extension of HTML, e.g. `.html` with `--view-extensions=ctp,php,html` or the `$ext` of
    `AppController`, was read as HTML only, so that `cakephp2-view-unescaped-output` and `cakephp2-view-raw-output`
    found nothing in it with Semgrep. On a real application with `.html` views, Semgrep found 4 places, PHPStan 273;
    Semgrep now finds the same 273
  - A `.ctp` view was also read with the rules of JavaScript, JSON, Python, ... of the Registry (e.g.
    `p/security-audit`, `p/owasp-top-ten`), whose parsers reported errors on the PHP and the HTML (e.g.
    `Lexical error ... WIERD end of file in quoted string`, 172 on that application), and found places that are not
    there. Semgrep read the PHP of the views without errors
- The views are copied, with the same lines, to a temporary directory mounted at `/views`: as `.php` files for the
  rules of PHP, and as `.html` files for those of HTML (e.g. `templates/Posts/view.ctp.php` and `.ctp.html`), so
  that `html.security.plaintext-http-link` of the Registry still reads the `.ctp` views. The findings, the errors
  and the number of the files are those of the views. The `.semgrepignore` of the project applies to the copies,
  which the views given one by one did not follow
- The errors of the rules of HTML in the views, which read the PHP of a template only in part, are said apart from
  the files that could not be read, in a note of the cover (`ScanResult::$viewErrors`)
- The page of a rule lists the places after the first 100 by their file and line, without the code, in place of
  `and N more places`

## 1.2.0

- The report lists what was checked besides the findings, on pages after the findings by risk
  (pieceofcake2/report 1.1):
  - **Passed checks**: the rules of this package that ran and found nothing, with their risk and CWE
  - **Other rules of Semgrep**: the number of the rules of `--semgrep-config` (e.g. `p/php`) that ran, that found
    places and that found nothing. Semgrep runs with `--time`, whose timing lists the rules that ran
  - **Not run**: the rules that did not run and why: the checks of the configuration when it is turned off, not
    found or not loaded, the check of the CakePHP of `composer.lock` without one or for a branch, a rule of the code
    that Semgrep did not run, and the rules that Semgrep skipped (`skipped_rules`)
- The findings by risk show Critical, High, Medium and Low also without findings (`None`), so that a reader tells a
  risk without findings from one that was left out. Unknown and Info are shown when a rule found places, as on the
  cover

## 1.1.0

- `cakephp2-redirect-request` no longer reports, with either engine, a URL of the origin of the application: a
  concatenation that begins with `Router::url('/', true)`, or with `Router::fullBaseUrl()` or
  `Configure::read('App.fullBaseUrl')` followed by a path that begins with `/` (`$this->request->here()`,
  `$this->request->here` or a string literal), e.g. `Router::fullBaseUrl() . $this->request->here()`. Whatever
  follows the `/` stays on the same host. A value of the request right after the origin, the origin after a
  value of the request, and `sprintf()` are still reported. The docs say that `here()` can begin with `//`
- The rules take into account the CakePHP of the `composer.lock` of the project (`pieceofcake2/cakephp` or
  `cakephp/cakephp`):
  - New rule `cakephp2-framework-protocol-relative-here` (medium): pieceofcake2/cakephp before 2.12.11 or
    cakephp/cakephp before 3.4.0, whose `$this->request->here()` keeps the leading `//` of the path
    ([GHSA-wh43-gc93-wh4c](https://github.com/pieceofcake2/cakephp/security/advisories/GHSA-wh43-gc93-wh4c)): for a request to
    `//evil.example/...`, `FormHelper::create()` without a `url` renders `<form action="//evil.example/...">`,
    which sends the data of the form to another host, and a redirect to `here()` goes there. Placed at the package
    in `composer.lock`; run by both engines, also with `--config-check=0`
  - With pieceofcake2/cakephp 2.12.11+ or cakephp/cakephp 3.4+, `cakephp2-redirect-request` no longer reports, with
    either engine, a redirect to `$this->request->here()`, `here(false)` or `$this->request->here`; a redirect with
    another value of the request still is. Its message says that `here()` can begin with `//` before 2.12.11
  - The PHPStan rule of the redirects, `RedirectRequestRule`, is added by `PhpstanEngine` with the CakePHP of the
    project, no longer by `resources/phpstan/rules.neon`

## 1.0.7

- New rule `cakephp2-config-session-cache-limiter` (low): the pages with a session get no
  `Cache-Control: no-store` unless `Session.cacheLimiter` is `nocache`. CakePHP 2 sets it to `must-revalidate` by
  default, for Internet Explorer 8 and before, which PHP does not know, so PHP sends no cache header at all

## 1.0.6

- `cakephp2-view-unescaped-output` no longer reports, with either engine, a variable set in the view to a number
  literal (`$width = 3;`, `-1`, `1.5`), which the docs list as safe; and Semgrep no longer reports a value cast to
  a number and printed as it is (`<?= (int)$level ?>`, `(float)`), nor a variable set to a value of the request
  cast to a number, as PHPStan does: Semgrep matched the value inside the cast. The other casts, e.g.
  `<?= (string)$level ?>`, are reported by both engines as the value they cast, which PHPStan left out

## 1.0.5

- New rule `cakephp2-view-raw-output` of a new risk, Info, which never fails the scan: HTML printed in a view with
  `raw()`, the function of pieceofcake2/cakephp 2.12.10+ that prints a value without escaping on purpose, so that
  a review sees every such place
- The example workflows of the docs are in the Composer package, which `docs/ci.md` links to
- New rule `cakephp2-order-request` (High): a value of the request as the `order`, `fields` or `group` of `find()`
  or `paginate`, which goes into the SQL as a name
- `cakephp2-conditions-string` also finds the conditions of `OR`, `AND`, `NOT` and `XOR`, those of `field()` and
  `hasAny()`, and the values of the fields of `updateAll()`; `cakephp2-query-concatenation` those of `fetchAll()`
  and `execute()`; `cakephp2-security-csrf-disabled` the settings of the component
  (`['Security' => ['csrfCheck' => false]]`)
- No longer reported: a redirect to a route array, a render with a ternary that only checks the request, and the
  helpers and the view classes of `View/` (e.g. `View/AppView.php`)
- A path of `--paths` that does not exist is an error, instead of a Semgrep scan of nothing that passes
- The report says when the project has a `.semgrepignore`, whose paths Semgrep leaves out; the Semgrep errors of
  a list type are no longer printed as `Array`
- Both engines find the same places in more cases, checked on the same code with Semgrep in Docker:
  - Semgrep finds SQL in a heredoc with a variable, values of the request read as an array
    (`$this->request['data']`), a variable of a view set to `''` and then to another value, and nested indexes
    (`$labels[$post['Post']['status']]`)
  - Semgrep no longer reports a call in the conditions of `updateAll()`, nor a literal `"$1"`
  - PHPStan finds a concatenation in a ternary, and a key of the conditions with a variable
    (`['Post.' . $field => $value]`), which CakePHP does not escape
- The suppressed findings of the report are the lines that the engine does not report, as it reads its comments,
  checked against both engines: Semgrep reads the text of the lines (` nosem` too, also in a string or an HTML
  comment, and not the word in a sentence), and neither engine applies a comment across another comment or an
  empty line, which the report listed as suppressed

## 1.0.5

- Semgrep finds the conditions strings of `cakephp2-conditions-string` in any place of the options, e.g. after
  `'recursive' => -1` or `'limit' => 20`, as PHPStan does: it matched the first key only

## 1.0.4

- `cakephp2-view-unescaped-output` reports the values of the request and of the session printed in a view, as
  they are or through a variable set to them: `$this->request` (`query()`, `data`, ...), `$this->data`,
  `$this->params`, `$this->passedArgs` and `$this->Session->read()`, which were taken for the output of a helper
  or left out as `$this`
- A file that PHPStan cannot parse is an error of the report, as with Semgrep, instead of a file left out
  without notice
- With `--config-check=0` and `--paths`, the code of the application is not run at all
- The message of `cakephp2-config-cookie-key` names the `rijndael` cookies too
- Documentation: the secrets of production in CI for the check of the configuration, the example workflow
  gives them; pieceofcake2/cakephp for the check of the configuration; what differs between the engines

## 1.0.3

- The comments of the code that suppress findings of the engine (`nosemgrep`, and the ignore comments of
  PHPStan for the rules of this package) are in the report, with their places, rules and reasons: their number
  on the cover and in the summary of the command, and a group "Suppressed findings". They do not fail the run

## 1.0.2

- `cakephp2-view-unescaped-output` no longer reports a variable set in the view to a string literal or to a
  translation of string literals only (`__('...')`, `__d('...', '...')`, `__x()`, `__dx()`), and leaves out the
  text mails of `Emails/text/`, which are not HTML. A translation with values, e.g. `__('Hello %s', $name)`, is
  still reported

## 1.0.1

- `cakephp2-conditions-string` also finds the conditions strings of `deleteAll()` and `updateAll()`, as the
  documentation said
- Semgrep and PHPStan find the same places: the Semgrep rules check every superglobal of the request (also in
  `element()`) and every concatenation with a value that is not a string literal, as PHPStan does
- A Semgrep error (e.g. a rule that could not be loaded) or an exit code above 1 stops the scan, instead of a
  scan without these rules that passes
- When the configuration cannot be loaded, the command exits with `2` after the report, instead of passing
- `--paths` and `--exclude` are anchored to the project with Semgrep: `src` is not also `plugins/Blog/src`
- PHPStan takes the views from the paths in the project, not from the directories of the project itself, e.g.
  `/home/templates/app`
- No temporary file of PHPStan is left
- `cakephp2-config-cookie-key` also checks the key of `rijndael` cookies; an empty `Cookie.key`, which
  CookieComponent replaces with the salt, is not set
- A `null` in the settings file is not set, e.g. `getenv('...') ?: null`
- Documentation: what a change of the salt breaks (also the sessions and the cookies), AES-256-CBC, the
  `rijndael` cookies, `(string)` casts in the fixes

## 1.0.0

- First release: `vendor/bin/security-sast` scans the code of a CakePHP 2 application with Semgrep (in Docker,
  with the PHP rules of the Semgrep Registry) or PHPStan, with 8 security rules for CakePHP 2, and writes a PDF
  report of the findings by rule and risk with pieceofcake2/report. `--fail-on` sets the lowest risk that fails
  (default `high`)
- The configuration of the application is checked as in production (`APP_ENV=prod`): the debug level, the
  default and sample values of `Security.salt`, `Security.cipherSeed` and `Cookie.key`, the `cipher` cookies,
  `Security.useOpenSsl` and the session cookie flags. `--config-check=0` turns it off
- The paths to scan, the views and the packages installed by Composer come from the application
- The extensions of the views are set with `--view-extensions` (default `ctp`, `php`); a view that prints a
  variable set from a helper, `h()`, `count()` or a number, and the variables of `--safe-view-variables`, is
  not reported
- The settings file `config/security.php` (`app/Config/security.php`) keeps the settings of the security
  checks
