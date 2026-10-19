# CHANGELOG

## Unreleased

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
