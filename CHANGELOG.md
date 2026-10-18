# CHANGELOG

## Unreleased

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
