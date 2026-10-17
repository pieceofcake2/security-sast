# CHANGELOG

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
