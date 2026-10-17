# CHANGELOG

## Unreleased

- First release: `vendor/bin/security-sast` scans the code of a CakePHP 2 application with Semgrep (in Docker,
  with the PHP rules of the Semgrep Registry) or PHPStan, with 8 security rules for CakePHP 2, and writes a PDF
  report of the findings by rule and risk with pieceofcake2/report. `--fail-on` sets the lowest risk that fails
  (default `high`)
