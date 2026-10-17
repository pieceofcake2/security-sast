# Security SAST Documentation

Static application security testing (SAST) of a CakePHP 2 application: its code is scanned for patterns that
lead to vulnerabilities, such as SQL built from strings, redirects to values of the request or variables printed
without escaping, and the findings are written as an A4 PDF report by rule and risk, in the design of the
reports of [pieceofcake2/report](https://pieceofcake2.github.io/report/). The exit code fails CI when a finding
reaches a risk.

- [Rules](rules.md): what each rule finds, and how to fix it
- [CI with GitHub Actions](ci.md)

It is one of the security checks of pieceofcake2, with
[pieceofcake2/security-sca](https://pieceofcake2.github.io/security-sca/) (the known vulnerabilities of the
Composer packages) and pieceofcake2/security-dast (the running application); pieceofcake2/security-check runs
them all.

## Two Engines

The rules of this package for CakePHP 2 are written for both engines, and find the same places. Choose one with
`--engine`:

| | Semgrep (default) | PHPStan |
| --- | --- | --- |
| Runs | in Docker (`semgrep/semgrep`) | with PHP, installed with this package |
| Rules | the CakePHP 2 rules of this package, and the PHP rules of the Semgrep Registry (`p/php`) or others | the CakePHP 2 rules of this package only |
| Views (`.ctp`) | yes | yes |
| Needs | Docker, and the network to download the rules of the Registry | nothing else |
| Suppress a place | `// nosemgrep: <rule>` | `// @phpstan-ignore <identifier>` |

Semgrep finds more, with the rules of the Registry; PHPStan runs anywhere PHP does, e.g. where Docker is not
allowed. The rules of the Registry are maintained by Semgrep and the community, and are not reviewed by this
package.

## Requirements

- PHP 8.0+
- Semgrep: Docker. The image `semgrep/semgrep` is pulled on the first run
- PHPStan: nothing else (`phpstan/phpstan` is a dependency of this package)
- Google Chrome or Chromium 131+ to print the PDF, and on Linux `fonts-noto-cjk` for a Japanese report

## Installation

```bash
composer require --dev pieceofcake2/security-sast
```

## Usage

```bash
# Semgrep in Docker
vendor/bin/security-sast --pdf=tmp/security-sast.pdf --language=ja

# PHPStan
vendor/bin/security-sast --engine=phpstan --pdf=tmp/security-sast.pdf
```

The command prints a summary and the path of the report:

```text
12 findings (5 high, 7 medium) of 8 rules in 3 files (Semgrep 1.180.0). Report: tmp/security-sast.pdf
```

The exit code is `0` when no finding reaches `--fail-on`, `1` when one does, and `2` when the scan or the
report fails. A finding whose risk is not known fails only with `--fail-on=low`.

### What is Scanned

By default the directories of the application that exist: `src`, `templates` and `plugins` (the modern
layout) and `app` (the legacy layout), without `vendor`, `tmp`, `logs`, `tests`, `node_modules`, `app/Vendor`,
`app/tmp` and `app/Test`. The PHP files (`.php`) and the views (`.ctp`) are scanned.

```bash
# Only src/ and the views, with the tests
vendor/bin/security-sast --paths=src,templates --exclude=vendor,tmp
```

### Options

| Option | Environment variable | Default | |
| --- | --- | --- | --- |
| `--engine=ENGINE` | `SECURITY_SAST_ENGINE` | `semgrep` | `semgrep` or `phpstan` |
| `--pdf=PATH` | `SECURITY_SAST_PDF` | `tmp/security-sast.pdf` | The PDF report |
| `--fail-on=RISK` | `SECURITY_SAST_FAIL_ON` | `high` | The lowest risk that fails: `critical`, `high`, `medium`, `low` or `none` |
| `--project=DIR` | | the current directory | The directory of the application |
| `--paths=LIST` | `SECURITY_SAST_PATHS` | `src`, `templates`, `plugins`, `app` that exist | Paths to scan, comma separated, relative to the project |
| `--exclude=LIST` | `SECURITY_SAST_EXCLUDE` | see above | Paths to leave out, comma separated; empty for none |
| `--semgrep-config=LIST` | `SECURITY_SAST_SEMGREP_CONFIG` | `p/php` | Semgrep rules besides those of this package: names of the Registry (`p/owasp-top-ten`), URLs, or YAML files of the project |
| `--semgrep-image=IMAGE` | `SECURITY_SAST_SEMGREP_IMAGE` | `semgrep/semgrep:latest` | The Docker image of Semgrep, e.g. a fixed version |
| `--docker=COMMAND` | `SECURITY_SAST_DOCKER` | `docker` | The Docker command, e.g. `podman` |
| `--phpstan=PATH` | `SECURITY_SAST_PHPSTAN` | the one of this package | The `phpstan` script |
| `--language=LANG` | `SECURITY_REPORT_LANGUAGE` | `en` | `en` or `ja`, or a language of `--locale-dir` |
| `--locale-dir=DIR` | `SECURITY_REPORT_LOCALE_DIR` | | `<language>.json` files that add or replace messages |
| `--title=TITLE` | `SECURITY_SAST_TITLE` | the title of the language | The title of the report |
| `--project-name=NAME` | `SECURITY_REPORT_PROJECT` | the name in `composer.json` | The project under the title |
| `--note=TEXT` | `SECURITY_SAST_NOTE` | | A note on the cover |

## The Report

1. **Cover**: the result, the numbers of findings by risk, the repository, branch and commit, the scanned paths
   and the number of files, the rules, the threshold, and the date, environment and software of the run (the
   engine and its version)
2. **Findings by risk**: Critical, High, Medium, Low and Unknown; each rule that found places, with their
   number, and a link to its page
3. **A page for each rule**: its title, ID, risk, CWE, OWASP Top 10 category and confidence, what it found and
   how to fix it, then each place (file and line) with its code, up to 100 places

The risks of Semgrep are `ERROR` (high), `WARNING` (medium) and `INFO` (low). The rules of this package set
their own risks (see [Rules](rules.md)).

## Suppressing a Finding

Check the place first: most findings are real. When a place is safe, e.g. the variable of a query is a constant,
suppress the finding there, with a comment that says why.

Semgrep:

```php
// The table name is a constant of the model
// nosemgrep: cakephp2-query-concatenation
$this->query('TRUNCATE ' . self::TABLE);
```

PHPStan, with the identifier of the rule ([Rules](rules.md)):

```php
// The table name is a constant of the model
$this->query('TRUNCATE ' . self::TABLE); // @phpstan-ignore securitySast.queryConcatenation
```

To leave out whole paths, use `--exclude`.

## Your Own Rules

Semgrep runs the YAML files of the project given with `--semgrep-config`, besides the rules of this package:

```bash
vendor/bin/security-sast --semgrep-config=p/php,config/semgrep/app.yml
```

See the [Semgrep rule syntax](https://semgrep.dev/docs/writing-rules/rule-syntax). The rules of this package,
[resources/semgrep/cakephp2.yml](../resources/semgrep/cakephp2.yml), are examples.

## Troubleshooting

**`Semgrep failed (exit code 125): Cannot connect to the Docker daemon`**: Docker is not running, or the user
cannot use it. Start Docker, or use `--engine=phpstan`.

**`Semgrep failed ... Failed to download configuration`**: the rules of the Registry (`p/php`) could not be
downloaded. Allow the network to `semgrep.dev`, or run only the rules of this package with
`--semgrep-config=` (empty).

**`Nothing to scan in .`**: none of `src`, `templates`, `plugins` and `app` exists in the project. Give the
paths with `--paths`.

**The report says that the engine reported errors**: a file could not be parsed, e.g. a PHP syntax error. The
other files are scanned.

**`Chrome is needed to print the report`**: install Chrome or Chromium, or set `REPORT_CHROME_BINARY` (see
[pieceofcake2/report](https://pieceofcake2.github.io/report/)).
