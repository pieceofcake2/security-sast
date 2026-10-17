# pieceofcake2/security-sast

[![GitHub License](https://img.shields.io/github/license/pieceofcake2/security-sast?label=License)](LICENSE)
[![Packagist Version](https://img.shields.io/packagist/v/pieceofcake2/security-sast?label=Packagist)](https://packagist.org/packages/pieceofcake2/security-sast)
![PHP](https://img.shields.io/packagist/dependency-v/pieceofcake2/security-sast/php?logo=php&logoColor=%23FFFFFF&label=PHP&labelColor=%23777BB4&color=%23FFFFFF)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%205-brightgreen?label=PHPStan)](https://github.com/pieceofcake2/security-sast/actions/workflows/CI.yml)
[![CI](https://img.shields.io/github/actions/workflow/status/pieceofcake2/security-sast/CI.yml?label=CI)](https://github.com/pieceofcake2/security-sast/actions/workflows/CI.yml)
[![Codecov](https://img.shields.io/codecov/c/gh/pieceofcake2/security-sast?label=Coverage)](https://codecov.io/gh/pieceofcake2/security-sast)

Static application security testing of a CakePHP 2 application: its code is scanned with Semgrep (in Docker) or
PHPStan and security rules for CakePHP 2 (SQL built from strings, redirects to values of the request, variables
printed without `h()`, ...), and the findings are written as an A4 PDF report by rule and risk in the design of
[pieceofcake2/report](https://github.com/pieceofcake2/report), with an exit code that fails CI.

```bash
composer require --dev pieceofcake2/security-sast
vendor/bin/security-sast --pdf=tmp/security-sast.pdf --fail-on=high                  # Semgrep in Docker
vendor/bin/security-sast --engine=phpstan --pdf=tmp/security-sast.pdf --fail-on=high # PHPStan
```

## Documentation

- Website: https://pieceofcake2.github.io/security-sast/ (日本語: https://pieceofcake2.github.io/security-sast/ja/)
- Markdown: [docs/README.md](docs/README.md) (日本語: [docs/ja/README.md](docs/ja/README.md)) (for AI tools and offline reading)

## Requirements

* PHP 8.0+
* Docker for Semgrep (PHPStan needs nothing else)
* Google Chrome or Chromium 131+

## Installation

```bash
composer require --dev pieceofcake2/security-sast
```

## Reporting Issues

Please open an issue on [GitHub](https://github.com/pieceofcake2/security-sast/issues).
To report a security vulnerability, use [private vulnerability reporting](https://github.com/pieceofcake2/security-sast/security/advisories/new).

## Contributing

See the [contribution guidelines](https://github.com/pieceofcake2/.github/blob/master/CONTRIBUTING.md).

## Origin

This package was created by [pieceofcake2](https://github.com/pieceofcake2), which also maintains it. It is
not a fork of another project and is not based on one.

## License

The MIT License. See [LICENSE](LICENSE).
