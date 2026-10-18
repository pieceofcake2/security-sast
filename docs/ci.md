# CI with GitHub Actions

[docs/examples/security-sast.yml](examples/security-sast.yml) scans the code on each push and pull request, and
every week, and uploads the report as a PDF (not a zip). The Ubuntu runners have Docker for Semgrep and Google
Chrome for the report.

```yaml
- run: composer install --no-interaction --no-progress
- run: sudo apt-get install -y fonts-noto-cjk
- run: vendor/bin/security-sast --pdf=tmp/security-sast.pdf --fail-on=high --language=ja
- uses: actions/upload-artifact@v7
  if: ${{ !cancelled() }}
  with:
    path: tmp/security-sast.pdf
    archive: false
```

- `if: ${{ !cancelled() }}` uploads the report also when the scan fails the job, which is when it is needed.
- Fix the version of Semgrep with `--semgrep-image=semgrep/semgrep:1.180.0` for results that do not change
  between runs; the rules of the Registry still change, so give your own copy of them with `--semgrep-config`
  for that too.
- Without Docker, e.g. on a self-hosted runner, use `--engine=phpstan`.

## The Configuration in CI

The check of the configuration loads it as in production (`APP_ENV=prod`), but the secrets of production are
not in the repository: without them, `Security.salt` is the default of the application, a High finding, and
the job fails. Give them to the job, as the example does, from the secrets of the repository:

```yaml
- name: Scan the code
  env:
    SECURITY_SALT: ${{ secrets.SECURITY_SALT }}
    SECURITY_CIPHER_SEED: ${{ secrets.SECURITY_CIPHER_SEED }}
    COOKIE_KEY: ${{ secrets.COOKIE_KEY }}
  run: vendor/bin/security-sast --fail-on=high
```

They are compared as their SHA-256 and length, and are not written to the report. The pull requests of forks do
not get the secrets of the repository: for them, turn the check off with `--config-check=0`, and check the
configuration in the jobs of the repository, or where production runs. When the secrets are not where CI can
read them at all, check the configuration only there: `vendor/bin/security-sast --engine=phpstan` on a copy of
production, or a deployment job with its environment.
- Start with `--fail-on=none` to see the findings of an existing application without failing the job, then
  raise it once they are fixed or suppressed.

The summary of the command is in the log of the job:

```text
12 findings (5 high, 7 medium) of 8 rules in 3 files (Semgrep 1.180.0). Report: tmp/security-sast.pdf
```
