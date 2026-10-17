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
- Start with `--fail-on=none` to see the findings of an existing application without failing the job, then
  raise it once they are fixed or suppressed.

The summary of the command is in the log of the job:

```text
12 findings (5 high, 7 medium) of 8 rules in 3 files (Semgrep 1.180.0). Report: tmp/security-sast.pdf
```
