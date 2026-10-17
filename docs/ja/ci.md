# GitHub Actions での CI

[docs/examples/security-sast.yml](../examples/security-sast.yml) は、push と pull request のたびと毎週、コードを検査し、
報告書を (zip ではなく) PDF のままアップロードします。Ubuntu のランナーには、Semgrep のための Docker と、報告書のための
Google Chrome が入っています。

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

- `if: ${{ !cancelled() }}` で、検査がジョブを失敗にしたときも報告書をアップロードします。報告書が必要なのはそのときです。
- 実行ごとに結果が変わらないようにするには、`--semgrep-image=semgrep/semgrep:1.180.0` で Semgrep のバージョンを固定します。
  Registry のルールは変わるので、そのためには `--semgrep-config` で、ルールの自分の写しを指定してください。
- セルフホストのランナーなど Docker がない環境では、`--engine=phpstan` を使ってください。
- 既存のアプリケーションでは、まず `--fail-on=none` で、ジョブを失敗にせずに指摘を見てください。直すか除外してから、
  基準を上げます。

コマンドの要約は、ジョブのログに出ます。

```text
12 findings (5 high, 7 medium) of 8 rules in 3 files (Semgrep 1.180.0). Report: tmp/security-sast.pdf
```
