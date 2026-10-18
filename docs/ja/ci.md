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

## CI での設定の検査

設定の検査は、本番と同じく `APP_ENV=prod` で設定を読み込みます。しかし本番の秘密の値はリポジトリにないので、そのまま
では `Security.salt` がアプリケーションの既定値になり、High の指摘でジョブが失敗します。例のように、リポジトリの
secrets からジョブに渡してください。

```yaml
- name: Scan the code
  env:
    SECURITY_SALT: ${{ secrets.SECURITY_SALT }}
    SECURITY_CIPHER_SEED: ${{ secrets.SECURITY_CIPHER_SEED }}
    COOKIE_KEY: ${{ secrets.COOKIE_KEY }}
  run: vendor/bin/security-sast --fail-on=high
```

秘密の値は SHA-256 と長さで比べ、報告書には書きません。フォークからの pull request にはリポジトリの secrets が渡らない
ので、`--config-check=0` で検査を止め、設定はリポジトリのジョブか本番の環境で確かめてください。CI から秘密の値を
読めないときは、本番の環境でだけ確かめます。本番のコピーで `vendor/bin/security-sast --engine=phpstan` を実行するか、
本番の環境変数のあるデプロイのジョブで実行します。
- 既存のアプリケーションでは、まず `--fail-on=none` で、ジョブを失敗にせずに指摘を見てください。修正するか除外してから、
  基準を上げます。

コマンドの要約は、ジョブのログに出ます。

```text
12 findings (5 high, 7 medium) of 8 rules in 3 files (Semgrep 1.180.0). Report: tmp/security-sast.pdf
```
