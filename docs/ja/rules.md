# ルール

このパッケージの、CakePHP 2 アプリケーション向けのルールです。どのルールも Semgrep
([resources/semgrep/cakephp2.yml](../../resources/semgrep/cakephp2.yml)) と PHPStan ([src/PHPStan/](../../src/PHPStan/))
の両方で書いてあり、どちらのエンジンでも同じ箇所を見つけます。Semgrep では、Semgrep Registry の PHP のルール (デフォルトは
`p/php`) も実行します。その内容は [semgrep.dev](https://semgrep.dev/p/php) をご覧ください。

| ルール | リスク | PHPStan の識別子 | CWE | OWASP Top 10 (2021) |
| --- | --- | --- | --- | --- |
| [`cakephp2-query-concatenation`](#cakephp2-query-concatenation) | 高 | `securitySast.queryConcatenation` | CWE-89 | A03 インジェクション |
| [`cakephp2-conditions-string`](#cakephp2-conditions-string) | 高 | `securitySast.conditionsString` | CWE-89 | A03 インジェクション |
| [`cakephp2-render-request`](#cakephp2-render-request) | 高 | `securitySast.renderRequest` | CWE-22 | A01 アクセス制御の不備 |
| [`cakephp2-unserialize-request`](#cakephp2-unserialize-request) | 高 | `securitySast.unserializeRequest` | CWE-502 | A08 ソフトウェアとデータの整合性の不具合 |
| [`cakephp2-redirect-request`](#cakephp2-redirect-request) | 中 | `securitySast.redirectRequest` | CWE-601 | A01 アクセス制御の不備 |
| [`cakephp2-xml-build-variable`](#cakephp2-xml-build-variable) | 中 | `securitySast.xmlBuildVariable` | CWE-918 | A10 サーバーサイドリクエストフォージェリ |
| [`cakephp2-security-csrf-disabled`](#cakephp2-security-csrf-disabled) | 中 | `securitySast.securityCsrfDisabled` | CWE-352 | A01 アクセス制御の不備 |
| [`cakephp2-view-unescaped-output`](#cakephp2-view-unescaped-output) | 中 | `securitySast.viewUnescapedOutput` | CWE-79 | A03 インジェクション |

ルールが見るのはコードの書き方で、値がどこから来たかではありません。そのため、指摘は確かめるべき箇所であって、いつも
脆弱性とは限りません。「リクエストの値」とは、`$this->request` (その `query()`、`data()`、`params` など) と、`$_GET`、
`$_POST`、`$_REQUEST`、`$_COOKIE`、`$_FILES` のことです。

## cakephp2-query-concatenation

連結やダブルクォートの文字列で変数を埋め込んで組み立てた SQL を、`Model::query()` に渡しています。値がそのまま SQL に
入るので、リクエストの値なら SQL インジェクションになります。

```php
// 見つかる書き方
$this->Post->query("SELECT * FROM posts WHERE title LIKE '%" . $q . "%'");
$this->Post->query("SELECT * FROM posts WHERE id = $id");

// 直し方: query() の値の配列か、find()
$this->Post->query('SELECT * FROM posts WHERE title LIKE ?', ['%' . $q . '%']);
$this->Post->find('all', ['conditions' => ['Post.title LIKE' => '%' . $q . '%']]);
```

## cakephp2-conditions-string

変数を含む条件の文字列です。`'conditions' => "..."` か、条件の配列のキーのない要素として書いたもので、`find()` や
`paginate` のオプションなどにあります。CakePHP は条件の配列の値をエスケープしますが、文字列はエスケープしません。

```php
// 見つかる書き方
$this->Post->find('all', ['conditions' => "Post.title = '$title'"]);
$this->Post->find('all', ['conditions' => ['Post.published' => 1, "Post.title = '" . $title . "'"]]);

// 直し方
$this->Post->find('all', ['conditions' => ['Post.title' => $title]]);
```

## cakephp2-render-request

リクエストの値を `$this->render()` や `$this->element()` に渡しています。パス (`../`) を含めると、どのテンプレートでも
表示でき、そのページで見せるべきでない変数まで表示されることがあります。

```php
// 見つかる書き方
$this->render($this->request->query('page'));

// 直し方: 値を許可したビューに対応させる
$pages = ['terms' => 'terms', 'privacy' => 'privacy'];
$page = $pages[$this->request->query('page')] ?? null;
if ($page === null) {
    throw new NotFoundException();
}
$this->render($page);
```

## cakephp2-unserialize-request

リクエストの値を `unserialize()` に渡しています。アプリケーションのどのクラスのオブジェクトでも作られ、そのメソッド
(`__destruct()` など) が実行されます。最悪の場合はリモートでのコード実行になります。

```php
// 見つかる書き方
$data = unserialize($this->request->data('payload'));

// 直し方
$data = json_decode((string)$this->request->data('payload'), true);
```

## cakephp2-redirect-request

リクエストの値を `$this->redirect()` に渡しています。攻撃者は、あなたのサイトのリンクで別のサイトへリダイレクトさせる
ことができます (オープンリダイレクト)。たとえば、ログインの後にフィッシングのページへ送られます。

```php
// 見つかる書き方
return $this->redirect($this->request->query('url'));

// 直し方: アプリケーション内のパスだけにする
$url = (string)$this->request->query('url');
if (!str_starts_with($url, '/') || str_starts_with($url, '//')) {
    $url = '/';
}
return $this->redirect($url);
```

`AuthComponent::redirectUrl()` は、ログインの後のリダイレクト先をサイト内に限ります (pieceofcake2/cakephp 2.12.5 以降、
[GHSA-x4p9-p4cx-gxwx](https://github.com/pieceofcake2/cakephp/security/advisories/GHSA-x4p9-p4cx-gxwx))。

## cakephp2-xml-build-variable

`['readFile' => false]` を付けずに、`Xml::build()` に変数を渡しています。`readFile` はデフォルトで `true` で、パスや URL
(`http://`、`https://`) の文字列は読み込まれます。リクエストの値なら、サーバーが攻撃者の URL にアクセスしたり (SSRF)、
ローカルのファイルを読んだりします。

```php
// 見つかる書き方
$xml = Xml::build($this->request->data('xml'));

// 直し方: XML の文字列だけを受け付ける
$xml = Xml::build((string)$this->request->data('xml'), ['readFile' => false]);
```

pieceofcake2/cakephp の 2.12.3 より前は、`['readFile' => false]` でも URL にアクセスしていました
([GHSA-wgww-24w3-wfqp](https://github.com/pieceofcake2/cakephp/security/advisories/GHSA-wgww-24w3-wfqp))。2.12.3 以降に
更新してください。`Xml::build()` にデータの配列を渡すときは、変換されるだけで読み込まれないので、その指摘は除外してください。

## cakephp2-security-csrf-disabled

`$this->Security->csrfCheck = false` や `$this->Security->validatePost = false` です。`SecurityComponent` の CSRF の
トークンや、フォームの改ざんの防止を無効にしています。コントローラーのすべてのアクションで無効になっていることがよく
あります。

```php
// 見つかる書き方
public function beforeFilter()
{
    parent::beforeFilter();
    $this->Security->csrfCheck = false;
}

// 直し方: 必要なアクションだけ。Webhook など
public function beforeFilter()
{
    parent::beforeFilter();
    $this->Security->unlockedActions = ['webhook'];
}
```

## cakephp2-view-unescaped-output

ビュー (`.ctp`) で、変数を `h()` を通さずに `<?= $var ?>` や `<?php echo $var; ?>` で出力しています。HTML を含む値は、
ブラウザで実行されます (XSS)。

```php
<!-- 見つかる書き方 -->
<div><?= $post['Post']['body'] ?></div>

<!-- 直し方 -->
<div><?= h($post['Post']['body']) ?></div>
```

ヘルパーの出力 (`$this->Html->link()`、`$this->Form->input()` など) は指摘しません。ヘルパーが値をエスケープするから
です。サニタイズする Markdown パーサーの結果など、わざと HTML を入れた変数は、コメントで除外できます
([指摘を除外する](README.md#指摘を除外する))。
