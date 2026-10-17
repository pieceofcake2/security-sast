# ルール

このパッケージの、CakePHP 2 アプリケーション向けのルールと、それぞれが見つけるもの、直し方です。どのルールも Semgrep
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
`$_POST`、`$_REQUEST`、`$_COOKIE`、`$_FILES` のことです。報告書の進め方は [指摘を直す](fixing.md) を、設定のルールは
[設定](#設定) をご覧ください。

## cakephp2-query-concatenation

連結やダブルクォートの文字列で変数を埋め込んで組み立てた SQL を、`Model::query()` に渡しています。

**なぜ危ないか。** 値がそのまま SQL に入ります。値がリクエストや、ユーザーが以前に保存したデータから来ると、値の
クォートで SQL の文字列が終わり、残りが攻撃者の SQL になります。ほかのテーブル (パスワード) を読む、レコードを変えたり
消したりする、誰としてでもログインする、などができます (SQL インジェクション)。

```php
// 見つかる書き方
$this->Post->query("SELECT * FROM posts WHERE title LIKE '%" . $q . "%'");
$this->Post->query("SELECT * FROM posts WHERE id = $id");

// 直し方: query() の値は、データベースのドライバーがエスケープします
$this->Post->query('SELECT * FROM posts WHERE title LIKE ?', ['%' . $q . '%']);
$this->Post->query('SELECT * FROM posts WHERE id = ?', [$id]);

// よりよい直し方: 条件の配列の find()。モデルのビヘイビアやコールバックも効きます
$this->Post->find('all', ['conditions' => ['Post.title LIKE' => '%' . $q . '%']]);
```

**プレースホルダーにできない値。** テーブルや列の名前、`ORDER BY` とその向きは、`?` の値にできません。許可した名前の
一覧に対応させ、リクエストの値を SQL に入れないでください。

```php
$columns = ['title' => 'Post.title', 'created' => 'Post.created'];
$sort = $columns[$this->request->query('sort')] ?? 'Post.created';
$direction = $this->request->query('direction') === 'asc' ? 'ASC' : 'DESC';
$posts = $this->Post->find('all', ['order' => [$sort => $direction]]);
```

値の一覧 (`IN`) は、条件に配列で渡します: `['Post.id' => $ids]`。`LIKE` では値の `%` と `_` がワイルドカードに
なります。ユーザーがそれらを文字として検索するなら、エスケープしてください。

**安全な場合。** 変数がコードの定数か、直前に `(int)` で整数にしたものの場合です。それでもプレースホルダーを
使ってください。使わない場合は、理由を書いて[除外](README.md#指摘を除外する)します。

**直ったことの確かめ方。** もう一度チェックします。値にクォートを入れたアクションのテスト (`O'Brien`) で、クエリが
動くことを確かめます。[pieceofcake2/security-dast](https://pieceofcake2.github.io/security-dast/ja/) のフルスキャンは、
ページのパラメーターに SQL を送ります。

## cakephp2-conditions-string

変数を含む条件の文字列を、`'conditions' => "..."` や、条件の配列のキーのない要素として渡しています。`find()`、
`paginate`、`updateAll()`、`deleteAll()` のオプションなどです。

**なぜ危ないか。** CakePHP は条件の配列 `['Post.title' => $title]` の値をエスケープしますが、文字列は SQL として
そのまま使います。`query()` と同じ SQL インジェクションになります。

```php
// 見つかる書き方
$this->Post->find('all', ['conditions' => "Post.title = '$title'"]);
$this->Post->find('all', ['conditions' => ['Post.published' => 1, "Post.title = '" . $title . "'"]]);
$this->Post->deleteAll("Post.user_id = $userId");

// 直し方: すべての値を配列の値に
$this->Post->find('all', ['conditions' => ['Post.title' => $title]]);
$this->Post->find('all', ['conditions' => ['Post.published' => 1, 'Post.title' => $title]]);
$this->Post->deleteAll(['Post.user_id' => $userId]);
```

演算子はキーに、値は値に書きます: `['Post.created >=' => $from]`、`['Post.title LIKE' => '%' . $q . '%']`、
`['NOT' => ['Post.id' => $ids]]`、`['OR' => [...]]`。コントローラーの `paginate` の設定にも同じ配列を使います。

**安全な場合。** 文字列にリクエストの変数がない場合です。定数の SQL の断片などです。変数は文字列に入れず、配列の値に
してください。

## cakephp2-render-request

リクエストの値を `$this->render()` や `$this->element()` に渡しています。

**なぜ危ないか。** 値がビューの名前になります。`../` を入れると、アプリケーションのどのテンプレートでも、アクションの
変数とともに表示できます。管理画面のエレメントなど、そのページが見せるべきでない情報や、想定していない値でコードを
実行するテンプレートが表示されます (パストラバーサル)。

```php
// 見つかる書き方
$this->render($this->request->query('page'));
echo $this->element($this->request->params['pass'][0]);

// 直し方: 値を、許可したビューの一覧に対応させる
$pages = ['terms' => 'terms', 'privacy' => 'privacy'];
$page = $pages[$this->request->query('page')] ?? null;
if ($page === null) {
    throw new NotFoundException();
}
$this->render($page);
```

静的なページには、パスの `..` を拒否する pieceofcake2/app の `PagesController` を使い、ページは `templates/Pages/` に
置いてください。読み込んだり include したりするファイルのパスも、リクエストから作らないでください。`file_get_contents()`、
`include`、`readfile()`、`$this->response->file()` にも同じ問題があります。

## cakephp2-unserialize-request

リクエストの値を `unserialize()` に渡しています。

**なぜ危ないか。** `unserialize()` は、アプリケーションが読み込めるどのクラスのオブジェクトでも作り、そのメソッド
(`__wakeup()`、`__destruct()` など) が攻撃者の値で動きます。アプリケーションやパッケージのクラスによっては、ファイルを
消したり、コードを実行したりできます (オブジェクトインジェクション)。

```php
// 見つかる書き方
$data = unserialize($this->request->data('payload'));
$cart = unserialize($_COOKIE['cart']);

// 直し方: 配列とスカラーしか作らない JSON
$data = json_decode((string)$this->request->data('payload'), true);
$cart = $this->Cookie->read('cart');
```

`CookieComponent` は値を暗号化し (`aes`、[cakephp2-config-cookie-cipher](#cakephp2-config-cookie-cipher) を参照)、配列を
JSON で書きます。ユーザーのデータはそこか、セッションに置いてください。サーバーのキャッシュなど、`unserialize()` の形式の
ままにする必要があるなら、`['allowed_classes' => false]` を付け、ユーザーが変えられる値は決して渡さないでください。

## cakephp2-redirect-request

リクエストの値を `$this->redirect()` に渡しています。

**なぜ危ないか。** 攻撃者は、`https://example.com/users/login?redirect=https://evil.example` のような、あなたのサイトの
リンクを送ります。ユーザーはあなたのドメインを見てログインし、攻撃者のページに着きます。もう一度パスワードを聞く、
ログインページの偽物などです (オープンリダイレクト、フィッシング)。

```php
// 見つかる書き方
return $this->redirect($this->request->query('url'));

// 直し方: アプリケーションのパスだけ
$url = (string)$this->request->query('url');
if (!str_starts_with($url, '/') || str_starts_with($url, '//') || str_starts_with($url, '/\\')) {
    $url = '/';
}
return $this->redirect($url);
```

`//evil.example` や `/\evil.example` は、ブラウザにとってはほかのサイトの URL です。上のように確かめてください。キーで
選んだルートの配列 `['controller' => 'orders', 'action' => 'index']` にリダイレクトするほうが、よりよい方法です。

`AuthComponent::redirectUrl()` は、ログインのあとのリダイレクトをサイトの中に保ちます (pieceofcake2/cakephp 2.12.5 以降、
[GHSA-x4p9-p4cx-gxwx](https://github.com/pieceofcake2/cakephp/security/advisories/GHSA-x4p9-p4cx-gxwx))。古い
バージョンなら更新してください。

## cakephp2-xml-build-variable

`['readFile' => false]` を付けずに、変数を `Xml::build()` に渡しています。

**なぜ危ないか。** `readFile` はデフォルトで `true` です。パスや URL (`http://`、`https://`) の文字列は読み込まれます。
リクエストの値なら、サーバーが攻撃者の URL (内部のネットワークやクラウドのメタデータのアドレスなど) を取得したり
(SSRF)、ローカルのファイルを読んだりします。

```php
// 見つかる書き方
$xml = Xml::build($this->request->data('xml'));

// 直し方: XML の文字列だけ
$xml = Xml::build((string)$this->request->data('xml'), ['readFile' => false]);
```

2.12.3 より前の pieceofcake2/cakephp は、`['readFile' => false]` でも URL を取得していました
([GHSA-wgww-24w3-wfqp](https://github.com/pieceofcake2/cakephp/security/advisories/GHSA-wgww-24w3-wfqp))。2.12.3 以降に
更新してください。`Xml::build()` にデータの配列を渡す場合は、読み込まずに変換されます。そうした呼び出しの指摘は、
理由を書いて除外してください。

## cakephp2-security-csrf-disabled

`$this->Security->csrfCheck = false` か `$this->Security->validatePost = false` です。

**なぜ危ないか。** `SecurityComponent` の CSRF トークンは、フォームがサイトのページから送られたことを確かめます。
これがないと、ほかのサイトが、ログイン中のユーザーのブラウザにフォームを送らせられます。アカウントのメールアドレスや
パスワードの変更、注文、データの削除などです (CSRF)。`validatePost` は、フォームの欄が足されたり変えられたりして
いないことも確かめます (フォームの改ざん)。`beforeFilter()` で無効にすると、コントローラーのすべてのアクションで
無効になりがちです。

```php
// 見つかる書き方
public function beforeFilter()
{
    parent::beforeFilter();
    $this->Security->csrfCheck = false;
}

// 直し方: ほかのサイトからのリクエストを受けるアクションだけ。Webhook など
public function beforeFilter()
{
    parent::beforeFilter();
    $this->Security->unlockedActions = ['webhook'];
}
```

- `unlockedActions` のアクションは、Webhook の署名など、リクエストを自分で確かめる必要があります。
- JavaScript が足したり変えたりする欄は、その欄だけを外します: `$this->Security->unlockedFields = ['Order.coupon'];`、
  またはビューで `$this->Form->unlockField('Order.coupon')`。
- JavaScript (Ajax) のリクエストでは、チェックを無効にせず、フォームのトークン (`data[_Token][key]`) を読んで、データと
  一緒に送ってください。

## cakephp2-view-unescaped-output

ビューで、変数を `h()` を通さずに `<?= $var ?>` や `<?php echo $var; ?>` で出力しています。ビューとは、`templates/` と
`View/` にある、ビューの拡張子のファイルです ([検査する範囲](README.md#検査する範囲))。

**なぜ危ないか。** HTML を含む値は、ブラウザで実行されます。名前、コメント、パラメーターの `<script>` が、ページを
開いた各ユーザーのセッションで動き、ページを読んだり、ユーザーになりすましてフォームを送ったりできます (XSS)。
ユーザーが保存した値 (持続型 XSS) は、管理者も含め、すべてのユーザーに届きます。

```php
<!-- 見つかる書き方 -->
<div><?= $post['Post']['body'] ?></div>
<a href="<?= $url ?>">Next</a>

<!-- 直し方 -->
<div><?= h($post['Post']['body']) ?></div>
<?= $this->Html->link('Next', $url) ?>
```

- `h()` は、HTML のテキストと属性 (属性は引用符で囲んで) のためにエスケープします。ヘルパー
  (`$this->Html->link()`、`$this->Form->input()` など) は値をエスケープします。
- URL の属性では、スキームも確かめてください。`h()` は `javascript:` を止めません。URL はルートか
  `$this->Html->url()` で作り、ユーザーの URL は `http`/`https` だけを受け付けてください。
- JavaScript には `json_encode()` で書きます:
  `var name = <?= json_encode($name, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) ?>;`。
- ユーザーが書く HTML (Markdown など) は、出力する前に、スクリプトやイベントの属性を取り除くライブラリで
  サニタイズしてください。

指摘が多くなりすぎないよう、次は指摘しません。

- ヘルパーや関数の呼び出しの出力
- 出力する前にビューの中で、ヘルパーの出力、`h()`、`count()`、`(int)` や `(float)` の数値を入れた変数
- レイアウトの HTML である `$content_for_layout` と `$scripts_for_layout`
- `--safe-view-variables` の変数。サニタイズした HTML を入れた変数など

```php
<?php $link = $this->Html->link('Back', '/'); ?>
<?= $link ?>            <!-- 指摘しない: ヘルパー -->
<?php $count = count($posts); ?>
<?= $count ?>           <!-- 指摘しない: 数値 -->
<?= $content_for_layout ?>  <!-- 指摘しない: レイアウト -->
<?= $post['Post']['body'] ?>  <!-- 指摘する -->
```

わざとサニタイズした HTML を入れた変数は、`--safe-view-variables` か設定ファイルで、`$` を除いた名前を指定すると、
すべてのビューで安全として扱います (そのキーやプロパティも含みます)。

```php
// config/security.php
return [
    'sast' => ['safeViewVariables' => ['body_html']],
];
```

1 箇所だけなら、コメントで除外することもできます ([指摘を除外する](README.md#指摘を除外する))。コントローラーが
セットした変数の中身までは追わないため、このルールの確度は低です。コントローラーでエスケープ済みの変数も指摘します。
それでも、文脈 (HTML、属性、JavaScript) がわかるビューでエスケープしてください。

## 設定

設定のルールは、`APP_ENV=prod` のときのアプリケーションの `Configure` の値を検査します ([設定](README.md#設定))。どちらの
エンジンでも実行し、`--config-check=0` で止められます。指摘は `core.php` のその設定の行に付きます。

| ルール | リスク | CWE | OWASP Top 10 (2021) |
| --- | --- | --- | --- |
| [`cakephp2-config-debug`](#cakephp2-config-debug) | 高 | CWE-489 | A05 セキュリティの設定ミス |
| [`cakephp2-config-salt`](#cakephp2-config-salt) | 高 | CWE-1188、CWE-330 | A02 暗号化の失敗 |
| [`cakephp2-config-cipher-seed`](#cakephp2-config-cipher-seed) | 中 (`aes` の Cookie なら低) | CWE-1188 | A02 暗号化の失敗 |
| [`cakephp2-config-cookie-cipher`](#cakephp2-config-cookie-cipher) | 中 | CWE-327 | A02 暗号化の失敗 |
| [`cakephp2-config-cookie-key`](#cakephp2-config-cookie-key) | 中 | CWE-321、CWE-326 | A02 暗号化の失敗 |
| [`cakephp2-config-session-cookie`](#cakephp2-config-session-cookie) | 中 | CWE-1004、CWE-614 | A05 セキュリティの設定ミス |
| [`cakephp2-config-openssl`](#cakephp2-config-openssl) | 低 | CWE-1104 | A06 脆弱で古くなったコンポーネント |

秘密の値は、CakePHP 2 と pieceofcake2 の配布時の値と、それらのドキュメントのサンプルと、SHA-256 と長さで比べます。報告書
には書きません。

秘密の値は本番の環境 (サーバーの環境変数か、コミットしない `config/.env.prod.local`) に設定し、コミットするファイルには
決して書かないでください。値は次のように作ります。

```bash
php -r 'echo bin2hex(random_bytes(32)), PHP_EOL;'   # 32 バイトの鍵を 16 進数 64 文字で
```

**秘密の値は慎重に変えてください。** 使われている秘密の値は、すでにデータに署名したり暗号化したりしています。パスワード、
Cookie、開いているページのフォームなどです。以下の各節に、変えると何が使えなくなるかと、その移行のしかたを書きます。

### cakephp2-config-debug

本番で `debug` が 0 ではありません。エラーページにコード、SQL、パス、設定が表示され、`DebugKit` が読み込まれることも
あります。攻撃者に必要なものがすべて見えます。

本番の環境で `APP_DEBUG=0` にするか、設定しないでください (pieceofcake2/app ではデフォルトで `debug` は 0 です)。
`DebugKit` は `debug` が 0 でないときだけ読み込みます。変えたあとは本番のエラーページを確かめてください。CakePHP は
`templates/Errors/error400.ctp` と `error500.ctp` (従来の構成では `app/View/Errors/`) を表示します。

### cakephp2-config-salt

`Security.salt` が配布時の値かドキュメントのサンプルのまま、または 32 文字より短い値です。これらの値は誰でも知って
います。ハッシュや、`SecurityComponent` のフォームのトークンなどの署名した値を偽造でき、salt でハッシュしたパスワードも
破られやすくなります。

本番の環境で `SECURITY_SALT` に 32 バイト以上のランダムな値を設定してください。変えると、次が使えなくなります。

- **`AuthComponent` の `Simple` ハッシャー (デフォルト) のパスワード**: `salt . password` をハッシュするので、新しい salt
  では誰もログインできなくなります。先に `Blowfish` ハッシャーに移ってください (下記)。
- **`Security::encrypt()` の値**: `CookieComponent` の `aes` の Cookie もです。HMAC に salt を使う (`Cookie.key` が
  なければ鍵も salt) ので、読めなくなります。ユーザーはこれらの Cookie を一度失い、データベースで暗号化したデータは
  復号して暗号化し直す必要があります。
- **変えたときに開いていたフォーム**: 一度だけ弾かれます。ユーザーはもう一度送ります。

パスワードを移すには、古いハッシュを確かめて新しいハッシュを Blowfish で作るハッシャーを使い、すべてのユーザーが一度
ログインするまで、古い salt を `Security.previousSalt` として残します。

```php
// src/Controller/Component/Auth/MigratingPasswordHasher.php (従来の構成では app/Controller/Component/Auth/)
App::uses('BlowfishPasswordHasher', 'Controller/Component/Auth');
App::uses('Security', 'Utility');

class MigratingPasswordHasher extends BlowfishPasswordHasher
{
    public function check($password, $hashedPassword)
    {
        if (str_starts_with((string)$hashedPassword, '$2')) {
            return parent::check($password, $hashedPassword);
        }

        // Simple ハッシャーの古いハッシュ: 古い salt とパスワードを Security::$hashType (sha1) で
        return $hashedPassword === Security::hash($password, null, (string)Configure::read('Security.previousSalt'));
    }
}
```

```php
// AppController: Form の認証に Migrating ハッシャー
public $components = ['Auth' => ['authenticate' => ['Form' => ['passwordHasher' => 'Migrating']]]];
```

そして、`$this->Auth->login()` が成功したあと、保存されたハッシュが `$2` で始まらなければ、ハッシャーでパスワードの
新しいハッシュを保存します (モデルの `beforeSave()` でもう一度ハッシュしないように)。新しいパスワード (登録、リセット) は
`hash()` で Blowfish になります。すべてのユーザーが移ったら、または残りのユーザーにパスワードのリセットを求めるなら、
`Security.previousSalt` と `check()` の古い分岐を消してください。

### cakephp2-config-cipher-seed

`Security.cipherSeed` が配布時の値かドキュメントのサンプルのままです。`CookieComponent` の `cipher` の Cookie と
`Security::cipher()` の鍵で、もともと弱い方式です。Cookie を `aes` に移すと
([cakephp2-config-cookie-cipher](#cakephp2-config-cookie-cipher))、seed は関係なくなり、このルールのリスクは低になります。
それまでは、`SECURITY_CIPHER_SEED` にランダムな数字を設定してください。古い seed で書いた `cipher` の Cookie は読めなく
なります (ユーザーは一度失います)。

### cakephp2-config-cookie-cipher

`CookieComponent` が `cipher` で暗号化しています (`Cookie.type` が未設定か `cipher`)。`mt_rand()` の列との XOR で、
いくつかの Cookie から破れます。

`config/core.php` (`app/Config/core.php`) に設定し、鍵は本番の環境に置きます。

```php
Configure::write('Cookie.type', 'aes');
Configure::write('Cookie.key', env('COOKIE_KEY') ?: null);
Configure::write('Security.useOpenSsl', true);
```

切り替えると `cipher` の Cookie は読めなくなり、中の値を一度失います (「ログインしたままにする」が切れる、カートが空に
なる、など)。リリースに合わせて切り替えてください。

### cakephp2-config-cookie-key

`aes` の Cookie の鍵 `Cookie.key` が、ドキュメントのサンプルのまま、または 32 バイトより短い値です。鍵を知っていれば、
Cookie を読んだり偽造したりできます。ほかのユーザーの ID を入れた「ログインしたままにする」の Cookie などです。

本番の環境で `COOKIE_KEY` に 32 バイト以上のランダムな値を設定してください。古い鍵で暗号化した Cookie は読めなくなります
(ユーザーは一度失い、「ログインしたままにする」ならもう一度ログインします)。

### cakephp2-config-session-cookie

セッションの Cookie に `HttpOnly` か `Secure` が付きません。`Session.ini` で `session.cookie_httponly` か
`session.cookie_secure` が false になっています。`HttpOnly` がないと XSS のスクリプトがセッションの Cookie を読め、
`Secure` がないと Cookie が HTTP でも送られ、ネットワークで読まれます。

CakePHP はどちらもデフォルトで付けます (`Secure` は HTTPS のとき)。それを無効にしている設定を消してください。ほかの
サイトからのリクエストのために、`SameSite` も足します。

```php
Configure::write('Session', [
    'defaults' => 'php',
    'ini' => ['session.cookie_samesite' => 'Lax'],
]);
```

HTTPS を終端するプロキシの後ろでは、CakePHP はリクエストを HTTPS と見たときだけ `Secure` を付けます。その場合は、本番の
`ini` に `'session.cookie_secure' => 1` を設定してください。

### cakephp2-config-openssl

`Security.useOpenSsl` が `true` ではありません。`Security::encrypt()` と `aes` の Cookie が mcrypt を使います。mcrypt は
メンテナンスされておらず、PHP 7.2 以降には同梱されていません。`Security.useOpenSsl` を `true` にしてください。CakePHP の
OpenSSL の実装は mcrypt のもの (AES-128-CBC) と互換なので、切り替える前に暗号化した値も、切り替えたあとに読めます。
