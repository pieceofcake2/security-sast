<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\Test;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use PieceOfCake2\Report\Environment;
use PieceOfCake2\Report\HtmlRenderer;
use PieceOfCake2\SecuritySast\Config;
use PieceOfCake2\SecuritySast\Finding;
use PieceOfCake2\SecuritySast\ReportBuilder;
use PieceOfCake2\SecuritySast\RuleCatalog;
use PieceOfCake2\SecuritySast\ScanResult;

class ReportBuilderTest extends TestCase
{
    private static function result(): ScanResult
    {
        return SemgrepEngineTest::recorded();
    }

    private static function html(Config $config, ?ScanResult $result = null): string
    {
        $doc = (new ReportBuilder(ReportBuilder::translator($config->language)))->build(
            $result ?? self::result(),
            $config,
            new Environment(),
            new DateTimeImmutable('2026-10-17 10:00:00'),
            new DateTimeImmutable('2026-10-17 10:00:25'),
        );

        return (new HtmlRenderer())->render($doc);
    }

    public function testReport(): void
    {
        $html = self::html(new Config(project: SemgrepEngineTest::APP));

        $this->assertStringContainsString('<h1>Static Application Security Testing Report</h1>', $html);
        $this->assertStringContainsString('<div class="project">acme/app</div>', $html);
        $this->assertStringContainsString('<div class="verdict failed">', $html);
        $this->assertStringContainsString('<b class="t-high">26</b><span>High</span>', $html);
        $this->assertStringContainsString('<b class="t-medium">40</b><span>Medium</span>', $html);
        $this->assertStringContainsString('src　templates', $html);
        $this->assertStringContainsString('pieceofcake2/security-sast (CakePHP 2)　p/php', $html);
        $this->assertStringContainsString('Semgrep 1.', $html);

        // The rules by risk, with their places
        // Every risk of the cover, also without findings
        $this->assertMatchesRegularExpression('#<h3>1\. Critical</h3>\s*<p class="empty">None</p>#', $html);
        $this->assertMatchesRegularExpression('#<h3>2\. High</h3>.*<h3>3\. Medium</h3>.*<h3>4\. Low</h3>\s*<p class="empty">None</p>.*<h3>5\. Info</h3>#s', $html);
        $this->assertStringNotContainsString('. Unknown</h3>', $html);
        $this->assertStringContainsString('SQL built with a variable in Model::query()', $html);
        $this->assertStringContainsString('<td class="num">2</td>', $html);
        $this->assertStringContainsString('<div class="loc">src/Controller/PostsController.php:19</div>', $html);
        $this->assertStringContainsString('<pre>$posts = $this-&gt;Post-&gt;query(', $html);
        $this->assertStringContainsString('CWE-89: Improper Neutralization', $html);
        $this->assertStringContainsString('.place pre', $html);
    }

    public function testJapanese(): void
    {
        $html = self::html(new Config(failOn: 'critical', project: SemgrepEngineTest::APP, language: 'ja', engine: 'phpstan'));

        $this->assertStringContainsString("<h1>静的アプリケーションセキュリティテスト\u{200b}報告書</h1>", $html);
        $this->assertStringContainsString('<div class="verdict passed">', $html);
        $this->assertStringContainsString('Model::query() に変数を含む SQL', $html);
        $this->assertStringContainsString('変数を含む文字列で組み立てた SQL を Model::query() (または fetchAll()、execute()) に渡しています。', $html);
        $this->assertStringContainsString('<td class="num">2箇所</td>', $html);
        $this->assertStringNotContainsString('p/php', $html);
    }

    public function testSemgrepignore(): void
    {
        $project = TMP . 'semgrepignore';
        is_dir($project) || mkdir($project);
        file_put_contents($project . DS . '.semgrepignore', "legacy/\n");

        $html = self::html(new Config(project: $project), new ScanResult([], 1, 'Semgrep 1.180.0'));
        $this->assertStringContainsString('Semgrep also leaves out the paths of the .semgrepignore of the project', $html);

        $html = self::html(new Config(project: $project, engine: 'phpstan'), new ScanResult([], 1, 'PHPStan 2.3.1'));
        $this->assertStringNotContainsString('.semgrepignore', $html);
    }

    public function testSuppressed(): void
    {
        $result = new ScanResult([], 3, 'PHPStan 2.3.1', suppressed: [['file' => 'src/Model/Post.php', 'line' => 12, 'rules' => ['cakephp2-query-concatenation'], 'reason' => 'The table name is a constant', 'code' => "\$this->query('TRUNCATE ' . self::TABLE);"]]);
        $html = self::html(new Config(project: SemgrepEngineTest::APP), $result);

        $this->assertStringContainsString('<div class="verdict passed">', $html);
        $this->assertMatchesRegularExpression('#<td>\s*1 \(comments in the code; they do not fail the scan\)\s*</td>#', $html);
        $this->assertMatchesRegularExpression('#<h3>4\. Low</h3>\s*<p class="empty">None</p>#', $html);
        $this->assertMatchesRegularExpression('#<h3>5\. Suppressed findings</h3>#', $html);
        $this->assertStringContainsString('<span class="badge suppressed">Suppressed</span>', $html);
        $this->assertStringContainsString('<div class="loc">src/Model/Post.php:12　cakephp2-query-concatenation</div><div class="reason">Reason: The table name is a constant</div>', $html);
    }

    public function testNoFinding(): void
    {
        $html = self::html(new Config(failOn: 'none', project: SemgrepEngineTest::APP), new ScanResult([], 10, 'PHPStan 2.1.0', ['Syntax error in a.php']));

        $this->assertStringContainsString('<div class="verdict passed">', $html);
        $this->assertStringContainsString('No finding in the scanned files.', $html);
        $this->assertStringContainsString('The engine reported 1 errors, e.g. files it could not parse: Syntax error in a.php', $html);
        $this->assertStringNotContainsString('rules of HTML', $html);
    }

    /**
     * The errors of the rules of HTML of Semgrep in the views are said apart from the files that could not be read
     *
     * @return void
     */
    public function testErrorsOfTheRulesOfHtmlInTheViews(): void
    {
        $result = new ScanResult([], 10, 'Semgrep 1.180.0', viewErrors: ['PartialParsing: templates/a.ctp:1', 'Syntax error: templates/b.html:1']);

        $html = self::html(new Config(failOn: 'none', project: SemgrepEngineTest::APP), $result);
        $this->assertStringContainsString('Semgrep reported 2 errors of its rules of HTML, which read only a part of the views as they contain PHP; the rules of PHP read the views as PHP.', $html);
        $this->assertStringNotContainsString('The engine reported', $html);

        $html = self::html(new Config(failOn: 'none', project: SemgrepEngineTest::APP, language: 'ja'), $result);
        $this->assertStringContainsString('Semgrep の HTML のルールが、PHP を含むビューを一部しか読めなかったとして 2 件のエラーを報告しました。', $html);
    }

    /**
     * The rules of this package that ran and found nothing, by risk, with their CWE
     *
     * @return void
     */
    public function testPassedChecks(): void
    {
        $result = self::result();
        $html = self::html(new Config(project: SemgrepEngineTest::APP), $result);

        $this->assertStringContainsString('<h2>Checks</h2>', $html);
        $this->assertStringContainsString('<h3>Passed checks</h3>', $html);
        $passed = self::section($html, 'Passed checks');
        $found = array_keys($result->byRule());
        foreach (array_keys(RuleCatalog::RULES) as $rule) {
            if (in_array($rule, $found, true)) {
                $this->assertStringNotContainsString('>' . $rule . '<', $passed);
            } else {
                $this->assertStringContainsString('<td class="mono">' . $rule . '</td>', $passed);
            }
        }
        $this->assertMatchesRegularExpression('#<td class="mono">cakephp2-config-debug</td>\s*<td>Debug level above 0 in production</td>\s*<td class="res"><span class="badge high">High</span></td>\s*<td>CWE-489</td>#', $passed);
        $this->assertStringContainsString('<td>CWE-1188, CWE-330</td>', $passed);
        // High before medium
        $this->assertLessThan(strpos($passed, 'cakephp2-config-cipher-seed'), strpos($passed, 'cakephp2-config-salt'));
        $this->assertStringContainsString('<h3>Not run</h3>', $html);
        $this->assertMatchesRegularExpression('#<h3>Not run</h3>\s*<p class="check-note">[^<]*</p>\s*<p class="empty">None</p>#', $html);
    }

    /**
     * The rules that did not run, with the reason, are not passed checks
     *
     * @return void
     */
    public function testNotRun(): void
    {
        $result = new ScanResult([], 3, 'Semgrep 1.180.0', engineRules: ['cakephp2-query-concatenation', 'php.lang.security.exec-use.exec-use'], skippedRules: [['id' => 'php.lang.security.new-rule', 'reason' => 'Requires Semgrep 2']]);
        $result->notRun = ['cakephp2-config-debug' => 'notRun.configOff', 'cakephp2-framework-protocol-relative-here' => 'notRun.noFramework'];
        $html = self::html(new Config(project: SemgrepEngineTest::APP), $result);

        $notRun = self::section($html, 'Not run');
        $this->assertMatchesRegularExpression('#<td class="mono">cakephp2-config-debug</td>\s*<td>Debug level above 0 in production</td>\s*<td>The check of the configuration is turned off \(--config-check=0\)</td>#', $notRun);
        $this->assertStringContainsString('<td>No CakePHP in the composer.lock of the project</td>', $notRun);
        // A rule of the code that Semgrep did not run
        $this->assertMatchesRegularExpression('#<td class="mono">cakephp2-render-request</td>\s*<td>[^<]*</td>\s*<td>The engine did not run it</td>#', $notRun);
        $this->assertStringContainsString('<td>Skipped by Semgrep: Requires Semgrep 2</td>', $notRun);
        $passed = self::section($html, 'Passed checks');
        $this->assertStringContainsString('cakephp2-query-concatenation', $passed);
        $this->assertStringNotContainsString('cakephp2-config-debug', $passed);
        $this->assertStringNotContainsString('cakephp2-render-request', $passed);
    }

    /**
     * The other rules of Semgrep, e.g. p/php, as numbers
     *
     * @return void
     */
    public function testOtherRules(): void
    {
        $findings = [new Finding('php.lang.security.exec-use.exec-use', 'high', 'Exec', 'src/A.php', 3)];
        $result = new ScanResult($findings, 3, 'Semgrep 1.180.0', engineRules: ['cakephp2-query-concatenation', 'php.lang.security.exec-use.exec-use', 'php.lang.security.eval-use.eval-use', 'php.lang.security.md5-loose-equality.md5-loose-equality']);
        $html = self::html(new Config(project: SemgrepEngineTest::APP, semgrepConfigs: ['p/php', 'rules/app.yml']), $result);

        $other = self::section($html, 'Other rules of Semgrep');
        $this->assertStringContainsString('<thead><tr><th>Rules</th><th>Name</th><th>Ran</th><th>Found places</th><th>Found nothing</th></tr></thead>', $other);
        $this->assertMatchesRegularExpression('#<td class="mono">p/php, rules/app.yml</td>\s*<td>Rules of the Semgrep Registry and of the project</td>\s*<td>3</td>\s*<td>1</td>\s*<td>2</td>#', $other);

        // Unknown without the timing of Semgrep
        $result->engineRules = null;
        $other = self::section(self::html(new Config(project: SemgrepEngineTest::APP), $result), 'Other rules of Semgrep');
        $this->assertStringContainsString('Semgrep did not tell which rules ran', $other);
        $this->assertMatchesRegularExpression('#<td>-</td>\s*<td>1</td>\s*<td>-</td>#', $other);

        // PHPStan runs the rules of this package only
        $html = self::html(new Config(project: SemgrepEngineTest::APP, engine: 'phpstan'), new ScanResult([], 3, 'PHPStan 2.1.0'));
        $this->assertStringNotContainsString('Other rules of Semgrep', $html);
    }

    public function testChecksInJapanese(): void
    {
        $html = self::html(new Config(project: SemgrepEngineTest::APP, language: 'ja'), new ScanResult([], 3, 'Semgrep 1.180.0'));

        $this->assertStringContainsString('<h2>確認した項目</h2>', $html);
        $this->assertStringContainsString('<h3>確認した項目（問題なし）</h3>', $html);
        $this->assertStringContainsString('<h3>実行しなかった項目</h3>', $html);
        $this->assertMatchesRegularExpression('#<h3>1\. 緊急</h3>\s*<p class="empty">なし</p>#', $html);
    }

    /**
     * The table of checks of a heading
     *
     * @param string $html HTML
     * @param string $title Heading
     * @return string
     */
    private static function section(string $html, string $title): string
    {
        $start = strpos($html, '<h3>' . $title . '</h3>');
        self::assertNotFalse($start, $title);
        $end = strpos($html, '</div>', $start);

        return substr($html, $start, $end - $start);
    }

    public function testTitleOfAnotherRule(): void
    {
        $builder = new ReportBuilder(ReportBuilder::translator('en'));

        $this->assertSame('Exec use', $builder->title('php.lang.security.exec-use.exec-use'));
        $this->assertSame('Variable printed in a view without h()', $builder->title('cakephp2-view-unescaped-output'));
    }

    public function testManyPlaces(): void
    {
        $findings = [];
        for ($i = 1; $i <= ReportBuilder::MAX_PLACES + 5; $i++) {
            $findings[] = new Finding('cakephp2-view-unescaped-output', 'medium', 'Message', 'templates/a.ctp', $i);
        }

        $html = self::html(new Config(project: SemgrepEngineTest::APP), new ScanResult($findings, 1, 'Semgrep'));

        $this->assertSame(ReportBuilder::MAX_PLACES, substr_count($html, '<div class="place">'));
        $this->assertStringContainsString('and 5 more places', $html);
    }
}
