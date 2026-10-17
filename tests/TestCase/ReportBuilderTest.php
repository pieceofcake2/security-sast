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
use PieceOfCake2\SecuritySast\ScanResult;
use PieceOfCake2\SecuritySast\SemgrepEngine;

class ReportBuilderTest extends TestCase
{
    private static function result(): ScanResult
    {
        $data = json_decode((string)file_get_contents(__DIR__ . DS . '..' . DS . 'fixtures' . DS . 'semgrep.json'), true);

        return SemgrepEngine::result($data, (string)realpath(SemgrepEngineTest::APP));
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
        $this->assertStringContainsString('<b class="t-high">5</b><span>High</span>', $html);
        $this->assertStringContainsString('<b class="t-medium">10</b><span>Medium</span>', $html);
        $this->assertStringContainsString('src　templates', $html);
        $this->assertStringContainsString('pieceofcake2/security-sast (CakePHP 2)　p/php', $html);
        $this->assertStringContainsString('Semgrep 1.', $html);

        // The rules by risk, with their places
        $this->assertMatchesRegularExpression('#<h3>1\. High</h3>.*<h3>2\. Medium</h3>#s', $html);
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
        $this->assertStringContainsString('変数を含む文字列で組み立てた SQL を Model::query() に渡しています。', $html);
        $this->assertStringContainsString('<td class="num">2箇所</td>', $html);
        $this->assertStringNotContainsString('p/php', $html);
    }

    public function testNoFinding(): void
    {
        $html = self::html(new Config(failOn: 'none', project: SemgrepEngineTest::APP), new ScanResult([], 10, 'PHPStan 2.1.0', ['Syntax error in a.php']));

        $this->assertStringContainsString('<div class="verdict passed">', $html);
        $this->assertStringContainsString('No finding in the scanned files.', $html);
        $this->assertStringContainsString('The engine reported 1 errors, e.g. files it could not parse: Syntax error in a.php', $html);
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
