<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\Test;

use PHPUnit\Framework\TestCase;
use PieceOfCake2\SecuritySast\PhpstanEngine;
use RuntimeException;

class PhpstanEngineTest extends TestCase
{
    public function testScan(): void
    {
        $result = (new PhpstanEngine())->scan(SemgrepEngineTest::APP, ['src', 'templates']);

        // The same places as the Semgrep rules, and no other error of PHPStan
        $this->assertSame(SemgrepEngineTest::EXPECTED, SemgrepEngineTest::places($result->findings));
        $this->assertSame(15, $result->files);
        $this->assertStringStartsWith('PHPStan 2.', $result->engine);
        $view = array_values(array_filter($result->findings, static fn($finding): bool => $finding->file === 'templates/Posts/view.ctp'))[0];
        $this->assertSame('<div><?= $post[\'Post\'][\'body\'] ?></div>', $view->code);
        $this->assertSame('medium', $view->severity);
    }

    public function testScanViewsOfMoreExtensions(): void
    {
        $result = (new PhpstanEngine(null, null, ['ctp', 'php', 'html']))->scan(SemgrepEngineTest::APP, ['src', 'templates']);

        $views = array_values(array_filter(SemgrepEngineTest::places($result->findings), static fn(string $place): bool => str_starts_with($place, 'cakephp2-view-unescaped')));
        $this->assertSame([
            'cakephp2-view-unescaped-output templates/Elements/banner.html:1',
            'cakephp2-view-unescaped-output templates/Emails/html/default.ctp:1',
            'cakephp2-view-unescaped-output templates/Posts/edit.ctp:10',
            'cakephp2-view-unescaped-output templates/Posts/edit.ctp:12',
            'cakephp2-view-unescaped-output templates/Posts/index.php:2',
            'cakephp2-view-unescaped-output templates/Posts/links.ctp:11',
            'cakephp2-view-unescaped-output templates/Posts/links.ctp:12',
            'cakephp2-view-unescaped-output templates/Posts/links.ctp:13',
            'cakephp2-view-unescaped-output templates/Posts/parity.ctp:28',
            'cakephp2-view-unescaped-output templates/Posts/parity.ctp:29',
            'cakephp2-view-unescaped-output templates/Posts/parity.ctp:30',
            'cakephp2-view-unescaped-output templates/Posts/parity.ctp:31',
            'cakephp2-view-unescaped-output templates/Posts/parity.ctp:7',
            'cakephp2-view-unescaped-output templates/Posts/parity.ctp:8',
            'cakephp2-view-unescaped-output templates/Posts/request.ctp:10',
            'cakephp2-view-unescaped-output templates/Posts/request.ctp:6',
            'cakephp2-view-unescaped-output templates/Posts/request.ctp:7',
            'cakephp2-view-unescaped-output templates/Posts/request.ctp:9',
            'cakephp2-view-unescaped-output templates/Posts/view.ctp:2',
            'cakephp2-view-unescaped-output templates/Posts/view.ctp:3',
        ], $views);
        $this->assertSame(16, $result->files);
    }

    public function testScanWithSafeViewVariables(): void
    {
        $result = (new PhpstanEngine(null, null, ['ctp'], ['body_html']))->scan(SemgrepEngineTest::APP, ['templates']);

        $this->assertNotContains('cakephp2-view-unescaped-output templates/Posts/edit.ctp:10', SemgrepEngineTest::places($result->findings));
        $this->assertContains('cakephp2-view-unescaped-output templates/Posts/edit.ctp:12', SemgrepEngineTest::places($result->findings));
    }

    public function testConfig(): void
    {
        $app = (string)realpath(SemgrepEngineTest::APP);
        mkdir($app . DS . "it's");
        try {
            $neon = PhpstanEngine::config($app, ['src', 'templates'], ['vendor', "it's"]);
        } finally {
            rmdir($app . DS . "it's");
        }

        $this->assertStringContainsString('rules.neon', $neon);
        $this->assertStringContainsString("    level: 0\n", $neon);
        $this->assertStringContainsString("        arguments: [['ctp', 'php'], [], '{$app}']\n", $neon);
        $this->assertStringContainsString("    fileExtensions:\n        - 'php'\n        - 'ctp'\n", $neon);
        $this->assertStringContainsString("        - '{$app}/src'\n        - '{$app}/templates'\n", $neon);
        // Only the paths that exist are left out
        $this->assertStringContainsString("        analyseAndScan:\n            - '{$app}/it''s'\n", $neon);
        $this->assertStringNotContainsString('/vendor', $neon);
    }

    public function testProjectInADirectoryOfViews(): void
    {
        // The directories of the project itself are not those of views
        $project = TMP . 'templates' . DS . 'app';
        is_dir($project . DS . 'src') || mkdir($project . DS . 'src', 0777, true);
        file_put_contents($project . DS . 'src' . DS . 'Export.php', "<?php\n\$csv = 'id';\necho \$csv;\n");
        $temp = glob(sys_get_temp_dir() . DS . 'security-sast-*');

        $result = (new PhpstanEngine())->scan($project, ['src']);

        $this->assertSame([], $result->findings);
        // No temporary file is left
        $this->assertSame($temp, glob(sys_get_temp_dir() . DS . 'security-sast-*'));
    }

    public function testParseError(): void
    {
        $app = (string)realpath(SemgrepEngineTest::APP);
        $data = ['files' => [$app . DS . 'src' . DS . 'Broken.php' => ['messages' => [['message' => 'Syntax error, unexpected EOF on line 3', 'line' => 3, 'identifier' => 'phpstan.parse']]]], 'errors' => []];

        // Not scanned, and said so
        $result = PhpstanEngine::result($data, $app);
        $this->assertSame([], $result->findings);
        $this->assertSame(['src/Broken.php: Syntax error, unexpected EOF on line 3'], $result->errors);
    }

    public function testCountFiles(): void
    {
        $this->assertSame(15, PhpstanEngine::countFiles(SemgrepEngineTest::APP, ['src', 'templates']));
        $this->assertSame(14, PhpstanEngine::countFiles(SemgrepEngineTest::APP, ['src', 'templates'], ['src/Model']));
        $this->assertSame(16, PhpstanEngine::countFiles(SemgrepEngineTest::APP, ['src', 'templates'], [], ['ctp', 'php', 'html']));
        $this->assertSame(1, PhpstanEngine::countFiles(SemgrepEngineTest::APP, ['templates/Posts/view.ctp']));
    }

    public function testFailure(): void
    {
        $engine = new PhpstanEngine('phpstan', static fn(array $command, string $dir): array => [255, 'PHP Fatal error', '']);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('PHPStan failed (exit code 255): PHP Fatal error');

        $engine->scan(SemgrepEngineTest::APP, ['src']);
    }
}
