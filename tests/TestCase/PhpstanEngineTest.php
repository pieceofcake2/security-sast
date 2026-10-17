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
        $this->assertSame(3, $result->files);
        $this->assertStringStartsWith('PHPStan 2.', $result->engine);
        $view = array_values(array_filter($result->findings, static fn($finding): bool => $finding->file === 'templates/Posts/view.ctp'))[0];
        $this->assertSame('<div><?= $post[\'Post\'][\'body\'] ?></div>', $view->code);
        $this->assertSame('medium', $view->severity);
    }

    public function testConfig(): void
    {
        $neon = PhpstanEngine::config('/app', ['src', 'templates'], ['vendor', "it's"]);

        $this->assertStringContainsString('rules.neon', $neon);
        $this->assertStringContainsString("    level: 0\n", $neon);
        $this->assertStringContainsString("        - '/app/src'\n        - '/app/templates'\n", $neon);
        $this->assertStringContainsString("            - '/app/vendor (?)'\n            - '/app/it''s (?)'\n", $neon);
    }

    public function testCountFiles(): void
    {
        $this->assertSame(3, PhpstanEngine::countFiles(SemgrepEngineTest::APP, ['src', 'templates']));
        $this->assertSame(2, PhpstanEngine::countFiles(SemgrepEngineTest::APP, ['src', 'templates'], ['src/Model']));
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
