<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\Test;

use PHPUnit\Framework\TestCase;
use PieceOfCake2\SecuritySast\Engine;
use PieceOfCake2\SecuritySast\PhpstanEngine;
use PieceOfCake2\SecuritySast\SemgrepEngine;
use PieceOfCake2\SecuritySast\Suppressions;

class SuppressionsTest extends TestCase
{
    private const CODE = __DIR__ . DS . '..' . DS . 'fixtures' . DS . 'suppressions.php';

    private const PROJECT = __DIR__ . DS . '..' . DS . 'fixtures' . DS . 'suppressed';

    public function testSemgrep(): void
    {
        $suppressions = Suppressions::inCode((string)file_get_contents(self::CODE), 'semgrep');

        $this->assertSame([
            // On a line of its own: the next line, with the comment before as the reason
            ['line' => 8, 'rules' => ['cakephp2-query-concatenation'], 'reason' => 'The table name is a constant of the model', 'code' => "\$this->query('TRUNCATE ' . self::TABLE);"],
            // At the end of a line, for every rule, with the reason after --
            ['line' => 12, 'rules' => [], 'reason' => 'a test value', 'code' => '$z = 1; // nosemgrep -- a test value'],
        ], $suppressions);
    }

    public function testPhpstan(): void
    {
        $suppressions = Suppressions::inCode((string)file_get_contents(self::CODE), 'phpstan');

        // The identifiers of this package as the IDs of the rules; not the ignores of the other identifiers
        $this->assertSame([10, 11, 14], array_column($suppressions, 'line'));
        $this->assertSame(['cakephp2-query-concatenation'], $suppressions[0]['rules']);
        $this->assertSame('The table name is a constant of the model', $suppressions[0]['reason']);
        $this->assertSame('signed by the server', $suppressions[1]['reason']);
        $this->assertSame([], $suppressions[2]['rules']);
        $this->assertSame('$w = foo();', $suppressions[2]['code']);
    }

    public function testFind(): void
    {
        $suppressions = Suppressions::find(dirname(self::CODE), ['suppressions.php'], [], ['php'], 'semgrep');

        $this->assertSame(['suppressions.php', 'suppressions.php'], array_column($suppressions, 'file'));
        $this->assertSame([], Suppressions::find(dirname(self::CODE), ['suppressions.php'], ['suppressions.php'], ['php'], 'semgrep'));
    }

    /**
     * The vulnerable places of the fixture project: every one is reported by the engine, or listed as suppressed,
     * never both
     *
     * @param \PieceOfCake2\SecuritySast\Engine $engine Engine
     * @param string $name `semgrep` or `phpstan`
     * @return void
     */
    private function assertListedAsTheEngineSuppresses(Engine $engine, string $name): void
    {
        $project = (string)realpath(self::PROJECT);
        $vulnerable = [];
        foreach (['src/Controller/SuppressedController.php', 'templates/Posts/suppressed.ctp'] as $file) {
            foreach (explode("\n", (string)file_get_contents($project . DS . $file)) as $i => $line) {
                if (str_contains($line, 'unserialize(') || preg_match('/<\?= \$\w+ \?>/', $line)) {
                    $vulnerable[] = $file . ':' . ($i + 1);
                }
            }
        }
        $findings = array_values(array_unique(array_map(static fn($finding): string => $finding->file . ':' . $finding->line, array_filter($engine->scan($project, ['src', 'templates'])->findings, static fn($finding): bool => str_starts_with($finding->rule, 'cakephp2-')))));
        $listed = array_map(static fn(array $suppression): string => $suppression['file'] . ':' . $suppression['line'], Suppressions::find($project, ['src', 'templates'], [], ['php', 'ctp'], $name));
        sort($findings);
        sort($listed);

        $places = (string)json_encode(['reported' => $findings, 'listed' => $listed]);
        $this->assertSame([], array_values(array_intersect($findings, $listed)), 'Listed as suppressed, but reported: ' . $places);
        $this->assertSame([], array_values(array_diff($vulnerable, $findings, $listed)), 'Neither reported nor listed as suppressed: ' . $places);
    }

    public function testListedAsPhpstanSuppresses(): void
    {
        $this->assertListedAsTheEngineSuppresses(new PhpstanEngine(), 'phpstan');
    }

    /**
     * With Semgrep in Docker, when Docker is available (as on GitHub Actions)
     *
     * @return void
     */
    public function testListedAsSemgrepSuppressesWithDocker(): void
    {
        exec('docker info > /dev/null 2>&1', $output, $code);
        if ($code !== 0) {
            $this->markTestSkipped('Docker is not available.');
        }
        $this->assertListedAsTheEngineSuppresses(new SemgrepEngine(configs: []), 'semgrep');
    }
}
