<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\Test;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use PieceOfCake2\Report\Environment;
use PieceOfCake2\Report\PdfPrinter;
use PieceOfCake2\Report\ReportWriter;
use PieceOfCake2\SecuritySast\Command;
use PieceOfCake2\SecuritySast\Config;
use PieceOfCake2\SecuritySast\PhpstanEngine;

class CommandTest extends TestCase
{
    public function testConfig(): void
    {
        $config = Command::config(['--pdf=out/sast.pdf', '--fail-on=MEDIUM', '--engine=PHPStan', '--paths=src, templates', '--exclude=', '--language=ja'], ['SECURITY_SAST_TITLE' => 'Scan', 'SECURITY_SAST_PDF' => 'env.pdf', 'SECURITY_SAST_SEMGREP_CONFIG' => 'p/php,p/owasp-top-ten']);

        $this->assertNotNull($config);
        $this->assertSame('out/sast.pdf', $config->pdf);
        $this->assertSame('medium', $config->failOn);
        $this->assertSame('phpstan', $config->engine);
        $this->assertSame(['src', 'templates'], $config->paths);
        $this->assertSame([], $config->exclude);
        $this->assertSame(['p/php', 'p/owasp-top-ten'], $config->semgrepConfigs);
        $this->assertSame('ja', $config->language);
        $this->assertSame('Scan', $config->title);
    }

    public function testDefaults(): void
    {
        $config = Command::config([]);

        $this->assertNotNull($config);
        $this->assertSame('tmp/security-sast.pdf', $config->pdf);
        $this->assertSame('high', $config->failOn);
        $this->assertSame('semgrep', $config->engine);
        $this->assertSame(Config::EXCLUDE, $config->exclude);
        $this->assertSame(['p/php'], $config->semgrepConfigs);
    }

    public function testInvalidOptions(): void
    {
        $this->assertNull(Command::config(['--help']));

        $this->expectException(InvalidArgumentException::class);
        Command::config(['--engine=sonar']);
    }

    public function testUnknownOption(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Unknown option: --verbose');
        Command::config(['--verbose']);
    }

    /**
     * Runs the command with the fixture
     *
     * @param array<string> $argv Arguments
     * @param string $output Receives the output
     * @return int
     */
    private static function runCommand(array $argv, string &$output = ''): int
    {
        $stdout = fopen('php://memory', 'w+');
        $stderr = fopen('php://memory', 'w+');
        $command = new Command($stdout, $stderr, new PhpstanEngine(), new ReportWriter(PdfPrinter::fromEnv($_SERVER)), new Environment());
        $code = $command->run(array_merge(['--project=' . SemgrepEngineTest::APP], $argv));
        rewind($stdout);
        rewind($stderr);
        $output = stream_get_contents($stdout) . stream_get_contents($stderr);

        return $code;
    }

    public function testRunWritesThePdf(): void
    {
        if (PdfPrinter::findChrome() === null && empty($_SERVER['REPORT_CHROME_BINARY'])) {
            $this->markTestSkipped('Chrome is not installed.');
        }
        $pdf = TMP . 'sast' . DS . 'report.pdf';
        $output = '';
        try {
            $this->assertSame(Command::FAILURE, self::runCommand(['--pdf=' . $pdf], $output));
            $this->assertStringContainsString('12 findings (5 high, 7 medium) of 8 rules in 3 files (PHPStan 2.', $output);
            $this->assertStringStartsWith('%PDF', (string)file_get_contents($pdf));

            $this->assertSame(Command::SUCCESS, self::runCommand(['--pdf=' . $pdf, '--fail-on=critical']));
        } finally {
            if (is_file($pdf)) {
                unlink($pdf);
                rmdir(dirname($pdf));
            }
        }
    }

    public function testRunWithAnInvalidOption(): void
    {
        $output = '';
        $this->assertSame(Command::ERROR, self::runCommand(['--fail-on=severe'], $output));
        $this->assertStringContainsString('--fail-on must be one of', $output);
        $this->assertStringContainsString('Usage: vendor/bin/security-sast', $output);
    }

    public function testRunWithNothingToScan(): void
    {
        $output = '';
        $this->assertSame(Command::ERROR, self::runCommand(['--project=' . TMP], $output));
        $this->assertStringContainsString('Nothing to scan in', $output);
    }
}
