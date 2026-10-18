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
use PieceOfCake2\SecuritySast\ConfigCheck;
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

    public function testSettingsFile(): void
    {
        $project = __DIR__ . DS . '..' . DS . 'fixtures' . DS . 'settings';
        $config = Command::config(['--project=' . $project, '--fail-on=low'], ['SECURITY_SAST_ENGINE' => 'semgrep']);

        $this->assertNotNull($config);
        // The option and the environment variable win over the file
        $this->assertSame('low', $config->failOn);
        $this->assertSame('semgrep', $config->engine);
        $this->assertSame(['src', 'templates'], $config->paths);
        $this->assertSame(['ctp', 'php', 'html'], $config->viewExtensions);
        $this->assertSame(['body_html'], $config->safeViewVariables);
        $this->assertSame('ja', $config->language);
        $this->assertSame('Acme', $config->projectName);
        $this->assertSame('tmp/security/security-sast.pdf', $config->pdf);
    }

    public function testSettingsFileOption(): void
    {
        $file = TMP . 'security.php';
        file_put_contents($file, "<?php\nreturn ['sast' => ['engine' => 'phpstan', 'unknown' => 1]];\n");
        try {
            $this->expectException(InvalidArgumentException::class);
            $this->expectExceptionMessage('Unknown setting of the sast section: unknown');
            Command::config(['--settings=' . $file]);
        } finally {
            unlink($file);
        }
    }

    public function testMissingSettingsFile(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('is not found');
        Command::config(['--settings=/nowhere/security.php']);
    }

    public function testLayoutOfTheApplication(): void
    {
        $config = Command::config(['--project=' . SemgrepEngineTest::APP]);
        $this->assertNotNull($config);
        $layout = ['app' => 'src', 'views' => ['src/View', 'templates'], 'plugins' => ['plugins'], 'viewExtension' => 'html', 'installed' => ['plugins/DebugKit']];

        // Only the paths that exist
        $this->assertSame(['src', 'src/View', 'templates'], $config->paths($layout));
        $this->assertSame(['ctp', 'php', 'html'], $config->viewExtensions($layout));
        $this->assertContains('plugins/DebugKit', $config->exclude($layout));
        $this->assertSame(['ctp', 'php'], $config->viewExtensions());

        $config = Command::config(['--paths=src', '--view-extensions=.CTP']);
        $this->assertNotNull($config);
        $this->assertSame(['src'], $config->paths($layout));
        $this->assertSame(['ctp'], $config->viewExtensions($layout));
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
            $this->assertStringContainsString('48 findings (26 high, 22 medium) of 9 rules in 14 files (PHPStan 2.', $output);
            $this->assertStringStartsWith('%PDF', (string)file_get_contents($pdf));

            $this->assertSame(Command::SUCCESS, self::runCommand(['--pdf=' . $pdf, '--fail-on=critical']));
        } finally {
            if (is_file($pdf)) {
                unlink($pdf);
                rmdir(dirname($pdf));
            }
        }
    }

    public function testRunWhenTheConfigurationCannotBeLoaded(): void
    {
        if (PdfPrinter::findChrome() === null && empty($_SERVER['REPORT_CHROME_BINARY'])) {
            $this->markTestSkipped('Chrome is not installed.');
        }
        $project = TMP . 'broken';
        foreach (['config', 'vendor', 'src'] as $dir) {
            is_dir($project . DS . $dir) || mkdir($project . DS . $dir, 0777, true);
        }
        file_put_contents($project . DS . 'config' . DS . 'core.php', "<?php\n");
        file_put_contents($project . DS . 'vendor' . DS . 'autoload.php', "<?php\n");
        file_put_contents($project . DS . 'src' . DS . 'A.php', "<?php\n");
        $stdout = fopen('php://memory', 'w+');
        $stderr = fopen('php://memory', 'w+');
        $check = new ConfigCheck('prod', static fn(array $command, string $dir, array $env): array => [0, '{"error":"Error: Class not found"}', '']);
        $command = new Command($stdout, $stderr, new PhpstanEngine(), new ReportWriter(PdfPrinter::fromEnv($_SERVER)), new Environment(), $check);

        // The report is written, but the run does not pass
        $code = $command->run(['--project=' . $project, '--pdf=' . $project . DS . 'report.pdf', '--fail-on=none']);

        rewind($stderr);
        $this->assertSame(Command::ERROR, $code);
        $this->assertStringContainsString('the configuration was not checked: The configuration could not be loaded: Error: Class not found', (string)stream_get_contents($stderr));
        $this->assertFileExists($project . DS . 'report.pdf');
    }

    public function testRunWithAnInvalidOption(): void
    {
        $output = '';
        $this->assertSame(Command::ERROR, self::runCommand(['--fail-on=severe'], $output));
        $this->assertStringContainsString('--fail-on must be one of', $output);
        $this->assertStringContainsString('Usage: vendor/bin/security-sast', $output);
    }

    public function testRunWithAMissingPath(): void
    {
        $output = '';
        $this->assertSame(Command::ERROR, self::runCommand(['--paths=src,srcc'], $output));
        $this->assertStringContainsString('--paths: not found in', $output);
        $this->assertStringContainsString(': srcc', $output);
    }

    public function testRunWithNothingToScan(): void
    {
        $output = '';
        $this->assertSame(Command::ERROR, self::runCommand(['--project=' . TMP], $output));
        $this->assertStringContainsString('Nothing to scan in', $output);
    }
}
