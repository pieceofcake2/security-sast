<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\Test;

use PHPUnit\Framework\TestCase;
use PieceOfCake2\SecuritySast\SemgrepEngine;
use RuntimeException;

class SemgrepEngineTest extends TestCase
{
    public const APP = __DIR__ . DS . '..' . DS . 'fixtures' . DS . 'app';

    /**
     * The rules of this package and the places they find in the fixture application
     */
    public const EXPECTED = [
        'cakephp2-conditions-string src/Controller/PostsController.php:22',
        'cakephp2-query-concatenation src/Controller/PostsController.php:19',
        'cakephp2-query-concatenation src/Controller/PostsController.php:20',
        'cakephp2-redirect-request src/Controller/PostsController.php:29',
        'cakephp2-redirect-request src/Controller/PostsController.php:34',
        'cakephp2-render-request src/Controller/PostsController.php:39',
        'cakephp2-security-csrf-disabled src/Controller/PostsController.php:12',
        'cakephp2-security-csrf-disabled src/Controller/PostsController.php:13',
        'cakephp2-unserialize-request src/Controller/PostsController.php:46',
        'cakephp2-view-unescaped-output templates/Posts/edit.ctp:10',
        'cakephp2-view-unescaped-output templates/Posts/edit.ctp:12',
        'cakephp2-view-unescaped-output templates/Posts/index.php:2',
        'cakephp2-view-unescaped-output templates/Posts/view.ctp:2',
        'cakephp2-view-unescaped-output templates/Posts/view.ctp:3',
        'cakephp2-xml-build-variable src/Controller/PostsController.php:44',
    ];

    /**
     * The places of a result, as `rule file:line`
     *
     * @param array<\PieceOfCake2\SecuritySast\Finding> $findings Findings
     * @return array<string>
     */
    public static function places(array $findings): array
    {
        $places = array_map(static fn($finding): string => $finding->rule . ' ' . $finding->file . ':' . $finding->line, $findings);
        sort($places);

        return $places;
    }

    public function testCommand(): void
    {
        $commands = [];
        $engine = new SemgrepEngine('semgrep/semgrep:1.180.0', ['p/php', 'rules/app.yml'], 'docker', static function (array $command, string $dir) use (&$commands): array {
            $commands[] = $command;

            return [0, (string)file_get_contents(__DIR__ . DS . '..' . DS . 'fixtures' . DS . 'semgrep.json'), ''];
        });

        $engine->scan(self::APP, ['src', 'templates'], ['vendor']);

        $command = implode(' ', $commands[0]);
        $this->assertStringStartsWith('docker run --rm -v ' . realpath(self::APP) . ':/src:ro -v ', $command);
        $this->assertStringContainsString(':/rules:ro -w /src semgrep/semgrep:1.180.0 semgrep scan --json --metrics=off', $command);
        $this->assertStringContainsString(' --scan-unknown-extensions ', $command);
        $this->assertStringContainsString('--config /rules/cakephp2.yml --config p/php --config /src/rules/app.yml --include src --include templates --exclude vendor . templates/Posts/edit.ctp templates/Posts/index.php templates/Posts/view.ctp', $command);
    }

    public function testResult(): void
    {
        $data = json_decode((string)file_get_contents(__DIR__ . DS . '..' . DS . 'fixtures' . DS . 'semgrep.json'), true);
        $result = SemgrepEngine::result($data, (string)realpath(self::APP));

        $this->assertSame(self::EXPECTED, self::places($result->findings));
        $this->assertSame(6, $result->files);
        $this->assertStringStartsWith('Semgrep 1.', $result->engine);
        $this->assertSame([], $result->errors);

        $query = array_values(array_filter($result->findings, static fn($finding): bool => $finding->rule === 'cakephp2-query-concatenation'))[0];
        $this->assertSame('high', $query->severity);
        $this->assertSame('$posts = $this->Post->query("SELECT * FROM posts WHERE title LIKE \'%" . $q . "%\'");', $query->code);
        $this->assertSame(['A03:2021 - Injection'], $query->owasp);
        $this->assertSame('MEDIUM', $query->confidence);
    }

    public function testResultOfAViewGivenTwice(): void
    {
        $result = ['check_id' => 'cakephp2-view-unescaped-output', 'path' => 'templates/Posts/view.ctp', 'start' => ['line' => 2, 'col' => 6], 'end' => ['line' => 2], 'extra' => ['severity' => 'WARNING', 'message' => 'Message']];
        $result = SemgrepEngine::result(['results' => [$result, $result]], (string)realpath(self::APP));

        $this->assertCount(1, $result->findings);
    }

    public function testRulesWithSafeViewVariables(): void
    {
        $rules = SemgrepEngine::rules(['ctp'], ['body_html', '$raw']);

        $this->assertStringContainsString('(?!(?:content_for_layout|scripts_for_layout|body_html|raw)\\b)', $rules);
    }

    public function testResultOfAnotherRule(): void
    {
        $result = SemgrepEngine::result(['results' => [[
            'check_id' => 'php.lang.security.exec-use.exec-use',
            'path' => 'src/Model/Post.php',
            'start' => ['line' => 9],
            'end' => ['line' => 9],
            'extra' => ['severity' => 'ERROR', 'message' => "Executing  a command\nwith a variable", 'metadata' => ['cwe' => 'CWE-94: Code Injection', 'source' => 'https://semgrep.dev/r/php.lang.security.exec-use.exec-use']],
        ]], 'errors' => [['type' => 'Syntax error', 'message' => 'at line 3']]], (string)realpath(self::APP));

        $finding = $result->findings[0];
        $this->assertSame('php.lang.security.exec-use.exec-use', $finding->rule);
        $this->assertSame('high', $finding->severity);
        $this->assertSame('Executing a command with a variable', $finding->message);
        $this->assertSame(['CWE-94: Code Injection'], $finding->cwe);
        $this->assertSame("return \$this->find('all', ['order' => ['Post.created' => 'DESC'], 'limit' => 10]);", $finding->code);
        $this->assertSame('https://semgrep.dev/r/php.lang.security.exec-use.exec-use', $finding->url);
        $this->assertSame(['Syntax error: at line 3'], $result->errors);
    }

    public function testFailure(): void
    {
        $engine = new SemgrepEngine(run: static fn(array $command, string $dir): array => [125, '', 'Cannot connect to the Docker daemon']);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Semgrep failed (exit code 125): Cannot connect to the Docker daemon');

        $engine->scan(self::APP, ['src']);
    }

    /**
     * Runs Semgrep in Docker, when Docker is available (as on GitHub Actions)
     *
     * @return void
     */
    public function testScanWithDocker(): void
    {
        exec('docker info > /dev/null 2>&1', $output, $code);
        if ($code !== 0) {
            $this->markTestSkipped('Docker is not available.');
        }

        $result = (new SemgrepEngine())->scan(self::APP, ['src', 'templates']);

        $this->assertSame(self::EXPECTED, self::places(array_filter($result->findings, static fn($finding): bool => str_starts_with($finding->rule, 'cakephp2-'))));

        $result = (new SemgrepEngine(safeViewVariables: ['body_html']))->scan(self::APP, ['templates']);

        $this->assertNotContains('cakephp2-view-unescaped-output templates/Posts/edit.ctp:10', self::places($result->findings));
        $this->assertContains('cakephp2-view-unescaped-output templates/Posts/edit.ctp:12', self::places($result->findings));
    }
}
