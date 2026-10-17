<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

use Closure;
use JsonException;
use RuntimeException;

/**
 * Scans with Semgrep in its Docker image (`semgrep/semgrep`), with the PHP rules of the Semgrep Registry and the
 * CakePHP 2 rules of this package.
 *
 * The project is mounted read-only at `/src`, the rules of this package at `/rules`. Semgrep runs without sending
 * metrics (`--metrics=off`); the rules of the Registry are downloaded by Semgrep.
 */
final class SemgrepEngine implements Engine
{
    public const IMAGE = 'semgrep/semgrep:latest';

    /**
     * The rules of the Semgrep Registry used by default
     */
    public const CONFIGS = ['p/php'];

    /**
     * The CakePHP 2 rules of this package
     */
    public const RULES = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'semgrep';

    /**
     * @var \Closure(array<string>, string): array{0: int, 1: string, 2: string}
     */
    private Closure $run;

    /**
     * Constructor
     *
     * @param string $image Docker image of Semgrep
     * @param array<string> $configs Rules besides those of this package: names of the Registry (`p/php`), URLs, or
     *  files of the project
     * @param string $docker Docker command
     * @param (\Closure(array<string>, string): array{0: int, 1: string, 2: string})|null $run Runs a command
     */
    public function __construct(
        private string $image = self::IMAGE,
        private array $configs = self::CONFIGS,
        private string $docker = 'docker',
        ?Closure $run = null,
    ) {
        $this->run = $run ?? Closure::fromCallable([Process::class, 'run']);
    }

    /**
     * @inheritDoc
     */
    public function scan(string $project, array $paths, array $exclude = []): ScanResult
    {
        $project = (string)realpath($project);
        $command = [
            $this->docker, 'run', '--rm',
            '-v', $project . ':/src:ro',
            '-v', (string)realpath(self::RULES) . ':/rules:ro',
            '-w', '/src',
            $this->image,
            'semgrep', 'scan', '--json', '--metrics=off', '--quiet', '--disable-version-check',
            '--config', '/rules/cakephp2.yml',
        ];
        foreach ($this->configs as $config) {
            $command[] = '--config';
            $command[] = self::isLocal($config) ? '/src/' . ltrim($config, '/') : $config;
        }
        foreach ($exclude as $path) {
            $command[] = '--exclude';
            $command[] = $path;
        }
        array_push($command, ...$paths);

        [$code, $output, $error] = ($this->run)($command, $project);
        try {
            $data = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new RuntimeException(sprintf('Semgrep failed (exit code %d): %s', $code, trim($error !== '' ? $error : $output)));
        }
        if (!is_array($data)) {
            throw new RuntimeException('Semgrep did not return a JSON object.');
        }

        return self::result($data, $project);
    }

    /**
     * The result of the JSON of Semgrep
     *
     * @param array<string, mixed> $data JSON
     * @param string $project Directory of the project, to read the code of the findings
     * @return \PieceOfCake2\SecuritySast\ScanResult
     */
    public static function result(array $data, string $project): ScanResult
    {
        $findings = [];
        foreach (is_array($data['results'] ?? null) ? $data['results'] : [] as $result) {
            if (!is_array($result)) {
                continue;
            }
            $extra = is_array($result['extra'] ?? null) ? $result['extra'] : [];
            $metadata = is_array($extra['metadata'] ?? null) ? $extra['metadata'] : [];
            $id = (string)($result['check_id'] ?? '');
            // Rules of a local file are named after its path, e.g. rules.cakephp2-query-concatenation
            $rule = str_contains($id, 'cakephp2-') ? substr($id, (int)strrpos($id, 'cakephp2-')) : $id;
            $file = (string)($result['path'] ?? '');
            $line = (int)($result['start']['line'] ?? 0);
            $endLine = (int)($result['end']['line'] ?? $line);
            $code = (string)($extra['lines'] ?? '');
            if ($code === '' || $code === 'requires login') {
                $code = Finding::lines($project . DIRECTORY_SEPARATOR . $file, $line, $endLine);
            }
            $findings[] = new Finding(
                $rule,
                isset(RuleCatalog::RULES[$rule]) ? RuleCatalog::RULES[$rule]['severity'] : Severity::fromSemgrep($extra['severity'] ?? null),
                trim((string)preg_replace('/\s+/', ' ', (string)($extra['message'] ?? ''))),
                $file,
                $line,
                $endLine,
                $code,
                self::strings($metadata['cwe'] ?? []),
                self::strings($metadata['owasp'] ?? []),
                is_string($metadata['confidence'] ?? null) ? strtoupper($metadata['confidence']) : null,
                is_string($metadata['source'] ?? null) ? $metadata['source'] : null,
            );
        }

        $errors = [];
        foreach (is_array($data['errors'] ?? null) ? $data['errors'] : [] as $error) {
            if (is_array($error)) {
                $errors[] = trim((string)($error['type'] ?? 'Error') . ': ' . (string)($error['message'] ?? $error['long_msg'] ?? ''));
            }
        }
        $scanned = $data['paths']['scanned'] ?? [];

        return new ScanResult(
            $findings,
            is_array($scanned) ? count($scanned) : 0,
            'Semgrep' . (is_string($data['version'] ?? null) ? ' ' . $data['version'] : ''),
            $errors,
        );
    }

    /**
     * Whether a config is a file of the project, not a name of the Registry or a URL
     *
     * @param string $config Config
     * @return bool
     */
    private static function isLocal(string $config): bool
    {
        return !preg_match('#\A(?:[pr]/|https?://|auto\z)#', $config);
    }

    /**
     * The strings of a value that is a string or a list of strings
     *
     * @param mixed $value Value
     * @return array<string>
     */
    private static function strings(mixed $value): array
    {
        $values = is_array($value) ? $value : [$value];

        return array_values(array_filter(array_map(static fn($v): string => is_scalar($v) ? (string)$v : '', $values)));
    }
}
