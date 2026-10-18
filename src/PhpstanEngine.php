<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

use Closure;
use Composer\InstalledVersions;
use JsonException;
use RuntimeException;

/**
 * Scans with PHPStan and the security rules of this package (`resources/phpstan/rules.neon`).
 *
 * PHPStan runs at level 0 with a configuration of its own, so the settings of the project do not change the
 * scan, and only the errors of the rules of this package are kept. The views (the extensions given, in `templates/`
 * and `View/`) are scanned as PHP.
 */
final class PhpstanEngine implements Engine
{
    /**
     * The rules of this package
     */
    public const RULES = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'phpstan' . DIRECTORY_SEPARATOR . 'rules.neon';

    /**
     * @var \Closure(array<string>, string): array{0: int, 1: string, 2: string}
     */
    private Closure $run;

    /**
     * Constructor
     *
     * @param string|null $phpstan The `phpstan` script, default: the one installed with this package
     * @param (\Closure(array<string>, string): array{0: int, 1: string, 2: string})|null $run Runs a command
     * @param array<string> $viewExtensions Extensions of the views, without the dot
     * @param array<string> $safeViewVariables Variables that the views may print without h(), e.g. `body_html`
     */
    public function __construct(private ?string $phpstan = null, ?Closure $run = null, private array $viewExtensions = Views::EXTENSIONS, private array $safeViewVariables = [])
    {
        $this->run = $run ?? Closure::fromCallable([Process::class, 'run']);
    }

    /**
     * @inheritDoc
     */
    public function scan(string $project, array $paths, array $exclude = []): ScanResult
    {
        $project = (string)realpath($project);
        $phpstan = $this->phpstan ?? (string)InstalledVersions::getInstallPath('phpstan/phpstan') . DIRECTORY_SEPARATOR . 'phpstan';
        // A name of its own: PHPStan reads the configuration by its extension, .neon
        $config = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'security-sast-' . bin2hex(random_bytes(6)) . '.neon';
        file_put_contents($config, self::config($project, $paths, $exclude, $this->viewExtensions, $this->safeViewVariables));
        try {
            [$code, $output, $error] = ($this->run)([PHP_BINARY, $phpstan, 'analyse', '--configuration=' . $config, '--error-format=json', '--no-progress', '--no-interaction', '--memory-limit=1G'], $project);
        } finally {
            unlink($config);
        }
        try {
            $data = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new RuntimeException(sprintf('PHPStan failed (exit code %d): %s', $code, trim($error !== '' ? $error : $output)));
        }
        if (!is_array($data)) {
            throw new RuntimeException('PHPStan did not return a JSON object.');
        }
        [, $version] = ($this->run)([PHP_BINARY, $phpstan, '--version', '--no-ansi'], $project);

        $result = self::result($data, $project, preg_match('/(\d+\.\d+\.\d+\S*)/', $version, $matches) ? $matches[1] : null);
        $result->files = self::countFiles($project, $paths, $exclude, $this->viewExtensions);

        return $result;
    }

    /**
     * The configuration of PHPStan for a scan
     *
     * @param string $project Directory of the project
     * @param array<string> $paths Paths to scan, relative to the project
     * @param array<string> $exclude Paths to leave out, relative to the project
     * @param array<string> $viewExtensions Extensions of the views, without the dot
     * @param array<string> $safeViewVariables Variables that the views may print without h()
     * @return string NEON
     */
    public static function config(string $project, array $paths, array $exclude = [], array $viewExtensions = Views::EXTENSIONS, array $safeViewVariables = []): string
    {
        $neon = "includes:\n    - " . self::neon((string)realpath(self::RULES)) . "\n";
        $neon .= "services:\n    -\n        class: PieceOfCake2\\SecuritySast\\PHPStan\\ViewUnescapedOutputRule\n";
        $neon .= '        arguments: [[' . implode(', ', array_map([self::class, 'neon'], $viewExtensions)) . '], [' . implode(', ', array_map([self::class, 'neon'], $safeViewVariables)) . '], ' . self::neon($project) . "]\n        tags: [phpstan.rules.rule]\n";
        $neon .= "parameters:\n    level: 0\n    reportUnmatchedIgnoredErrors: false\n    fileExtensions:\n";
        foreach (array_unique(array_merge(['php'], $viewExtensions)) as $extension) {
            $neon .= '        - ' . self::neon($extension) . "\n";
        }
        $neon .= "    paths:\n";
        foreach ($paths as $path) {
            $neon .= '        - ' . self::neon($project . DIRECTORY_SEPARATOR . $path) . "\n";
        }
        // Only the paths that exist: PHPStan fails on another, and its (?) suffix does not work in a quoted path
        $exclude = array_values(array_filter($exclude, static fn(string $path): bool => file_exists($project . DIRECTORY_SEPARATOR . $path)));
        if ($exclude !== []) {
            $neon .= "    excludePaths:\n        analyseAndScan:\n";
            foreach ($exclude as $path) {
                $neon .= '            - ' . self::neon($project . DIRECTORY_SEPARATOR . $path) . "\n";
            }
        }

        return $neon;
    }

    /**
     * The result of the JSON of PHPStan: the errors of the rules of this package only
     *
     * @param array<string, mixed> $data JSON
     * @param string $project Directory of the project
     * @param string|null $version Version of PHPStan
     * @return \PieceOfCake2\SecuritySast\ScanResult
     */
    public static function result(array $data, string $project, ?string $version = null): ScanResult
    {
        $findings = [];
        $files = is_array($data['files'] ?? null) ? $data['files'] : [];
        foreach ($files as $path => $file) {
            foreach (is_array($file['messages'] ?? null) ? $file['messages'] : [] as $message) {
                $rule = is_array($message) ? RuleCatalog::idOf((string)($message['identifier'] ?? '')) : null;
                if ($rule === null) {
                    continue;
                }
                $line = (int)($message['line'] ?? 0);
                $definition = RuleCatalog::RULES[$rule];
                $findings[] = new Finding(
                    $rule,
                    $definition['severity'],
                    $definition['message'],
                    self::relative((string)$path, $project),
                    $line,
                    $line,
                    Finding::lines((string)$path, $line, $line),
                    $definition['cwe'],
                    $definition['owasp'],
                    $definition['confidence'],
                );
            }
        }

        return new ScanResult(
            $findings,
            is_array($data['files'] ?? null) ? count($data['files']) : 0,
            'PHPStan' . ($version !== null ? ' ' . $version : ''),
            array_values(array_map('strval', is_array($data['errors'] ?? null) ? $data['errors'] : [])),
        );
    }

    /**
     * The number of the PHP files and views of the paths
     *
     * @param string $project Directory of the project
     * @param array<string> $paths Paths, relative to the project
     * @param array<string> $exclude Paths to leave out, relative to the project
     * @param array<string> $viewExtensions Extensions of the views, without the dot
     * @return int
     */
    public static function countFiles(string $project, array $paths, array $exclude = [], array $viewExtensions = Views::EXTENSIONS): int
    {
        return count(Files::find($project, $paths, $exclude, array_values(array_unique(array_merge(['php'], $viewExtensions)))));
    }

    /**
     * A path relative to the project
     *
     * @param string $path Absolute path
     * @param string $project Directory of the project
     * @return string
     */
    private static function relative(string $path, string $project): string
    {
        $prefix = rtrim($project, '/\\') . DIRECTORY_SEPARATOR;

        return str_starts_with($path, $prefix) ? substr($path, strlen($prefix)) : $path;
    }

    /**
     * A NEON string
     *
     * @param string $value Value
     * @return string
     */
    private static function neon(string $value): string
    {
        return "'" . str_replace("'", "''", $value) . "'";
    }
}
