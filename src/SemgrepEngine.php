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
     * @param array<string> $viewExtensions Extensions of the views, without the dot
     * @param array<string> $safeViewVariables Variables that the views may print without h(), e.g. `body_html`
     */
    public function __construct(
        private string $image = self::IMAGE,
        private array $configs = self::CONFIGS,
        private string $docker = 'docker',
        ?Closure $run = null,
        private array $viewExtensions = Views::EXTENSIONS,
        private array $safeViewVariables = [],
    ) {
        $this->run = $run ?? Closure::fromCallable([Process::class, 'run']);
    }

    /**
     * @inheritDoc
     */
    public function scan(string $project, array $paths, array $exclude = []): ScanResult
    {
        $project = (string)realpath($project);
        $rules = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'security-sast-rules-' . bin2hex(random_bytes(6));
        mkdir($rules, 0755, true);
        file_put_contents($rules . DIRECTORY_SEPARATOR . 'cakephp2.yml', self::rules($this->viewExtensions, $this->safeViewVariables));
        $command = [
            $this->docker, 'run', '--rm',
            '-v', $project . ':/src:ro',
            '-v', $rules . ':/rules:ro',
            '-w', '/src',
            $this->image,
            'semgrep', 'scan', '--json', '--metrics=off', '--quiet', '--disable-version-check', '--scan-unknown-extensions',
            '--config', '/rules/cakephp2.yml',
        ];
        foreach ($this->configs as $config) {
            $command[] = '--config';
            $command[] = self::isLocal($config) ? '/src/' . ltrim($config, '/') : $config;
        }
        // The project is the target, so that the paths of the rules (e.g. templates/ of the views) are relative to
        // it; the paths to scan are included. A leading / anchors a pattern to the project: src is not also
        // plugins/Blog/src
        foreach ($paths as $path) {
            $command[] = '--include';
            $command[] = self::anchored($path);
        }
        foreach ($exclude as $path) {
            $command[] = '--exclude';
            $command[] = self::anchored($path);
        }
        $command[] = '.';
        // The views, given one by one: Semgrep reads a file of an extension it does not know (.ctp) as PHP only
        // when it is given
        foreach (Files::find($project, $paths, $exclude, $this->viewExtensions) as $file) {
            if (Views::isView($file, $this->viewExtensions)) {
                $command[] = $file;
            }
        }

        try {
            [$code, $output, $error] = ($this->run)($command, $project);
        } finally {
            unlink($rules . DIRECTORY_SEPARATOR . 'cakephp2.yml');
            rmdir($rules);
        }
        try {
            $data = json_decode($output, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new RuntimeException(sprintf('Semgrep failed (exit code %d): %s', $code, trim($error !== '' ? $error : $output)));
        }
        if (!is_array($data)) {
            throw new RuntimeException('Semgrep did not return a JSON object.');
        }
        // 0 without and 1 with findings; another code, or an error that is not a warning (e.g. a rule or a config
        // of the Registry that could not be loaded), means that the scan did not run as configured
        $fatal = self::errors($data, 'error');
        if ($code > 1 || $fatal !== []) {
            throw new RuntimeException(sprintf('Semgrep failed (exit code %d): %s', $code, $fatal !== [] ? implode(' ', $fatal) : trim($error !== '' ? $error : $output)));
        }

        return self::result($data, $project);
    }

    /**
     * The rules of this package, with the views of the extensions given
     *
     * @param array<string> $viewExtensions Extensions of the views, without the dot
     * @param array<string> $safeViewVariables Variables that the views may print without h()
     * @return string YAML
     */
    public static function rules(array $viewExtensions = Views::EXTENSIONS, array $safeViewVariables = []): string
    {
        $yaml = (string)file_get_contents(self::RULES . DIRECTORY_SEPARATOR . 'cakephp2.yml');
        $names = array_merge(Views::SAFE_VARIABLES, array_map(static fn(string $name): string => preg_quote(ltrim($name, '$'), '/'), $safeViewVariables));
        $yaml = str_replace('(?:' . implode('|', Views::SAFE_VARIABLES) . ')', '(?:' . implode('|', $names) . ')', $yaml);
        $include = '';
        foreach (Views::semgrepIncludes($viewExtensions) as $pattern) {
            $include .= '        - ' . json_encode($pattern, JSON_UNESCAPED_SLASHES) . "\n";
        }

        // The views of every rule of the views
        return (string)preg_replace('/(    paths:\n      include:\n)(?:        - .*\n)+/', '$1' . str_replace('$', '\\$', $include), $yaml);
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
        $seen = [];
        foreach (is_array($data['results'] ?? null) ? $data['results'] : [] as $result) {
            if (!is_array($result)) {
                continue;
            }
            // A view given one by one is also found through the project
            $key = ($result['check_id'] ?? '') . ' ' . ($result['path'] ?? '') . ' ' . ($result['start']['line'] ?? '') . ' ' . ($result['start']['col'] ?? '');
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
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

        $scanned = $data['paths']['scanned'] ?? [];

        return new ScanResult(
            $findings,
            is_array($scanned) ? count($scanned) : 0,
            'Semgrep' . (is_string($data['version'] ?? null) ? ' ' . $data['version'] : ''),
            self::errors($data),
        );
    }

    /**
     * The errors of the JSON of Semgrep
     *
     * @param array<string, mixed> $data JSON
     * @param string|null $level Only the errors of this level (`error`, `warn`), default: all
     * @return array<string>
     */
    public static function errors(array $data, ?string $level = null): array
    {
        $errors = [];
        foreach (is_array($data['errors'] ?? null) ? $data['errors'] : [] as $error) {
            if (is_array($error) && ($level === null || ($error['level'] ?? null) === $level)) {
                // Some types are lists, e.g. ["PartialParsing", [...]]
                $type = is_array($error['type'] ?? null) ? ($error['type'][0] ?? 'Error') : ($error['type'] ?? 'Error');
                $errors[] = trim((is_scalar($type) ? (string)$type : 'Error') . ': ' . trim((string)($error['message'] ?? $error['long_msg'] ?? '')));
            }
        }

        return $errors;
    }

    /**
     * A path of the project as a pattern of Semgrep anchored to the project
     *
     * @param string $path Path, relative to the project
     * @return string
     */
    private static function anchored(string $path): string
    {
        return '/' . trim(str_replace('\\', '/', $path), '/');
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
