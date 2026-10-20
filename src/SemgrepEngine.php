<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

use Closure;
use FilesystemIterator;
use JsonException;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;

/**
 * Scans with Semgrep in its Docker image (`semgrep/semgrep`), with the PHP rules of the Semgrep Registry and the
 * CakePHP 2 rules of this package.
 *
 * The project is mounted read-only at `/src`, the rules of this package at `/rules`. Semgrep runs without sending
 * metrics (`--metrics=off`); the rules of the Registry are downloaded by Semgrep.
 *
 * Semgrep tells the language of a file by its extension, and reads a view of another extension than `.php` (e.g.
 * `.ctp`, `.html`) with the rules of another language, or not at all. The views are copied to a temporary directory,
 * mounted at `/views`, as a `.php` file for the rules of PHP, and as an `.html` file for those of HTML (the views
 * that are not `.html` already), e.g. `templates/Posts/view.ctp.php` and `templates/Posts/view.ctp.html`. The
 * copies have the same lines, and the results are placed in the views.
 */
final class SemgrepEngine implements Engine
{
    public const IMAGE = 'semgrep/semgrep:latest';

    /**
     * The rules of the Semgrep Registry used by default
     */
    public const CONFIGS = ['p/php'];

    /**
     * The patterns of `cakephp2-redirect-request` that leave out `here()` of the request, a path of the application
     * with a fixed CakePHP (`Framework::hereIsPath()`): a redirect with a value of the request besides it is still
     * reported. They are added after the comment that ends with `(SemgrepEngine::HERE_IS_PATH)`
     */
    public const HERE_IS_PATH = <<<'YAML'
      - pattern: $this->redirect($URL, ...)
      - metavariable-pattern:
          metavariable: $URL
          patterns:
            - pattern-either:
                - pattern: $this->request
                - pattern: $_GET
                - pattern: $_POST
                - pattern: $_REQUEST
                - pattern: $_COOKIE
                - pattern: $_FILES
            - pattern-not-inside: $this->request->here

YAML;

    /**
     * The CakePHP 2 rules of this package
     */
    public const RULES = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'semgrep';

    /**
     * Where the copies of the views are mounted
     */
    public const VIEWS = '/views';

    /**
     * The extensions that Semgrep reads as HTML
     */
    public const HTML_EXTENSIONS = ['html', 'htm'];

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
        $hereIsPath = Framework::detect($project)?->hereIsPath() ?? false;
        file_put_contents($rules . DIRECTORY_SEPARATOR . 'cakephp2.yml', self::rules($this->viewExtensions, $this->safeViewVariables, $hereIsPath));
        // The copies of the views, read as PHP and as HTML
        $viewsDir = $rules . '-views';
        $views = self::viewCopies(Files::find($project, $paths, $exclude, $this->viewExtensions), $this->viewExtensions);
        $command = [
            $this->docker, 'run', '--rm',
            '-v', $project . ':/src:ro',
            '-v', $rules . ':/rules:ro',
            ...($views !== [] ? ['-v', $viewsDir . ':' . self::VIEWS . ':ro'] : []),
            '-w', '/src',
            $this->image,
            // --time: the timing in the JSON lists the rules that ran
            'semgrep', 'scan', '--json', '--time', '--metrics=off', '--quiet', '--disable-version-check',
            '--config', '/rules/cakephp2.yml',
        ];
        foreach ($this->configs as $config) {
            $command[] = '--config';
            $command[] = self::isLocal($config) ? '/src/' . ltrim($config, '/') : $config;
        }
        // The project is the target, so that the paths of the rules (e.g. templates/ of the views) are relative to
        // it; the paths to scan are included. A leading / anchors a pattern to the project: src is not also
        // plugins/Blog/src. The copies of the views have the paths of the project
        foreach ($paths as $path) {
            $command[] = '--include';
            $command[] = self::anchored($path);
            // A view given by its path: its copies
            foreach (array_keys($views, str_replace('\\', '/', trim($path, '/\\')), true) as $copy) {
                $command[] = '--include';
                $command[] = self::anchored($copy);
            }
        }
        foreach ($exclude as $path) {
            $command[] = '--exclude';
            $command[] = self::anchored($path);
        }
        $command[] = '.';
        if ($views !== []) {
            $command[] = self::VIEWS;
        }

        try {
            self::copyViews($project, $views, $viewsDir);
            [$code, $output, $error] = ($this->run)($command, $project);
        } finally {
            unlink($rules . DIRECTORY_SEPARATOR . 'cakephp2.yml');
            rmdir($rules);
            self::remove($viewsDir);
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
        $fatal = self::errors($data, 'error', $views);
        if ($code > 1 || $fatal !== []) {
            throw new RuntimeException(sprintf('Semgrep failed (exit code %d): %s', $code, $fatal !== [] ? implode(' ', $fatal) : trim($error !== '' ? $error : $output)));
        }

        return self::result($data, $project, $views);
    }

    /**
     * The copies of the views that Semgrep would not read as PHP, or not as HTML: the path of the view with the
     * extension of the language added, e.g. `templates/Posts/view.ctp.php` and `templates/Posts/view.ctp.html`
     *
     * @param array<string> $files Files of the extensions of the views, relative to the project
     * @param array<string> $viewExtensions Extensions of the views, without the dot
     * @return array<string, string> The views by the paths of their copies
     */
    public static function viewCopies(array $files, array $viewExtensions = Views::EXTENSIONS): array
    {
        $views = [];
        foreach ($files as $file) {
            if (!Views::isView($file, $viewExtensions)) {
                continue;
            }
            $file = str_replace('\\', '/', $file);
            $extension = strtolower(pathinfo($file, PATHINFO_EXTENSION));
            if ($extension !== 'php') {
                $views[$file . '.php'] = $file;
            }
            if (!in_array($extension, self::HTML_EXTENSIONS, true)) {
                $views[$file . '.html'] = $file;
            }
        }

        return $views;
    }

    /**
     * Copies the views (`viewCopies()`) to a directory
     *
     * @param string $project Directory of the project
     * @param array<string, string> $views The views by the paths of their copies
     * @param string $dir Directory of the copies, made when there is a view
     * @return void
     */
    private static function copyViews(string $project, array $views, string $dir): void
    {
        foreach ($views as $copy => $view) {
            $target = $dir . DIRECTORY_SEPARATOR . $copy;
            is_dir(dirname($target)) || mkdir(dirname($target), 0755, true);
            copy($project . DIRECTORY_SEPARATOR . $view, $target);
        }
        // The paths that Semgrep leaves out of the project, also out of the copies
        if ($views !== [] && is_file($project . DIRECTORY_SEPARATOR . '.semgrepignore')) {
            copy($project . DIRECTORY_SEPARATOR . '.semgrepignore', $dir . DIRECTORY_SEPARATOR . '.semgrepignore');
        }
    }

    /**
     * Removes a directory and its files
     *
     * @param string $dir Directory
     * @return void
     */
    private static function remove(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($files as $file) {
            /** @var \SplFileInfo $file */
            $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }
        rmdir($dir);
    }

    /**
     * Whether a file of an error of Semgrep is a view read as HTML: a copy of a view as HTML, or a view of an
     * extension of HTML
     *
     * @param string $path Path of Semgrep
     * @param array<string, string> $views The views by the paths of their copies (`viewCopies()`)
     * @return bool
     */
    private static function isHtmlOfView(string $path, array $views): bool
    {
        if (str_starts_with($path, self::VIEWS . '/')) {
            return isset($views[substr($path, strlen(self::VIEWS) + 1)]) && str_ends_with($path, '.html');
        }

        return in_array(strtolower(pathinfo($path, PATHINFO_EXTENSION)), self::HTML_EXTENSIONS, true) && in_array($path, $views, true);
    }

    /**
     * The path of the project of a path of Semgrep: a copy of a view is the view
     *
     * @param string $path Path of Semgrep
     * @param array<string, string> $views The views by the paths of their copies (`viewCopies()`)
     * @return string
     */
    public static function path(string $path, array $views = []): string
    {
        $prefix = self::VIEWS . '/';
        if (str_starts_with($path, $prefix) && isset($views[substr($path, strlen($prefix))])) {
            return $views[substr($path, strlen($prefix))];
        }

        return $path;
    }

    /**
     * The rules of this package, with the views of the extensions given
     *
     * @param array<string> $viewExtensions Extensions of the views, without the dot
     * @param array<string> $safeViewVariables Variables that the views may print without h()
     * @param bool $hereIsPath Whether `here()` of the request is a path of the application (`Framework::hereIsPath()`)
     * @return string YAML
     */
    public static function rules(array $viewExtensions = Views::EXTENSIONS, array $safeViewVariables = [], bool $hereIsPath = false): string
    {
        $yaml = (string)file_get_contents(self::RULES . DIRECTORY_SEPARATOR . 'cakephp2.yml');
        if ($hereIsPath) {
            $yaml = str_replace("(SemgrepEngine::HERE_IS_PATH)\n", "(SemgrepEngine::HERE_IS_PATH)\n" . self::HERE_IS_PATH, $yaml);
        }
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
     * @param array<string, string> $views The views by the paths of their copies (`viewCopies()`)
     * @return \PieceOfCake2\SecuritySast\ScanResult
     */
    public static function result(array $data, string $project, array $views = []): ScanResult
    {
        $findings = [];
        $seen = [];
        foreach (is_array($data['results'] ?? null) ? $data['results'] : [] as $result) {
            if (!is_array($result)) {
                continue;
            }
            $file = self::path((string)($result['path'] ?? ''), $views);
            // A view found by the rules of both copies
            $key = ($result['check_id'] ?? '') . ' ' . $file . ' ' . ($result['start']['line'] ?? '') . ' ' . ($result['start']['col'] ?? '');
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $extra = is_array($result['extra'] ?? null) ? $result['extra'] : [];
            $metadata = is_array($extra['metadata'] ?? null) ? $extra['metadata'] : [];
            $id = (string)($result['check_id'] ?? '');
            // Rules of a local file are named after its path, e.g. rules.cakephp2-query-concatenation
            $rule = self::ruleId($id);
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

        // A view and its copies are one file
        $scanned = [];
        foreach (is_array($data['paths']['scanned'] ?? null) ? $data['paths']['scanned'] : [] as $path) {
            $scanned[self::path((string)$path, $views)] = true;
        }
        // The rules of HTML read the PHP of the views in part: apart from the files that could not be read
        $errors = [];
        $viewErrors = [];
        foreach (is_array($data['errors'] ?? null) ? $data['errors'] : [] as $error) {
            if (!is_array($error)) {
                continue;
            }
            $messages = self::errors(['errors' => [$error]], null, $views);
            if (self::isHtmlOfView((string)($error['path'] ?? ''), $views)) {
                array_push($viewErrors, ...$messages);
            } else {
                array_push($errors, ...$messages);
            }
        }

        return new ScanResult(
            $findings,
            count($scanned),
            'Semgrep' . (is_string($data['version'] ?? null) ? ' ' . $data['version'] : ''),
            $errors,
            engineRules: self::rulesRun($data),
            skippedRules: self::skippedRules($data),
            viewErrors: $viewErrors,
        );
    }

    /**
     * The ID of a rule of Semgrep: the rules of a local file are named after its path, e.g.
     * `rules.cakephp2-query-concatenation` is `cakephp2-query-concatenation`
     *
     * @param string $id ID of Semgrep
     * @return string
     */
    private static function ruleId(string $id): string
    {
        return str_contains($id, 'cakephp2-') ? substr($id, (int)strrpos($id, 'cakephp2-')) : $id;
    }

    /**
     * The IDs of the rules that ran, from the timing of the JSON (`--time`), or null without it
     *
     * @param array<string, mixed> $data JSON
     * @return array<string>|null
     */
    public static function rulesRun(array $data): ?array
    {
        $rules = $data['time']['rules'] ?? null;
        if (!is_array($rules) || $rules === []) {
            return null;
        }
        $ids = [];
        foreach ($rules as $rule) {
            $id = is_array($rule) ? ($rule['id'] ?? null) : $rule;
            if (is_string($id) && $id !== '') {
                $ids[] = self::ruleId($id);
            }
        }

        return array_values(array_unique($ids));
    }

    /**
     * The rules that Semgrep skipped, e.g. for a newer version of Semgrep, and why
     *
     * @param array<string, mixed> $data JSON
     * @return array<array{id: string, reason: string}>
     */
    public static function skippedRules(array $data): array
    {
        $skipped = [];
        foreach (is_array($data['skipped_rules'] ?? null) ? $data['skipped_rules'] : [] as $rule) {
            if (is_array($rule) && is_string($rule['rule_id'] ?? null)) {
                $skipped[] = ['id' => self::ruleId($rule['rule_id']), 'reason' => trim((string)preg_replace('/\s+/', ' ', is_string($rule['details'] ?? null) ? $rule['details'] : ''))];
            }
        }

        return $skipped;
    }

    /**
     * The errors of the JSON of Semgrep
     *
     * @param array<string, mixed> $data JSON
     * @param string|null $level Only the errors of this level (`error`, `warn`), default: all
     * @param array<string, string> $views The views by the paths of their copies (`viewCopies()`), named in the
     *  messages in place of the copies
     * @return array<string>
     */
    public static function errors(array $data, ?string $level = null, array $views = []): array
    {
        $errors = [];
        foreach (is_array($data['errors'] ?? null) ? $data['errors'] : [] as $error) {
            if (is_array($error) && ($level === null || ($error['level'] ?? null) === $level)) {
                // Some types are lists, e.g. ["PartialParsing", [...]]
                $type = is_array($error['type'] ?? null) ? ($error['type'][0] ?? 'Error') : ($error['type'] ?? 'Error');
                $message = trim((string)($error['message'] ?? $error['long_msg'] ?? ''));
                foreach ($views as $copy => $view) {
                    $message = str_replace(self::VIEWS . '/' . $copy, $view, $message);
                }
                $errors[] = trim((is_scalar($type) ? (string)$type : 'Error') . ': ' . $message);
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
