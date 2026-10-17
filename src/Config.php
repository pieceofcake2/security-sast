<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

/**
 * The settings of a run: the options of `security-sast`, or the environment variables of the same names.
 */
final class Config
{
    public const ENGINES = ['semgrep', 'phpstan'];
    public const THRESHOLDS = [Severity::CRITICAL, Severity::HIGH, Severity::MEDIUM, Severity::LOW, 'none'];

    /**
     * The paths scanned when none is given, when they exist: the modern layout and the legacy `app/`
     */
    public const PATHS = ['src', 'templates', 'plugins', 'app'];

    /**
     * The paths left out when none is given
     */
    public const EXCLUDE = ['vendor', 'tmp', 'logs', 'tests', 'node_modules', 'app/Vendor', 'app/tmp', 'app/Test'];

    /**
     * Constructor
     *
     * @param string $engine `semgrep` or `phpstan`
     * @param string $pdf Path of the PDF report
     * @param string $failOn Lowest risk that fails, or `none`
     * @param string $project Directory of the project
     * @param array<string> $paths Paths to scan, relative to the project, default: those of the layout of the
     *  application, or of `PATHS` that exist
     * @param array<string> $exclude Paths to leave out
     * @param array<string> $semgrepConfigs Semgrep rules besides those of this package
     * @param string $semgrepImage Docker image of Semgrep
     * @param string $docker Docker command
     * @param string|null $phpstan The `phpstan` script
     * @param array<string>|null $viewExtensions Extensions of the views, without the dot, default: `ctp`, `php` and the
     *  extension of the views of the application
     * @param array<string> $safeViewVariables Variables that the views may print without h(), e.g. `body_html`
     * @param bool $configCheck Whether to check the configuration of the application
     * @param string $configEnv `APP_ENV` of the configuration to check
     * @param string $language Language of the report
     * @param string|null $localeDir Directory of more messages
     * @param string|null $title Title
     * @param string|null $projectName Name of the project
     * @param string|null $note Note on the cover
     */
    public function __construct(
        public string $engine = 'semgrep',
        public string $pdf = 'tmp/security-sast.pdf',
        public string $failOn = Severity::HIGH,
        public string $project = '.',
        public array $paths = [],
        public array $exclude = self::EXCLUDE,
        public array $semgrepConfigs = SemgrepEngine::CONFIGS,
        public string $semgrepImage = SemgrepEngine::IMAGE,
        public string $docker = 'docker',
        public ?string $phpstan = null,
        public ?array $viewExtensions = null,
        public array $safeViewVariables = [],
        public bool $configCheck = true,
        public string $configEnv = 'prod',
        public string $language = 'en',
        public ?string $localeDir = null,
        public ?string $title = null,
        public ?string $projectName = null,
        public ?string $note = null,
    ) {
    }

    /**
     * The paths to scan: those given, or those of the layout of the application (its directory, views and plugins),
     * or those of `PATHS` that exist in the project
     *
     * @param array<string, mixed>|null $layout Layout of the application (`ConfigCheck::load()`)
     * @return array<string>
     */
    public function paths(?array $layout = null): array
    {
        if ($this->paths !== []) {
            return $this->paths;
        }
        $paths = self::PATHS;
        if ($layout !== null) {
            $paths = array_merge([$layout['app'] ?? null], (array)($layout['views'] ?? []), (array)($layout['plugins'] ?? []));
        }

        return array_values(array_unique(array_filter($paths, fn(mixed $path): bool => is_string($path) && $path !== '' && is_dir($this->project . DIRECTORY_SEPARATOR . $path))));
    }

    /**
     * The paths to leave out: those given or of `EXCLUDE`, and the packages that Composer installed in the project
     *
     * @param array<string, mixed>|null $layout Layout of the application (`ConfigCheck::load()`)
     * @return array<string>
     */
    public function exclude(?array $layout = null): array
    {
        return array_values(array_unique(array_merge($this->exclude, array_map('strval', (array)($layout['installed'] ?? [])))));
    }

    /**
     * The extensions of the views: those given, or `ctp`, `php` and the extension of the views of the application
     *
     * @param array<string, mixed>|null $layout Layout of the application (`ConfigCheck::load()`)
     * @return array<string>
     */
    public function viewExtensions(?array $layout = null): array
    {
        if ($this->viewExtensions !== null) {
            return $this->viewExtensions;
        }
        $extension = is_string($layout['viewExtension'] ?? null) && $layout['viewExtension'] !== '' ? [strtolower($layout['viewExtension'])] : [];

        return array_values(array_unique(array_merge(Views::EXTENSIONS, $extension)));
    }

    /**
     * The engine of the settings
     *
     * @param array<string>|null $viewExtensions Extensions of the views, default: those given or by default
     * @return \PieceOfCake2\SecuritySast\Engine
     */
    public function engine(?array $viewExtensions = null): Engine
    {
        $viewExtensions ??= $this->viewExtensions();

        return $this->engine === 'phpstan'
            ? new PhpstanEngine($this->phpstan, null, $viewExtensions, $this->safeViewVariables)
            : new SemgrepEngine($this->semgrepImage, $this->semgrepConfigs, $this->docker, null, $viewExtensions, $this->safeViewVariables);
    }
}
