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
     * @param array<string> $paths Paths to scan, relative to the project, default: those of `PATHS` that exist
     * @param array<string> $exclude Paths to leave out
     * @param array<string> $semgrepConfigs Semgrep rules besides those of this package
     * @param string $semgrepImage Docker image of Semgrep
     * @param string $docker Docker command
     * @param string|null $phpstan The `phpstan` script
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
        public string $language = 'en',
        public ?string $localeDir = null,
        public ?string $title = null,
        public ?string $projectName = null,
        public ?string $note = null,
    ) {
    }

    /**
     * The paths to scan: those given, or those of `PATHS` that exist in the project
     *
     * @return array<string>
     */
    public function paths(): array
    {
        if ($this->paths !== []) {
            return $this->paths;
        }

        return array_values(array_filter(self::PATHS, fn(string $path): bool => is_dir($this->project . DIRECTORY_SEPARATOR . $path)));
    }

    /**
     * The engine of the settings
     *
     * @return \PieceOfCake2\SecuritySast\Engine
     */
    public function engine(): Engine
    {
        return $this->engine === 'phpstan'
            ? new PhpstanEngine($this->phpstan)
            : new SemgrepEngine($this->semgrepImage, $this->semgrepConfigs, $this->docker);
    }
}
