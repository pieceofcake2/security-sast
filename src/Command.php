<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

use DateTimeImmutable;
use DateTimeZone;
use InvalidArgumentException;
use PieceOfCake2\Report\Environment;
use PieceOfCake2\Report\ReportWriter;
use RuntimeException;
use Throwable;

/**
 * The command `security-sast`: scans the code of a project with Semgrep or PHPStan and writes the PDF report.
 *
 * The exit code is 0 when no finding reaches `--fail-on`, 1 when one does, and 2 when the scan or the report
 * fails.
 */
final class Command
{
    public const SUCCESS = 0;
    public const FAILURE = 1;
    public const ERROR = 2;

    /**
     * Constructor
     *
     * @param resource $stdout Output
     * @param resource $stderr Error output
     * @param \PieceOfCake2\SecuritySast\Engine|null $engine Engine, default: the one of the settings
     * @param \PieceOfCake2\Report\ReportWriter|null $writer Writer of the PDF
     * @param \PieceOfCake2\Report\Environment|null $environment Environment, default: detected
     * @param \PieceOfCake2\SecuritySast\ConfigCheck|null $configCheck Check of the configuration, default: with the settings
     */
    public function __construct(
        private $stdout = STDOUT,
        private $stderr = STDERR,
        private ?Engine $engine = null,
        private ?ReportWriter $writer = null,
        private ?Environment $environment = null,
        private ?ConfigCheck $configCheck = null,
    ) {
    }

    /**
     * Runs the command
     *
     * @param array<string> $argv Arguments, without the name of the command
     * @param array<string, mixed> $env Environment variables, e.g. `$_SERVER`
     * @return int Exit code
     */
    public function run(array $argv, array $env = []): int
    {
        try {
            $config = self::config($argv, $env);
        } catch (Throwable $e) {
            fwrite($this->stderr, $e->getMessage() . "\n\n" . self::usage());

            return self::ERROR;
        }
        if ($config === null) {
            fwrite($this->stdout, self::usage());

            return self::SUCCESS;
        }

        try {
            $timezone = new DateTimeZone(date_default_timezone_get());
            $startedAt = new DateTimeImmutable('now', $timezone);
            // The configuration of the application, for its check and for its layout
            $values = null;
            $loadError = null;
            // Without the check and with the paths given, the code of the application is not run at all
            if (ConfigCheck::applies($config->project) && ($config->configCheck || $config->paths === [])) {
                try {
                    $values = ($this->configCheck ?? new ConfigCheck($config->configEnv))->load($config->project);
                } catch (RuntimeException $e) {
                    $loadError = $e->getMessage();
                }
            }
            $layout = is_array($values['layout'] ?? null) ? $values['layout'] : null;

            $paths = $config->paths($layout);
            // A path given that does not exist: Semgrep would scan nothing and pass
            $missing = array_values(array_filter($config->paths, static fn(string $path): bool => !file_exists($config->project . DIRECTORY_SEPARATOR . $path)));
            if ($missing !== []) {
                throw new InvalidArgumentException(sprintf('--paths: not found in %s: %s', $config->project, implode(', ', $missing)));
            }
            if ($paths === []) {
                throw new InvalidArgumentException(sprintf('Nothing to scan in %s: give the paths with --paths.', $config->project));
            }
            $engine = $this->engine ?? $config->engine($config->viewExtensions($layout));
            $result = $engine->scan($config->project, $paths, $config->exclude($layout));
            if ($config->configCheck && $values !== null) {
                $result->findings = array_merge($result->findings, ConfigCheck::findings($values, (string)realpath($config->project)));
                $result->configEnv = $config->configEnv;
            } elseif ($config->configCheck && $loadError !== null) {
                $result->errors[] = $loadError;
            }
            $result->paths = $paths;
            $result->suppressed = Suppressions::find(
                (string)realpath($config->project),
                $paths,
                $config->exclude($layout),
                array_values(array_unique(array_merge(['php'], $config->viewExtensions($layout)))),
                str_starts_with($result->engine, 'PHPStan') ? 'phpstan' : 'semgrep',
            );
            $finishedAt = new DateTimeImmutable('now', $timezone);

            $translator = ReportBuilder::translator($config->language, $config->localeDir);
            $doc = (new ReportBuilder($translator))->build($result, $config, $this->environment ?? Environment::detect($config->project), $startedAt, $finishedAt);
            ($this->writer ?? new ReportWriter())->write($doc, $config->pdf);
        } catch (Throwable $e) {
            fwrite($this->stderr, 'security-sast: ' . $e->getMessage() . "\n");

            return self::ERROR;
        }

        $counts = array_fill_keys(Severity::ALL, 0);
        foreach ($result->findings as $finding) {
            $counts[$finding->severity]++;
        }
        $summary = [];
        foreach ($counts as $severity => $count) {
            if ($count > 0) {
                $summary[] = $count . ' ' . $severity;
            }
        }
        fwrite($this->stdout, sprintf(
            "%d findings%s of %d rules in %d files (%s)%s. Report: %s\n",
            count($result->findings),
            $summary === [] ? '' : ' (' . implode(', ', $summary) . ')',
            count($result->byRule()),
            $result->files,
            $result->engine,
            $result->suppressed === [] ? '' : sprintf(', %d suppressed', count($result->suppressed)),
            $config->pdf,
        ));

        // The configuration was not checked: the report says so, and the run does not pass
        if ($config->configCheck && $loadError !== null) {
            fwrite($this->stderr, sprintf("security-sast: the configuration was not checked: %s\nFix the error, or turn the check off with --config-check=0.\n", $loadError));

            return self::ERROR;
        }

        return $result->fails($config->failOn) ? self::FAILURE : self::SUCCESS;
    }

    /**
     * The settings of the arguments and the environment variables, or null for `--help`
     *
     * @param array<string> $argv Arguments
     * @param array<string, mixed> $env Environment variables
     * @return \PieceOfCake2\SecuritySast\Config|null
     * @throws \InvalidArgumentException When an argument is invalid
     */
    public static function config(array $argv, array $env = []): ?Config
    {
        $value = static function (string $name) use ($env): ?string {
            $value = $env[$name] ?? null;

            return is_scalar($value) && trim((string)$value) !== '' ? (string)$value : null;
        };
        $options = [
            'engine' => $value('SECURITY_SAST_ENGINE'),
            'pdf' => $value('SECURITY_SAST_PDF'),
            'fail-on' => $value('SECURITY_SAST_FAIL_ON'),
            'project' => null,
            'paths' => $value('SECURITY_SAST_PATHS'),
            'exclude' => $value('SECURITY_SAST_EXCLUDE'),
            'semgrep-config' => $value('SECURITY_SAST_SEMGREP_CONFIG'),
            'semgrep-image' => $value('SECURITY_SAST_SEMGREP_IMAGE'),
            'docker' => $value('SECURITY_SAST_DOCKER'),
            'phpstan' => $value('SECURITY_SAST_PHPSTAN'),
            'view-extensions' => $value('SECURITY_SAST_VIEW_EXTENSIONS'),
            'safe-view-variables' => $value('SECURITY_SAST_SAFE_VIEW_VARIABLES'),
            'config-check' => $value('SECURITY_SAST_CONFIG_CHECK'),
            'config-env' => $value('SECURITY_SAST_CONFIG_ENV'),
            'language' => $value('SECURITY_REPORT_LANGUAGE'),
            'locale-dir' => $value('SECURITY_REPORT_LOCALE_DIR'),
            'title' => $value('SECURITY_SAST_TITLE'),
            'project-name' => $value('SECURITY_REPORT_PROJECT'),
            'note' => $value('SECURITY_SAST_NOTE'),
        ];
        $arguments = [];
        foreach ($argv as $arg) {
            if ($arg === '--help' || $arg === '-h') {
                return null;
            }
            if (!preg_match('/\A--([a-z-]+)=(.*)\z/s', $arg, $matches) || (!array_key_exists($matches[1], $options) && $matches[1] !== 'settings')) {
                throw new InvalidArgumentException(sprintf('Unknown option: %s', $arg));
            }
            $arguments[$matches[1]] = $matches[2];
        }

        // The options of the command, then the environment variables, then the settings file
        $file = Settings::options((string)($arguments['project'] ?? '.'), 'sast', $arguments['settings'] ?? $value('SECURITY_SETTINGS'), 'security-sast.pdf');
        foreach ($file as $name => $setting) {
            if (!array_key_exists($name, $options) || $name === 'project') {
                throw new InvalidArgumentException(sprintf('Unknown setting of the sast section: %s', $name));
            }
            $options[$name] ??= is_bool($setting) ? ($setting ? '1' : '0') : $setting;
        }
        unset($arguments['settings']);
        $options = array_merge($options, $arguments);

        $engine = strtolower((string)($options['engine'] ?? 'semgrep'));
        if (!in_array($engine, Config::ENGINES, true)) {
            throw new InvalidArgumentException(sprintf('--engine must be one of %s.', implode(', ', Config::ENGINES)));
        }
        $failOn = strtolower((string)($options['fail-on'] ?? Severity::HIGH));
        if (!in_array($failOn, Config::THRESHOLDS, true)) {
            throw new InvalidArgumentException(sprintf('--fail-on must be one of %s.', implode(', ', Config::THRESHOLDS)));
        }
        $list = static fn(?string $value): array => $value === null ? [] : array_values(array_filter(array_map('trim', explode(',', $value)), static fn(string $item): bool => $item !== ''));

        return new Config(
            $engine,
            (string)($options['pdf'] ?? 'tmp/security-sast.pdf'),
            $failOn,
            (string)($options['project'] ?? '.'),
            $list($options['paths']),
            $options['exclude'] === null ? Config::EXCLUDE : $list($options['exclude']),
            $options['semgrep-config'] === null ? SemgrepEngine::CONFIGS : $list($options['semgrep-config']),
            (string)($options['semgrep-image'] ?? SemgrepEngine::IMAGE),
            (string)($options['docker'] ?? 'docker'),
            $options['phpstan'],
            $options['view-extensions'] === null ? null : array_map(static fn(string $ext): string => strtolower(ltrim($ext, '.')), $list($options['view-extensions'])),
            array_map(static fn(string $name): string => ltrim($name, '$'), $list($options['safe-view-variables'])),
            filter_var($options['config-check'] ?? true, FILTER_VALIDATE_BOOLEAN),
            (string)($options['config-env'] ?? 'prod'),
            (string)($options['language'] ?? 'en'),
            $options['locale-dir'],
            $options['title'],
            $options['project-name'],
            $options['note'],
        );
    }

    /**
     * The help of the command
     *
     * @return string
     */
    public static function usage(): string
    {
        return <<<'TEXT'
Usage: vendor/bin/security-sast [options]

Scans the code of the project with Semgrep (Docker) or PHPStan, with the security rules for CakePHP 2,
and writes a PDF report of the findings by rule and risk.

Options:
  --engine=ENGINE        semgrep or phpstan (SECURITY_SAST_ENGINE, default: semgrep)
  --pdf=PATH             PDF report (SECURITY_SAST_PDF, default: tmp/security-sast.pdf)
  --fail-on=RISK         Lowest risk that fails: critical, high, medium, low or none
                         (SECURITY_SAST_FAIL_ON, default: high)
  --project=DIR          Directory of the project (default: the current directory)
  --paths=LIST           Paths to scan, comma separated (SECURITY_SAST_PATHS,
                         default: src, templates, plugins and app, when they exist)
  --exclude=LIST         Paths to leave out (SECURITY_SAST_EXCLUDE,
                         default: vendor, tmp, logs, tests, node_modules, app/Vendor, app/tmp, app/Test)
  --semgrep-config=LIST  Semgrep rules besides the CakePHP 2 ones (SECURITY_SAST_SEMGREP_CONFIG, default: p/php)
  --semgrep-image=IMAGE  Docker image of Semgrep (SECURITY_SAST_SEMGREP_IMAGE, default: semgrep/semgrep:latest)
  --docker=COMMAND       Docker command (SECURITY_SAST_DOCKER, default: docker)
  --phpstan=PATH         The phpstan script (SECURITY_SAST_PHPSTAN, default: the one of this package)
  --view-extensions=LIST Extensions of the views, comma separated (SECURITY_SAST_VIEW_EXTENSIONS, default: ctp,php),
                         in templates/ and View/
  --safe-view-variables=LIST
                         Variables that the views may print without h(), comma separated
                         (SECURITY_SAST_SAFE_VIEW_VARIABLES), e.g. body_html
  --config-check=0       Do not check the configuration of the application (SECURITY_SAST_CONFIG_CHECK, default: 1)
  --config-env=ENV       APP_ENV of the configuration to check (SECURITY_SAST_CONFIG_ENV, default: prod)
  --language=LANG        en or ja (SECURITY_REPORT_LANGUAGE, default: en)
  --locale-dir=DIR       Directory of <language>.json files (SECURITY_REPORT_LOCALE_DIR)
  --title=TITLE          Title of the report (SECURITY_SAST_TITLE)
  --project-name=NAME    Name of the project (SECURITY_REPORT_PROJECT, default: the name in composer.json)
  --note=TEXT            Note on the cover (SECURITY_SAST_NOTE)
  --settings=FILE        Settings file (SECURITY_SETTINGS, default: config/security.php or app/Config/security.php)
  --help                 Show this help

Exit code: 0 passed, 1 a finding reaches --fail-on, 2 error.

TEXT;
    }
}
