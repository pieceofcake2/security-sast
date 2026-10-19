<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

/**
 * The result of a scan: the findings, how many files were scanned, and the engine.
 */
final class ScanResult
{
    /**
     * Constructor
     *
     * @param array<\PieceOfCake2\SecuritySast\Finding> $findings Findings
     * @param int $files Number of the scanned files
     * @param string $engine Engine and its version, e.g. `Semgrep 1.180.0`
     * @param array<string> $errors Errors of the engine that did not stop the scan, e.g. files it could not parse
     * @param string|null $configEnv `APP_ENV` of the checked configuration, or null when it was not checked
     * @param array<string> $paths Scanned paths, relative to the project
     * @param array<array{file: string, line: int, rules: array<string>, reason: string|null, code: string}> $suppressed
     *  The comments of the code that suppress findings of the engine (`Suppressions`): reported, but they do not
     *  fail the scan
     * @param array<string>|null $engineRules The IDs of the rules that the engine ran, e.g. from the timing of
     *  Semgrep (`--time`), or null when the engine does not tell them: then it ran every rule of the code of this
     *  package
     * @param array<array{id: string, reason: string}> $skippedRules The rules that the engine skipped, and why
     * @param array<string, string> $notRun The rules of this package that did not run, by ID, with the key of the
     *  message of the reason (`notRun.*`), e.g. the checks of the configuration when it is turned off
     * @param array<string> $viewErrors Errors of the rules of HTML in the views, which they read in part as they
     *  contain PHP, e.g. of Semgrep; the views are read as PHP besides
     */
    public function __construct(
        public array $findings = [],
        public int $files = 0,
        public string $engine = '',
        public array $errors = [],
        public ?string $configEnv = null,
        public array $paths = [],
        public array $suppressed = [],
        public ?array $engineRules = null,
        public array $skippedRules = [],
        public array $notRun = [],
        public array $viewErrors = [],
    ) {
    }

    /**
     * The findings by rule, from the highest risk, then by rule
     *
     * @return array<string, array<\PieceOfCake2\SecuritySast\Finding>>
     */
    public function byRule(): array
    {
        $rules = [];
        foreach ($this->findings as $finding) {
            $rules[$finding->rule][] = $finding;
        }
        uasort($rules, static fn(array $a, array $b): int => [Severity::rank($a[0]->severity), $a[0]->rule] <=> [Severity::rank($b[0]->severity), $b[0]->rule]);
        foreach ($rules as &$findings) {
            usort($findings, static fn(Finding $a, Finding $b): int => [$a->file, $a->line] <=> [$b->file, $b->line]);
        }

        return $rules;
    }

    /**
     * Whether a rule of this package ran: not one that did not run (`$notRun`), and, for a rule of the code, one
     * that the engine ran when it tells which
     *
     * @param string $rule ID of the rule
     * @return bool
     */
    public function ran(string $rule): bool
    {
        if (isset($this->notRun[$rule])) {
            return false;
        }
        if ($this->engineRules === null || !RuleCatalog::isCode($rule)) {
            return true;
        }

        return in_array($rule, $this->engineRules, true);
    }

    /**
     * The number of the rules of each risk, from the highest
     *
     * @return array<string, int>
     */
    public function counts(): array
    {
        $counts = array_fill_keys(Severity::ALL, 0);
        foreach ($this->byRule() as $findings) {
            $counts[$findings[0]->severity]++;
        }

        return $counts;
    }

    /**
     * Whether a finding has the risk of the threshold or higher
     *
     * @param string $threshold Lowest risk that counts, or `none`
     * @return bool
     */
    public function fails(string $threshold): bool
    {
        foreach ($this->findings as $finding) {
            if (Severity::reaches($finding->severity, $threshold)) {
                return true;
            }
        }

        return false;
    }
}
