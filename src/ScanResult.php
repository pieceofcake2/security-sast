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
     */
    public function __construct(
        public array $findings = [],
        public int $files = 0,
        public string $engine = '',
        public array $errors = [],
        public ?string $configEnv = null,
        public array $paths = [],
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
