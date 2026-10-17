<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

/**
 * An engine of the static analysis: Semgrep or PHPStan.
 */
interface Engine
{
    /**
     * Scans the code of a project
     *
     * @param string $project Directory of the project
     * @param array<string> $paths Directories and files to scan, relative to the project
     * @param array<string> $exclude Paths to leave out, relative to the project
     * @return \PieceOfCake2\SecuritySast\ScanResult
     * @throws \RuntimeException When the engine fails
     */
    public function scan(string $project, array $paths, array $exclude = []): ScanResult;
}
