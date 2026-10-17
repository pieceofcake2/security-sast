<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * The files of the paths of a project.
 */
final class Files
{
    /**
     * The files of the paths with one of the extensions, without the excluded paths
     *
     * @param string $project Directory of the project
     * @param array<string> $paths Paths, relative to the project
     * @param array<string> $exclude Paths to leave out, relative to the project
     * @param array<string> $extensions Extensions, without the dot
     * @return array<string> Paths relative to the project, sorted
     */
    public static function find(string $project, array $paths, array $exclude, array $extensions): array
    {
        $project = rtrim($project, '/\\');
        $excluded = array_map(static fn(string $path): string => rtrim($project . DIRECTORY_SEPARATOR . $path, '/\\'), $exclude);
        $found = [];
        foreach ($paths as $path) {
            $path = $project . DIRECTORY_SEPARATOR . $path;
            $files = is_dir($path)
                ? new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS))
                : [new SplFileInfo($path)];
            foreach ($files as $file) {
                /** @var \SplFileInfo $file */
                $name = $file->getPathname();
                if (!$file->isFile() || !in_array(strtolower($file->getExtension()), $extensions, true)) {
                    continue;
                }
                foreach ($excluded as $prefix) {
                    if ($name === $prefix || str_starts_with($name, $prefix . DIRECTORY_SEPARATOR)) {
                        continue 2;
                    }
                }
                $found[substr($name, strlen($project) + 1)] = true;
            }
        }
        $found = array_keys($found);
        sort($found);

        return $found;
    }
}
