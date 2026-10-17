<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

/**
 * Which files are views, for the rule of the variables printed without `h()`: the files of the extensions of the
 * views in a directory of views (`templates/`, `View/`).
 */
final class Views
{
    /**
     * The extensions of the views by default
     */
    public const EXTENSIONS = ['ctp', 'php'];

    /**
     * The variables that a view prints as they are: the HTML of the layouts of CakePHP
     */
    public const SAFE_VARIABLES = ['content_for_layout', 'scripts_for_layout'];

    /**
     * The directories of views: `templates/` of the modern layout, `View/` of the legacy layout and the plugins
     */
    public const DIRECTORIES = ['templates', 'View'];

    /**
     * Whether a file is a view
     *
     * @param string $path Path of the file
     * @param array<string> $extensions Extensions of the views, without the dot
     * @return bool
     */
    public static function isView(string $path, array $extensions = self::EXTENSIONS): bool
    {
        $path = '/' . ltrim(str_replace('\\', '/', $path), '/');
        $extension = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if (!in_array($extension, array_map('strtolower', $extensions), true)) {
            return false;
        }
        foreach (self::DIRECTORIES as $directory) {
            if (str_contains($path, '/' . $directory . '/')) {
                return true;
            }
        }

        return false;
    }

    /**
     * The `paths: include` patterns of Semgrep for the views
     *
     * @param array<string> $extensions Extensions of the views, without the dot
     * @return array<string>
     */
    public static function semgrepIncludes(array $extensions = self::EXTENSIONS): array
    {
        $patterns = [];
        foreach ($extensions as $extension) {
            foreach (self::DIRECTORIES as $directory) {
                $patterns[] = '**/' . $directory . '/**/*.' . $extension;
            }
        }

        return array_values(array_unique($patterns));
    }
}
