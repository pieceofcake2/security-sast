<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

use JsonException;

/**
 * The CakePHP of a project, as installed with Composer: its package and version in the `composer.lock` of the
 * project, which the rules take into account.
 *
 * `$this->request->here()` keeps the leading `//` of the path before pieceofcake2/cakephp 2.12.11 and
 * cakephp/cakephp 3.4.0 (GHSA-wh43-gc93-wh4c): `https://example.com//evil.example` gives `//evil.example`, a URL
 * of another site. With a fixed version it is a path of the application.
 */
final class Framework
{
    /**
     * The packages of CakePHP, and the first version where `here()` is always a path of the application
     */
    public const HERE_FIXED = [
        'pieceofcake2/cakephp' => '2.12.11',
        'cakephp/cakephp' => '3.4.0',
    ];

    /**
     * Constructor
     *
     * @param string $package Name of the package, e.g. `pieceofcake2/cakephp`
     * @param string $version Version as Composer writes it, e.g. `v2.12.11` or `dev-master`
     * @param string $file `composer.lock`, relative to the project
     * @param int $line Line of the package in the file
     * @param string $code Code of the line
     */
    public function __construct(
        public string $package,
        public string $version,
        public string $file = 'composer.lock',
        public int $line = 0,
        public string $code = '',
    ) {
    }

    /**
     * The CakePHP of a project, or null when its `composer.lock` has none (or the project has no `composer.lock`)
     *
     * @param string $project Directory of the project
     * @return self|null
     */
    public static function detect(string $project): ?self
    {
        $path = $project . DIRECTORY_SEPARATOR . 'composer.lock';
        if (!is_file($path)) {
            return null;
        }
        $text = (string)file_get_contents($path);
        try {
            $lock = json_decode($text, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }
        if (!is_array($lock)) {
            return null;
        }
        $packages = array_merge(
            is_array($lock['packages'] ?? null) ? $lock['packages'] : [],
            is_array($lock['packages-dev'] ?? null) ? $lock['packages-dev'] : [],
        );
        foreach (array_keys(self::HERE_FIXED) as $name) {
            foreach ($packages as $package) {
                if (is_array($package) && ($package['name'] ?? null) === $name && is_string($package['version'] ?? null)) {
                    [$line, $code] = self::place($text, $name);

                    return new self($name, $package['version'], 'composer.lock', $line, $code);
                }
            }
        }

        return null;
    }

    /**
     * The version of a release, e.g. `2.12.11` of `v2.12.11` (a pre-release, `2.12.11-RC1`, comes before it), or
     * null for a branch (`dev-master`, `2.12.x-dev`)
     *
     * @return string|null
     */
    public function release(): ?string
    {
        return preg_match('/\Av?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)\z/', $this->version, $matches) && !str_ends_with($this->version, '-dev')
            ? $matches[1]
            : null;
    }

    /**
     * Whether `$this->request->here()` is always a path of the application: a release of the fixed version or later
     *
     * @return bool
     */
    public function hereIsPath(): bool
    {
        $release = $this->release();

        return $release !== null && version_compare($release, self::HERE_FIXED[$this->package], '>=');
    }

    /**
     * Whether `$this->request->here()` can begin with `//`: a release before the fixed version. A branch is
     * neither this nor fixed
     *
     * @return bool
     */
    public function hereCanBeProtocolRelative(): bool
    {
        $release = $this->release();

        return $release !== null && version_compare($release, self::HERE_FIXED[$this->package], '<');
    }

    /**
     * The findings of the CakePHP of a project: `cakephp2-framework-protocol-relative-here` for a release before
     * the fixed version
     *
     * @param string $project Directory of the project
     * @return array<\PieceOfCake2\SecuritySast\Finding>
     */
    public static function findings(string $project): array
    {
        $framework = self::detect($project);
        if ($framework === null || !$framework->hereCanBeProtocolRelative()) {
            return [];
        }
        $rule = 'cakephp2-framework-protocol-relative-here';
        $definition = RuleCatalog::RULES[$rule];

        return [new Finding(
            $rule,
            $definition['severity'],
            $definition['message'],
            $framework->file,
            $framework->line,
            $framework->line,
            $framework->code,
            $definition['cwe'],
            $definition['owasp'],
            $definition['confidence'],
        )];
    }

    /**
     * The line of a package in `composer.lock`, and its code
     *
     * @param string $text Text of the file
     * @param string $name Name of the package
     * @return array{0: int, 1: string}
     */
    private static function place(string $text, string $name): array
    {
        foreach (preg_split('/\R/', $text) ?: [] as $i => $line) {
            if (preg_match('/"name"\s*:\s*' . preg_quote(json_encode($name, JSON_UNESCAPED_SLASHES) ?: '', '/') . '/', $line)) {
                return [$i + 1, trim($line)];
            }
        }

        return [0, ''];
    }
}
