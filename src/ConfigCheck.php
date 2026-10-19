<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

use Closure;
use JsonException;
use RuntimeException;

/**
 * Checks the configuration of a CakePHP 2 application as it runs: its `config/core.php` and
 * `config/bootstrap.php` are loaded in a process of their own with `APP_ENV` (`prod` by default), with the `.env`
 * files, and the values of `Configure` are checked, e.g. a salt that is the default of the distribution or a
 * sample of the documentation.
 *
 * The secrets (the salt, the cipher seed and the key of the cookies) are compared by their SHA-256; their values
 * are never printed.
 */
final class ConfigCheck
{
    public const DUMP = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'config-dump.php';

    /**
     * Salts of the distributions and samples of the documentation of CakePHP 2 and pieceofcake2
     */
    public const KNOWN_SALTS = [
        'DYhG93b0qyJfIxfs2guVoUubWwvniR2G0FgaC9mi',
        'YJfIxfs2guVoUubWDYhG93b0qyJfIxfs2guwvniR2G0FgaC9mi',
        'pl345e-P45s_7h3',
        'customsalt',
        'a-long-random-string',
        'a-default-salt',
    ];

    /**
     * Cipher seeds of the distributions and samples of the documentation
     */
    public const KNOWN_CIPHER_SEEDS = [
        '76859309657453542496749683645',
        '2659758734',
        '7485712659625147843639846751',
    ];

    /**
     * Keys of the cookies of samples of the documentation
     */
    public const KNOWN_COOKIE_KEYS = [
        'qSI232qs*&sXOw!adre@34SAv!@*(XSL#$%)asGb$@11~_+!@#HKis~#^',
    ];

    /**
     * @var \Closure(array<string>, string, array<string, string>): array{0: int, 1: string, 2: string}
     */
    private Closure $run;

    /**
     * Constructor
     *
     * @param string $appEnv `APP_ENV` of the configuration to check
     * @param (\Closure(array<string>, string, array<string, string>): array{0: int, 1: string, 2: string})|null $run Runs a command
     */
    public function __construct(private string $appEnv = 'prod', ?Closure $run = null)
    {
        $this->run = $run ?? Closure::fromCallable([Process::class, 'run']);
    }

    /**
     * Whether a project has a configuration to check: `config/core.php` (or `app/Config/core.php`) and the
     * packages installed with Composer
     *
     * @param string $project Directory of the project
     * @return bool
     */
    public static function applies(string $project): bool
    {
        return (is_file($project . '/config/core.php') || is_file($project . '/app/Config/core.php'))
            && is_file($project . '/vendor/autoload.php');
    }

    /**
     * Checks the configuration of a project
     *
     * @param string $project Directory of the project
     * @return array<\PieceOfCake2\SecuritySast\Finding>
     * @throws \RuntimeException When the configuration cannot be loaded
     */
    public function check(string $project): array
    {
        return self::findings($this->load($project), (string)realpath($project));
    }

    /**
     * Loads the configuration of a project: the values to check, and its layout (`layout`: `app`, `webroot`,
     * `views`, `plugins`, `viewExtension` and the `installed` packages of Composer)
     *
     * @param string $project Directory of the project
     * @return array<string, mixed>
     * @throws \RuntimeException When the configuration cannot be loaded
     */
    public function load(string $project): array
    {
        $project = (string)realpath($project);
        [$code, $output, $error] = ($this->run)([PHP_BINARY, (string)realpath(self::DUMP), $project], $project, ['APP_ENV' => $this->appEnv]);
        try {
            $values = json_decode(trim($output), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new RuntimeException(sprintf('The configuration could not be loaded (exit code %d): %s', $code, trim($error !== '' ? $error : $output)));
        }
        if (!is_array($values)) {
            throw new RuntimeException('The configuration could not be loaded.');
        }
        if (isset($values['error'])) {
            throw new RuntimeException(sprintf('The configuration could not be loaded: %s', (string)$values['error']));
        }

        return $values;
    }

    /**
     * The findings of the values of the configuration
     *
     * @param array<string, mixed> $values Values printed by `resources/config-dump.php`
     * @param string $project Directory of the project
     * @return array<\PieceOfCake2\SecuritySast\Finding>
     */
    public static function findings(array $values, string $project): array
    {
        $core = is_string($values['core'] ?? null) ? $values['core'] : null;
        $findings = [];
        $add = static function (string $rule, string $key, ?string $severity = null) use (&$findings, $core, $project): void {
            [$file, $line, $code] = self::place($core, $project, $key);
            $definition = RuleCatalog::RULES[$rule];
            $findings[] = new Finding($rule, $severity ?? $definition['severity'], $definition['message'], $file, $line, $line, $code, $definition['cwe'], $definition['owasp'], $definition['confidence']);
        };

        if ((int)($values['debug'] ?? 0) > 0) {
            $add('cakephp2-config-debug', "'debug'");
        }
        $salt = is_array($values['salt'] ?? null) ? $values['salt'] : null;
        if ($salt === null || (int)$salt['length'] < 32 || self::isKnown($salt, self::KNOWN_SALTS)) {
            $add('cakephp2-config-salt', "'Security.salt'");
        }
        $cipher = !in_array($values['cookieType'] ?? null, ['aes', 'rijndael'], true);
        $seed = is_array($values['cipherSeed'] ?? null) ? $values['cipherSeed'] : null;
        if ($seed !== null && self::isKnown($seed, self::KNOWN_CIPHER_SEEDS)) {
            $add('cakephp2-config-cipher-seed', "'Security.cipherSeed'", $cipher ? Severity::MEDIUM : Severity::LOW);
        }
        if ($cipher) {
            $add('cakephp2-config-cookie-cipher', "'Cookie.type'");
        }
        $key = is_array($values['cookieKey'] ?? null) ? $values['cookieKey'] : null;
        if (!$cipher && $key !== null && ((int)$key['length'] < 32 || self::isKnown($key, self::KNOWN_COOKIE_KEYS))) {
            $add('cakephp2-config-cookie-key', "'Cookie.key'");
        }
        if (empty($values['useOpenSsl'])) {
            $add('cakephp2-config-openssl', "'Security.useOpenSsl'");
        }
        if (($values['sessionHttpOnly'] ?? null) === false || ($values['sessionSecure'] ?? null) === false) {
            $add('cakephp2-config-session-cookie', "'Session'");
        }
        $limiter = $values['sessionCacheLimiter'] ?? null;
        if (is_string($limiter) && strtolower($limiter) !== 'nocache') {
            $add('cakephp2-config-session-cache-limiter', self::place($core, $project, "'Session.cacheLimiter'")[1] > 0 ? "'Session.cacheLimiter'" : "'Session'");
        }

        return $findings;
    }

    /**
     * Whether a secret is one of the known values
     *
     * @param array{sha256: string, length: int} $secret SHA-256 and length of the secret
     * @param array<string> $known Known values
     * @return bool
     */
    private static function isKnown(array $secret, array $known): bool
    {
        foreach ($known as $value) {
            if (hash_equals(hash('sha256', $value), (string)$secret['sha256'])) {
                return true;
            }
        }

        return false;
    }

    /**
     * The place of a setting in `core.php`: the file relative to the project, the line and its code
     *
     * @param string|null $core Path of `core.php`
     * @param string $project Directory of the project
     * @param string $key Text of the setting, e.g. `'Security.salt'`
     * @return array{0: string, 1: int, 2: string}
     */
    private static function place(?string $core, string $project, string $key): array
    {
        if ($core === null || !is_file($core)) {
            return ['config/core.php', 0, ''];
        }
        $file = str_starts_with($core, $project . DIRECTORY_SEPARATOR) ? substr($core, strlen($project) + 1) : $core;
        foreach (file($core, FILE_IGNORE_NEW_LINES) ?: [] as $i => $text) {
            if (str_contains($text, 'Configure::write(' . $key)) {
                return [$file, $i + 1, trim($text)];
            }
        }

        return [$file, 0, ''];
    }
}
