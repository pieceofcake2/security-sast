<?php

/**
 * Loads the configuration of a CakePHP 2 application (config/core.php and config/bootstrap.php, with its .env
 * files) and prints the values that ConfigCheck checks, and the layout of the application (its directories and
 * the extension of its views), as JSON. Secrets are printed as their SHA-256 and length
 * only. Run in a process of its own by PieceOfCake2\SecuritySast\ConfigCheck:
 *
 *     php resources/config-dump.php <project>
 */
use Composer\InstalledVersions;

$project = rtrim((string)($argv[1] ?? '.'), '/\\');
$result = [];
ob_start();
try {
    if (!defined('DS')) {
        define('DS', DIRECTORY_SEPARATOR);
    }
    if (is_file($project . DS . 'config' . DS . 'define.php')) {
        require_once $project . DS . 'config' . DS . 'define.php';
    } else {
        // The legacy layout: app/Config/core.php
        define('ROOT', $project);
        define('APP_DIR', 'app');
        define('WEBROOT_DIR', 'webroot');
        define('WWW_ROOT', ROOT . DS . APP_DIR . DS . WEBROOT_DIR . DS);
    }
    $vendors = defined('VENDORS') ? VENDORS : $project . DS . 'vendor' . DS;
    require_once $vendors . 'autoload.php';
    require_once InstalledVersions::getInstallPath('pieceofcake2/cakephp') . DS . 'src' . DS . 'Cake' . DS . 'bootstrap.php';

    $secret = static function (mixed $value): ?array {
        if ($value === null || $value === false) {
            return null;
        }
        $value = (string)$value;

        return ['sha256' => hash('sha256', $value), 'length' => strlen($value)];
    };
    $session = Configure::read('Session');
    $ini = is_array($session) && is_array($session['ini'] ?? null) ? $session['ini'] : [];
    $result = [
        'appEnv' => (string)env('APP_ENV'),
        'debug' => (int)Configure::read('debug'),
        'salt' => $secret(Configure::read('Security.salt')),
        'cipherSeed' => $secret(Configure::read('Security.cipherSeed')),
        'cookieType' => Configure::read('Cookie.type'),
        // CookieComponent uses Security.salt when Cookie.key is empty
        'cookieKey' => Configure::read('Cookie.key') === '' ? null : $secret(Configure::read('Cookie.key')),
        'useOpenSsl' => (bool)Configure::read('Security.useOpenSsl'),
        'sessionHttpOnly' => array_key_exists('session.cookie_httponly', $ini) ? (bool)$ini['session.cookie_httponly'] : null,
        'sessionSecure' => array_key_exists('session.cookie_secure', $ini) ? (bool)$ini['session.cookie_secure'] : null,
        // The cache limiter that PHP gets: CakeSession sets 'must-revalidate' when it is not set, and leaves the one of
        // PHP when it is empty
        'sessionCacheLimiter' => is_array($session) && array_key_exists('cacheLimiter', $session)
            ? (string)$session['cacheLimiter'] ?: (string)($ini['session.cache_limiter'] ?? ini_get('session.cache_limiter'))
            : 'must-revalidate',
        'core' => is_file(CONFIG . 'core.php') ? realpath(CONFIG . 'core.php') : null,
    ];

    // The layout of the application, so that the settings of the scan need not repeat it
    $inProject = static function (string $path) use ($project): ?string {
        $real = realpath($path);
        $root = realpath($project);
        if ($real === false || $root === false || !str_starts_with($real . DS, $root . DS) || $real === $root) {
            return null;
        }

        return substr($real, strlen($root) + 1);
    };
    $paths = static fn(array $list): array => array_values(array_unique(array_filter(array_map($inProject, $list))));
    $ext = '.ctp';
    // Not App::uses(), deprecated in pieceofcake2/cakephp 2.13, which finds AppController without it, as Composer
    // does in most applications. App::import() finds it in the others on 2.12.
    if (!class_exists('AppController')) {
        App::import('Controller', 'App');
    }
    if (class_exists('AppController')) {
        $ext = (string)((new ReflectionClass('AppController'))->getDefaultProperties()['ext'] ?? '.ctp');
    }
    $installed = [];
    foreach (InstalledVersions::getInstalledPackages() as $package) {
        $path = InstalledVersions::getInstallPath($package);
        if ($path !== null) {
            $installed[] = $path;
        }
    }
    $result['layout'] = [
        'app' => $inProject(APP),
        'webroot' => $inProject(WWW_ROOT),
        'views' => $paths(App::path('View')),
        'plugins' => $paths(App::path('Plugin')),
        'viewExtension' => ltrim($ext, '.'),
        // Packages that Composer installed in the project, out of vendor/, e.g. plugins/DebugKit
        'installed' => array_values(array_filter($paths($installed), static fn(string $path): bool => !str_starts_with($path, 'vendor/') && $path !== 'vendor')),
    ];
} catch (Throwable $e) {
    $result = ['error' => get_class($e) . ': ' . $e->getMessage()];
}
ob_end_clean();
echo json_encode($result), "\n";
