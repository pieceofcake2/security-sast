<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\Test;

use PHPUnit\Framework\TestCase;
use PieceOfCake2\SecuritySast\ConfigCheck;
use RuntimeException;

class ConfigCheckTest extends TestCase
{
    private const PROJECT = __DIR__ . DS . '..' . DS . 'fixtures';

    /**
     * Values as resources/config-dump.php prints them
     *
     * @param array<string, mixed> $values Values that differ from a safe configuration
     * @return array<string, mixed>
     */
    private static function values(array $values = []): array
    {
        $secret = static fn(string $value): array => ['sha256' => hash('sha256', $value), 'length' => strlen($value)];

        return $values + [
            'appEnv' => 'prod',
            'debug' => 0,
            'salt' => $secret(str_repeat('s', 64)),
            'cipherSeed' => $secret('1234567890'),
            'cookieType' => 'aes',
            'cookieKey' => $secret(str_repeat('k', 32)),
            'useOpenSsl' => true,
            'sessionHttpOnly' => null,
            'sessionSecure' => null,
            'core' => realpath(self::PROJECT) . DS . 'config' . DS . 'core.php',
        ];
    }

    private static function rules(array $findings): array
    {
        return array_map(static fn($finding): string => $finding->rule . ' ' . $finding->severity . ' ' . $finding->file . ':' . $finding->line, $findings);
    }

    public function testSafeConfiguration(): void
    {
        $this->assertSame([], ConfigCheck::findings(self::values(), (string)realpath(self::PROJECT)));
    }

    public function testUnsafeConfiguration(): void
    {
        $secret = static fn(string $value): array => ['sha256' => hash('sha256', $value), 'length' => strlen($value)];
        $findings = ConfigCheck::findings(self::values([
            'debug' => 2,
            'salt' => $secret('DYhG93b0qyJfIxfs2guVoUubWwvniR2G0FgaC9mi'),
            'cipherSeed' => $secret('76859309657453542496749683645'),
            'cookieType' => null,
            'useOpenSsl' => false,
            'sessionHttpOnly' => false,
        ]), (string)realpath(self::PROJECT));

        $this->assertSame([
            'cakephp2-config-debug high config/core.php:2',
            'cakephp2-config-salt high config/core.php:3',
            'cakephp2-config-cipher-seed medium config/core.php:4',
            'cakephp2-config-cookie-cipher medium config/core.php:5',
            'cakephp2-config-openssl low config/core.php:6',
            'cakephp2-config-session-cookie medium config/core.php:7',
        ], self::rules($findings));
        $this->assertSame("Configure::write('Security.salt', 'DYhG93b0qyJfIxfs2guVoUubWwvniR2G0FgaC9mi');", $findings[1]->code);
        // The secrets are never in the findings
        $this->assertStringNotContainsString(hash('sha256', 'DYhG93b0qyJfIxfs2guVoUubWwvniR2G0FgaC9mi'), serialize($findings));
    }

    public function testShortSecretsAndSampleKeys(): void
    {
        $secret = static fn(string $value): array => ['sha256' => hash('sha256', $value), 'length' => strlen($value)];
        $findings = ConfigCheck::findings(self::values([
            'salt' => $secret('short'),
            'cipherSeed' => $secret('2659758734'),
            'cookieKey' => $secret('qSI232qs*&sXOw!adre@34SAv!@*(XSL#$%)asGb$@11~_+!@#HKis~#^'),
            'sessionSecure' => false,
            'core' => null,
        ]), (string)realpath(self::PROJECT));

        // With 'aes' cookies, the cipher seed is a low risk
        $this->assertSame([
            'cakephp2-config-salt high config/core.php:0',
            'cakephp2-config-cipher-seed low config/core.php:0',
            'cakephp2-config-cookie-key medium config/core.php:0',
            'cakephp2-config-session-cookie medium config/core.php:0',
        ], self::rules($findings));
    }

    public function testLoad(): void
    {
        $commands = [];
        $check = new ConfigCheck('staging', static function (array $command, string $dir, array $env) use (&$commands): array {
            $commands[] = [$command, $env];

            return [0, json_encode(['debug' => 0, 'layout' => ['app' => 'src']]) . "\n", ''];
        });

        $values = $check->load(self::PROJECT);

        $this->assertSame(['app' => 'src'], $values['layout']);
        $this->assertSame(['APP_ENV' => 'staging'], $commands[0][1]);
        $this->assertStringEndsWith('config-dump.php', $commands[0][0][1]);
    }

    public function testLoadFails(): void
    {
        $check = new ConfigCheck('prod', static fn(array $command, string $dir, array $env): array => [0, '{"error":"Error: Class not found"}', '']);

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('The configuration could not be loaded: Error: Class not found');

        $check->load(self::PROJECT);
    }

    public function testApplies(): void
    {
        $this->assertFalse(ConfigCheck::applies(self::PROJECT));
        $this->assertFalse(ConfigCheck::applies(SemgrepEngineTest::APP));
    }
}
