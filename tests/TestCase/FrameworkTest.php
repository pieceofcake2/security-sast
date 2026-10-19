<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\Test;

use PHPUnit\Framework\TestCase;
use PieceOfCake2\SecuritySast\Framework;

class FrameworkTest extends TestCase
{
    /**
     * The fixture of the redirects to here(), whose composer.lock has pieceofcake2/cakephp v2.12.11
     */
    public const HERE = __DIR__ . DS . '..' . DS . 'fixtures' . DS . 'here';

    /**
     * A copy of the fixture of the redirects to here(), with a composer.lock of a package and version, or none
     *
     * @param string|null $package Package, or null for no composer.lock
     * @param string $version Version
     * @param string $key `packages` or `packages-dev`
     * @return string Directory
     */
    public static function project(?string $package, string $version = '', string $key = 'packages'): string
    {
        $project = TMP . 'here-' . bin2hex(random_bytes(4));
        mkdir($project . DS . 'src' . DS . 'Controller', 0777, true);
        copy(self::HERE . DS . 'src' . DS . 'Controller' . DS . 'PagesController.php', $project . DS . 'src' . DS . 'Controller' . DS . 'PagesController.php');
        if ($package !== null) {
            $lock = ['packages' => [], 'packages-dev' => []];
            $lock[$key][] = ['name' => $package, 'version' => $version];
            file_put_contents($project . DS . 'composer.lock', json_encode($lock, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n");
        }

        return (string)realpath($project);
    }

    /**
     * @return array<string, array{0: string, 1: string, 2: bool, 3: bool}>
     */
    public static function versions(): array
    {
        return [
            'pieceofcake2 before the fix' => ['pieceofcake2/cakephp', 'v2.12.10', false, true],
            'pieceofcake2 old' => ['pieceofcake2/cakephp', '2.12.0', false, true],
            'pieceofcake2 fixed' => ['pieceofcake2/cakephp', 'v2.12.11', true, false],
            'pieceofcake2 later' => ['pieceofcake2/cakephp', 'v2.13.0', true, false],
            'pieceofcake2 pre-release of the fix' => ['pieceofcake2/cakephp', 'v2.12.11-RC1', false, true],
            'pieceofcake2 branch' => ['pieceofcake2/cakephp', 'dev-master', false, false],
            'pieceofcake2 version branch' => ['pieceofcake2/cakephp', '2.12.x-dev', false, false],
            'cakephp 2' => ['cakephp/cakephp', '2.10.24', false, true],
            'cakephp 3.3' => ['cakephp/cakephp', '3.3.16', false, true],
            'cakephp 3.4' => ['cakephp/cakephp', '3.4.0', true, false],
            'cakephp 4' => ['cakephp/cakephp', '4.5.8', true, false],
        ];
    }

    /**
     * @dataProvider versions
     */
    public function testVersions(string $package, string $version, bool $hereIsPath, bool $protocolRelative): void
    {
        $framework = new Framework($package, $version);

        $this->assertSame($hereIsPath, $framework->hereIsPath());
        $this->assertSame($protocolRelative, $framework->hereCanBeProtocolRelative());
    }

    public function testDetect(): void
    {
        $framework = Framework::detect(self::HERE);

        $this->assertNotNull($framework);
        $this->assertSame('pieceofcake2/cakephp', $framework->package);
        $this->assertSame('v2.12.11', $framework->version);
        $this->assertSame(11, $framework->line);
        $this->assertSame('"name": "pieceofcake2/cakephp",', $framework->code);
        $this->assertTrue($framework->hereIsPath());
    }

    public function testDetectInTheDevelopmentPackages(): void
    {
        $framework = Framework::detect(self::project('cakephp/cakephp', '2.10.24', 'packages-dev'));

        $this->assertNotNull($framework);
        $this->assertSame('cakephp/cakephp', $framework->package);
    }

    public function testDetectWithoutCakephp(): void
    {
        $this->assertNull(Framework::detect(self::project(null)));
        $this->assertNull(Framework::detect(self::project('psr/log', '3.0.2')));
        $project = self::project(null);
        file_put_contents($project . DS . 'composer.lock', '{');
        $this->assertNull(Framework::detect($project));
    }

    public function testFindings(): void
    {
        $findings = Framework::findings(self::project('pieceofcake2/cakephp', 'v2.12.10'));

        $this->assertCount(1, $findings);
        $this->assertSame('cakephp2-framework-protocol-relative-here', $findings[0]->rule);
        $this->assertSame('medium', $findings[0]->severity);
        $this->assertSame('composer.lock', $findings[0]->file);
        $this->assertSame(4, $findings[0]->line);
        $this->assertSame('"name": "pieceofcake2/cakephp",', $findings[0]->code);
        $this->assertStringContainsString('GHSA-wh43-gc93-wh4c', $findings[0]->message);
        $this->assertSame('https://github.com/pieceofcake2/cakephp/security/advisories/GHSA-wh43-gc93-wh4c', $findings[0]->url);

        $this->assertCount(1, Framework::findings(self::project('cakephp/cakephp', '3.3.16')));
    }

    public function testNoFindings(): void
    {
        $this->assertSame([], Framework::findings(self::HERE));
        $this->assertSame([], Framework::findings(self::project('cakephp/cakephp', '3.4.0')));
        $this->assertSame([], Framework::findings(self::project('pieceofcake2/cakephp', 'dev-master')));
        $this->assertSame([], Framework::findings(self::project(null)));
    }
}
