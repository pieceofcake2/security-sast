<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\Test;

use PHPUnit\Framework\TestCase;
use PieceOfCake2\SecuritySast\Settings;

class SettingsTest extends TestCase
{
    public function testNullIsNotSet(): void
    {
        $file = TMP . 'settings-null.php';
        file_put_contents($file, "<?php\nreturn ['report' => ['note' => null], 'sast' => ['engine' => null, 'failOn' => 'low']];\n");

        $this->assertSame(['fail-on' => 'low'], Settings::options('.', 'sast', $file));
    }
}
