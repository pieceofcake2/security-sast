<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\Test;

use PHPUnit\Framework\TestCase;
use PieceOfCake2\SecuritySast\Severity;

class SeverityTest extends TestCase
{
    public function testFromSemgrep(): void
    {
        $this->assertSame('high', Severity::fromSemgrep('ERROR'));
        $this->assertSame('medium', Severity::fromSemgrep('warning'));
        $this->assertSame('low', Severity::fromSemgrep('INFO'));
        $this->assertSame('unknown', Severity::fromSemgrep(null));
    }

    public function testReaches(): void
    {
        $this->assertTrue(Severity::reaches('high', 'high'));
        $this->assertFalse(Severity::reaches('medium', 'high'));
        $this->assertTrue(Severity::reaches('medium', 'medium'));
        $this->assertFalse(Severity::reaches('high', 'none'));
    }
}
