<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\Test;

use PHPUnit\Framework\TestCase;
use PieceOfCake2\SecuritySast\Suppressions;

class SuppressionsTest extends TestCase
{
    private const CODE = __DIR__ . DS . '..' . DS . 'fixtures' . DS . 'suppressions.php';

    public function testSemgrep(): void
    {
        $suppressions = Suppressions::inCode((string)file_get_contents(self::CODE), 'semgrep');

        $this->assertSame([
            // On a line of its own: the next line, with the comment before as the reason
            ['line' => 8, 'rules' => ['cakephp2-query-concatenation'], 'reason' => 'The table name is a constant of the model', 'code' => "\$this->query('TRUNCATE ' . self::TABLE);"],
            // At the end of a line, for every rule, with the reason after --
            ['line' => 12, 'rules' => [], 'reason' => 'a test value', 'code' => '$z = 1; // nosemgrep -- a test value'],
        ], $suppressions);
    }

    public function testPhpstan(): void
    {
        $suppressions = Suppressions::inCode((string)file_get_contents(self::CODE), 'phpstan');

        // The identifiers of this package as the IDs of the rules; not the ignores of the other identifiers
        $this->assertSame([10, 11, 14], array_column($suppressions, 'line'));
        $this->assertSame(['cakephp2-query-concatenation'], $suppressions[0]['rules']);
        $this->assertSame('The table name is a constant of the model', $suppressions[0]['reason']);
        $this->assertSame('signed by the server', $suppressions[1]['reason']);
        $this->assertSame([], $suppressions[2]['rules']);
        $this->assertSame('$w = foo();', $suppressions[2]['code']);
    }

    public function testFind(): void
    {
        $suppressions = Suppressions::find(dirname(self::CODE), ['suppressions.php'], [], ['php'], 'semgrep');

        $this->assertSame(['suppressions.php', 'suppressions.php'], array_column($suppressions, 'file'));
        $this->assertSame([], Suppressions::find(dirname(self::CODE), ['suppressions.php'], ['suppressions.php'], ['php'], 'semgrep'));
    }
}
