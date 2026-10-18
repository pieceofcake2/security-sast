<?php
class A
{
    public function a()
    {
        // The table name is a constant of the model
        // nosemgrep: cakephp2-query-concatenation
        $this->query('TRUNCATE ' . self::TABLE);
        // The table name is a constant of the model
        $this->query('TRUNCATE ' . self::TABLE); // @phpstan-ignore securitySast.queryConcatenation
        $x = unserialize($y); // @phpstan-ignore securitySast.unserializeRequest (signed by the server)
        $z = 1; // nosemgrep -- a test value
        // @phpstan-ignore-next-line
        $w = foo();
        $v = bar(); // @phpstan-ignore argument.type
        $s = '// nosemgrep in a string';
    }
}
