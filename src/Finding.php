<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

/**
 * A place in the code that a rule reports.
 */
final class Finding
{
    /**
     * Constructor
     *
     * @param string $rule ID of the rule, e.g. `cakephp2-query-concatenation`
     * @param string $severity Risk (`Severity`)
     * @param string $message Message of the rule
     * @param string $file Path of the file, relative to the project
     * @param int $line First line
     * @param int $endLine Last line
     * @param string $code The code of the lines
     * @param array<string> $cwe CWE of the rule, e.g. `CWE-89: ...`
     * @param array<string> $owasp OWASP Top 10 categories of the rule, e.g. `A03:2021 - Injection`
     * @param string|null $confidence Confidence of the rule: `HIGH`, `MEDIUM` or `LOW`
     * @param string|null $url Documentation of the rule
     */
    public function __construct(
        public string $rule,
        public string $severity,
        public string $message,
        public string $file,
        public int $line,
        public int $endLine = 0,
        public string $code = '',
        public array $cwe = [],
        public array $owasp = [],
        public ?string $confidence = null,
        public ?string $url = null,
    ) {
        if ($this->endLine < $this->line) {
            $this->endLine = $this->line;
        }
    }

    /**
     * The lines of a file, for the code of a finding
     *
     * @param string $path Path of the file
     * @param int $line First line
     * @param int $endLine Last line
     * @param int $max Most lines
     * @return string
     */
    public static function lines(string $path, int $line, int $endLine, int $max = 8): string
    {
        if (!is_file($path) || $line < 1) {
            return '';
        }
        $lines = file($path, FILE_IGNORE_NEW_LINES) ?: [];
        $code = array_slice($lines, $line - 1, max(1, min($endLine - $line + 1, $max)));

        // Without the indentation that the lines share
        $indent = null;
        foreach ($code as $text) {
            if (trim($text) !== '') {
                $width = strlen($text) - strlen(ltrim($text, " \t"));
                $indent = $indent === null ? $width : min($indent, $width);
            }
        }
        $code = array_map(static fn(string $text): string => (string)substr($text, (int)$indent), $code);

        return rtrim(implode("\n", $code));
    }
}
