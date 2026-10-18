<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

/**
 * The comments of the code that suppress findings of an engine, for the report: `nosemgrep` for Semgrep, and for
 * PHPStan its ignore comment with an identifier of this package, or its ignore comments of a line and of the next
 * line, which suppress every rule (written here without their at sign, which PHPStan would read).
 *
 * They are read from the code, as PHP tokens, so that both engines report them the same way, with the reason of the
 * comment: the text after `--` or in parentheses, else the comment lines just before.
 */
final class Suppressions
{
    /**
     * The suppressions of the files of the paths
     *
     * @param string $project Directory of the project
     * @param array<string> $paths Paths, relative to the project
     * @param array<string> $exclude Paths to leave out, relative to the project
     * @param array<string> $extensions Extensions of the PHP files and the views, without the dot
     * @param string $engine `semgrep` or `phpstan`
     * @return array<array{file: string, line: int, rules: array<string>, reason: string|null, code: string}>
     */
    public static function find(string $project, array $paths, array $exclude, array $extensions, string $engine): array
    {
        $found = [];
        foreach (Files::find($project, $paths, $exclude, $extensions) as $file) {
            $code = (string)file_get_contents($project . DIRECTORY_SEPARATOR . $file);
            foreach (self::inCode($code, $engine) as $suppression) {
                $found[] = ['file' => $file] + $suppression;
            }
        }

        return $found;
    }

    /**
     * The suppressions of the code of a file
     *
     * @param string $code PHP code, or a view
     * @param string $engine `semgrep` or `phpstan`
     * @return array<array{line: int, rules: array<string>, reason: string|null, code: string}>
     */
    public static function inCode(string $code, string $engine): array
    {
        $lines = explode("\n", $code);
        $comments = [];
        foreach (token_get_all($code) as $token) {
            if (is_array($token) && in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                $comments[] = [$token[2], $token[1]];
            }
        }

        $found = [];
        foreach ($comments as [$line, $text]) {
            $suppression = $engine === 'phpstan' ? self::phpstan($text) : self::semgrep($text);
            if ($suppression === null) {
                continue;
            }
            [$rules, $reason, $nextLine] = $suppression;
            // The IDs of the rules of this package for the identifiers of PHPStan
            $rules = array_map(static fn(string $rule): string => RuleCatalog::idOf($rule) ?? $rule, $rules);
            // A comment on a line of its own suppresses the next line, one at the end of a line suppresses that line
            $source = $lines[$line - 1] ?? '';
            $start = strpos($source, (string)strtok($text, "\n"));
            $own = $start !== false && preg_match('/\A\s*(?:<\?php)?\s*\z/', substr($source, 0, $start)) === 1;
            $target = $nextLine || $own ? self::nextCodeLine($lines, $line) : $line;
            $found[] = [
                'line' => $target,
                'rules' => $rules,
                'reason' => $reason ?? self::commentBefore($lines, $line),
                'code' => trim($lines[$target - 1] ?? ''),
            ];
        }

        return $found;
    }

    /**
     * The rules and the reason of a comment of Semgrep: `nosemgrep`, `nosemgrep: rule-a, rule-b`, with a reason after
     * `--`
     *
     * @param string $text Comment
     * @return array{0: array<string>, 1: string|null, 2: bool}|null Rules (empty for all), reason, whether it is
     *  about the next line
     */
    private static function semgrep(string $text): ?array
    {
        if (!preg_match('/\bnosemgrep\b(?::\s*([\w.\-]+(?:\s*,\s*[\w.\-]+)*))?(.*)/s', $text, $matches)) {
            return null;
        }
        $rules = $matches[1] !== '' ? array_map('trim', explode(',', $matches[1])) : [];

        return [$rules, self::reason($matches[2]), false];
    }

    /**
     * The rules and the reason of a comment of PHPStan that concerns the rules of this package
     *
     * @param string $text Comment
     * @return array{0: array<string>, 1: string|null, 2: bool}|null Rules (empty for all), reason, whether it is
     *  about the next line
     */
    private static function phpstan(string $text): ?array
    {
        if (preg_match('/@phpstan-ignore-(next-line|line)\b(.*)/s', $text, $matches)) {
            return [[], self::reason($matches[2]), $matches[1] === 'next-line'];
        }
        if (!preg_match('/@phpstan-ignore\s+([\w.\-]+(?:\s*,\s*[\w.\-]+)*)(.*)/s', $text, $matches)) {
            return null;
        }
        $rules = array_values(array_filter(array_map('trim', explode(',', $matches[1])), static fn(string $id): bool => str_starts_with($id, 'securitySast.')));
        if ($rules === []) {
            return null;
        }

        return [$rules, self::reason($matches[2]), false];
    }

    /**
     * The reason after the rules of a comment: in parentheses, or after `--`
     *
     * @param string $rest Text after the rules
     * @return string|null
     */
    private static function reason(string $rest): ?string
    {
        $rest = trim((string)preg_replace('#\s*(?:\*/|\?>)\s*\z#', '', $rest));
        if (preg_match('/\A\((.*)\)/s', $rest, $matches) || preg_match('/\A--\s*(.*)/s', $rest, $matches)) {
            $rest = $matches[1];
        }
        $rest = trim((string)preg_replace('/\s+/', ' ', $rest));

        return $rest !== '' ? $rest : null;
    }

    /**
     * The comment lines just before a line, as the reason of a suppression
     *
     * @param array<string> $lines Lines of the file
     * @param int $line Line of the suppression, from 1
     * @return string|null
     */
    private static function commentBefore(array $lines, int $line): ?string
    {
        $texts = [];
        for ($i = $line - 2; $i >= 0; $i--) {
            if (!preg_match('#\A\s*(?://|\#(?!\[)|\*|/\*)\s?(.*?)\s*(?:\*/)?\s*\z#', $lines[$i], $matches)) {
                break;
            }
            if (preg_match('/\bnosemgrep\b|@phpstan-ignore/', $matches[1])) {
                break;
            }
            array_unshift($texts, $matches[1]);
        }
        $text = trim(implode(' ', array_filter($texts, static fn(string $text): bool => $text !== '' && $text !== '*')));

        return $text !== '' ? $text : null;
    }

    /**
     * The next line of code after a line, without the comment lines
     *
     * @param array<string> $lines Lines of the file
     * @param int $line Line, from 1
     * @return int
     */
    private static function nextCodeLine(array $lines, int $line): int
    {
        $count = count($lines);
        for ($i = $line; $i < $count; $i++) {
            if (!preg_match('#\A\s*(?://|\#|\*|/\*|\z)#', $lines[$i])) {
                return $i + 1;
            }
        }

        return $line;
    }
}
