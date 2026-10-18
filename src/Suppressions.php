<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

/**
 * The comments of the code that suppress findings of an engine, for the report: `nosemgrep` for Semgrep, and for
 * PHPStan its ignore comment with an identifier of this package, or its ignore comments of a line and of the next
 * line, which suppress every rule (written here without their at sign, which PHPStan would read).
 *
 * They are read from the code, as each engine reads them, so that the report lists the lines whose findings the
 * engine does not report, with the reason of the comment: the text after `--` or in parentheses, else the comment
 * lines just before.
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
     * The suppressions of the code of a file: the lines whose findings the engine does not report
     *
     * @param string $code PHP code, or a view
     * @param string $engine `semgrep` or `phpstan`
     * @return array<array{line: int, rules: array<string>, reason: string|null, code: string}>
     */
    public static function inCode(string $code, string $engine): array
    {
        $lines = explode("\n", $code);
        [$codeLines, $comments] = self::tokens($code);
        $found = $engine === 'phpstan' ? self::phpstanLines($comments, $codeLines) : self::semgrepLines($lines, $codeLines);

        $suppressions = [];
        foreach ($found as $target => [$rules, $reason, $line]) {
            // The IDs of the rules of this package for the identifiers of PHPStan
            $rules = array_values(array_unique(array_map(static fn(string $rule): string => RuleCatalog::idOf($rule) ?? $rule, $rules)));
            $suppressions[] = [
                'line' => $target,
                'rules' => $rules,
                'reason' => $reason ?? self::commentBefore($lines, $line),
                'code' => trim($lines[$target - 1] ?? ''),
            ];
        }

        return $suppressions;
    }

    /**
     * The lines of code and the comments of a file, as PHP tokens
     *
     * @param string $code PHP code, or a view
     * @return array{0: array<int, true>, 1: array<array{0: int, 1: string, 2: bool}>} The lines with code, and the
     *  comments: their line, text, and whether they are first on their line
     */
    private static function tokens(string $code): array
    {
        $codeLines = [];
        $comments = [];
        $first = [];
        foreach (token_get_all($code) as $token) {
            if (!is_array($token)) {
                // A character, e.g. ; or (, is code of the line of the token before it
                continue;
            }
            [$id, $text, $line] = $token;
            if (in_array($id, [T_COMMENT, T_DOC_COMMENT], true)) {
                $comments[] = [$line, $text, !isset($first[$line])];
            }
            // Whitespace and inline HTML start no line of code; the open tag is a token before a comment
            if (!in_array($id, [T_WHITESPACE, T_INLINE_HTML], true)) {
                $first[$line] = true;
            }
            if (!in_array($id, [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_OPEN_TAG, T_CLOSE_TAG, T_INLINE_HTML], true)) {
                $codeLines[$line] = true;
            }
        }

        return [$codeLines, $comments];
    }

    /**
     * The lines that Semgrep does not report: it reads the text of the lines, not the comments. ` nosem` (or
     * ` nosemgrep`) anywhere in a line suppresses the findings of that line, and a line that starts with it, after
     * signs only (e.g. `//`, `#`, `<!--`), those of the next line. `: rule-a, rule-b` limits it to these rules.
     *
     * @param array<string> $lines Lines of the file
     * @param array<int, true> $codeLines The lines with code
     * @return array<int, array{0: array<string>, 1: string|null, 2: int}> Rules, reason and line of the comment, by
     *  the line of code it suppresses
     */
    private static function semgrepLines(array $lines, array $codeLines): array
    {
        $found = [];
        foreach ($lines as $i => $text) {
            $line = $i + 1;
            if (!preg_match('/ nosem(?:grep)?\b(?:[:=]\s?((?:[^,\s](?:[,\s]+)?)+))?(.*)/', $text, $matches)) {
                continue;
            }
            // The rules after a colon, then a reason after --; without rules, the reason after --
            [$rules, $reason] = $matches[1] !== ''
                ? self::semgrepRules($matches[1])
                : [[], preg_match('/\A\s*--\s/', $matches[2]) ? self::reason((string)preg_replace('#\s*(?:\*/|-->|\?>).*\z#s', '', $matches[2])) : null];
            if (isset($codeLines[$line])) {
                $found[$line] ??= [$rules, $reason, $line];
            }
            if (preg_match('/\A[^a-zA-Z0-9]* nosem/', $text) && isset($codeLines[$line + 1])) {
                $found[$line + 1] ??= [$rules, $reason, $line];
            }
        }
        ksort($found);

        return $found;
    }

    /**
     * The rules and the reason of the text after `nosemgrep:`, with a reason after `--`
     *
     * @param string $text Text
     * @return array{0: array<string>, 1: string|null}
     */
    private static function semgrepRules(string $text): array
    {
        $text = trim((string)preg_replace('#\s*(?:\*/|-->|\?>).*\z#s', '', $text));
        [$ids, $reason] = array_pad(preg_split('/(?:\A|\s)--(?:\s|\z)/', $text, 2) ?: [''], 2, null);
        $rules = array_values(array_filter(preg_split('/[,\s]+/', trim((string)$ids)) ?: [], static fn(string $rule): bool => $rule !== ''));

        return [$rules, $reason !== null ? self::reason('-- ' . $reason) : null];
    }

    /**
     * The lines that PHPStan does not report for the rules of this package: its ignore comment first on its line
     * applies to the next line, one after code to its own line, and those of a line or of the next line to these
     *
     * @param array<array{0: int, 1: string, 2: bool}> $comments Comments: line, text, first on the line
     * @param array<int, true> $codeLines The lines with code
     * @return array<int, array{0: array<string>, 1: string|null, 2: int}> Rules, reason and line of the comment, by
     *  the line of code it suppresses
     */
    private static function phpstanLines(array $comments, array $codeLines): array
    {
        $found = [];
        foreach ($comments as [$line, $text, $first]) {
            if (preg_match('/@phpstan-ignore-(next-line|line)\b(.*)/s', $text, $matches)) {
                $target = $matches[1] === 'next-line' ? $line + 1 : $line;
                $rules = [];
                $reason = self::reason($matches[2]);
            } elseif (preg_match('/@phpstan-ignore\s+([\w.\-]+(?:\s*,\s*[\w.\-]+)*)(.*)/s', $text, $matches)) {
                $rules = array_values(array_filter(array_map('trim', explode(',', $matches[1])), static fn(string $id): bool => str_starts_with($id, 'securitySast.')));
                if ($rules === []) {
                    continue;
                }
                $target = $first ? $line + 1 : $line;
                $reason = self::reason($matches[2]);
            } else {
                continue;
            }
            // On a line without code, e.g. a comment or an empty line, it suppresses nothing
            if (isset($codeLines[$target])) {
                $found[$target] ??= [$rules, $reason, $line];
            }
        }
        ksort($found);

        return $found;
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
}
