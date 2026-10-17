<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

/**
 * The risks of the findings, from the highest. Semgrep `ERROR` is `high`, `WARNING` `medium` and `INFO` `low`.
 */
final class Severity
{
    public const CRITICAL = 'critical';
    public const HIGH = 'high';
    public const MEDIUM = 'medium';
    public const LOW = 'low';
    public const UNKNOWN = 'unknown';

    /**
     * The risks from the highest
     */
    public const ALL = [self::CRITICAL, self::HIGH, self::MEDIUM, self::LOW, self::UNKNOWN];

    /**
     * The risk of a value of an advisory, `unknown` when it has none
     *
     * @param mixed $value Value, e.g. `high` or `moderate`
     * @return string
     */
    public static function normalize(mixed $value): string
    {
        $value = is_string($value) ? strtolower(trim($value)) : '';
        if ($value === 'moderate') {
            return self::MEDIUM;
        }

        return in_array($value, self::ALL, true) ? $value : self::UNKNOWN;
    }

    /**
     * The risk of a severity of Semgrep
     *
     * @param mixed $value `ERROR`, `WARNING` or `INFO`
     * @return string
     */
    public static function fromSemgrep(mixed $value): string
    {
        return match (is_string($value) ? strtoupper($value) : '') {
            'ERROR' => self::HIGH,
            'WARNING' => self::MEDIUM,
            'INFO' => self::LOW,
            default => self::UNKNOWN,
        };
    }

    /**
     * The rank of a risk: 0 for `critical`, 4 for `unknown`
     *
     * @param string $severity Risk
     * @return int
     */
    public static function rank(string $severity): int
    {
        $rank = array_search($severity, self::ALL, true);

        return $rank === false ? count(self::ALL) - 1 : $rank;
    }

    /**
     * Whether a risk is the threshold or higher
     *
     * @param string $severity Risk
     * @param string $threshold Lowest risk that counts, or `none` for no risk
     * @return bool
     */
    public static function reaches(string $severity, string $threshold): bool
    {
        if ($threshold === 'none') {
            return false;
        }
        if ($severity === self::UNKNOWN) {
            // An advisory without a risk counts unless only the higher risks do
            return in_array($threshold, [self::LOW, self::UNKNOWN], true);
        }

        return self::rank($severity) <= self::rank(self::normalize($threshold));
    }
}
