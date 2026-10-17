<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

/**
 * The rules of this package for CakePHP 2 applications: the same checks for Semgrep
 * (`resources/semgrep/cakephp2.yml`) and PHPStan (`resources/phpstan/rules.neon`).
 */
final class RuleCatalog
{
    private const SQL = "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')";

    /**
     * The rules by ID
     *
     * @var array<string, array{identifier: string, severity: string, cwe: array<string>, owasp: array<string>, confidence: string, message: string}>
     */
    public const RULES = [
        'cakephp2-query-concatenation' => [
            'identifier' => 'securitySast.queryConcatenation',
            'severity' => Severity::HIGH,
            'cwe' => [self::SQL],
            'owasp' => ['A03:2021 - Injection'],
            'confidence' => 'MEDIUM',
            'message' => "SQL built from a string with a variable is passed to Model::query(). Use the values array of query() (\$this->Model->query('... WHERE id = ?', [\$id])) or find() with conditions arrays.",
        ],
        'cakephp2-conditions-string' => [
            'identifier' => 'securitySast.conditionsString',
            'severity' => Severity::HIGH,
            'cwe' => [self::SQL],
            'owasp' => ['A03:2021 - Injection'],
            'confidence' => 'MEDIUM',
            'message' => "A conditions string with a variable is passed to find(). Use a conditions array (['Post.title' => \$title]) so that the value is escaped.",
        ],
        'cakephp2-redirect-request' => [
            'identifier' => 'securitySast.redirectRequest',
            'severity' => Severity::MEDIUM,
            'cwe' => ["CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"],
            'owasp' => ['A01:2021 - Broken Access Control'],
            'confidence' => 'HIGH',
            'message' => 'A value of the request is passed to redirect(). Redirect only to paths of the application, e.g. with Router::url() of a route array, or check the URL against a list.',
        ],
        'cakephp2-render-request' => [
            'identifier' => 'securitySast.renderRequest',
            'severity' => Severity::HIGH,
            'cwe' => ["CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')"],
            'owasp' => ['A01:2021 - Broken Access Control'],
            'confidence' => 'HIGH',
            'message' => 'A value of the request is passed to render() or element(). A path in it can render any template. Map the value to a list of allowed views.',
        ],
        'cakephp2-xml-build-variable' => [
            'identifier' => 'securitySast.xmlBuildVariable',
            'severity' => Severity::MEDIUM,
            'cwe' => ['CWE-918: Server-Side Request Forgery (SSRF)'],
            'owasp' => ['A10:2021 - Server-Side Request Forgery (SSRF)'],
            'confidence' => 'MEDIUM',
            'message' => "Xml::build() is called with a variable: a URL or a path in it is read. Pass ['readFile' => false] for a string of XML, and do not pass values of the request.",
        ],
        'cakephp2-unserialize-request' => [
            'identifier' => 'securitySast.unserializeRequest',
            'severity' => Severity::HIGH,
            'cwe' => ['CWE-502: Deserialization of Untrusted Data'],
            'owasp' => ['A08:2021 - Software and Data Integrity Failures'],
            'confidence' => 'HIGH',
            'message' => 'A value of the request is passed to unserialize(): it can create objects of any class. Use json_decode().',
        ],
        'cakephp2-security-csrf-disabled' => [
            'identifier' => 'securitySast.securityCsrfDisabled',
            'severity' => Severity::MEDIUM,
            'cwe' => ['CWE-352: Cross-Site Request Forgery (CSRF)'],
            'owasp' => ['A01:2021 - Broken Access Control'],
            'confidence' => 'MEDIUM',
            'message' => 'The CSRF check or the form tampering check of SecurityComponent is turned off. Turn it off only for the actions that need it, e.g. with unlockedActions.',
        ],
        'cakephp2-view-unescaped-output' => [
            'identifier' => 'securitySast.viewUnescapedOutput',
            'severity' => Severity::MEDIUM,
            'cwe' => ["CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"],
            'owasp' => ['A03:2021 - Injection'],
            'confidence' => 'LOW',
            'message' => 'A variable is printed in a view without h(). Escape it with h(), or use a helper that escapes.',
        ],
    ];

    /**
     * The ID of a rule of a PHPStan identifier, or null for another identifier
     *
     * @param string $identifier PHPStan identifier, e.g. `securitySast.queryConcatenation`
     * @return string|null
     */
    public static function idOf(string $identifier): ?string
    {
        foreach (self::RULES as $id => $rule) {
            if ($rule['identifier'] === $identifier) {
                return $id;
            }
        }

        return null;
    }

    /**
     * The message of a rule
     *
     * @param string $id ID of the rule
     * @return string
     */
    public static function message(string $id): string
    {
        return self::RULES[$id]['message'];
    }
}
