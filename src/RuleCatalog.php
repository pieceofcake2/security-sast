<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

/**
 * The rules of this package for CakePHP 2 applications: the same checks of the code for Semgrep
 * (`resources/semgrep/cakephp2.yml`) and PHPStan (`resources/phpstan/rules.neon`), and the checks of the
 * configuration (`ConfigCheck`, `cakephp2-config-*`) and of the installed framework (`Framework`,
 * `cakephp2-framework-*`), which have no PHPStan identifier.
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
            'message' => "SQL built from a string with a variable is passed to Model::query() (or fetchAll(), execute()). Use the values array of query() (\$this->Model->query('... WHERE id = ?', [\$id])) or find() with conditions arrays.",
        ],
        'cakephp2-conditions-string' => [
            'identifier' => 'securitySast.conditionsString',
            'severity' => Severity::HIGH,
            'cwe' => [self::SQL],
            'owasp' => ['A03:2021 - Injection'],
            'confidence' => 'MEDIUM',
            'message' => "A conditions string with a variable is passed to find(), deleteAll(), updateAll(), field() or hasAny(), or as a value of the fields of updateAll(). Use a conditions array (['Post.title' => \$title]) so that the value is escaped.",
        ],
        'cakephp2-order-request' => [
            'identifier' => 'securitySast.orderRequest',
            'severity' => Severity::HIGH,
            'cwe' => [self::SQL],
            'owasp' => ['A03:2021 - Injection'],
            'confidence' => 'MEDIUM',
            'message' => 'A value of the request is the order, fields or group of find() or paginate: it goes into the SQL as a name. Map the value to a list of allowed fields.',
        ],
        'cakephp2-redirect-request' => [
            'identifier' => 'securitySast.redirectRequest',
            'severity' => Severity::MEDIUM,
            'cwe' => ["CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"],
            'owasp' => ['A01:2021 - Broken Access Control'],
            'confidence' => 'HIGH',
            'message' => 'A value of the request is passed to redirect(). Redirect only to paths of the application, e.g. with Router::url() of a route array, or check the URL against a list. Before pieceofcake2/cakephp 2.12.11, $this->request->here() can begin with // (a URL of another site): update CakePHP, or put Router::fullBaseUrl() before it.',
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
        'cakephp2-view-raw-output' => [
            'identifier' => 'securitySast.viewRawOutput',
            'severity' => Severity::INFO,
            'cwe' => ["CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"],
            'owasp' => ['A03:2021 - Injection'],
            'confidence' => 'LOW',
            'message' => 'HTML is printed without escaping on purpose with raw(). Check that it is built by the application or sanitized, never a value of the request.',
        ],
        'cakephp2-view-unescaped-output' => [
            'identifier' => 'securitySast.viewUnescapedOutput',
            'severity' => Severity::MEDIUM,
            'cwe' => ["CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"],
            'owasp' => ['A03:2021 - Injection'],
            'confidence' => 'LOW',
            'message' => 'A variable is printed in a view without h(). Escape it with h(), or use a helper that escapes.',
        ],
        'cakephp2-config-debug' => [
            'identifier' => '',
            'severity' => Severity::HIGH,
            'cwe' => ['CWE-489: Active Debug Code'],
            'owasp' => ['A05:2021 - Security Misconfiguration'],
            'confidence' => 'HIGH',
            'message' => 'The debug level is not 0 in production. Error pages show the code, the SQL and the configuration. Set APP_DEBUG to 0, or leave it unset, in production.',
        ],
        'cakephp2-config-salt' => [
            'identifier' => '',
            'severity' => Severity::HIGH,
            'cwe' => ['CWE-1188: Initialization of a Resource with an Insecure Default', 'CWE-330: Use of Insufficiently Random Values'],
            'owasp' => ['A02:2021 - Cryptographic Failures'],
            'confidence' => 'HIGH',
            'message' => 'Security.salt is the default of the distribution or a sample of the documentation, or shorter than 32 characters. The hashes and the signed values (e.g. the tokens of forms) can be forged. Set SECURITY_SALT to a random value of 32 bytes or more.',
        ],
        'cakephp2-config-cipher-seed' => [
            'identifier' => '',
            'severity' => Severity::MEDIUM,
            'cwe' => ['CWE-1188: Initialization of a Resource with an Insecure Default'],
            'owasp' => ['A02:2021 - Cryptographic Failures'],
            'confidence' => 'HIGH',
            'message' => 'Security.cipherSeed is the default of the distribution or a sample of the documentation. It is used by the \'cipher\' type of CookieComponent. Set SECURITY_CIPHER_SEED to a random number, and move the cookies to the \'aes\' type.',
        ],
        'cakephp2-config-cookie-cipher' => [
            'identifier' => '',
            'severity' => Severity::MEDIUM,
            'cwe' => ['CWE-327: Use of a Broken or Risky Cryptographic Algorithm'],
            'owasp' => ['A02:2021 - Cryptographic Failures'],
            'confidence' => 'HIGH',
            'message' => 'CookieComponent encrypts with the \'cipher\' type (Cookie.type is not set, or is \'cipher\'), which is not secure. Set Cookie.type to \'aes\', Cookie.key to a random value of 32 bytes or more, and Security.useOpenSsl to true.',
        ],
        'cakephp2-config-cookie-key' => [
            'identifier' => '',
            'severity' => Severity::MEDIUM,
            'cwe' => ['CWE-321: Use of Hard-coded Cryptographic Key', 'CWE-326: Inadequate Encryption Strength'],
            'owasp' => ['A02:2021 - Cryptographic Failures'],
            'confidence' => 'HIGH',
            'message' => 'Cookie.key, the key of the \'aes\' and \'rijndael\' cookies, is a sample of the documentation or shorter than 32 bytes. Set COOKIE_KEY to a random value of 32 bytes or more.',
        ],
        'cakephp2-config-openssl' => [
            'identifier' => '',
            'severity' => Severity::LOW,
            'cwe' => ['CWE-1104: Use of Unmaintained Third Party Components'],
            'owasp' => ['A06:2021 - Vulnerable and Outdated Components'],
            'confidence' => 'HIGH',
            'message' => 'Security.useOpenSsl is not true: Security::encrypt() and the \'aes\' cookies use mcrypt, which is not maintained and not bundled with PHP 7.2+. Set Security.useOpenSsl to true.',
        ],
        'cakephp2-config-session-cookie' => [
            'identifier' => '',
            'severity' => Severity::MEDIUM,
            'cwe' => ['CWE-1004: Sensitive Cookie Without \'HttpOnly\' Flag', 'CWE-614: Sensitive Cookie in HTTPS Session Without \'Secure\' Attribute'],
            'owasp' => ['A05:2021 - Security Misconfiguration'],
            'confidence' => 'HIGH',
            'message' => 'The session cookie is configured without HttpOnly or Secure (session.cookie_httponly or session.cookie_secure is false in Session.ini). CakePHP sets both by default (Secure on HTTPS); remove the settings that turn them off.',
        ],
        'cakephp2-config-session-cache-limiter' => [
            'identifier' => '',
            'severity' => Severity::LOW,
            'cwe' => ['CWE-525: Use of Web Browser Cache Containing Sensitive Information'],
            'owasp' => ['A05:2021 - Security Misconfiguration'],
            'confidence' => 'HIGH',
            'message' => 'The pages with a session get no Cache-Control: no-store, as Session.cacheLimiter is not \'nocache\'. CakePHP 2 sets it to \'must-revalidate\' by default, for Internet Explorer 8 and before, which PHP does not know: PHP then sends no cache header. Set Session.cacheLimiter to \'nocache\', as CakePHP 5 leaves it.',
        ],
        'cakephp2-framework-protocol-relative-here' => [
            'identifier' => '',
            'severity' => Severity::MEDIUM,
            'cwe' => ["CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"],
            'owasp' => ['A06:2021 - Vulnerable and Outdated Components'],
            'confidence' => 'HIGH',
            'message' => 'The installed CakePHP keeps the leading // of the path of the request in $this->request->here() (pieceofcake2/cakephp before 2.12.11, cakephp/cakephp before 3.4.0, GHSA-wh43-gc93-wh4c): a redirect to it, or a URL built from it, can go to another site, e.g. //evil.example. Update to pieceofcake2/cakephp 2.12.11 or later.',
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
            if ($rule['identifier'] !== '' && $rule['identifier'] === $identifier) {
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
