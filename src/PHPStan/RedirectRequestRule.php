<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;

/**
 * `cakephp2-redirect-request`: a value of the request passed to `$this->redirect()`.
 *
 * @implements \PHPStan\Rules\Rule<\PhpParser\Node\Expr\MethodCall>
 */
final class RedirectRequestRule implements Rule
{
    /**
     * @inheritDoc
     */
    public function getNodeType(): string
    {
        return MethodCall::class;
    }

    /**
     * @inheritDoc
     */
    public function processNode(Node $node, Scope $scope): array
    {
        if (!Nodes::isMethod($node, ['redirect']) || !$node->var instanceof Variable || $node->var->name !== 'this') {
            return [];
        }
        $args = $node->getArgs();
        // A route array is a URL of the application, whatever the values of the request in it
        if ($args === [] || $args[0]->value instanceof Node\Expr\Array_ || !Nodes::hasRequestValue($args[0]->value)) {
            return [];
        }
        if (self::isOwnOriginUrl($args[0]->value)) {
            return [];
        }

        return [Nodes::error('cakephp2-redirect-request')];
    }

    /**
     * Whether an expression is a URL of the own origin of the application: a concatenation that begins with
     * `Router::url('/', true)`, or with `Router::fullBaseUrl()` or `Configure::read('App.fullBaseUrl')` followed by
     * a path, which begins with `/`: `$this->request->here()`, `$this->request->here` or a string literal
     *
     * Whatever follows the path, even `//evil.example`, is in the path of the same host. Without the `/`, a value
     * of the request after the origin can change the host: `@evil.example`, `.evil.example`.
     *
     * @param \PhpParser\Node\Expr $expr Expression
     * @return bool
     */
    private static function isOwnOriginUrl(Expr $expr): bool
    {
        $parts = self::concatenated($expr);
        if (count($parts) < 2) {
            return false;
        }
        $router = self::staticCall($parts[0], 'Router', 'url', 2);
        if ($router !== null) {
            [$url, $full] = $router->getArgs();

            return $url->value instanceof String_ && $url->value->value === '/'
                && $full->value instanceof ConstFetch && $full->value->name->toLowerString() === 'true';
        }

        return self::isOrigin($parts[0]) && self::isPath($parts[1]);
    }

    /**
     * The operands of a concatenation, from the left
     *
     * @param \PhpParser\Node\Expr $expr Expression
     * @return array<\PhpParser\Node\Expr>
     */
    private static function concatenated(Expr $expr): array
    {
        if ($expr instanceof Concat) {
            return [...self::concatenated($expr->left), ...self::concatenated($expr->right)];
        }

        return [$expr];
    }

    /**
     * Whether an expression is the origin of the application: `Router::fullBaseUrl()` or
     * `Configure::read('App.fullBaseUrl')`
     *
     * @param \PhpParser\Node\Expr $expr Expression
     * @return bool
     */
    private static function isOrigin(Expr $expr): bool
    {
        if (self::staticCall($expr, 'Router', 'fullBaseUrl', 0) !== null) {
            return true;
        }
        $read = self::staticCall($expr, 'Configure', 'read', 1);
        if ($read === null) {
            return false;
        }
        $key = $read->getArgs()[0]->value;

        return $key instanceof String_ && $key->value === 'App.fullBaseUrl';
    }

    /**
     * Whether an expression is a path that begins with `/`: `$this->request->here()`, `$this->request->here` or
     * a string literal
     *
     * @param \PhpParser\Node\Expr $expr Expression
     * @return bool
     */
    private static function isPath(Expr $expr): bool
    {
        if ($expr instanceof String_) {
            return str_starts_with($expr->value, '/');
        }
        if (!$expr instanceof MethodCall && !$expr instanceof PropertyFetch) {
            return false;
        }

        return Nodes::isThisProperty($expr->var, 'request')
            && $expr->name instanceof Identifier && $expr->name->toLowerString() === 'here';
    }

    /**
     * The expression, when it is a call of a static method with a number of arguments, of a class written
     * without a namespace, as Semgrep finds it (`Router::url()`, not `\Router::url()`)
     *
     * @param \PhpParser\Node\Expr $expr Expression
     * @param string $class Class
     * @param string $method Method
     * @param int $count Number of the arguments
     * @return \PhpParser\Node\Expr\StaticCall|null
     */
    private static function staticCall(Expr $expr, string $class, string $method, int $count): ?StaticCall
    {
        if (!$expr instanceof StaticCall || !$expr->class instanceof Name || !$expr->name instanceof Identifier) {
            return null;
        }
        // The name as written, before PHPStan resolves it
        $name = $expr->class->getAttribute('originalName', $expr->class);
        if (!$name instanceof Name || $name->isFullyQualified() || $name->toString() !== $class) {
            return null;
        }

        return $expr->name->toLowerString() === strtolower($method) && count($expr->getArgs()) === $count ? $expr : null;
    }
}
