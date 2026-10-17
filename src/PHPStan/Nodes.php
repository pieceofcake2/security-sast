<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\BinaryOp\Concat;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Scalar\InterpolatedString;
use PhpParser\NodeFinder;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\RuleErrorBuilder;
use PieceOfCake2\SecuritySast\RuleCatalog;

/**
 * Checks of the nodes that the rules share.
 */
final class Nodes
{
    /**
     * The superglobals of the request
     */
    public const SUPERGLOBALS = ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES'];

    /**
     * Whether a node holds a value of the request: `$this->request` or a superglobal of the request
     *
     * @param \PhpParser\Node $node Node
     * @return bool
     */
    public static function hasRequestValue(Node $node): bool
    {
        return (new NodeFinder())->findFirst($node, static function (Node $node): bool {
            if (self::isThisProperty($node, 'request')) {
                return true;
            }

            return $node instanceof Variable && is_string($node->name) && in_array($node->name, self::SUPERGLOBALS, true);
        }) !== null;
    }

    /**
     * Whether an expression is a string built with a variable: a concatenation or a double-quoted string with a
     * variable in it
     *
     * @param \PhpParser\Node\Expr $expr Expression
     * @return bool
     */
    public static function isStringWithVariable(Expr $expr): bool
    {
        if ($expr instanceof InterpolatedString) {
            return true;
        }

        return $expr instanceof Concat && !self::isLiteral($expr);
    }

    /**
     * Whether a concatenation is of string literals only
     *
     * @param \PhpParser\Node\Expr $expr Expression
     * @return bool
     */
    private static function isLiteral(Expr $expr): bool
    {
        if ($expr instanceof Concat) {
            return self::isLiteral($expr->left) && self::isLiteral($expr->right);
        }

        return $expr instanceof Node\Scalar\String_ || $expr instanceof Node\Scalar\Int_ || $expr instanceof Node\Scalar\Float_;
    }

    /**
     * Whether a node is `$this->$name`
     *
     * @param \PhpParser\Node $node Node
     * @param string $name Property
     * @return bool
     */
    public static function isThisProperty(Node $node, string $name): bool
    {
        return $node instanceof PropertyFetch
            && $node->var instanceof Variable && $node->var->name === 'this'
            && $node->name instanceof Identifier && $node->name->toString() === $name;
    }

    /**
     * Whether a node is a call of a method of one of the names
     *
     * @param \PhpParser\Node\Expr\MethodCall $node Call
     * @param array<string> $names Names, in lower case
     * @return bool
     */
    public static function isMethod(Expr\MethodCall $node, array $names): bool
    {
        return $node->name instanceof Identifier && in_array($node->name->toLowerString(), $names, true);
    }

    /**
     * The error of a rule of the catalog
     *
     * @param string $id ID of the rule
     * @param int|null $line Line, when not the line of the node
     * @return \PHPStan\Rules\IdentifierRuleError
     */
    public static function error(string $id, ?int $line = null): IdentifierRuleError
    {
        $error = RuleErrorBuilder::message(RuleCatalog::message($id))->identifier(RuleCatalog::RULES[$id]['identifier']);
        if ($line !== null) {
            $error = $error->line($line);
        }

        return $error->build();
    }
}
