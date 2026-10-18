<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;

/**
 * `cakephp2-query-concatenation`: SQL built from a string with a variable passed to `Model::query()`.
 *
 * @implements \PHPStan\Rules\Rule<\PhpParser\Node\Expr\MethodCall>
 */
final class QueryConcatenationRule implements Rule
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
        if (!Nodes::isMethod($node, ['query', 'fetchall', 'execute']) || Nodes::isThisProperty($node->var, 'request')) {
            return [];
        }
        $args = $node->getArgs();
        if ($args === [] || !Nodes::isStringWithVariable($args[0]->value)) {
            return [];
        }

        return [Nodes::error('cakephp2-query-concatenation')];
    }
}
