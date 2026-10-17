<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;

/**
 * `cakephp2-conditions-string`: a conditions string with a variable passed to `Model::deleteAll()` (its first
 * argument) or `Model::updateAll()` (its second argument). The `conditions` of the options are checked by
 * `ConditionsStringRule`.
 *
 * @implements \PHPStan\Rules\Rule<\PhpParser\Node\Expr\MethodCall>
 */
final class ConditionsArgumentRule implements Rule
{
    /**
     * The argument of the conditions, by method
     */
    private const ARGUMENTS = ['deleteall' => 0, 'updateall' => 1];

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
        if (!Nodes::isMethod($node, array_keys(self::ARGUMENTS))) {
            return [];
        }
        $args = $node->getArgs();
        $index = self::ARGUMENTS[$node->name instanceof Node\Identifier ? $node->name->toLowerString() : ''] ?? null;
        if ($index === null || !isset($args[$index]) || !Nodes::isStringWithVariable($args[$index]->value)) {
            return [];
        }

        return [Nodes::error('cakephp2-conditions-string')];
    }
}
