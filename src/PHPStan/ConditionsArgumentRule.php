<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;

/**
 * `cakephp2-conditions-string`: a conditions string with a variable passed to `Model::deleteAll()` and
 * `Model::hasAny()` (their first argument), `Model::updateAll()` and `Model::field()` (their second argument), or
 * as a value of the fields of `updateAll()`. The `conditions` of the options are checked by
 * `ConditionsStringRule`.
 *
 * @implements \PHPStan\Rules\Rule<\PhpParser\Node\Expr\MethodCall>
 */
final class ConditionsArgumentRule implements Rule
{
    /**
     * The argument of the conditions, by method
     */
    private const ARGUMENTS = ['deleteall' => 0, 'updateall' => 1, 'field' => 1, 'hasany' => 0];

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
        // The fields of updateAll() are SQL too: ['Post.title' => "'" . $title . "'"]
        if ($index === 1 && $node->name instanceof Node\Identifier && $node->name->toLowerString() === 'updateall' && isset($args[0]) && $args[0]->value instanceof Node\Expr\Array_) {
            foreach ($args[0]->value->items as $item) {
                if (Nodes::isStringWithVariable($item->value)) {
                    return [Nodes::error('cakephp2-conditions-string')];
                }
            }
        }
        if ($index === null || !isset($args[$index]) || !Nodes::isStringWithVariable($args[$index]->value)) {
            return [];
        }

        return [Nodes::error('cakephp2-conditions-string')];
    }
}
