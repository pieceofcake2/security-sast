<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;

/**
 * `cakephp2-conditions-string`: a conditions string with a variable, as `['conditions' => "..."]` or in the list
 * of a conditions array.
 *
 * @implements \PHPStan\Rules\Rule<\PhpParser\Node\Expr\Array_>
 */
final class ConditionsStringRule implements Rule
{
    /**
     * @inheritDoc
     */
    public function getNodeType(): string
    {
        return Array_::class;
    }

    /**
     * @inheritDoc
     */
    public function processNode(Node $node, Scope $scope): array
    {
        foreach ($node->items as $item) {
            if (!$item->key instanceof String_ || $item->key->value !== 'conditions') {
                continue;
            }
            if (Nodes::isStringWithVariable($item->value)) {
                return [Nodes::error('cakephp2-conditions-string')];
            }
            if ($item->value instanceof Array_) {
                foreach ($item->value->items as $condition) {
                    // A string without a key, or a key with a variable: CakePHP escapes the values only
                    if (($condition->key === null && Nodes::isStringWithVariable($condition->value)) || ($condition->key !== null && Nodes::isStringWithVariable($condition->key))) {
                        return [Nodes::error('cakephp2-conditions-string')];
                    }
                }
            }
        }

        return [];
    }
}
