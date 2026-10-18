<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\BinaryOp\Coalesce;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;

/**
 * `cakephp2-order-request`: a value of the request as the `order`, `fields` or `group` of the options of `find()` or
 * of `paginate`, which CakePHP puts into the SQL as names. A lookup in a list of allowed values,
 * `$columns[$this->request->query('sort')] ?? 'Post.id'`, is not reported.
 *
 * @implements \PHPStan\Rules\Rule<\PhpParser\Node\Expr\Array_>
 */
final class OrderRequestRule implements Rule
{
    /**
     * The options that are names of the SQL
     */
    public const OPTIONS = ['order', 'fields', 'group'];

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
            if (!$item->key instanceof String_ || !in_array($item->key->value, self::OPTIONS, true)) {
                continue;
            }
            if (Nodes::hasRequestValue($item->value) && !self::isLookup($item->value)) {
                return [Nodes::error('cakephp2-order-request')];
            }
        }

        return [];
    }

    /**
     * Whether a value is a lookup of the request in an array, with a default or not
     *
     * @param \PhpParser\Node\Expr $expr Value
     * @return bool
     */
    private static function isLookup(Expr $expr): bool
    {
        if ($expr instanceof Coalesce) {
            $expr = $expr->left;
        }

        return $expr instanceof ArrayDimFetch && !Nodes::hasRequestValue($expr->var);
    }
}
