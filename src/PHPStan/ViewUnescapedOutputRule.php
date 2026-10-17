<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Stmt\Echo_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;

/**
 * `cakephp2-view-unescaped-output`: a variable printed in a view (`.ctp`) without `h()`.
 *
 * @implements \PHPStan\Rules\Rule<\PhpParser\Node\Stmt\Echo_>
 */
final class ViewUnescapedOutputRule implements Rule
{
    /**
     * @inheritDoc
     */
    public function getNodeType(): string
    {
        return Echo_::class;
    }

    /**
     * @inheritDoc
     */
    public function processNode(Node $node, Scope $scope): array
    {
        if (!str_ends_with($scope->getFile(), '.ctp')) {
            return [];
        }
        foreach ($node->exprs as $expr) {
            $root = $expr;
            while ($root instanceof ArrayDimFetch || $root instanceof PropertyFetch) {
                $root = $root->var;
            }
            if ($root instanceof Variable && $root->name !== 'this') {
                return [Nodes::error('cakephp2-view-unescaped-output')];
            }
        }

        return [];
    }
}
