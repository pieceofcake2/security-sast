<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\Variable;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;

/**
 * `cakephp2-render-request`: a value of the request passed to `$this->render()` or `$this->element()`.
 *
 * @implements \PHPStan\Rules\Rule<\PhpParser\Node\Expr\MethodCall>
 */
final class RenderRequestRule implements Rule
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
        if (!Nodes::isMethod($node, ['render', 'element']) || !$node->var instanceof Variable || $node->var->name !== 'this') {
            return [];
        }
        $args = $node->getArgs();
        if ($args === [] || !Nodes::hasRequestValue($args[0]->value)) {
            return [];
        }

        return [Nodes::error('cakephp2-render-request')];
    }
}
