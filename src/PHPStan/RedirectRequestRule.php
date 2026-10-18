<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\Variable;
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

        return [Nodes::error('cakephp2-redirect-request')];
    }
}
