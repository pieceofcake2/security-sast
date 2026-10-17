<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Name;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;

/**
 * `cakephp2-unserialize-request`: a value of the request passed to `unserialize()`.
 *
 * @implements \PHPStan\Rules\Rule<\PhpParser\Node\Expr\FuncCall>
 */
final class UnserializeRequestRule implements Rule
{
    /**
     * @inheritDoc
     */
    public function getNodeType(): string
    {
        return FuncCall::class;
    }

    /**
     * @inheritDoc
     */
    public function processNode(Node $node, Scope $scope): array
    {
        if (!$node->name instanceof Name || $node->name->toLowerString() !== 'unserialize') {
            return [];
        }
        $args = $node->getArgs();
        if ($args === [] || !Nodes::hasRequestValue($args[0]->value)) {
            return [];
        }

        return [Nodes::error('cakephp2-unserialize-request')];
    }
}
