<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Identifier;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;

/**
 * `cakephp2-security-csrf-disabled`: `$this->Security->csrfCheck = false` or `validatePost = false`.
 *
 * @implements \PHPStan\Rules\Rule<\PhpParser\Node\Expr\Assign>
 */
final class SecurityCsrfDisabledRule implements Rule
{
    /**
     * @inheritDoc
     */
    public function getNodeType(): string
    {
        return Assign::class;
    }

    /**
     * @inheritDoc
     */
    public function processNode(Node $node, Scope $scope): array
    {
        $var = $node->var;
        if (
            !$var instanceof PropertyFetch
            || !$var->name instanceof Identifier
            || !in_array($var->name->toString(), ['csrfCheck', 'validatePost'], true)
            || !Nodes::isThisProperty($var->var, 'Security')
            || !$node->expr instanceof ConstFetch
            || $node->expr->name->toLowerString() !== 'false'
        ) {
            return [];
        }

        return [Nodes::error('cakephp2-security-csrf-disabled')];
    }
}
