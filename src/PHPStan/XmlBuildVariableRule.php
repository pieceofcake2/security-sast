<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;

/**
 * `cakephp2-xml-build-variable`: `Xml::build()` with a variable, without `['readFile' => false]`.
 *
 * @implements \PHPStan\Rules\Rule<\PhpParser\Node\Expr\StaticCall>
 */
final class XmlBuildVariableRule implements Rule
{
    /**
     * @inheritDoc
     */
    public function getNodeType(): string
    {
        return StaticCall::class;
    }

    /**
     * @inheritDoc
     */
    public function processNode(Node $node, Scope $scope): array
    {
        if (!$node->class instanceof Name || $node->class->getLast() !== 'Xml' || !$node->name instanceof Identifier || $node->name->toLowerString() !== 'build') {
            return [];
        }
        $args = $node->getArgs();
        if ($args === [] || $args[0]->value instanceof String_) {
            return [];
        }
        $options = $args[1]->value ?? null;
        if ($options instanceof Array_) {
            foreach ($options->items as $item) {
                if ($item->key instanceof String_ && $item->key->value === 'readFile' && $item->value instanceof ConstFetch && $item->value->name->toLowerString() === 'false') {
                    return [];
                }
            }
        }

        return [Nodes::error('cakephp2-xml-build-variable')];
    }
}
