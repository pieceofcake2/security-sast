<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr\Array_;
use PhpParser\Node\Expr\ConstFetch;
use PhpParser\Node\Scalar\String_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\Rule;

/**
 * `cakephp2-security-csrf-disabled`: the CSRF check or the form tampering check turned off in the settings of
 * `SecurityComponent`, `$components = ['Security' => ['csrfCheck' => false]]`. `SecurityCsrfDisabledRule` finds
 * the assignments.
 *
 * @implements \PHPStan\Rules\Rule<\PhpParser\Node\Expr\Array_>
 */
final class SecuritySettingsRule implements Rule
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
            if (!$item->key instanceof String_ || $item->key->value !== 'Security' || !$item->value instanceof Array_) {
                continue;
            }
            foreach ($item->value->items as $setting) {
                if (
                    $setting->key instanceof String_ && in_array($setting->key->value, ['csrfCheck', 'validatePost'], true)
                    && $setting->value instanceof ConstFetch && $setting->value->name->toLowerString() === 'false'
                ) {
                    return [Nodes::error('cakephp2-security-csrf-disabled')];
                }
            }
        }

        return [];
    }
}
