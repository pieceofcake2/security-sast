<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\PHPStan;

use PhpParser\Node;
use PhpParser\Node\Expr;
use PhpParser\Node\Expr\ArrayDimFetch;
use PhpParser\Node\Expr\Assign;
use PhpParser\Node\Expr\Cast\Double;
use PhpParser\Node\Expr\Cast\Int_;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\PropertyFetch;
use PhpParser\Node\Expr\Variable;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Echo_;
use PhpParser\NodeFinder;
use PhpParser\PrettyPrinter\Standard;
use PHPStan\Analyser\Scope;
use PHPStan\Node\FileNode;
use PHPStan\Rules\Rule;
use PieceOfCake2\SecuritySast\Views;

/**
 * `cakephp2-view-unescaped-output`: a variable printed in a view without `h()` (see `Views`).
 *
 * Like the rule of Semgrep, it leaves out a variable that holds the output of a helper, an escaped value or a
 * number, and the safe variables.
 *
 * @implements \PHPStan\Rules\Rule<\PHPStan\Node\FileNode>
 */
final class ViewUnescapedOutputRule implements Rule
{
    /**
     * Constructor
     *
     * @param array<string> $extensions Extensions of the views, without the dot
     * @param array<string> $safeVariables Variables that the views may print without h(), e.g. `body_html`
     * @param string $project Directory of the project: the directories of views are those of the paths in it, not
     *  those of the project itself, e.g. /home/templates/app
     */
    public function __construct(private array $extensions = Views::EXTENSIONS, private array $safeVariables = [], private string $project = '')
    {
    }

    /**
     * @inheritDoc
     */
    public function getNodeType(): string
    {
        return FileNode::class;
    }

    /**
     * @inheritDoc
     */
    public function processNode(Node $node, Scope $scope): array
    {
        $file = $scope->getFile();
        $prefix = rtrim($this->project, '/\\') . DIRECTORY_SEPARATOR;
        if ($this->project !== '' && str_starts_with($file, $prefix)) {
            $file = substr($file, strlen($prefix));
        }
        if (!Views::isView($file, $this->extensions)) {
            return [];
        }
        $safeNames = array_merge(Views::SAFE_VARIABLES, array_map(static fn(string $name): string => ltrim($name, '$'), $this->safeVariables));
        $printer = new Standard();
        $safe = [];
        $errors = [];
        // In the order of the file: an assignment comes before the echo that it makes safe
        $found = (new NodeFinder())->find($node->getNodes(), static fn(Node $node): bool => $node instanceof Assign || $node instanceof Echo_);
        usort($found, static fn(Node $a, Node $b): int => $a->getStartFilePos() <=> $b->getStartFilePos());
        foreach ($found as $statement) {
            if ($statement instanceof Assign) {
                $safe[$printer->prettyPrintExpr($statement->var)] = self::isSafe($statement->expr);
                continue;
            }
            if (!$statement instanceof Echo_) {
                continue;
            }
            foreach ($statement->exprs as $expr) {
                $root = $expr;
                while ($root instanceof ArrayDimFetch || ($root instanceof PropertyFetch && $root->name instanceof Identifier)) {
                    $root = $root->var;
                }
                if (
                    $root instanceof Variable && is_string($root->name) && $root->name !== 'this'
                    && !in_array($root->name, $safeNames, true)
                    && !($safe[$printer->prettyPrintExpr($expr)] ?? false)
                ) {
                    $errors[] = Nodes::error('cakephp2-view-unescaped-output', $statement->getStartLine());
                    break;
                }
            }
        }

        return $errors;
    }

    /**
     * Whether a value is safe to print: the output of a helper, an escaped value or a number
     *
     * @param \PhpParser\Node\Expr $expr Value
     * @return bool
     */
    private static function isSafe(Expr $expr): bool
    {
        if ($expr instanceof Int_ || $expr instanceof Double) {
            return true;
        }
        if ($expr instanceof FuncCall && $expr->name instanceof Name) {
            return in_array(strtolower($expr->name->toString()), ['h', 'count'], true);
        }

        return $expr instanceof MethodCall && $expr->var instanceof PropertyFetch
            && $expr->var->var instanceof Variable && $expr->var->var->name === 'this';
    }
}
