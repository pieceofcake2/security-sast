<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast\Test;

use PHPUnit\Framework\TestCase;
use PieceOfCake2\SecuritySast\SemgrepEngine;
use PieceOfCake2\SecuritySast\Views;

class ViewsTest extends TestCase
{
    public function testIsView(): void
    {
        $this->assertTrue(Views::isView('templates/Posts/view.ctp'));
        $this->assertFalse(Views::isView('/app/src/Lib/legacy.ctp'));
        $this->assertTrue(Views::isView('/app/templates/Posts/index.php'));
        $this->assertTrue(Views::isView('app/View/Posts/index.php'));
        $this->assertTrue(Views::isView('plugins/Blog/templates/Posts/index.php'));
        $this->assertFalse(Views::isView('src/Controller/PostsController.php'));
        $this->assertFalse(Views::isView('templates/Elements/banner.html'));
        $this->assertTrue(Views::isView('templates/Elements/banner.html', ['ctp', 'php', 'html']));
        $this->assertFalse(Views::isView('templates/Posts/index.php', ['ctp']));
    }

    public function testSemgrepIncludes(): void
    {
        $this->assertSame(['**/templates/**/*.ctp', '**/View/**/*.ctp', '**/templates/**/*.php', '**/View/**/*.php'], Views::semgrepIncludes());
        $this->assertSame(['**/templates/**/*.html', '**/View/**/*.html'], Views::semgrepIncludes(['html']));
    }

    public function testRulesOfSemgrep(): void
    {
        $yaml = SemgrepEngine::rules(['ctp', 'html']);

        $this->assertStringContainsString("    paths:\n      include:\n        - \"**/templates/**/*.ctp\"\n        - \"**/View/**/*.ctp\"\n        - \"**/templates/**/*.html\"\n        - \"**/View/**/*.html\"\n    metadata:", $yaml);
        $this->assertSame(1, substr_count($yaml, 'include:'));
    }
}
