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
        // The views of another extension than .php in their copies as PHP
        $this->assertSame(['**/templates/**/*.ctp.php', '**/View/**/*.ctp.php', '**/templates/**/*.php', '**/View/**/*.php'], Views::semgrepIncludes());
        $this->assertSame(['**/templates/**/*.html.php', '**/View/**/*.html.php'], Views::semgrepIncludes(['html']));
    }

    public function testTextMails(): void
    {
        $this->assertFalse(Views::isView('templates/Emails/text/default.ctp'));
        $this->assertFalse(Views::isView('app/View/Emails/text/default.ctp'));
        // The classes of the directories of views
        $this->assertFalse(Views::isView('src/View/AppView.php'));
        $this->assertFalse(Views::isView('app/View/Helper/PostHelper.php'));
        $this->assertTrue(Views::isView('app/View/Posts/view.php'));
        $this->assertTrue(Views::isView('templates/Emails/html/default.ctp'));
    }

    public function testRulesOfSemgrep(): void
    {
        $yaml = SemgrepEngine::rules(['ctp', 'html']);

        $this->assertStringContainsString("    paths:\n      include:\n        - \"**/templates/**/*.ctp.php\"\n        - \"**/View/**/*.ctp.php\"\n        - \"**/templates/**/*.html.php\"\n        - \"**/View/**/*.html.php\"\n      # The text mails are not HTML\n      exclude:\n        - \"**/Emails/text/**\"\n        # The classes of the directories of views: the helpers, and the views, e.g. View/AppView.php\n        - \"**/View/Helper/**\"\n        - \"**/View/*View.php\"\n    metadata:", $yaml);
        // The rules of the views: the unescaped output and raw()
        $this->assertSame(2, substr_count($yaml, 'include:'));
    }
}
