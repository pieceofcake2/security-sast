<?php
/**
 * Values of the request passed to unserialize(), with the comments that suppress the findings in different ways,
 * for the tests of Suppressions against the engines
 */
class SuppressedController extends AppController
{
    public function semgrep()
    {
        // nosemgrep: cakephp2-unserialize-request
        $a = unserialize($_GET['a']);

        // nosemgrep: rules.cakephp2-unserialize-request
        $b = unserialize($_GET['b']);

        // nosemgrep: cakephp2-unserialize-request
        // A comment between the suppression and the code
        $c = unserialize($_GET['c']);

        $d = unserialize($_GET['d']); // nosemgrep

        $e = unserialize($_GET['e']); // nosem

        // We never use nosemgrep here
        $f = unserialize($_GET['f']);

        $g = unserialize($_GET['g'] . ' nosemgrep');

        $this->set(compact('a', 'b', 'c', 'd', 'e', 'f', 'g'));
    }

    public function phpstan()
    {
        // @phpstan-ignore securitySast.unserializeRequest
        $a = unserialize($_GET['a']);

        // @phpstan-ignore securitySast.unserializeRequest
        // A comment between the suppression and the code
        $b = unserialize($_GET['b']);

        // @phpstan-ignore-next-line

        $c = unserialize($_GET['c']);

        $d = unserialize($_GET['d']); // @phpstan-ignore securitySast.unserializeRequest (signed by the server)

        $this->set(compact('a', 'b', 'c', 'd'));
    }
}
