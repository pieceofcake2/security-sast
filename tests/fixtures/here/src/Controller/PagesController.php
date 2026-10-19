<?php
/**
 * Redirects to here() of the request, for the tests of the CakePHP of composer.lock: with pieceofcake2/cakephp
 * 2.12.11+, here() is a path of the application
 */
class PagesController extends AppController
{
    public function here()
    {
        // Not reported with a fixed CakePHP
        $this->redirect($this->request->here());
        $this->redirect($this->request->here(false));
        $this->redirect($this->request->here);
        $this->redirect($this->request->here() . '?page=2');
        // Reported with any CakePHP
        $this->redirect($this->request->here() . $this->request->query('back'));
        $this->redirect($this->request->query('back') . $this->request->here());
        $this->redirect($_GET['back'] . $this->request->here);
        $this->redirect($this->request->webroot);
        $this->redirect($this->request->here($this->request->query('base')));
    }
}
