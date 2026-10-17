<?php
/**
 * A controller with vulnerable code, for the tests of the rules
 */
class PostsController extends AppController
{
    public $components = ['Security'];

    public function beforeFilter()
    {
        parent::beforeFilter();
        $this->Security->csrfCheck = false;
        $this->Security->validatePost = false;
    }

    public function search()
    {
        $q = $this->request->query('q');
        $posts = $this->Post->query("SELECT * FROM posts WHERE title LIKE '%" . $q . "%'");
        $more = $this->Post->query("SELECT * FROM posts WHERE id = $q");
        $safe = $this->Post->query('SELECT * FROM posts WHERE id = ?', [$q]);
        $found = $this->Post->find('all', ['conditions' => "Post.title = '$q'"]);
        $ok = $this->Post->find('all', ['conditions' => ['Post.title' => $q]]);
        $this->set(compact('posts', 'more', 'safe', 'found', 'ok'));
    }

    public function back()
    {
        return $this->redirect($this->request->query('url'));
    }

    public function backData()
    {
        return $this->redirect($this->request->data['Post']['url']);
    }

    public function page()
    {
        $this->render($this->request->query('page'));
    }

    public function import()
    {
        $xml = Xml::build($this->request->data('xml'));
        $safe = Xml::build('<root/>');
        $data = unserialize($this->request->data('payload'));
        $this->set(compact('xml', 'safe', 'data'));
    }
}
