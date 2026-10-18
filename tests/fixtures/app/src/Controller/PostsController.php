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

    public function remove()
    {
        $id = $this->request->query('id');
        $this->Post->deleteAll("Post.user_id = $id");
        $this->Post->updateAll(['Post.published' => 0], 'Post.user_id = ' . $id);
        $this->Post->deleteAll(['Post.user_id' => $id]);
        $this->Post->query('SELECT * FROM ' . 'posts' . " WHERE 1");
        $this->Post->query('SELECT * FROM posts WHERE id = ' . $id . ' LIMIT 1');
        $this->Post->query($this->table . $id);
        $this->Post->query(sprintf('SELECT * FROM posts WHERE id = %d', (int)$id));
        $this->Post->find('all', ['conditions' => ['Post.published' => 1, 'Post.id = ' . $id]]);
        $this->Post->find('all', ['conditions' => ['Post.title LIKE' => '%' . $id . '%']]);
        $this->Post->find('all', ['conditions' => ['Post.title' => "x$id"]]);
    }

    public function superglobals()
    {
        $this->element($_GET['element']);
        $data = unserialize($_COOKIE['data']);
        $this->set(compact('data'));

        return $this->redirect($_REQUEST['back']);
    }

    public function index()
    {
        $id = $this->request->query('id');
        $this->Post->find('all', ['recursive' => -1, 'conditions' => "Post.id = $id"]);
        $this->paginate = ['limit' => 20, 'conditions' => 'Post.user_id = ' . $id];
        $this->Post->find('all', ['recursive' => -1, 'conditions' => ['Post.published' => 1, "Post.id = $id"]]);
        $this->Post->find('all', ['limit' => 1, 'conditions' => ['Post.id' => $id]]);
    }

    public function parity()
    {
        $id = $this->request->query('id');
        $this->Post->query(<<<SQL
SELECT * FROM posts WHERE id = $id
SQL
        );
        $data = unserialize($this->request['data']['payload']);
        $this->Post->updateAll(['Post.published' => 1], sprintf('Post.id = %d', 'a' . $id));
        $this->Post->query($id ? 'SELECT * FROM posts WHERE id = ' . $id : 'SELECT 1');
        $this->Post->find('all', ['conditions' => ['Post.' . $id => 1]]);
        $this->Post->query('SELECT * FROM posts WHERE price > ' . "$1");
        $this->set(compact('data'));
    }
}
