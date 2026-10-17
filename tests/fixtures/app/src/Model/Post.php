<?php
/**
 * A model without vulnerable code
 */
class Post extends AppModel
{
    public function recent()
    {
        return $this->find('all', ['order' => ['Post.created' => 'DESC'], 'limit' => 10]);
    }
}
