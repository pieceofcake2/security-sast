<?php
class PostHelper extends AppHelper
{
    public function title($post)
    {
        $title = h($post['Post']['title']);
        echo $title . $post['Post']['id'];
    }
}
