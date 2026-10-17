<?php $back = $this->Html->link('Back', '/'); ?>
<p><?= $back ?></p>
<?php $count = count($posts); ?>
<p><?= $count ?></p>
<?php $id = (int)$post['Post']['id']; ?>
<p><?= $id ?></p>
<?php $name = h($post['Post']['name']); ?>
<p><?= $name ?></p>
<div><?= $content_for_layout ?></div>
<div><?= $body_html ?></div>
<?php $summary = $post['Post']['summary']; ?>
<p><?= $summary ?></p>
<?php
if (!isset($params['escape']) || $params['escape'] !== false) {
    $message = h($message);
}
?>
<p><?= $message ?></p>
