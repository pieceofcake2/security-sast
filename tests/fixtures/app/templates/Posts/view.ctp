<h1><?= h($post['Post']['title']) ?></h1>
<div><?= $post['Post']['body'] ?></div>
<p><?php echo $post['Post']['summary']; ?></p>
<p><?php echo h($post['Post']['summary']); ?></p>
<p><?= $this->Html->link('Back', '/') ?></p>
