<?php
$q = $this->request->query('q');
$name = $this->Session->read('Auth.User.name');
$link = $this->Html->link('Back', '/');
?>
<p><?php echo $q; ?></p>
<p><?php echo $name; ?></p>
<p><?php echo $link; ?></p>
<p><?= $this->request->data['Post']['title'] ?></p>
<p><?= $this->data['Post']['title'] ?></p>
<p><?= h($this->request->query('q')) ?></p>
<p><?= $this->Html->link('Next', '/') ?></p>
