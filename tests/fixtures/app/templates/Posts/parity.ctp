<?php
$name = '';
if (!empty($user)) {
    $name = $user['User']['name'];
}
?>
<p><?= $name ?></p>
<p><?= $labels[$post['Post']['status']] ?></p>
<?php
$width = 3;
$ratio = 1.5;
$offset = -2;
$hex = 0x1F;
$page = (int)$this->request->query('page');
$total = '';
if (!empty($posts)) {
    $total = 10;
}
$level = $post['Post']['level'];
$unit = 3 . $post['Post']['unit'];
?>
<p><?= $width ?> <?= $ratio ?> <?= $offset ?> <?= $hex ?></p>
<p><?php echo (int)$level; ?></p>
<p><?= (float)$post['Post']['price'] ?></p>
<p><?= (integer)$this->request->query('page') ?></p>
<p><?= $page ?></p>
<p><?= $total ?></p>
<p><?= $level ?></p>
<p><?= $unit ?></p>
<p><?= (string)$level ?></p>
<p><?= (bool)$this->request->query('q') ?></p>
