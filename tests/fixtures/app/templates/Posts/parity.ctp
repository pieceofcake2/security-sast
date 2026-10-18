<?php
$name = '';
if (!empty($user)) {
    $name = $user['User']['name'];
}
?>
<p><?= $name ?></p>
<p><?= $labels[$post['Post']['status']] ?></p>
