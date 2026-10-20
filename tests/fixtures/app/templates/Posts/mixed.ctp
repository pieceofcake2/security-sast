<?php
// PHP and HTML: the alternative syntax, the short echo, braces closed in their own tags, quotes in the text
?>
<?php if (!empty($posts)): ?>
	<ul>
	<?php foreach ($posts as $post): ?>
		<li><a href="/posts/<?= $post['Post']['id'] ?>"><?= $post['Post']['title'] ?></a></li>
	<?php endforeach; ?>
	</ul>
<?php elseif ($draft): ?>
	<p>Don't publish what isn't ready: <?php echo $draft['Post']['title']; ?></p>
<?php else: ?>
	<p>There's nothing yet.</p>
<?php endif; ?>
<?php if ($user) { ?>
	<p class="user"><?php echo $user['User']['name'] ?></p>
<?php } else { ?>
	<p><?= h($message) ?></p>
<?php } ?>
<script>var title = '<?php echo $jsTitle; ?>';</script>
<p><?=$post['Post']['summary']?></p>
<p>Read the <a href="http://example.com/">news</a>.</p>
