<?php
$docsUrl = 'https://example.com/docs/';
$title = __('Posts');
$label = __d('blog', 'Label');
$name = "x$foo";
$greeting = __('Hello %s', $user);
$other = __d('blog', $text);
?>
<a href="<?php echo $docsUrl; ?>"><?php echo $title; ?></a>
<?php echo $label; ?>
<?php echo $name; ?>
<?php echo $greeting; ?>
<?php echo $other; ?>
