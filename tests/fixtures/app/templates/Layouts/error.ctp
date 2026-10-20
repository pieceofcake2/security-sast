<?php
/**
 * A layout as the one of CakePHP(tm) : Rapid Development Framework (http://cakephp.org): PHP and HTML, which
 * Semgrep read with the rules of every language
 */
$cakeDescription = __d('cake_dev', 'CakePHP: the rapid development php framework');
?>
<!DOCTYPE html>
<html>
<head>
	<?php echo $this->Html->charset(); ?>
	<title>
		<?php echo $cakeDescription; ?>:
		<?php echo $title; ?>
	</title>
	<?php
        echo $this->Html->meta('icon');
        echo $this->fetch('css');
    ?>
</head>
<body>
	<div id="header">
		<h1><?php echo $this->Html->link($cakeDescription, 'http://cakephp.org'); ?></h1>
	</div>
	<div id="content">
		<?php echo $this->fetch('content'); ?>
	</div>
	<div id="footer">
		<?php echo $this->Html->link(
                $this->Html->image('cake.power.gif', ['alt' => $cakeDescription, 'border' => '0']),
                'http://www.cakephp.org/',
                ['target' => '_blank', 'escape' => false]
            );
        ?>
	</div>
</body>
</html>
