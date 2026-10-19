<?php // Body HTML that the application sanitized when it was saved ?>
<div><?= raw($post['Post']['body_html']) ?></div>
<?php echo raw($this->Text->autoParagraph($post['Post']['body_html'])); ?>
<p><?= h($post['Post']['title']) ?></p>
