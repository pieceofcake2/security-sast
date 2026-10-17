<?php
return [
    'report' => ['language' => 'ja', 'dir' => 'tmp/security', 'project' => 'Acme'],
    'sca' => ['failOn' => 'critical'],
    'sast' => ['engine' => 'phpstan', 'failOn' => 'medium', 'paths' => ['src', 'templates'], 'viewExtensions' => ['ctp', 'php', 'html'], 'safeViewVariables' => ['body_html']],
];
