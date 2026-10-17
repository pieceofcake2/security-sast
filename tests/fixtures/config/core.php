<?php
Configure::write('debug', 2);
Configure::write('Security.salt', 'DYhG93b0qyJfIxfs2guVoUubWwvniR2G0FgaC9mi');
Configure::write('Security.cipherSeed', '76859309657453542496749683645');
Configure::write('Cookie.type', 'cipher');
Configure::write('Security.useOpenSsl', false);
Configure::write('Session', ['defaults' => 'php', 'ini' => ['session.cookie_httponly' => false]]);
