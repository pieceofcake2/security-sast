<?php
/**
 * Writes the sample reports of the documentation from the recorded scan of a fictional application
 * (`report-sample.json`), with the report of this version:
 *
 *     php docs/examples/report-sample.php
 *
 * It writes `docs/public/report-sample.pdf` and `report-sample-ja.pdf`, and, with `pdftoppm` (Poppler) and
 * `magick` (ImageMagick), the images of their first pages, `docs/img/report-sample.png` and `report-sample-ja.png`.
 * The rules of Semgrep that ran (`engineRules`) are those of a scan of the fixture application of the tests with
 * `--time`, which `--record` makes again with Semgrep in Docker (the Samples workflow):
 *
 *     php docs/examples/report-sample.php --record
 */
declare(strict_types=1);

use PieceOfCake2\Report\Environment;
use PieceOfCake2\Report\ReportWriter;
use PieceOfCake2\Report\Row;
use PieceOfCake2\SecuritySast\Config;
use PieceOfCake2\SecuritySast\Finding;
use PieceOfCake2\SecuritySast\ReportBuilder;
use PieceOfCake2\SecuritySast\RuleCatalog;
use PieceOfCake2\SecuritySast\ScanResult;
use PieceOfCake2\SecuritySast\SemgrepEngine;

$root = dirname(__DIR__, 2);
require $root . '/vendor/autoload.php';

/** @var array<string, mixed> $scan */
$scan = json_decode((string)file_get_contents(__DIR__ . '/report-sample.json'), true, 512, JSON_THROW_ON_ERROR);

if (in_array('--record', $argv, true)) {
    $result = (new SemgrepEngine($scan['semgrepImage']))->scan($root . '/tests/fixtures/app', ['src', 'templates']);
    $scan['engine'] = $result->engine;
    $scan['engineRules'] = $result->engineRules;
    file_put_contents(__DIR__ . '/report-sample.json', json_encode($scan, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
    printf("%s: %d rules\n", $result->engine, count($result->engineRules ?? []));
    exit(0);
}

// The pages of the image: the cover, the findings by risk, the checks and the page of a rule
$pages = [1, 2, 3, 4];

foreach (['en' => 'report-sample', 'ja' => 'report-sample-ja'] as $language => $name) {
    $findings = [];
    foreach ($scan['findings'] as $finding) {
        $rule = RuleCatalog::RULES[$finding['rule']];
        $findings[] = new Finding($finding['rule'], $rule['severity'], $rule['message'], $finding['file'], $finding['line'], $finding['line'], $finding['code'], $rule['cwe'], $rule['owasp'], $rule['confidence']);
    }
    $result = new ScanResult($findings, $scan['files'], $scan['engine'], [], $scan['configEnv'], $scan['paths'], [], $scan['engineRules'], [], $scan['notRun']);
    $config = new Config(project: $root . '/tests/fixtures/app', language: $language, projectName: $scan['project']);
    $doc = (new ReportBuilder(ReportBuilder::translator($language)))->build(
        $result,
        $config,
        new Environment(),
        new DateTimeImmutable($scan['startedAt'], new DateTimeZone('UTC')),
        new DateTimeImmutable($scan['finishedAt'], new DateTimeZone('UTC')),
    );
    // The software of the recorded scan, not of this machine
    $doc->run[count($doc->run) - 1] = new Row($doc->run[count($doc->run) - 1]->label, $scan['software']);

    $pdf = $root . '/docs/public/' . $name . '.pdf';
    (new ReportWriter())->write($doc, $pdf);
    echo $pdf . "\n";

    $png = $root . '/docs/img/' . $name . '.png';
    $dir = sys_get_temp_dir() . '/report-sample-' . bin2hex(random_bytes(4));
    mkdir($dir);
    $images = [];
    foreach ($pages as $page) {
        exec(sprintf('pdftoppm -png -scale-to-x 595 -scale-to-y 842 -f %d -l %d %s %s', $page, $page, escapeshellarg($pdf), escapeshellarg($dir . '/p' . $page)), $output, $code);
        $images = array_merge($images, glob($dir . '/p' . $page . '*.png') ?: []);
    }
    // The pages side by side on a grey background: 595 x 842 (A4 at 72 dpi), 12px apart from the edges and 24px
    // from each other
    exec(sprintf('magick %s -bordercolor "#e9e9e9" -border 12 +append %s', implode(' ', array_map('escapeshellarg', $images)), escapeshellarg($png)), $output, $code);
    array_map('unlink', glob($dir . '/*') ?: []);
    rmdir($dir);
    echo $png . "\n";
}
