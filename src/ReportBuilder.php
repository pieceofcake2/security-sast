<?php
declare(strict_types=1);

namespace PieceOfCake2\SecuritySast;

use DateTimeImmutable;
use PieceOfCake2\Report\Count;
use PieceOfCake2\Report\Cover;
use PieceOfCake2\Report\Document;
use PieceOfCake2\Report\Environment;
use PieceOfCake2\Report\Group;
use PieceOfCake2\Report\Item;
use PieceOfCake2\Report\Row;
use PieceOfCake2\Report\Translator;
use PieceOfCake2\Report\Verdict;

/**
 * Builds the report of a scan: the rules that found places by risk, and a page for each rule with its places.
 */
final class ReportBuilder
{
    /**
     * The directory of the messages and the CSS of this package
     */
    public const RESOURCE_DIR = __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'resources';

    /**
     * The most places shown on the page of a rule
     */
    public const MAX_PLACES = 100;

    /**
     * Constructor
     *
     * @param \PieceOfCake2\Report\Translator $translator Messages
     */
    public function __construct(private Translator $translator)
    {
    }

    /**
     * The messages of the report in a language: those of pieceofcake2/report, of this package and of a directory
     *
     * @param string $language Language
     * @param string|null $localeDir Directory of more messages
     * @return \PieceOfCake2\Report\Translator
     */
    public static function translator(string $language, ?string $localeDir = null): Translator
    {
        return new Translator($language, [self::RESOURCE_DIR . DIRECTORY_SEPARATOR . 'locales', $localeDir]);
    }

    /**
     * The report of a scan
     *
     * @param \PieceOfCake2\SecuritySast\ScanResult $result Scan
     * @param \PieceOfCake2\SecuritySast\Config $config Settings
     * @param \PieceOfCake2\Report\Environment $environment Where it ran
     * @param \DateTimeImmutable $startedAt Start
     * @param \DateTimeImmutable $finishedAt End
     * @return \PieceOfCake2\Report\Document
     */
    public function build(ScanResult $result, Config $config, Environment $environment, DateTimeImmutable $startedAt, DateTimeImmutable $finishedAt): Document
    {
        $cover = new Cover($this->translator);
        $title = $config->title ?? $this->t('title');
        $project = $config->projectName ?? self::projectName($config->project) ?? Cover::rootPackage();
        $passed = !$result->fails($config->failOn);

        $counts = [new Count(count($result->findings), $this->t('count.findings'))];
        $bySeverity = array_fill_keys(Severity::ALL, 0);
        foreach ($result->findings as $finding) {
            $bySeverity[$finding->severity]++;
        }
        foreach ($bySeverity as $severity => $count) {
            if ($severity !== Severity::UNKNOWN || $count > 0) {
                $counts[] = new Count($count, $this->t('severity.' . $severity), $count > 0 ? 't-' . $severity : '');
            }
        }

        $target = $cover->target($environment);
        $target[] = new Row($this->t('field.paths'), implode('　', $result->paths !== [] ? $result->paths : $config->paths()), monoValue: true);
        $target[] = new Row($this->t('field.files'), (string)$result->files);
        $rules = ['pieceofcake2/security-sast (CakePHP 2)'];
        if ($config->engine === 'semgrep') {
            array_push($rules, ...$config->semgrepConfigs);
        }
        $target[] = new Row($this->t('field.rules'), implode('　', $rules));
        if ($result->suppressed !== []) {
            $target[] = new Row($this->t('field.suppressed'), $this->t('suppressed.count', ['count' => count($result->suppressed)]));
        }
        $target[] = new Row($this->t('field.config'), $result->configEnv !== null ? $this->t('config.env', ['env' => $result->configEnv]) : $this->t('config.none'));
        $target[] = new Row($this->t('field.threshold'), $config->failOn === 'none'
            ? $this->t('threshold.none')
            : $this->t('threshold.value', ['severity' => $this->t('severity.' . $config->failOn)]));

        $software = ['PHP ' . PHP_VERSION, $result->engine, Cover::package('pieceofcake2/security-sast')];

        $notes = [];
        if ($result->findings === []) {
            $notes[] = $this->t('note.none');
        }
        if ($result->errors !== []) {
            $notes[] = $this->t('note.errors', ['count' => count($result->errors), 'first' => mb_strimwidth($result->errors[0], 0, 200, '…')]);
        }
        if ($config->note !== null) {
            $notes[] = $config->note;
        }

        return new Document(
            title: $title,
            verdict: new Verdict($passed, $this->t($passed ? 'verdict.passed' : 'verdict.failed'), $counts),
            columns: [$this->t('field.no'), $this->t('field.rule'), $this->t('field.risk'), $this->t('field.count')],
            groups: $this->groups($result),
            project: $project,
            target: $target,
            run: array_merge(
                $cover->run($startedAt, $finishedAt, (float)$finishedAt->format('U.u') - (float)$startedAt->format('U.u'), $environment),
                [new Row($this->t('field.software'), implode('　', array_filter($software)))],
            ),
            note: $notes === [] ? null : implode(' ', $notes),
            listTitle: $this->t('section.findings'),
            targetTitle: $this->t('section.target'),
            runTitle: $this->t('section.run'),
            headerLeft: Cover::headerLeft($title, $project),
            headerRight: $cover->headerRight($startedAt, $environment),
            css: (string)file_get_contents(self::RESOURCE_DIR . DIRECTORY_SEPARATOR . 'sast.css'),
            language: $this->translator->language(),
        );
    }

    /**
     * The name of the package of a project, from its `composer.json`
     *
     * @param string $dir Directory of the project
     * @return string|null
     */
    public static function projectName(string $dir): ?string
    {
        $file = $dir . DIRECTORY_SEPARATOR . 'composer.json';
        $data = is_file($file) ? json_decode((string)file_get_contents($file), true) : null;
        $name = is_array($data) ? ($data['name'] ?? null) : null;

        return is_string($name) && $name !== '' ? $name : null;
    }

    /**
     * The rules that found places, by risk
     *
     * @param \PieceOfCake2\SecuritySast\ScanResult $result Scan
     * @return array<\PieceOfCake2\Report\Group>
     */
    private function groups(ScanResult $result): array
    {
        $groups = [];
        $rules = $result->byRule();
        foreach (Severity::ALL as $severity) {
            $group = new Group(count($groups) + 1, $this->t('severity.' . $severity));
            foreach ($rules as $rule => $findings) {
                if ($findings[0]->severity === $severity) {
                    $group->items[] = $this->rule($group->no . '-' . (count($group->items) + 1), $rule, $findings);
                }
            }
            if ($group->items !== []) {
                $groups[] = $group;
            }
        }

        if ($result->suppressed !== []) {
            $group = new Group(count($groups) + 1, $this->t('group.suppressed'));
            $group->items[] = new Item(
                $group->no . '-1',
                $this->t('suppressed.title'),
                'suppressed',
                $this->t('badge.suppressed'),
                (string)count($result->suppressed),
                [new Row($this->t('field.suppressed'), (string)count($result->suppressed))],
                $this->t('suppressed.description'),
                body: $this->suppressed($result->suppressed),
            );
            $groups[] = $group;
        }

        return $groups;
    }

    /**
     * The suppressions of the code: the place and the rules, the reason, then the code
     *
     * @param array<array{file: string, line: int, rules: array<string>, reason: string|null, code: string}> $suppressed
     *  Suppressions
     * @return string HTML
     */
    private function suppressed(array $suppressed): string
    {
        $h = static fn(string $text): string => htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $html = '<div class="places">';
        foreach ($suppressed as $suppression) {
            $rules = $suppression['rules'] !== [] ? implode(', ', $suppression['rules']) : $this->t('suppressed.allRules');
            $html .= '<div class="place"><div class="loc">' . $h($suppression['file'] . ':' . $suppression['line']) . '　' . $h($rules) . '</div>'
                . '<div class="reason">' . $h($this->t('field.reason')) . ': ' . $h($suppression['reason'] ?? $this->t('suppressed.noReason')) . '</div>';
            if ($suppression['code'] !== '') {
                $html .= '<pre>' . $h($suppression['code']) . '</pre>';
            }
            $html .= '</div>';
        }

        return $html . '</div>';
    }

    /**
     * The item of a rule
     *
     * @param string $no Number
     * @param string $rule ID of the rule
     * @param array<\PieceOfCake2\SecuritySast\Finding> $findings Places it found
     * @return \PieceOfCake2\Report\Item
     */
    private function rule(string $no, string $rule, array $findings): Item
    {
        $first = $findings[0];
        $meta = [
            new Row($this->t('field.rule'), $rule, monoValue: true),
            new Row($this->t('field.risk'), $this->t('severity.' . $first->severity)),
        ];
        if ($first->cwe !== []) {
            $meta[] = new Row($this->t('field.cwe'), implode('　', $first->cwe));
        }
        if ($first->owasp !== []) {
            $meta[] = new Row($this->t('field.owasp'), implode('　', $first->owasp));
        }
        if ($first->confidence !== null) {
            $meta[] = new Row($this->t('field.confidence'), $first->confidence);
        }
        $places = $this->t('count.places', ['count' => count($findings)]);
        $meta[] = new Row($this->t('field.count'), $places);

        return new Item(
            $no,
            $this->title($rule),
            $first->severity,
            $this->t('severity.' . $first->severity),
            $places,
            $meta,
            $this->message($rule, $first->message),
            body: $this->places($findings),
        );
    }

    /**
     * The title of a rule: its title in the language, or its ID as words
     *
     * @param string $rule ID of the rule
     * @return string
     */
    public function title(string $rule): string
    {
        $title = $this->t('rule.' . $rule);
        if ($title !== 'rule.' . $rule) {
            return $title;
        }
        $name = substr($rule, (int)strrpos('.' . $rule, '.'));

        return ucfirst(str_replace(['-', '_'], ' ', $name));
    }

    /**
     * The message of a rule: the one of the language for the rules of this package
     *
     * @param string $rule ID of the rule
     * @param string $message Message of the engine
     * @return string
     */
    private function message(string $rule, string $message): string
    {
        $translated = $this->t('message.' . $rule);

        return $translated !== 'message.' . $rule ? $translated : $message;
    }

    /**
     * The places of a rule: the file and lines, then the code
     *
     * @param array<\PieceOfCake2\SecuritySast\Finding> $findings Places
     * @return string HTML
     */
    private function places(array $findings): string
    {
        $h = static fn(string $text): string => htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $html = '<div class="places">';
        foreach (array_slice($findings, 0, self::MAX_PLACES) as $finding) {
            $location = $finding->file . ':' . $finding->line . ($finding->endLine > $finding->line ? '-' . $finding->endLine : '');
            $html .= '<div class="place"><div class="loc">' . $h($location) . '</div>';
            if ($finding->code !== '') {
                $html .= '<pre>' . $h($finding->code) . '</pre>';
            }
            $html .= '</div>';
        }
        if (count($findings) > self::MAX_PLACES) {
            $html .= '<p class="place-more">' . $h($this->t('occurrences.more', ['count' => count($findings) - self::MAX_PLACES])) . '</p>';
        }

        return $html . '</div>';
    }

    /**
     * A message
     *
     * @param string $key Key
     * @param array<string, string|int|float> $params Placeholders
     * @return string
     */
    private function t(string $key, array $params = []): string
    {
        return $this->translator->translate($key, $params);
    }
}
