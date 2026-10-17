# Fixing the Findings

The way through a report, from the first scan of an existing application to a CI that keeps it clean.

## 1. Read the Report from the Top

The findings are grouped by risk. Start with **High** (SQL, views rendered from the request, `unserialize()` of
the request, a debug level or a salt of production), then **Medium**. Each page of a rule says what it found, and
lists the places with their code: open them in the code, and read [the page of the rule](rules.md) for the fix.

The rules look at the code, not at where the values come from: for each place, decide first whether the value can
come from a user (the request, a cookie, a header, a file uploaded, or data that a user saved earlier). If it
can, it is a vulnerability: fix it. If it cannot, fix it anyway when it is easy (the fixed code is also safer
when the code changes later), or suppress it with the reason.

## 2. Fix a Rule Everywhere

Most rules have one fix for all their places: the placeholders of `query()`, the conditions arrays of `find()`,
`h()` in the views, a list of allowed values. Fix all the places of a rule in one change, and look for the same
pattern in the code that the scan does not cover (the shells, the plugins, the libraries of the application).

A finding of the configuration is fixed in the configuration of production, not in the code: see
[The Configuration](rules.md#the-configuration), and its notes on what a change of a secret breaks.

## 3. Check the Fix

- Run the check again: the place is no longer reported.
- Add a test of the action with a value that would have broken it: a quote in a search (`O'Brien`), `<b>` in a
  name that must be shown as text, a URL of another site in a redirect.
- Run the full scan of [pieceofcake2/security-dast](https://pieceofcake2.github.io/security-dast/) on the
  End-to-End tests: it attacks the pages and forms as an attacker would.

## 4. Suppress What Is Safe, with the Reason

A place that is safe, e.g. a constant in a query, is suppressed where it is, with a comment that says why
([Suppressing a Finding](README.md#suppressing-a-finding)). Never suppress a rule for the whole application to
make a report pass: the next place of the rule would not be reported.

For the views, a variable that holds sanitized HTML on purpose is set safe once with `safeViewVariables`
([cakephp2-view-unescaped-output](rules.md#cakephp2-view-unescaped-output)).

## 5. Keep It Clean in CI

Run the check on each push and pull request ([CI with GitHub Actions](ci.md)):

1. Start with `--fail-on=none`: the report shows the findings without failing the job.
2. Fix the High findings, then set `--fail-on=high`: a new High finding fails the pull request that adds it.
3. Fix the Medium findings, then set `--fail-on=medium`.

Keep the report of each run (the artifact of the job): it is the record of the checks of the application.
