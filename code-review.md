# Code Review Guide

## Review order

1. Understand the intended behavior from the PR description and existing tests.
2. Inspect the complete diff.
3. Identify changed interfaces and invariants.
4. Follow affected data/control flows.
5. Inspect error and boundary cases.
6. Inspect tests and determine whether important behavior is actually covered.
7. Run relevant validation commands.

## Critical invariants

### API compatibility

Changes to public API responses require consideration of existing clients.
Do not remove or rename fields without an explicit migration strategy.

## Review priorities

Prioritize:

1. Security vulnerabilities
2. Incorrect behavior
3. Data loss/corruption
4. Concurrency/race conditions
5. Breaking API or persistence changes
6. Missing error handling
7. Significant performance regressions

Do not spend review attention on formatting or lint issues handled by CI.

## Evidence requirement

A finding must identify a concrete path from the changed code to the
failure. If the concern depends on an assumption, state the assumption.

If no actionable issue is found, say so rather than inventing findings.

