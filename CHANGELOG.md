# Changelog

All notable changes to this project will be documented in this file.

## 0.2.0

- fix(EXPLAIN-001): only flag plaintext password comparison against a STORED
  credential. Bare `password == ...` matched empty-string guards
  (`password == ""`) and registration confirm-password checks
  (`password == confirmPassword`) — neither is an authentication weakness.
- fix(EXPLAIN-003): suppress the access-control-gap finding when an
  authorization guard (Express/Go inline middleware or a Python auth
  decorator such as `@login_required`) is present within a few lines of the
  privileged route. Drop the function-name heuristic (`def admin_*`) — a
  handler's name is not an access-control gap.
- test: add `testdata/clean/` negative fixtures and `TestCleanCodeNoFindings`
  asserting idiomatic safe code produces zero findings.

- chore: add CI/CD, lint config, pre-commit hooks, and fix lint issues
- chore: add LICENSE, .gitignore, and tidy go.mod

