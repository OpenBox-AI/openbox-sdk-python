# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-07-23

### Changed
- **BREAKING:** Renamed the public BLOCK remediation contract from `retry_plan` to `patch`.
  `RetryPlan` is now `Patch`, `RetryDirective` is now `PatchDirective`, and
  `handle_retryable_block()` is now `handle_patch()`. `EvaluationResult.retry_plan` and
  `ApprovalResult.retry_plan` are now `.patch`. The parser now reads only the canonical outer
  wire key `patch`; the old `retry_plan` key is no longer recognized.
- The verdict gate is unchanged: a directive is still surfaced only for an exact `BLOCK` verdict
  carrying a valid patch — never for HALT/`should_stop()`, and never for an expired approval
  result.

### Notes
- This is a breaking release: the old public names (`RetryPlan`, `RetryDirective`,
  `handle_retryable_block`, `.retry_plan`) are removed, not aliased. Consumers still pinned to
  `1.1.0` remain fail-safe — they ignore the unknown `patch` field but still enforce the `BLOCK`
  verdict.

## [1.1.0] - 2026-07-21

### Added
- `RetryPlan` and `RetryDirective` dataclasses in `openbox_core.contracts.results`.
- Optional `retry_plan` directive parsing on both `EvaluationResult` and `ApprovalResult`.
  A `_MISSING` sentinel keeps a present `new_input: null` distinct from an absent field; falsy
  values (`null`, `""`, `0`, `[]`, `{}`) are preserved; a boolean `new_input` is rejected; and every
  number (recursively) must be finite and, if integral, a JS-safe integer (`|n| <= 2^53 - 1`).
- `handle_retryable_block(result)` — an opt-in, pure inspector that returns a `RetryDirective` only
  for a `BLOCK` verdict carrying a valid plan. Returns `None` for a plain BLOCK, every non-BLOCK
  verdict (including HALT), a pending verdict, and an expired `ApprovalResult`.

### Notes
- Default enforcement is unchanged: a `BLOCK` verdict still raises `GovernanceBlockedError`. The new
  helper is opt-in and never triggers an automatic retry; malformed or ineligible plans are treated
  as absent (never fail open).
