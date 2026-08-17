<!--
Delete the sections that do not apply. The checklists are not ceremony: each
line corresponds to a standing rule in CLAUDE.md §5 or a phase Definition of
Done, and those are the things this project has actually got wrong before.
-->

## What and why

<!-- One paragraph. What changed, and what problem it solves. -->

**Phase / stage:** <!-- e.g. 2b, or "infrastructure" -->

## Standing rules (CLAUDE.md §5)

- [ ] **Consensus-neutral.** Nothing here changes which blocks a node accepts.
      (Required until Phase 7. If this is false, stop and flag it.)
- [ ] **No `unwrap`/`expect`/`panic` in accumulator or apply paths.** A panic in
      block application is a remote crash vector. Test-only exemptions are
      justified in a comment.
- [ ] **Every new hash has a domain separator**, distinct per structure, pool,
      and role.
- [ ] **Deterministic.** No `HashMap` iteration, no floats, no system time in
      any path that reaches a root.
- [ ] **Benchmarks accompany any optimisation.** No "this should be faster".

## Correctness

- [ ] `cargo test --workspace --locked` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` is clean
- [ ] `cargo fmt --all --check` is clean
- [ ] Differential tests still agree — a green unit suite with a divergent root
      is a failure, not a pass

**If this PR fixes a divergence:**

- [ ] The divergence was added to `crates/zutreexo-testkit/corpus/` as a seed
      and **confirmed failing before the fix**
- [ ] The seed now passes

**If this PR changes a root, a leaf hash, or a personalization string:**

- [ ] Pinned vectors in `crates/zutreexo-testkit/src/vectors.rs` were
      regenerated deliberately, and the PR body says why the old ones were wrong
- [ ] The change is called out explicitly below — a silently moved root is the
      failure mode vectors exist to prevent

## Definition of Done

<!--
Paste the DoD for this phase from CLAUDE.md §4 and tick what holds. If an item
does not hold, say so here and record it in PLAN.md under "Known gaps" rather
than leaving it implicit. A phase called done against an unverified criterion is
how Phase 1 shipped with its coverage requirement unmeasured.
-->

## Notes for review

<!--
What you are least sure about. Where a reviewer's time is best spent. Anything
deliberately deferred, and to where.
-->
