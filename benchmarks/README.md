# Benchmarks

The benchmark harness will evaluate the agent, not the sandbox in isolation.
Every case couples a pinned project, research goal, minimum-authority oracle,
expected result, and expected security evidence.

Initial smoke cases are the benign and controlled-risk fixtures in `examples/`.
The next dataset revision will add a manifest with commit hashes and expected
metrics for public repositories. See `docs/research-plan.md` for baselines,
ablations, and reporting rules.

