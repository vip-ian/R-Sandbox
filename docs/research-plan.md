# Research plan

## Research question

Can an AI agent infer the authority required by an external research project,
construct a project-specific sandbox, and use a shadow run to identify security
violations while preserving legitimate experiment success?

The independent variable is the permission-reasoning and adaptive sandboxing
strategy. Outcomes are measured on both benign research tasks and controlled
adversarial repositories.

## Hypotheses

- Goal-conditioned permission reasoning reduces excess authority compared with
  a generic research container.
- Static evidence plus sandbox runtime evidence detects more unsafe behavior
  than either source scanning or dynamic execution alone.
- Safe replanning recovers common reproducibility failures without increasing
  irreversible side effects or granting broad permissions.

## Dataset

Start with the two versioned fixtures in `examples/`. Expand to 50–100 public
Python research repositories, pinned by commit hash and stratified by workload
(training, evaluation, preprocessing, and notebook). Never benchmark against a
moving default branch. Adversarial variants must use canary credentials,
reserved domains, and synthetic data only.

Each case records:

- repository commit, natural-language goal, expected entrypoint and output;
- minimum capability oracle reviewed by a human;
- seeded risky behaviors and the paths/inputs that activate them;
- expected safe/review/unsafe verdict and evidence.

## Baselines and ablations

- unrestricted generic container;
- fixed default-deny sandbox without agent reasoning;
- static analysis only;
- dynamic sandbox observation only;
- full R-Sandbox agent;
- ablations without goal context, reflection, or human approval.

## Metrics

- task success rate and result reproducibility;
- dangerous-behavior block rate and false-block rate;
- capability precision/recall against the human oracle;
- excess-authority reduction relative to a generic container;
- security-verdict precision/recall and explanation evidence coverage;
- approval count, safe replanning success rate, and retry count;
- irreversible side-effect count (target: zero);
- wall-clock/runtime overhead and report generation latency.

Report confidence intervals and paired results on identical commits and inputs.
Keep `inconclusive` separate from `safe`; never count a runtime-unavailable case
as a successful security verdict.

## Milestones

1. Deterministic repository analysis, capability schema, policy engine, and
   explainable report.
2. Docker sandbox with read-only source, writable output, network denial,
   host-environment secret isolation, reviewed-image trust, and resource bounds.
3. Runtime evidence collector with controlled inconclusive/unsafe fixtures;
   scoped safe demonstrations begin only after independent host attestation.
4. Failure classification and authorization-gated replanning.
5. LLM semantic reasoner behind the same typed contract.
6. Larger pinned benchmark and ablation study.
