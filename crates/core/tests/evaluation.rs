use bgp_hijack_core::{
    evaluation::{EvaluationInput, evaluate},
    evidence::{AssertionKey, AssertionResult},
    model::{AddressFamily, CleanupStatus, Verdict},
};
use serde::Deserialize;

const FAMILIES: [AddressFamily; 2] = [AddressFamily::Ipv4, AddressFamily::Ipv6];

fn assertions() -> Vec<AssertionResult> {
    FAMILIES
        .iter()
        .map(|&address_family| AssertionResult {
            id: "delivery".into(),
            address_family,
            expectation: "selected probes reach the target".into(),
            observation: "all selected probes received".into(),
            result: Verdict::Passed,
            evidence_refs: vec!["snapshots/target.json".into()],
        })
        .collect()
}

fn input<'a>(
    expected: &'a [AssertionKey],
    assertions: &'a [AssertionResult],
) -> EvaluationInput<'a> {
    EvaluationInput {
        expected,
        assertions,
        address_families: &FAMILIES,
        completed: true,
        interrupted: false,
        cleanup_status: CleanupStatus::Completed,
        evidence_gaps: &[],
    }
}

#[test]
fn golden_verdict_matrix() {
    #[derive(Deserialize)]
    struct Case {
        name: String,
        results: Vec<Verdict>,
        completed: bool,
        interrupted: bool,
        cleanup: CleanupStatus,
        gap: bool,
        want: Verdict,
    }
    let cases: Vec<Case> = serde_json::from_str(include_str!("fixtures/verdicts.json")).unwrap();
    for case in cases {
        let mut observed = assertions();
        for (assertion, result) in observed.iter_mut().zip(case.results) {
            assertion.result = result;
        }
        let expected: Vec<_> = observed.iter().map(AssertionResult::key).collect();
        let gaps = if case.gap {
            vec!["capture incomplete".to_owned()]
        } else {
            vec![]
        };
        let mut state = input(&expected, &observed);
        state.completed = case.completed;
        state.interrupted = case.interrupted;
        state.cleanup_status = case.cleanup;
        state.evidence_gaps = &gaps;
        assert_eq!(evaluate(&state), case.want, "{}", case.name);
    }
}

#[test]
fn empty_and_incomplete_family_coverage_never_passes() {
    let observed = assertions();
    let expected: Vec<_> = observed.iter().map(AssertionResult::key).collect();
    for state in [
        input(&[], &[]),
        input(&expected, &[]),
        input(&expected, &observed[..1]),
        input(&expected[..1], &observed[..1]),
    ] {
        assert_eq!(evaluate(&state), Verdict::Inconclusive);
    }
    let mut state = input(&expected, &observed);
    state.address_families = &[];
    assert_eq!(evaluate(&state), Verdict::Inconclusive);
}

#[test]
fn duplicates_and_unexpected_assertions_do_not_create_a_pass() {
    let observed = assertions();
    let expected: Vec<_> = observed.iter().map(AssertionResult::key).collect();
    let mut duplicate = observed.clone();
    duplicate.push(observed[0].clone());
    assert_eq!(
        evaluate(&input(&expected, &duplicate)),
        Verdict::Inconclusive
    );
    duplicate[2].id = "unexpected".into();
    assert_eq!(
        evaluate(&input(&expected, &duplicate)),
        Verdict::Inconclusive
    );
    let mut duplicate_expected = expected.clone();
    duplicate_expected.push(expected[0].clone());
    assert_eq!(
        evaluate(&input(&duplicate_expected, &observed)),
        Verdict::Inconclusive
    );
    let mut state = input(&expected, &observed);
    state.address_families = &[AddressFamily::Ipv4, AddressFamily::Ipv4];
    assert_eq!(evaluate(&state), Verdict::Inconclusive);
}

#[test]
fn observations_require_evidence_and_known_failures_take_precedence() {
    let mut observed = assertions();
    let expected: Vec<_> = observed.iter().map(AssertionResult::key).collect();
    observed[0].evidence_refs.clear();
    assert_eq!(
        evaluate(&input(&expected, &observed)),
        Verdict::Inconclusive
    );
    observed[0].result = Verdict::Failed;
    assert_eq!(
        evaluate(&input(&expected, &observed)),
        Verdict::Inconclusive
    );
    observed[1].result = Verdict::Failed;
    assert_eq!(evaluate(&input(&expected, &observed)), Verdict::Failed);
    observed[1].evidence_refs = vec![" ".into()];
    assert_eq!(
        evaluate(&input(&expected, &observed)),
        Verdict::Inconclusive
    );
}

#[test]
fn unknown_or_disabled_family_failure_is_not_attributed_to_the_run() {
    let mut observed = assertions();
    let expected: Vec<_> = observed.iter().map(AssertionResult::key).collect();
    observed[1].result = Verdict::Failed;
    observed[1].id = "not_an_expected_assertion".into();
    assert_eq!(
        evaluate(&input(&expected, &observed)),
        Verdict::Inconclusive
    );
    observed[1].id = "delivery".into();
    let mut state = input(&expected, &observed);
    state.address_families = &[AddressFamily::Ipv4];
    assert_eq!(evaluate(&state), Verdict::Inconclusive);
}

#[test]
fn single_family_complete_run_can_pass() {
    let observed = assertions();
    let expected = [observed[0].key()];
    let mut state = input(&expected, &observed[..1]);
    state.address_families = &[AddressFamily::Ipv4];
    assert_eq!(evaluate(&state), Verdict::Passed);
}
