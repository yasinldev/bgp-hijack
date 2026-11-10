use std::collections::{HashMap, HashSet};

use crate::{
    evidence::{AssertionKey, AssertionResult},
    model::{AddressFamily, CleanupStatus, Verdict},
};

/// Inputs must be supplied by the observation/evidence layer. This pure function
/// checks coverage and precedence; it does not read or authenticate artifacts.
pub struct EvaluationInput<'a> {
    pub expected: &'a [AssertionKey],
    pub assertions: &'a [AssertionResult],
    pub address_families: &'a [AddressFamily],
    pub completed: bool,
    pub interrupted: bool,
    pub cleanup_status: CleanupStatus,
    pub evidence_gaps: &'a [String],
}

pub fn evaluate(input: &EvaluationInput<'_>) -> Verdict {
    let expected: HashSet<_> = input.expected.iter().cloned().collect();
    let families: HashSet<_> = input.address_families.iter().copied().collect();

    // A proven violation remains a failure even if another observation is absent.
    if input.cleanup_status == CleanupStatus::Failed
        || input.assertions.iter().any(|assertion| {
            expected.contains(&assertion.key())
                && families.contains(&assertion.address_family)
                && assertion.result == Verdict::Failed
                && assertion.has_evidence()
        })
    {
        return Verdict::Failed;
    }

    if expected.is_empty()
        || families.is_empty()
        || expected.len() != input.expected.len()
        || families.len() != input.address_families.len()
        || !input.completed
        || input.interrupted
        || input.cleanup_status != CleanupStatus::Completed
        || !input.evidence_gaps.is_empty()
        || expected
            .iter()
            .any(|key| key.id.trim().is_empty() || !families.contains(&key.address_family))
        || families
            .iter()
            .any(|family| !expected.iter().any(|key| &key.address_family == family))
    {
        return Verdict::Inconclusive;
    }

    let mut observed = HashMap::new();
    for assertion in input.assertions {
        let key = assertion.key();
        if !expected.contains(&key)
            || observed.insert(key, assertion).is_some()
            || assertion.result != Verdict::Passed
            || !assertion.has_evidence()
            || assertion.expectation.trim().is_empty()
        {
            return Verdict::Inconclusive;
        }
    }

    if expected.iter().all(|key| observed.contains_key(key)) {
        Verdict::Passed
    } else {
        Verdict::Inconclusive
    }
}
