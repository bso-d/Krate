<!--
PR Description Guidelines (Skill: writing-pr-descriptions):
- Title format: One line naming the phase/system and the change (e.g., "Phase 4: Keycloak Auth Integration & Monitoring Hardening").
  No ticket dumps, no "WIP" once reviewable, no history.
- Purpose: A PR description is a review document, not a work log. Answer:
  1) What is this?
  2) What should I look at?
  3) What proof exists?
  4) What is still outstanding?
- Link to forensic details (transcripts, receipts, trackers); do not paste large transcripts.
- Keep length to 1-2 screens. Rewrite at each milestone push so it always describes the current candidate.
-->

## Overview

<!-- Two or three sentences: what the PR delivers and which specification or issue defines it (link it). -->

**Current Candidate:** <!-- Full or short commit SHA on this PR branch -->
**Current State:** <!-- One honest phrase, e.g., "Ready for code review; formal runtime acceptance gates remain pending" -->

## What Changed

<!-- Group by product area (not by commit, not by chronology).
Each bullet: behaviour change and why it matters, naming key file or mechanism.
Mention review-comment fixes as behaviour, not "addressed comment X".
Call out any breaking changes, deployment/migration steps, or data-loss risks. -->

- **`area/component`**: <!-- e.g., kraft/krate, epc/krate, monitoring/, sso/ -->
  - <!-- Behaviour change and why it matters -->

## Verification & Status

<!-- Split into two subsections that must NEVER be merged:
A green CI is admission for review and running gates; it is never written up as acceptance of runtime behaviour. -->

### Automated CI & Static Checks
<!-- Hosted check totals on the named head, scanning alerts, review-thread counts, and built artefacts, each as counts plus a link. -->
- **Static checks (`make check`)**: <!-- e.g., Passed on <SHA> -->
- **CodeQL / Security scans**: <!-- e.g., 0 alerts -->
- **Broker CI / Build artifacts**: <!-- e.g., Images built and tested (link to action run) -->
- **Review threads**: <!-- e.g., 0 open threads (all resolved) -->

### Formal Acceptance Gates
<!-- Checklist of runtime proofs still outstanding or completed, each with environment (OS, edition) and what it proves.
Tick only from a candidate-bound receipt (e.g. scripts/gate-identity.sh). Never soften a pending gate into "verified". -->
- [ ] <!-- Environment (Ubuntu noble / RHEL 9), Edition (kraft / epc) — Proof statement -->

## How to Review

<!-- 3 to 5 numbered pointers to the highest-risk areas:
1. The config to compare against its contract
2. The permission or security invariant to verify
3. The one edge-case fix worth reading closely (name its commit)
Reviewers should not have to discover the risk map themselves. -->
1. <!-- Risk area 1 -->
2. <!-- Risk area 2 -->
3. <!-- Risk area 3 -->
