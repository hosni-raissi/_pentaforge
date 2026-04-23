# PentaForge Orchestrator Runtime

This document explains how the current orchestrator works after the warmup-recon refactor.

## Overview

The scan now runs in two major stages:

1. Warmup stage
2. Main pentest stage

The main goal is:

- do not start exploitation too early
- build real target evidence first
- create a better checklist after recon
- reduce fake scenarios and false positives

## Full Flow

### 1. Scan Start

When a scan starts, the orchestrator:

- loads the project
- reads target and target type
- reads any uploaded custom checklist
- extracts `scope` from `info`

### 2. Intel Update-Only Pass

The first Intel pass does **not** build the final checklist.

It only:

- checks whether RAG is fresh
- updates RAG if needed
- returns update stats

Purpose:

- make sure knowledge is ready
- avoid building the main checklist too early

### 3. Warmup Planner

The Planner is called in a special warmup mode.

Its job is to create a recon-only startup plan.

Before the Planner does that, the orchestrator loads the target-type static recon plan from the database.

This first planner pass is now an adaptation step, not a discovery step.

The Planner receives:

- target
- target type
- scope
- target description from `info`
- static recon plan for that target type

At this stage, the Planner does **not** use tools.

Instead it:

- starts from the static plan
- keeps it or adapts it to the target description
- returns a recon-only warmup plan

The static plan:

- is capped to `20` common recon scenarios for that target type
- is saved into project/scan state
- is intended to be shown in the UI so the user can follow or edit it
- is used as the default recon baseline before exploitation

That plan is normalized by the orchestrator to:

- exactly `8` recon scenarios
- no exploit scenarios
- no report scenarios

The warmup scenarios focus on things like:

- tech fingerprinting
- headers and security controls
- crawling
- content discovery
- parameter discovery
- JavaScript and static assets
- auth/session surface
- API or alternate surfaces

### 4. Warmup Recon Execution

The warmup stage runs:

- `2` recon agents
- for `2` cycles
- each agent gets `2` scenarios per cycle

That means:

- cycle 1 = 4 recon scenarios total
- cycle 2 = 4 recon scenarios total
- total = 8 recon scenarios

These warmup cycles are also counted as executer cycles:

- warmup cycle 1 = executer cycle `1`
- warmup cycle 2 = executer cycle `2`
- main steady-state starts at executer cycle `3`

This stage is recon-only.

No exploit agent runs here.

Each warmup cycle uses two parallel workers:

- `[RECON][1]`
- `[RECON][2]`

### 5. Perceptor Warmup Summaries

After each warmup recon scenario finishes:

- Perceptor analyzes the tool results
- creates a compact summary
- classifies the result
- stores the summary in cache/event history

These cached warmup summaries become the evidence foundation for the next Intel pass.

### 6. Intel Synthesis Pass

After warmup recon is complete, Intel runs a second time.

This time it builds the real prioritized checklist using:

- warmup recon summaries
- uploaded custom checklist from the user
- built-in resource checklists
- RAG-guided synthesis

Important behavior:

- uploaded custom checklist is now merged, not used as a full replacement
- final checklist is capped to `20` prioritized items

### 7. Checklist Approval

After Intel synthesis:

- the checklist is emitted to the UI
- the user can review/edit it
- Planner waits for approval before continuing

### 8. Main Planner

After approval, Planner builds the main pentest plan using:

- target info
- target-type static recon plan
- synthesized checklist
- warmup-informed context

This plan may contain:

- recon scenarios
- exploit scenarios

### 9. Main Execution Loop

The steady-state loop now works like this:

- choose `1` recon scenario
- choose `1` exploit scenario
- run them in parallel

This repeats until:

- Planner says pentest is complete
- or there are no more meaningful scenarios left

### 10. Perceptor Classification

For each result in the main loop:

- Perceptor inspects the tool output
- classifies it as `vulnerability` or `info`

Routing rules:

- `info` -> Planner
- `vulnerability` -> Verify

Extra safety:

- exploit results with `not_vulnerable` are downgraded to `info`

### 11. Verify

Verify runs before replanning.

Its job:

- confirm whether a suspected vulnerability is real
- reject false positives
- return a structured verdict

Valid verdicts:

- `real_vulnerability`
- `false_positive`
- `inconclusive`

Verify now also returns:

- `confidence` from `0.0` to `1.0`

### 12. Retest

Retest does **not** run for every verified issue anymore.

Retest runs only when:

- verdict is `real_vulnerability`
- confidence is high enough
- the result is not just weak version/banner disclosure

Current retest threshold:

- confidence `>= 0.75`

Purpose:

- generate PoC
- capture screenshot/evidence
- avoid noise from weak findings

### 13. Planner Replan

Planner receives the batch after Verify finishes.

It uses:

- real vulnerabilities
- false positives
- inconclusives
- informational recon results

Planner then:

- updates the plan
- keeps good scenarios
- removes or deprioritizes weak paths
- continues the loop

## Safety Improvements

The new orchestration improves safety by:

- forcing recon-first warmup
- preventing exploit-first guessing
- requiring Verify before replan on suspected vulns
- requiring stronger confidence before Retest
- filtering weak version-only findings from PoC generation

## Short Summary

The runtime is now:

`Intel update-only -> warmup planner adapts stored static plan using target description -> 2 recon warmup cycles -> perceptor cache -> Intel synthesis -> checklist approval -> main planner -> 1 recon + 1 exploit loop -> perceptor -> verify -> optional retest -> planner -> repeat`
