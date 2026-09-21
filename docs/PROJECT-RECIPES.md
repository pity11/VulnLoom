# Project Recipe Registry

## Purpose

The Project Recipe Registry is the trusted Control Plane boundary for building and testing an already
ingested local project snapshot. An Agent may select a registered recipe identifier. It cannot provide a
command, executable, image, environment variable, working directory, or runtime argument.

## A1.1 offline-tested contract

A `ProjectRecipeStep` seals one absolute, non-shell executable and its complete argument vector, explicit
secret-free environment, phase, tool identifier, wall-clock budget, and content digest. A versioned
`ProjectRecipe` binds an exact image digest, sorted build-system requirements, and an ordered Build→Test
step sequence. `ProjectRecipeRegistry` rejects duplicate identities and tool identifiers and derives its own
digest plus the exact `DockerTool` entries from those sealed steps.

`ProjectRecipePlanningService` accepts only a registered recipe ID and an existing `RepositoryIndex`. It
requires an approved, live Scope and compatible detected build systems, then materializes deterministic
Runner requests with:

- the exact registered image and command;
- no runtime arguments and no shell;
- one allowed tool per step;
- a read-only content-addressed Snapshot mount;
- no network grants;
- zero model-token budget and one tool call;
- bindings to the Registry, Recipe, RepositoryIndex, Manifest, Target, Scope and Policy digests.

The resulting plan is itself content-addressed. Execution requires an exact `RUN_UNTRUSTED_BUILD` Approval
over that plan. Before invoking a Runner, the execution service reconstructs the expected plan from the
trusted Registry and rejects any image, command, argument, environment, Scope, Snapshot, registry or budget
drift—even if the caller presents an Approval over the altered plan.

`ProjectRecipeRunStore` checkpoints each completed step transactionally and provides exact idempotent replay.
Failed, timed-out and cancelled Runner results become terminal non-success outcomes. A
`RunnerCleanupFailed` exception is persisted as `cleanup_unverified`; it can never be represented as a
successful recipe run.

## Current boundary

A1.1 uses the offline Runner only. It does not pull images, install dependencies, access a package registry,
execute a real project, invoke a model, or expose a generic recipe-file CLI. Recipe construction is a trusted
deployment/configuration action, not an Agent capability.

The next A1 vertical slice is a deliberately local, prebuilt, network-disabled Docker admission fixture. It
must prove actual read-only source/root mounts, non-root execution, resource limits, timeout and container
cleanup for a registered non-fixed project recipe before A1 can be closed or described as generally usable.
