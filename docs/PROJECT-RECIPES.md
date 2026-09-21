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

## A1.2 local Docker admission

The opt-in A1.2 admission uses a digest-pinned, locally available `python:3.11-slim` filesystem copied into
a `scratch` final stage. This intentionally strips the upstream image metadata environment—including its
`GPG_KEY`, which the first admission attempt correctly rejected—then declares only `PATH`, `LANG`, and
`LC_ALL`. The build command must not pull or access a network:

```bash
docker build --network none --pull=false \
  -t vulnloom-project-recipe-python:local \
  tests/fixtures/project_recipe_python

VULNLOOM_PROJECT_RECIPE_INTEGRATION=1 \
  .venv/bin/pytest -q tests/test_project_recipes_docker_integration.py
```

The successful path compiles and tests a dependency-free Python project in two fresh containers. The
admission reuses the production Docker Runner's post-create verification and additionally checks UID/GID
65532, read-only root and source, no capabilities, `NoNewPrivileges`, `network=none`, no Docker socket,
bounded tmpfs/resource controls, complete cleanup, and absence of every created container. A second real
container exceeds a one-second sealed step budget and must end `timed_out` with the container removed. A
third path deliberately uses the upstream image with inherited environment metadata; it must persist a
terminal `runner_rejected` outcome and still remove the rejected container.

The local Docker Desktop daemon is not claimed to be rootless. Production still requires the separately
qualified S1 rootless engine policy; setting `VULNLOOM_ROOTLESS_QUALIFICATION=1` makes this admission enforce
that policy as well. No image pull, package installation, public access, model invocation, or attack occurs.

## Current boundary

A1.1 uses the offline Runner and A1.2 adds the explicit local Docker admission above. Neither path pulls
images, installs dependencies, accesses a package registry, invokes a model, or exposes a generic recipe-file
CLI. Recipe construction is a trusted deployment/configuration action, not an Agent capability.

The next A1 vertical slice must exercise a non-fixture local project snapshot and bind its recipe outcome into
the Source Hunt Candidate→Validation flow. A1 remains open until that repeatable end-to-end path is proven.

A1.2 acceptance: 1612 passed, 42 skipped, 85.45% coverage in the default offline suite; 3 passed in the
explicit Docker admission; 448 JSON Schemas, Ruff, and diff check passed.
