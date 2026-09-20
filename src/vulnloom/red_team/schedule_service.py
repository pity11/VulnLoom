"""Trusted application service for recurring exact Endpoint checks."""

from __future__ import annotations

from datetime import datetime, timedelta

from vulnloom.domain.models import Scope, ScopeState
from vulnloom.workflows import Visibility

from .schedule_models import (
    EndpointCheckSchedule,
    EndpointScheduleCheckpoint,
    EndpointScheduleRun,
    EndpointScheduleRunState,
    EndpointScheduleState,
)
from .schedule_state_machine import (
    EndpointScheduleTransitionRejected,
    cancel_endpoint_schedule,
    expire_endpoint_schedule,
    pause_endpoint_schedule,
    resume_endpoint_schedule,
)
from .schedule_store import (
    EndpointScheduleClaim,
    EndpointScheduleStore,
    EndpointScheduleStoreRejected,
)
from .seed_models import EndpointReconLimits, EndpointReconReservationState
from .seed_service import EndpointReconService
from .seed_store import EndpointReconStore
from .service import RedTeamService
from .state_machine import TERMINAL_STATUSES
from .store import RedTeamStore


class EndpointScheduleRejected(ValueError):
    pass


class EndpointScheduleMaterializationInterrupted(RuntimeError):
    pass


class EndpointScheduleService:
    """Materializes bounded plans; it never dispatches a network action."""

    def __init__(
        self,
        *,
        schedule_store: EndpointScheduleStore,
        red_team_store: RedTeamStore,
        recon_store: EndpointReconStore,
        endpoint_service: EndpointReconService,
    ):
        self.schedule_store = schedule_store
        self.red_team_store = red_team_store
        self.recon_store = recon_store
        self.endpoint_service = endpoint_service

    def create(
        self,
        *,
        scope: Scope,
        target_url: str,
        visibility: Visibility,
        test_class: str,
        operator_ref: str,
        emergency_contact_ref: str,
        paths: tuple[str, ...],
        interval_seconds: int,
        run_ttl_seconds: int,
        max_consecutive_failures: int,
        recon_limits: EndpointReconLimits,
        active_from: datetime,
        active_until: datetime,
        now: datetime,
        idempotency_key: str,
    ) -> tuple[EndpointCheckSchedule, EndpointScheduleCheckpoint]:
        self._scope(scope, now)
        if active_until > scope.valid_until:
            raise EndpointScheduleRejected("Endpoint Schedule exceeds approved Scope lifetime")
        canonical_paths = tuple(sorted(paths))
        try:
            preflight = RedTeamService(store=self.red_team_store).prepare(
                scope=scope,
                target_url=target_url,
                visibility=visibility,
                allowed_test_classes=(test_class,),
                max_actions=len(canonical_paths),
                max_consecutive_failures=max_consecutive_failures,
                emergency_contact_ref=emergency_contact_ref,
                now=now,
                deadline=min(now + timedelta(seconds=run_ttl_seconds), active_until),
                idempotency_key=f"schedule-preflight:{idempotency_key}",
            )
            for path in canonical_paths:
                self.endpoint_service._authorize_exact(
                    preflight, scope, path, now, test_class=test_class
                )
        except ValueError as exc:
            raise EndpointScheduleRejected("Endpoint Schedule preflight is invalid") from exc
        try:
            schedule = EndpointCheckSchedule.create(
                scope_id=scope.scope_id,
                scope_version=scope.version,
                target_url=target_url,
                visibility=visibility,
                test_class=test_class,
                operator_ref=operator_ref,
                emergency_contact_ref=emergency_contact_ref,
                paths=canonical_paths,
                interval_seconds=interval_seconds,
                run_ttl_seconds=run_ttl_seconds,
                max_consecutive_failures=max_consecutive_failures,
                recon_limits=recon_limits,
                active_from=active_from,
                active_until=active_until,
                created_at=now,
                idempotency_key=idempotency_key,
            )
            existing = self.schedule_store.schedule_by_key(idempotency_key)
            if existing is not None:
                if self._configuration(existing) != self._configuration(schedule):
                    raise EndpointScheduleRejected(
                        "Endpoint Schedule idempotency key was reused for different content"
                    )
                return existing, self.schedule_store.latest(existing.schedule_id)
            return self.schedule_store.create(schedule)
        except EndpointScheduleStoreRejected as exc:
            raise EndpointScheduleRejected(str(exc)) from exc
        except ValueError as exc:
            raise EndpointScheduleRejected("Endpoint Schedule contract is invalid") from exc

    def trigger(
        self,
        schedule_id: str,
        *,
        scope: Scope,
        now: datetime,
    ) -> EndpointScheduleClaim:
        schedule = self.schedule_store.schedule(schedule_id)
        checkpoint = self.schedule_store.latest(schedule_id)
        self._binding(schedule, checkpoint, scope, now)
        replay = self._not_due_replay(checkpoint, now=now)
        if replay is not None:
            return EndpointScheduleClaim(checkpoint=checkpoint, run=replay, created=False)
        self._prior_run_clean(checkpoint)
        try:
            claim = self.schedule_store.claim(schedule, checkpoint, now=now)
        except (ValueError, RuntimeError) as exc:
            raise EndpointScheduleRejected(str(exc)) from exc
        return self._materialize_claim(schedule, claim, scope=scope, now=now)

    def recover(
        self,
        schedule_id: str,
        *,
        scope: Scope,
        now: datetime,
    ) -> EndpointScheduleClaim:
        schedule = self.schedule_store.schedule(schedule_id)
        checkpoint = self.schedule_store.latest(schedule_id)
        if checkpoint.active_run_id is None:
            raise EndpointScheduleRejected("Endpoint Schedule has no run to recover")
        run = self.schedule_store.run(checkpoint.active_run_id)
        self._identity_binding(schedule, scope)
        if now >= run.deadline:
            cleanup = self._cleanup_partial(schedule, run, scope=scope, now=now)
            try:
                return self.schedule_store.timeout(
                    schedule,
                    checkpoint,
                    run,
                    cleanup_complete=cleanup,
                    now=now,
                )
            except (ValueError, RuntimeError) as exc:
                raise EndpointScheduleRejected(str(exc)) from exc
        self._scope(scope, now)
        try:
            claim = self.schedule_store.recover(run.schedule_run_id, now=now)
        except (ValueError, RuntimeError) as exc:
            raise EndpointScheduleRejected(str(exc)) from exc
        return self._materialize_claim(schedule, claim, scope=scope, now=now)

    def pause(self, schedule_id: str, *, operator_ref: str, now: datetime):
        return self._lifecycle(
            schedule_id, operator_ref=operator_ref, now=now, transition=pause_endpoint_schedule
        )

    def resume(
        self, schedule_id: str, *, scope: Scope, operator_ref: str, now: datetime
    ):
        schedule = self.schedule_store.schedule(schedule_id)
        self._identity_binding(schedule, scope)
        self._scope(scope, now)
        self._prior_run_clean(self.schedule_store.latest(schedule_id))
        return self._lifecycle(
            schedule_id,
            operator_ref=operator_ref,
            now=now,
            transition=resume_endpoint_schedule,
        )

    def cancel(self, schedule_id: str, *, operator_ref: str, now: datetime):
        schedule = self.schedule_store.schedule(schedule_id)
        checkpoint = self.schedule_store.latest(schedule_id)
        self._operator(schedule, operator_ref)
        try:
            advanced = cancel_endpoint_schedule(schedule, checkpoint, now=now)
            return (
                checkpoint
                if advanced == checkpoint
                else self.schedule_store.advance(checkpoint, advanced)
            )
        except (ValueError, RuntimeError) as exc:
            raise EndpointScheduleRejected(str(exc)) from exc

    def expire(self, schedule_id: str, *, now: datetime):
        schedule = self.schedule_store.schedule(schedule_id)
        checkpoint = self.schedule_store.latest(schedule_id)
        try:
            advanced = expire_endpoint_schedule(schedule, checkpoint, now=now)
            return (
                checkpoint
                if advanced == checkpoint
                else self.schedule_store.advance(checkpoint, advanced)
            )
        except (ValueError, RuntimeError) as exc:
            raise EndpointScheduleRejected(str(exc)) from exc

    def _materialize_claim(self, schedule, claim, *, scope, now):
        try:
            flow, seed_set, endpoint_plan = self._materialize(
                schedule, claim.run, scope=scope
            )
        except (ValueError, RuntimeError) as exc:
            if claim.run.attempt < 3:
                raise EndpointScheduleMaterializationInterrupted(
                    "Endpoint Schedule materialization was interrupted"
                ) from exc
            cleanup = self._cleanup_partial(schedule, claim.run, scope=scope, now=now)
            return self.schedule_store.fail(
                schedule,
                claim.checkpoint,
                claim.run,
                cleanup_complete=cleanup,
                now=now,
            )
        try:
            return self.schedule_store.materialize(
                schedule,
                claim.checkpoint,
                claim.run,
                flow_plan_id=flow.plan_id,
                seed_set_id=seed_set.seed_set_id,
                endpoint_recon_plan_id=endpoint_plan.endpoint_recon_plan_id,
                now=now,
            )
        except (ValueError, RuntimeError) as exc:
            raise EndpointScheduleRejected(str(exc)) from exc

    def _materialize(self, schedule, run, *, scope):
        flow_key, seed_key, endpoint_key = self._keys(run)
        flow_service = RedTeamService(store=self.red_team_store)
        flow = flow_service.prepare(
            scope=scope,
            target_url=schedule.target_url,
            visibility=schedule.visibility,
            allowed_test_classes=(schedule.test_class,),
            max_actions=len(schedule.paths),
            max_consecutive_failures=schedule.max_consecutive_failures,
            emergency_contact_ref=schedule.emergency_contact_ref,
            now=run.started_at,
            deadline=run.deadline,
            idempotency_key=flow_key,
        )
        flow_service.create_and_start(flow, scope=scope, now=run.started_at)
        source = self.red_team_store.checkpoint_revision(flow.plan_id, 1)
        if self.red_team_store.latest(flow.plan_id) != source:
            raise EndpointScheduleRejected(
                "Endpoint Schedule materialization Flow was already used"
            )
        seed_set = self.endpoint_service.seal_seed_set(
            flow_plan=flow,
            checkpoint=source,
            scope=scope,
            operator_ref=schedule.operator_ref,
            paths=schedule.paths,
            now=run.started_at,
            expires_at=run.deadline,
            idempotency_key=seed_key,
        )
        endpoint_plan = self.endpoint_service.prepare(
            seed_set_id=seed_set.seed_set_id,
            scope=scope,
            test_class=schedule.test_class,
            limits=schedule.recon_limits,
            now=run.started_at,
            deadline=run.deadline,
            idempotency_key=endpoint_key,
        )
        return flow, seed_set, endpoint_plan

    def _cleanup_partial(self, schedule, run, *, scope, now):
        flow_key, _, endpoint_key = self._keys(run)
        cleanup = True
        endpoint_plan = self.recon_store.plan_by_key(endpoint_key)
        if endpoint_plan is not None:
            reservation = self.recon_store.reservation(
                endpoint_plan.endpoint_recon_plan_id
            )
            state = self.recon_store.state(endpoint_plan.endpoint_recon_plan_id)
            if state is not None and state[0].value == "started":
                cleanup = False
            elif reservation.state is EndpointReconReservationState.ACTIVE:
                try:
                    self.endpoint_service.cancel_reservation(
                        endpoint_plan.endpoint_recon_plan_id,
                        operator_ref=schedule.operator_ref,
                        now=now,
                    )
                except ValueError:
                    cleanup = False
        flow = self.red_team_store.plan_by_key(flow_key)
        if flow is not None:
            checkpoint = self.red_team_store.latest(flow.plan_id)
            if checkpoint.status not in TERMINAL_STATUSES:
                try:
                    RedTeamService(store=self.red_team_store).cancel(
                        flow, checkpoint, scope=scope, now=now
                    )
                except ValueError:
                    cleanup = False
        return cleanup

    def _prior_run_clean(self, checkpoint):
        if checkpoint.active_run_id is not None:
            raise EndpointScheduleRejected("Endpoint Schedule already has an active run")
        if checkpoint.last_run_id is None:
            return
        run = self.schedule_store.run(checkpoint.last_run_id)
        if run.cleanup_complete is not True:
            raise EndpointScheduleRejected(
                "Endpoint Schedule previous run cleanup is unproven"
            )
        if run.state is not EndpointScheduleRunState.MATERIALIZED:
            return
        flow = self.red_team_store.plan(run.flow_plan_id)
        reservation = self.recon_store.reservation(run.endpoint_recon_plan_id)
        recon_state = self.recon_store.state(run.endpoint_recon_plan_id)
        if (
            self.red_team_store.latest(flow.plan_id).status not in TERMINAL_STATUSES
            or reservation.state is EndpointReconReservationState.ACTIVE
            or (recon_state is not None and recon_state[0].value == "started")
        ):
            raise EndpointScheduleRejected(
                "Endpoint Schedule previous Flow has not reached a clean terminal state"
            )

    def _not_due_replay(self, checkpoint, *, now):
        if (
            checkpoint.state is EndpointScheduleState.ACTIVE
            and checkpoint.active_run_id is None
            and checkpoint.last_run_id is not None
            and now < checkpoint.next_due_at
        ):
            run = self.schedule_store.run(checkpoint.last_run_id)
            if run.state is EndpointScheduleRunState.MATERIALIZED:
                return run
        return None

    def _binding(self, schedule, checkpoint, scope, now):
        self._identity_binding(schedule, scope)
        self._scope(scope, now)
        if (
            self.schedule_store.schedule(schedule.schedule_id) != schedule
            or self.schedule_store.latest(schedule.schedule_id) != checkpoint
            or checkpoint.state is not EndpointScheduleState.ACTIVE
            or now >= schedule.active_until
        ):
            raise EndpointScheduleRejected("Endpoint Schedule binding is invalid")

    @staticmethod
    def _identity_binding(schedule, scope):
        if schedule.scope_id != scope.scope_id or schedule.scope_version != scope.version:
            raise EndpointScheduleRejected("Endpoint Schedule Scope binding is invalid")

    @staticmethod
    def _scope(scope, now):
        if (
            scope.state is not ScopeState.APPROVED
            or not scope.valid_from <= now < scope.valid_until
        ):
            raise EndpointScheduleRejected("Endpoint Schedule requires current approved Scope")

    @staticmethod
    def _operator(schedule, operator_ref):
        if operator_ref != schedule.operator_ref:
            raise EndpointScheduleRejected("Endpoint Schedule operator binding is invalid")

    def _lifecycle(self, schedule_id, *, operator_ref, now, transition):
        schedule = self.schedule_store.schedule(schedule_id)
        checkpoint = self.schedule_store.latest(schedule_id)
        self._operator(schedule, operator_ref)
        try:
            advanced = transition(schedule, checkpoint, now=now)
            return (
                checkpoint
                if advanced == checkpoint
                else self.schedule_store.advance(checkpoint, advanced)
            )
        except (EndpointScheduleTransitionRejected, EndpointScheduleStoreRejected) as exc:
            raise EndpointScheduleRejected(str(exc)) from exc

    @staticmethod
    def _keys(run: EndpointScheduleRun) -> tuple[str, str, str]:
        prefix = f"endpoint-schedule:{run.schedule_id}:{run.schedule_run_id}"
        return f"{prefix}:flow", f"{prefix}:seeds", f"{prefix}:recon"

    @staticmethod
    def _configuration(schedule: EndpointCheckSchedule) -> dict[str, object]:
        values = schedule.model_dump(
            mode="python",
            exclude={"schedule_id", "created_at", "active_from", "active_until"},
        )
        values["active_duration_seconds"] = (
            schedule.active_until - schedule.active_from
        ).total_seconds()
        return values
