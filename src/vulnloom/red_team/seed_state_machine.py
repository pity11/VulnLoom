"""Pure transitions for Endpoint Recon action-budget reservations."""

from __future__ import annotations

from datetime import datetime

from .seed_models import (
    EndpointReconPlan,
    EndpointReconReservation,
    EndpointReconReservationState,
)


class EndpointReconReservationTransitionRejected(ValueError):
    pass


def _replace(reservation: EndpointReconReservation, **changes: object) -> EndpointReconReservation:
    values = reservation.model_dump(mode="python")
    values.update(changes)
    return EndpointReconReservation.model_validate(values)


def reserve_endpoint_recon(plan: EndpointReconPlan) -> EndpointReconReservation:
    return EndpointReconReservation(
        endpoint_recon_plan_id=plan.endpoint_recon_plan_id,
        state=EndpointReconReservationState.ACTIVE,
        reserved_requests=len(plan.steps),
        consumed_requests=0,
        created_at=plan.created_at,
        updated_at=plan.created_at,
    )


def consume_endpoint_recon_request(
    reservation: EndpointReconReservation, *, now: datetime
) -> EndpointReconReservation:
    _monotonic_time(reservation, now)
    if reservation.state is not EndpointReconReservationState.ACTIVE:
        raise EndpointReconReservationTransitionRejected(
            "only an active Endpoint Recon reservation can be consumed"
        )
    consumed = reservation.consumed_requests + 1
    if consumed > reservation.reserved_requests:
        raise EndpointReconReservationTransitionRejected("Endpoint Recon reservation is exhausted")
    terminal = consumed == reservation.reserved_requests
    return _replace(
        reservation,
        state=(
            EndpointReconReservationState.CONSUMED
            if terminal
            else EndpointReconReservationState.ACTIVE
        ),
        consumed_requests=consumed,
        updated_at=now,
        terminal_reason="all_steps_consumed" if terminal else None,
    )


def cancel_endpoint_recon(
    reservation: EndpointReconReservation,
    *,
    now: datetime,
    reason: str = "operator_cancelled",
) -> EndpointReconReservation:
    _monotonic_time(reservation, now)
    if reservation.state is EndpointReconReservationState.CANCELLED:
        return reservation
    if reservation.state is not EndpointReconReservationState.ACTIVE:
        raise EndpointReconReservationTransitionRejected(
            "only an active Endpoint Recon reservation can be cancelled"
        )
    return _replace(
        reservation,
        state=EndpointReconReservationState.CANCELLED,
        updated_at=now,
        terminal_reason=reason,
    )


def expire_endpoint_recon(
    reservation: EndpointReconReservation, *, now: datetime
) -> EndpointReconReservation:
    _monotonic_time(reservation, now)
    if reservation.state is EndpointReconReservationState.EXPIRED:
        return reservation
    if reservation.state is not EndpointReconReservationState.ACTIVE:
        raise EndpointReconReservationTransitionRejected(
            "only an active Endpoint Recon reservation can expire"
        )
    return _replace(
        reservation,
        state=EndpointReconReservationState.EXPIRED,
        updated_at=now,
        terminal_reason="reservation_expired",
    )


def _monotonic_time(reservation: EndpointReconReservation, now: datetime) -> None:
    if now < reservation.updated_at:
        raise EndpointReconReservationTransitionRejected(
            "Endpoint Recon reservation time cannot move backwards"
        )
