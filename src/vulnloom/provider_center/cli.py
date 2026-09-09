"""Stable local JSON CLI surface for Provider Center application services."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .models import (
    CapabilityProbeFixture,
    CapabilityProbeRequest,
    DisableProviderCommand,
    EnableProviderCommand,
    RegisterProviderCommand,
    SetDefaultRouteCommand,
    UpdateProviderCommand,
)
from .service import FixtureCapabilityProbeAdapter, ProviderCenterService
from .store import ProviderCenterStore


def _load(path: str, model):
    return model.model_validate_json(Path(path).read_text(encoding="utf-8"))


def _emit(value) -> int:
    print(json.dumps(value.model_dump(mode="json"), indent=2, sort_keys=True))
    return 0


def _rejected() -> int:
    print(json.dumps({"status": "provider_center_rejected"}, sort_keys=True))
    return 1


def _mutate(args: argparse.Namespace) -> int:
    methods = {
        "add": (RegisterProviderCommand, "register"),
        "update": (UpdateProviderCommand, "update"),
        "enable": (EnableProviderCommand, "enable"),
        "disable": (DisableProviderCommand, "disable"),
    }
    model, method = methods[args.provider_action]
    try:
        command = _load(args.command_file, model)
        with ProviderCenterStore(Path(args.provider_db)) as store:
            result = getattr(ProviderCenterService(store), method)(command)
        return _emit(result)
    except (OSError, ValueError, RuntimeError):
        return _rejected()


def _probe(args: argparse.Namespace) -> int:
    try:
        request = _load(args.request_file, CapabilityProbeRequest)
        fixture = _load(args.fixture_file, CapabilityProbeFixture)
        with ProviderCenterStore(Path(args.provider_db)) as store:
            result = ProviderCenterService(store).probe(
                request, FixtureCapabilityProbeAdapter(fixture.observation)
            )
        return _emit(result)
    except (OSError, ValueError, RuntimeError):
        return _rejected()


def _view(args: argparse.Namespace) -> int:
    try:
        with ProviderCenterStore(Path(args.provider_db)) as store:
            view = store.view(audit_limit=args.audit_limit)
    except (OSError, ValueError, RuntimeError):
        return _rejected()
    if args.provider_action == "audit":
        print(
            json.dumps(
                [item.model_dump(mode="json") for item in view.recent_audit],
                indent=2,
                sort_keys=True,
            )
        )
        return 0
    return _emit(view)


def _route(args: argparse.Namespace) -> int:
    try:
        if args.route_action == "list":
            with ProviderCenterStore(Path(args.provider_db)) as store:
                routes = store.view(audit_limit=0).default_routes
            print(
                json.dumps(
                    [item.model_dump(mode="json") for item in routes],
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        command = _load(args.command_file, SetDefaultRouteCommand)
        with ProviderCenterStore(Path(args.provider_db)) as store:
            result = ProviderCenterService(store).set_default_route(command)
        return _emit(result)
    except (OSError, ValueError, RuntimeError):
        return _rejected()


def register_provider_center_commands(subparsers) -> None:
    provider = subparsers.add_parser("provider")
    provider.add_argument("--provider-db", default=".vulnloom/provider-center.db")
    actions = provider.add_subparsers(dest="provider_action", required=True)
    for name in ("add", "update", "enable", "disable"):
        command = actions.add_parser(name)
        command.add_argument("--command-file", required=True)
        command.set_defaults(handler=_mutate)
    probe = actions.add_parser("probe-offline")
    probe.add_argument("--request-file", required=True)
    probe.add_argument("--fixture-file", required=True)
    probe.set_defaults(handler=_probe)
    for name in ("list", "audit"):
        query = actions.add_parser(name)
        query.add_argument("--audit-limit", type=int, choices=range(0, 1001), default=50)
        query.set_defaults(handler=_view)

    routes = subparsers.add_parser("model-route")
    routes.add_argument("--provider-db", default=".vulnloom/provider-center.db")
    route_actions = routes.add_subparsers(dest="route_action", required=True)
    route_set = route_actions.add_parser("set")
    route_set.add_argument("--command-file", required=True)
    route_set.set_defaults(handler=_route)
    route_list = route_actions.add_parser("list")
    route_list.set_defaults(handler=_route)
