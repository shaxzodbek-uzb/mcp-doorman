"""``mcp-doorman`` command-line entry point (argparse, stdlib only)."""

from __future__ import annotations

import argparse
import importlib
import sys
from typing import Any

from . import __version__
from .config import Settings
from .doorman import Doorman
from .errors import DoormanError
from .redaction import DEFAULT_KEYS


def _load_app(target: str) -> Any:
    """Import ``module:attr`` and return the attribute (a FastAPI app)."""
    if ":" not in target:
        raise DoormanError(f"expected 'module:app', got {target!r}")
    module_name, attr = target.split(":", 1)
    module = importlib.import_module(module_name)
    return getattr(module, attr)


def _cmd_doctor(_: argparse.Namespace) -> int:
    settings = Settings()
    print("mcp-doorman doctor")
    print(f"  version:           {__version__}")
    print(f"  endpoint:          {settings.endpoint}")
    print(f"  rate_limit:        {settings.rate_limit}")
    print(f"  audit sink:        {settings.audit}")
    print(f"  tenant_claim:      {settings.tenant_claim}")
    print(f"  require_auth_remote {settings.require_auth_for_remote}")
    print(f"  redaction keys:    {', '.join(DEFAULT_KEYS)}")
    try:
        import mcp  # type: ignore  # noqa: F401

        mcp_state = "available"
    except ImportError:
        mcp_state = "MISSING (pip install 'mcp-doorman[mcp]')"
    print(f"  mcp extra:         {mcp_state}")
    return 0


def _cmd_lint(args: argparse.Namespace) -> int:
    app = _load_app(args.target)
    doorman = Doorman.dev(app)
    specs = doorman.registry.specs()
    if not specs:
        print("no exposed tools found (deny-by-default: decorate routes with @expose)")
        return 0
    warnings = 0
    print(f"{len(specs)} exposed tool(s):")
    for spec in specs:
        ann = spec.annotations()
        flags = []
        if spec.destructive:
            flags.append("destructive")
        if spec.read_only:
            flags.append("read-only")
        print(
            f"  - {spec.name}  methods={sorted(spec.methods)}  scopes={list(spec.scopes)}  "
            f"[{', '.join(flags)}]  hints={ann}"
        )
        if not spec.scopes:
            print(f"      ! WARNING: {spec.name!r} is exposed with NO scopes (open to any caller)")
            warnings += 1
        if spec.destructive and not spec.scopes:
            print(f"      ! WARNING: destructive tool {spec.name!r} has no scope guard")
            warnings += 1
    if warnings:
        print(f"\n{warnings} warning(s).")
        return 1
    return 0


def _cmd_version(_: argparse.Namespace) -> int:
    print(__version__)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-doorman", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="print settings + extra availability")
    doctor.set_defaults(func=_cmd_doctor)

    lint = sub.add_parser("lint", help="scan a FastAPI app and report exposed tools")
    lint.add_argument("target", help="module:app, e.g. myapp.main:app")
    lint.set_defaults(func=_cmd_lint)

    sub.add_parser("version", help="print the version").set_defaults(func=_cmd_version)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except DoormanError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
