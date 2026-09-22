"""Generate ../types/api.d.ts from models.py. The contract test fails if the file drifts from the models.

    python generate_types.py          # rewrite types/api.d.ts
"""
import json
import pathlib
import types
import typing
from typing import Any, Union, get_args, get_origin

from pydantic import BaseModel

import models

OUT = pathlib.Path(__file__).resolve().parent.parent / "types" / "api.d.ts"


def ts_type(tp: Any, use_alias: bool = True) -> str:
    origin = get_origin(tp)
    args = get_args(tp)
    if origin is typing.Annotated:
        return ts_type(args[0])
    if tp is Any:
        return "unknown"
    if tp is type(None):
        return "null"
    if tp is str:
        return "string"
    if tp is bool:
        return "boolean"
    if tp in (int, float):
        return "number"
    if origin is typing.Literal:
        if use_alias:
            for name, alias in models.TS_ALIASES.items():
                if alias == tp:
                    return name
        return " | ".join(json.dumps(a) for a in args)
    if origin in (Union, types.UnionType):
        parts = [ts_type(a) for a in args]
        return " | ".join(parts)
    if origin in (list, typing.List):
        inner = ts_type(args[0])
        return f"({inner})[]" if " | " in inner else f"{inner}[]"
    if origin in (dict, typing.Dict):
        return f"Record<string, {ts_type(args[1])}>"
    if isinstance(tp, type) and issubclass(tp, BaseModel):
        return tp.__name__
    raise TypeError(f"cannot map {tp!r} to TypeScript")


def render() -> str:
    lines = [
        "// GENERATED from backend/models.py by backend/generate_types.py. DO NOT EDIT BY HAND.",
        "// Contract change process: brief Part C4 (edit models.py, regenerate, bump CONTRACT_VERSION, tell Gaurav).",
        "",
        f'export declare const CONTRACT_VERSION: "{models.CONTRACT_VERSION}";',
        "",
    ]
    for name, alias in models.TS_ALIASES.items():
        lines.append(f"export type {name} = {ts_type(alias, use_alias=False)};")
    lines.append("")
    for model in models.ALL_MODELS:
        lines.append(f"export interface {model.__name__} {{")
        for fname, info in model.model_fields.items():
            optional = "?" if not info.is_required() else ""
            lines.append(f"  {fname}{optional}: {ts_type(info.annotation)};")
        lines.append("}")
        lines.append("")
    return "\n".join(lines)


if __name__ == "__main__":
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(render(), encoding="utf-8")
    print(f"wrote {OUT}")
