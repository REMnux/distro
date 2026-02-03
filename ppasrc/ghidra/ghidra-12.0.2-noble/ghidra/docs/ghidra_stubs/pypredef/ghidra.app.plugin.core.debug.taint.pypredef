from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.plugin.core.decompiler.taint # type: ignore


class AngrTaintState(ghidra.app.plugin.core.decompiler.taint.AbstractTaintState):
    """
    Container for all the decompiler elements the users "selects" via the menu. This data is used to
    build queries.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.app.plugin.core.decompiler.taint.TaintPlugin):
        ...



__all__ = ["AngrTaintState"]
