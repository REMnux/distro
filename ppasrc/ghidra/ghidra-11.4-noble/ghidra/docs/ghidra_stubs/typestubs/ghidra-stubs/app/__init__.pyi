from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.plugintool.util
import java.lang # type: ignore


class ExamplesPluginPackage(ghidra.framework.plugintool.util.PluginPackage):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Examples"

    def __init__(self):
        ...


class DeveloperPluginPackage(ghidra.framework.plugintool.util.PluginPackage):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Developer"

    def __init__(self):
        ...


class CorePluginPackage(ghidra.framework.plugintool.util.PluginPackage):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "Ghidra Core"

    def __init__(self):
        ...



__all__ = ["ExamplesPluginPackage", "DeveloperPluginPackage", "CorePluginPackage"]
