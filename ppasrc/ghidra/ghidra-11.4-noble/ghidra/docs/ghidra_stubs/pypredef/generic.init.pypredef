from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework
import java.lang # type: ignore
import utility.application


class GenericInitializer(ghidra.framework.ModuleInitializer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GenericApplicationSettings(utility.application.ApplicationSettings):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["GenericInitializer", "GenericApplicationSettings"]
