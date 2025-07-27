from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.model
import ghidra.framework.project


class TestProjectManager(ghidra.framework.project.DefaultProjectManager):
    """
    This class exists to open access to the :obj:`DefaultProjectManager` for tests
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def get() -> ghidra.framework.model.ProjectManager:
        ...



__all__ = ["TestProjectManager"]
