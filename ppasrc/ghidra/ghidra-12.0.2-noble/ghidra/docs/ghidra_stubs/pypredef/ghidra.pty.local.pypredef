from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pty
import ghidra.pty.windows
import java.lang # type: ignore


class LocalWindowsNativeProcessPtySession(ghidra.pty.PtySession):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pid: typing.Union[jpype.JInt, int], tid: typing.Union[jpype.JInt, int], processHandle: ghidra.pty.windows.Handle, threadHandle: ghidra.pty.windows.Handle, ptyName: typing.Union[java.lang.String, str], jobHandle: ghidra.pty.windows.Handle):
        ...


class LocalProcessPtySession(ghidra.pty.PtySession):
    """
    A pty session consisting of a local process and its descendants
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, process: java.lang.Process, ptyName: typing.Union[java.lang.String, str]):
        ...



__all__ = ["LocalWindowsNativeProcessPtySession", "LocalProcessPtySession"]
