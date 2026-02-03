from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.pty
import ghidra.pty.unix
import java.lang # type: ignore


class MacosPtyFactory(java.lang.Enum[MacosPtyFactory], ghidra.pty.PtyFactory):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[MacosPtyFactory]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MacosPtyFactory:
        ...

    @staticmethod
    def values() -> jpype.JArray[MacosPtyFactory]:
        ...


class MacosIoctls(java.lang.Enum[MacosIoctls], ghidra.pty.unix.PosixC.Ioctls):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[MacosIoctls]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> MacosIoctls:
        ...

    @staticmethod
    def values() -> jpype.JArray[MacosIoctls]:
        ...


class MacosPtySessionLeader(ghidra.pty.unix.UnixPtySessionLeader):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...



__all__ = ["MacosPtyFactory", "MacosIoctls", "MacosPtySessionLeader"]
