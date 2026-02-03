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


class LinuxIoctls(java.lang.Enum[LinuxIoctls], ghidra.pty.unix.PosixC.Ioctls):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[LinuxIoctls]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> LinuxIoctls:
        ...

    @staticmethod
    def values() -> jpype.JArray[LinuxIoctls]:
        ...


class LinuxPtyFactory(java.lang.Enum[LinuxPtyFactory], ghidra.pty.PtyFactory):

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[LinuxPtyFactory]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> LinuxPtyFactory:
        ...

    @staticmethod
    def values() -> jpype.JArray[LinuxPtyFactory]:
        ...


class LinuxPtySessionLeader(ghidra.pty.unix.UnixPtySessionLeader):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...



__all__ = ["LinuxIoctls", "LinuxPtyFactory", "LinuxPtySessionLeader"]
