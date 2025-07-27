from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import java.lang # type: ignore


class LinearExecutable(java.lang.Object):
    """
    A class to manage loading Linear Executables (LX).
     
    NOTE: this is not implemented yet.
    """

    class_: typing.ClassVar[java.lang.Class]
    IMAGE_LX_SIGNATURE: typing.Final = 22604
    """
    The magic number for LX executables.
    """


    def __init__(self, bp: ghidra.app.util.bin.ByteProvider):
        ...



__all__ = ["LinearExecutable"]
