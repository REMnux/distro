from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.net # type: ignore


class Handler(java.net.URLStreamHandler):
    """
    Dummy stream handler, so we can create URL objects with protocol "postgresql"
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def registerHandler():
        ...



__all__ = ["Handler"]
