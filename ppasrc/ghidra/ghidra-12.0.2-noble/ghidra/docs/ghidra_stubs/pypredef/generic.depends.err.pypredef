from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.util # type: ignore


E = typing.TypeVar("E")


class UnsatisfiedFieldsException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, missing: java.util.Set[java.lang.Class[typing.Any]]):
        ...

    def getMissing(self) -> java.util.Set[java.lang.Class[typing.Any]]:
        ...

    @property
    def missing(self) -> java.util.Set[java.lang.Class[typing.Any]]:
        ...


class UnsatisfiedParameterException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, left: java.util.Set[java.lang.Class[typing.Any]]):
        ...

    def getLeft(self) -> java.util.Set[java.lang.Class[typing.Any]]:
        ...

    @property
    def left(self) -> java.util.Set[java.lang.Class[typing.Any]]:
        ...


class ServiceConstructionException(java.lang.Exception):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...

    def unwrap(self, cls: java.lang.Class[E]):
        ...



__all__ = ["UnsatisfiedFieldsException", "UnsatisfiedParameterException", "ServiceConstructionException"]
