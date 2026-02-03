from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.util # type: ignore


T = typing.TypeVar("T")


class ValStr(java.lang.Record, typing.Generic[T]):

    class Decoder(java.lang.Object, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def decode(self, string: typing.Union[java.lang.String, str]) -> T:
            ...

        def decodeValStr(self, string: typing.Union[java.lang.String, str]) -> ValStr[T]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, val: T, str: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def cast(cls: java.lang.Class[T], value: ValStr[typing.Any]) -> ValStr[T]:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    @staticmethod
    def fromPlainMap(map: collections.abc.Mapping) -> java.util.Map[java.lang.String, ValStr[typing.Any]]:
        ...

    @staticmethod
    def from_(value: T) -> ValStr[T]:
        ...

    def hashCode(self) -> int:
        ...

    @staticmethod
    @typing.overload
    def normStr(val: ValStr[typing.Any]) -> str:
        ...

    @typing.overload
    def normStr(self) -> str:
        ...

    @staticmethod
    @typing.overload
    def str(value: typing.Union[java.lang.String, str]) -> ValStr[java.lang.String]:
        ...

    @typing.overload
    def str(self) -> str:
        ...

    @staticmethod
    def toPlainMap(map: collections.abc.Mapping) -> java.util.Map[java.lang.String, java.lang.Object]:
        ...

    def toString(self) -> str:
        ...

    def val(self) -> T:
        ...



__all__ = ["ValStr"]
