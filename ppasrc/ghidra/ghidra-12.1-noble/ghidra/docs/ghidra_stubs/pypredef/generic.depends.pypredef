from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore


T = typing.TypeVar("T")


@typing.type_check_only
class DependentServiceConstructor(java.lang.Object, typing.Generic[T]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class DependentServiceResolver(java.lang.Object, typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def get(cls: java.lang.Class[T]) -> DependentServiceResolver[T]:
        ...

    @staticmethod
    def inject(t: T) -> None:
        ...

    def injectServices(self, obj: T) -> None:
        ...



__all__ = ["DependentServiceConstructor", "DependentServiceResolver"]
