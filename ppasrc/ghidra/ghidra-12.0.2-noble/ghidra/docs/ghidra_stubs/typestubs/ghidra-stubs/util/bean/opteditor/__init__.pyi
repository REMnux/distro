from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore


class OptionsVetoException(java.lang.RuntimeException):
    """
    Intended to be thrown from 
    :meth:`OptionsChangeListener.optionsChanged(ToolOptions, String, Object, Object) <OptionsChangeListener.optionsChanged>` to signal that 
    the setting of an option property is invalid and should not happen.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, message: typing.Union[java.lang.String, str]):
        ...



__all__ = ["OptionsVetoException"]
