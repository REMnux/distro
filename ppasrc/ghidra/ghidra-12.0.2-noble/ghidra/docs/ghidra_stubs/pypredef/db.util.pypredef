from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.io # type: ignore


class ErrorHandler(java.lang.Object):
    """
    Report database errors.
    """

    class_: typing.ClassVar[java.lang.Class]

    def dbError(self, e: java.io.IOException):
        """
        Notification that an IO exception occurred.
        
        :param java.io.IOException e: :obj:`IOException` which was cause of error
        :raises java.lang.RuntimeException: optional exception which may be thrown when
        responding to error condition.
        """



__all__ = ["ErrorHandler"]
