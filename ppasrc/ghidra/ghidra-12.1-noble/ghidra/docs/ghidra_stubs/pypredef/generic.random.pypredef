from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore
import java.security # type: ignore


class SecureRandomFactory(java.lang.Object):
    """
    ``SecureRandomFactory`` provides a static singleton instance of SecureRandom
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getSecureRandom() -> java.security.SecureRandom:
        ...



__all__ = ["SecureRandomFactory"]
