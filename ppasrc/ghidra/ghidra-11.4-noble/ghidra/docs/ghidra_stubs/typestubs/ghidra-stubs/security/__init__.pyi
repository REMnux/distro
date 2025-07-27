from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.lang # type: ignore


class KeyStorePasswordProvider(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getKeyStorePassword(self, keystorePath: typing.Union[java.lang.String, str], passwordError: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[jpype.JChar]:
        """
        Requests password for keystore file
        
        :param java.lang.String or str keystorePath: keystore file path
        :param jpype.JBoolean or bool passwordError: if true this is a repeated prompt due to a password use failure
        :return: password or null, if not null caller will clear array
        when no longer needed.
        :rtype: jpype.JArray[jpype.JChar]
        """



__all__ = ["KeyStorePasswordProvider"]
