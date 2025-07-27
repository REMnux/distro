from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.io # type: ignore
import java.lang # type: ignore


class Password(java.io.Closeable):
    """
    Wrapper for a password, held in a char[] array.
     
    
    :meth:`Closing <.close>` an instance will clear the characters of the char array.
    """

    class_: typing.ClassVar[java.lang.Class]

    def close(self):
        """
        Clears the password characters by overwriting them with '\0's.
        """

    @staticmethod
    def copyOf(password: jpype.JArray[jpype.JChar]) -> Password:
        """
        Creates a new ``Password`` using a copy the specified characters.
        
        :param jpype.JArray[jpype.JChar] password: password characters
        :return: new ``Password`` instance
        :rtype: Password
        """

    def getPasswordChars(self) -> jpype.JArray[jpype.JChar]:
        """
        Returns a reference to the current password characters.
        
        :return: reference to the current password characters
        :rtype: jpype.JArray[jpype.JChar]
        """

    @staticmethod
    def wrap(password: jpype.JArray[jpype.JChar]) -> Password:
        """
        Creates a new ``Password`` by wrapping the specified character array.
         
        
        The new instance will take ownership of the char array, and
        clear it when the instance is :meth:`closed <.close>`.
        
        :param jpype.JArray[jpype.JChar] password: password characters
        :return: new ``Password`` instance
        :rtype: Password
        """

    @property
    def passwordChars(self) -> jpype.JArray[jpype.JChar]:
        ...



__all__ = ["Password"]
