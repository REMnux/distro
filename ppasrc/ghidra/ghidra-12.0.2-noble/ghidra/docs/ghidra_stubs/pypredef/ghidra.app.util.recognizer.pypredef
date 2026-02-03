from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.classfinder
import java.lang # type: ignore
import java.util # type: ignore


class Recognizer(ghidra.util.classfinder.ExtensionPoint):
    """
    NOTE:  ALL Recognizer CLASSES MUST END IN "Recognizer".  If not,
    the ClassSearcher will not find them.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getPriority(self) -> int:
        """
        Return the recognizer priority; for instance, a GZIP/TAR recognizer
        should have higher priority than just the GZIP recognizer (because the
        GZIP/TAR will unzip part of the payload and then test against the TAR
        recognizer...so every GZIP/TAR match will also match GZIP). Note that
        higher is more specific, which is opposite the convention used with the
        Loader hierarchy.
        
        :return: the recognizer priority
        :rtype: int
        """

    def numberOfBytesRequired(self) -> int:
        """
        How many bytes (maximum) does this recognizer need to recognize its
        format?
        
        :return: the maximum number of bytes needed to send to this recognizer in
                the recognize(...) method
        :rtype: int
        """

    def recognize(self, bytes: jpype.JArray[jpype.JByte]) -> str:
        """
        Ask the recognizer to recognize some bytes. Return a description String
        if recognized; otherwise, null. DO NOT MUNGE THE BYTES. Right now for
        efficiency's sake the array of bytes is just passed to each recognizer in
        turn. Abuse this and we will need to create copies, and everyone loses.
        
        :param jpype.JArray[jpype.JByte] bytes: the bytes to recognize
        :return: a String description of the recognition, or null if it is not
                recognized
        :rtype: str
        """

    @property
    def priority(self) -> jpype.JInt:
        ...


class RecognizerService(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getAllRecognizers() -> java.util.List[Recognizer]:
        ...



__all__ = ["Recognizer", "RecognizerService"]
