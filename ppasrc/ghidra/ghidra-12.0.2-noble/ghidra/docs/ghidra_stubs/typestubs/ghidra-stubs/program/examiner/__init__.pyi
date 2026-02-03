from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class ProgramExaminer(java.lang.Object):
    """
    Wrapper for Ghidra code to find images (and maybe other artifacts later) in a program
     
    NOTE: This is intended for end-user use and has no direct references within Ghidra.  
    Typical use of the class entails generating a ghidra.jar (see BuildGhidraJarScript.java)
    and referencing this class from end-user code.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, bytes: jpype.JArray[jpype.JByte]):
        """
        Constructs a new ProgramExaminer.
        
        :param jpype.JArray[jpype.JByte] bytes: the bytes of the potential program to be examined.
        :raises GhidraException: if any exception occurs while processing the bytes.
        """

    @typing.overload
    def __init__(self, file: jpype.protocol.SupportsPath):
        """
        Constructs a new ProgramExaminer.
        
        :param jpype.protocol.SupportsPath file: file object containing the bytes to be examined.
        :raises GhidraException: if any exception occurs while processing the bytes.
        """

    def dispose(self):
        """
        Releases file/database resources.
        """

    def getImages(self) -> java.util.List[jpype.JArray[jpype.JByte]]:
        """
        Returns a list of byte[] containing image data.  The bytes will be either a png, a gif, or
        a bitmap
        """

    def getType(self) -> str:
        """
        Returns a string indication the program format. i.e. PE, elf, raw
        """

    @staticmethod
    def initializeGhidra():
        ...

    @property
    def images(self) -> java.util.List[jpype.JArray[jpype.JByte]]:
        ...

    @property
    def type(self) -> java.lang.String:
        ...



__all__ = ["ProgramExaminer"]
