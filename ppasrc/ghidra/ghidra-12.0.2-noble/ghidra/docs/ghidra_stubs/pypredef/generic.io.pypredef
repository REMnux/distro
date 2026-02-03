from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util.jar # type: ignore


class NullWriter(java.io.Writer):
    """
    An implementation of :obj:`Writer` to use when you wish to not use any writing, but to also
    avoid null checks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class JarWriter(java.lang.Object):
    """
    JarWriter is a class for writing to a jar output stream.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, jarOut: java.util.jar.JarOutputStream):
        """
        
        
        :param java.util.jar.JarOutputStream jarOut: the jar file output stream the zip entries are
        to be written to.
        """

    @typing.overload
    def __init__(self, jarOut: java.util.jar.JarOutputStream, excludedExtensions: jpype.JArray[java.lang.String]):
        ...

    def getJarOutputStream(self) -> java.util.jar.JarOutputStream:
        """
        Return the jar output stream being used by this JarWriter.
        """

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        """
        Simple test for the JarWriter
        
        :param jpype.JArray[java.lang.String] args: args[0] is the source directory, args[1] is the output filename
        """

    def outputEntry(self, path: typing.Union[java.lang.String, str], time: typing.Union[jpype.JLong, int], in_: java.io.InputStream, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Outputs an individual entry to the jar.  The data input stream will be read until and EOF is read.
        
        :param java.lang.String or str path: entry path within the jar file
        :param jpype.JLong or int time: entry time
        :param java.io.InputStream in: data input stream
        :param ghidra.util.task.TaskMonitor monitor: cancellable task monitor
        :return: true if entry is output to the jar file successfully.
        :rtype: bool
        """

    def outputFile(self, baseFile: jpype.protocol.SupportsPath, jarPath: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Outputs an individual file to the jar.
        
        :param jpype.protocol.SupportsPath baseFile: the file to be output
        :param java.lang.String or str jarPath: the base path to prepend to the file as it is written
        to the jar output stream.
        :param ghidra.util.task.TaskMonitor monitor: cancellable task monitor
        :return: true if file is output to the jar file successfully.
        :rtype: bool
        """

    def outputRecursively(self, baseFile: jpype.protocol.SupportsPath, jarPath: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Recursively outputs a directory to the jar output stream
        If baseFile is a file then it is simply output to the jar.
        
        :param jpype.protocol.SupportsPath baseFile: the file or directory to be output
        :param java.lang.String or str jarPath: the base path to prepend to the files as they are written
        to the jar output stream.
        :return: true if all files are recursively output to the jar file.
        :rtype: bool
        """

    @property
    def jarOutputStream(self) -> java.util.jar.JarOutputStream:
        ...


class NullPrintWriter(java.io.PrintWriter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def dummyIfNull(pw: java.io.PrintWriter) -> java.io.PrintWriter:
        ...



__all__ = ["NullWriter", "JarWriter", "NullPrintWriter"]
