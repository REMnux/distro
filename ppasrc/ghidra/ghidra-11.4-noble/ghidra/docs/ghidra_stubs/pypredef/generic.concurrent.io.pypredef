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
import java.util.concurrent # type: ignore
import java.util.function # type: ignore


class ProcessConsumer(java.lang.Object):
    """
    A class that allows clients to **asynchronously** consume the output of a :obj:`Process`s
    input and error streams.  The task is asynchronous to avoid deadlocks when both streams need
    to be read in order for the process to proceed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def consume(is_: java.io.InputStream) -> java.util.concurrent.Future[IOResult]:
        """
        Read the given input stream line-by-line. 
         
         
        To get all output after all reading is done you can call the blocking operation 
        :meth:`Future.get() <Future.get>`.
        
        :param java.io.InputStream is: the input stream
        :return: the future that will be complete when all lines are read
        :rtype: java.util.concurrent.Future[IOResult]
        """

    @staticmethod
    @typing.overload
    def consume(is_: java.io.InputStream, lineConsumer: java.util.function.Consumer[java.lang.String]) -> java.util.concurrent.Future[IOResult]:
        """
        Read the given input stream line-by-line.
         
         
        If you wish to get all output after all reading is done you can call the blocking 
        operation :meth:`Future.get() <Future.get>`.
        
        :param java.io.InputStream is: the input stream
        :param java.util.function.Consumer[java.lang.String] lineConsumer: the line consumer; may be null
        :return: the future that will be complete when all lines are read
        :rtype: java.util.concurrent.Future[IOResult]
        """


class IOResult(java.lang.Runnable):
    """
    Class to pass to a thread pool that will consume all output from an external process.  This is
    a :obj:`Runnable` that get submitted to a thread pool.  This class records the data it reads
    """

    class_: typing.ClassVar[java.lang.Class]
    THREAD_POOL_NAME: typing.Final = "I/O Thread Pool"

    @typing.overload
    def __init__(self, input: java.io.InputStream):
        ...

    @typing.overload
    def __init__(self, inception: java.lang.Throwable, input: java.io.InputStream):
        ...

    def getOutput(self) -> java.util.List[java.lang.String]:
        ...

    def getOutputAsString(self) -> str:
        ...

    def setConsumer(self, consumer: java.util.function.Consumer[java.lang.String]):
        ...

    @property
    def output(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def outputAsString(self) -> java.lang.String:
        ...



__all__ = ["ProcessConsumer", "IOResult"]
