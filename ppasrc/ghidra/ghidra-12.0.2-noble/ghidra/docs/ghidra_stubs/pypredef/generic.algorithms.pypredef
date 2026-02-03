from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


I = typing.TypeVar("I")
T = typing.TypeVar("T")


class CRC64(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def finish(self) -> int:
        ...

    def update(self, buf: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]):
        ...


class ReducingListBasedLcs(ReducingLcs[java.util.List[T], T], typing.Generic[T]):
    """
    An implementation of the :obj:`ReducingLcs` that takes as its input a list of <T>items, where
    the list is the 'sequence' being checked for the Longest Common Subsequence.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, x: java.util.List[T], y: java.util.List[T]):
        ...


class ReducingLcs(Lcs[T], typing.Generic[I, T]):
    """
    Calculates the longest common subsequence (LCS) between two sequences of Matchable 
    objects, ``x`` and ``y``.
     
     
    This is an optimizing version of the :obj:`Lcs` that will pre-calculate all similar 
    items from the beginning and end of the two given sequences.  Doing this will reduce 
    the size of the matrix created by the parent class, greatly so in the case that the 
    two inputs are mostly the same in the beginning and end.  (Imagine an edit of a source 
    code file, where the typical change is somewhere in the middle of the file.  In this example, 
    the optimization performed here can greatly decrease the amount of work to be performed when 
    calculating the LCS.)
     
     
    Note: the parent LCS algorithm is bound by :meth:`getSizeLimit() <.getSizeLimit>`.  However, this class 
    allows clients to work around this restriction when the data has a similar beginning and ending, 
    as the similar parts will not be counted against the size limit.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, ix: I, iy: I):
        """
        Constructor
        
        :param I ix: the input sequence ``x``
        :param I iy: the input sequence ``y``
        """


class Lcs(java.lang.Object, typing.Generic[T]):
    """
    Abstract class for finding the Longest Common Subsequence (LCS) between two 
    sequences of Matchable objects, ``x`` and ``y``.
     
     
    The performance of this algorithm is O(n^2).  Thus, large inputs can cause much processor
    and memory usage.   This class has an upper limit (see :meth:`getSizeLimit() <.getSizeLimit>`) to prevent
    accidental system failure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @typing.overload
    def getLcs(self) -> java.util.List[T]:
        """
        Returns a list of the longest common subsequence.  This result will be empty if the 
        :meth:`getSizeLimit() <.getSizeLimit>` has been reached.
        
        :return: the list
        :rtype: java.util.List[T]
        """

    @typing.overload
    def getLcs(self, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[T]:
        """
        Returns a list of the longest common subsequence. This result will be empty if the 
        :meth:`getSizeLimit() <.getSizeLimit>` has been reached.
        
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the LCS list
        :rtype: java.util.List[T]
        :raises CancelledException: if the monitor is cancelled
        """

    def getSizeLimit(self) -> int:
        """
        Returns the current size limit, past which no calculations will be performed
        
        :return: the size limit
        :rtype: int
        
        .. seealso::
        
            | :obj:`.setSizeLimit(int)`
        """

    def setSizeLimit(self, newLimit: typing.Union[jpype.JInt, int]):
        """
        Changes the size limit of this LCS, past which no calculations will be performed
        
        :param jpype.JInt or int newLimit: the new limit
        """

    @property
    def sizeLimit(self) -> jpype.JInt:
        ...

    @sizeLimit.setter
    def sizeLimit(self, value: jpype.JInt):
        ...

    @property
    def lcs(self) -> java.util.List[T]:
        ...



__all__ = ["CRC64", "ReducingListBasedLcs", "ReducingLcs", "Lcs"]
