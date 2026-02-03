from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.target.iface
import java.lang # type: ignore
import java.util # type: ignore


class TraceThread(ghidra.trace.model.TraceUniqueObject, ghidra.trace.model.target.iface.TraceObjectInterface):
    """
    A thread in a trace
     
     
    
    This object must be associated with a suitable :obj:`TraceExecutionStateful`. In most
    cases, the object should just implement it.
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_TID: typing.Final = "_tid"
    """
    The key that gives the TID, as assigned by the target's platform
    """


    def delete(self):
        """
        Delete this thread from the trace
        """

    def getComment(self, snap: typing.Union[jpype.JLong, int]) -> str:
        """
        Get the comment on this thread
        
        :param jpype.JLong or int snap: the snap
        :return: the comment, possibly ``null``
        :rtype: str
        """

    def getKey(self) -> int:
        """
        Get a key identifying this thread, unique among all threads in this trace for all time
        
        :return: the key
        :rtype: int
        """

    def getName(self, snap: typing.Union[jpype.JLong, int]) -> str:
        """
        Get the "short name" of this thread
        
        :param jpype.JLong or int snap: the snap
        :return: the name
        :rtype: str
        """

    def getPath(self) -> str:
        """
        Get the "full name" of this thread
        
        :return: the path
        :rtype: str
        """

    def getRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        """
        A convenience to obtain the registers from the containing trace's base language
        
        :return: the list of registers
        :rtype: java.util.List[ghidra.program.model.lang.Register]
        """

    def getTrace(self) -> ghidra.trace.model.Trace:
        """
        Get the trace containing this thread
        
        :return: the trace
        :rtype: ghidra.trace.model.Trace
        """

    def isAlive(self, span: ghidra.trace.model.Lifespan) -> bool:
        """
        Check if the module is alive for any of the given span
        
        :param ghidra.trace.model.Lifespan span: the span
        :return: true if its life intersects the span
        :rtype: bool
        """

    def isValid(self, snap: typing.Union[jpype.JLong, int]) -> bool:
        """
        Check if the thread is valid at the given snapshot
         
         
        
        In object mode, a thread's life may be disjoint, so checking if the snap occurs between
        creation and destruction is not quite sufficient. This method encapsulates validity. In
        object mode, it checks that the thread object has a canonical parent at the given snapshot.
        In table mode, it checks that the lifespan contains the snap.
        
        :param jpype.JLong or int snap: the snapshot key
        :return: true if valid, false if not
        :rtype: bool
        """

    def remove(self, snap: typing.Union[jpype.JLong, int]):
        """
        Remove this thread from the given snapshot on
        
        :param jpype.JLong or int snap: the snapshot key
        """

    def setComment(self, snap: typing.Union[jpype.JLong, int], comment: typing.Union[java.lang.String, str]):
        """
        Set a comment on this thread
        
        :param jpype.JLong or int snap: the snap
        :param java.lang.String or str comment: the comment, possibly ``null``
        """

    @typing.overload
    def setName(self, lifespan: ghidra.trace.model.Lifespan, name: typing.Union[java.lang.String, str]):
        """
        Set the "short name" of this thread
        
        :param ghidra.trace.model.Lifespan lifespan: the span of time
        :param java.lang.String or str name: the name
        """

    @typing.overload
    def setName(self, snap: typing.Union[jpype.JLong, int], name: typing.Union[java.lang.String, str]):
        """
        Set the "short name" of this thread
        
        :param jpype.JLong or int snap: the starting snap
        :param java.lang.String or str name: the name
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def trace(self) -> ghidra.trace.model.Trace:
        ...

    @property
    def alive(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def registers(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    @property
    def comment(self) -> java.lang.String:
        ...

    @property
    def key(self) -> jpype.JLong:
        ...


class TraceProcess(ghidra.trace.model.target.iface.TraceObjectInterface):
    """
    A marker interface which indicates a process, usually on a host operating system
     
     
    
    If this object does not support :obj:`TraceExecutionStateful`, then its mere existence in
    the model implies that it is :obj:`TraceExecutionState.ALIVE`. TODO: Should allow association
    via convention to a different :obj:`TraceExecutionStateful`, but that may have to wait
    until schemas are introduced.
    """

    class_: typing.ClassVar[java.lang.Class]
    KEY_PID: typing.Final = "_pid"


class TraceThreadManager(java.lang.Object):
    """
    A store for observed threads over time in a trace
     
     
    
    Note that the methods returning collections of threads order them eldest first. "Eldest" means
    lowest database key, which does not necessarily correlate to earliest creation snap.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def addThread(self, path: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan) -> TraceThread:
        """
        Add a thread with the given lifespan
        
        :param java.lang.String or str path: the "full name" of the thread
        :param ghidra.trace.model.Lifespan lifespan: the lifespan of the thread
        :return: the new thread
        :rtype: TraceThread
        :raises DuplicateNameException: if a thread with the given full name already exists within an
                    overlapping snap
        """

    @typing.overload
    def addThread(self, path: typing.Union[java.lang.String, str], display: typing.Union[java.lang.String, str], lifespan: ghidra.trace.model.Lifespan) -> TraceThread:
        """
        Add a thread with the given lifespan
        
        :param java.lang.String or str path: the "full name" of the thread
        :param java.lang.String or str display: "short name" of the thread
        :param ghidra.trace.model.Lifespan lifespan: the lifespan of the thread
        :return: the new thread
        :rtype: TraceThread
        :raises DuplicateNameException: if a thread with the given full name already exists within an
                    overlapping snap
        """

    @typing.overload
    def createThread(self, path: typing.Union[java.lang.String, str], creationSnap: typing.Union[jpype.JLong, int]) -> TraceThread:
        """
        Add a thread with the given creation snap
        
        
        .. seealso::
        
            | :obj:`.addThread(String, Lifespan)`
        """

    @typing.overload
    def createThread(self, path: typing.Union[java.lang.String, str], display: typing.Union[java.lang.String, str], creationSnap: typing.Union[jpype.JLong, int]) -> TraceThread:
        """
        Add a thread with the given creation snap
        
        
        .. seealso::
        
            | :obj:`.addThread(String, String, Lifespan)`
        """

    def getAllThreads(self) -> java.util.Collection[TraceThread]:
        """
        Get all threads ordered eldest first
        
        :return: the collection
        :rtype: java.util.Collection[TraceThread]
        """

    def getLiveThreadByPath(self, snap: typing.Union[jpype.JLong, int], path: typing.Union[java.lang.String, str]) -> TraceThread:
        """
        Get the live thread at the given snap by the given path
        
        :param jpype.JLong or int snap: the snap which the thread's lifespan must contain
        :param java.lang.String or str path: the path of the thread
        :return: the thread, or ``null`` if no thread matches
        :rtype: TraceThread
        """

    def getLiveThreads(self, snap: typing.Union[jpype.JLong, int]) -> java.util.Collection[TraceThread]:
        """
        Get live threads at the given snap, ordered eldest first
         
         
        
        Note that thread whose destruction was observed at the given snap are not considered alive,
        i.e, the upper end of the lifespan is treated as open.
        
        :param jpype.JLong or int snap: the snap
        :return: the collection
        :rtype: java.util.Collection[TraceThread]
        """

    def getThread(self, key: typing.Union[jpype.JLong, int]) -> TraceThread:
        """
        Get the thread with the given key
        
        :param jpype.JLong or int key: the database key
        :return: the thread
        :rtype: TraceThread
        """

    def getThreadsByPath(self, name: typing.Union[java.lang.String, str]) -> java.util.Collection[TraceThread]:
        """
        Get all threads with the given name, ordered eldest first
        
        :param java.lang.String or str name: the name
        :return: the collection
        :rtype: java.util.Collection[TraceThread]
        """

    @property
    def allThreads(self) -> java.util.Collection[TraceThread]:
        ...

    @property
    def liveThreads(self) -> java.util.Collection[TraceThread]:
        ...

    @property
    def thread(self) -> TraceThread:
        ...

    @property
    def threadsByPath(self) -> java.util.Collection[TraceThread]:
        ...



__all__ = ["TraceThread", "TraceProcess", "TraceThreadManager"]
