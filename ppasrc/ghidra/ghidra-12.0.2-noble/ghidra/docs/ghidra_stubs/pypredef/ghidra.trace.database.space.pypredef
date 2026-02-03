from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.framework.data
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.database
import ghidra.trace.database.thread
import ghidra.trace.util
import ghidra.util.database
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import java.util.concurrent.locks # type: ignore
import java.util.function # type: ignore


E = typing.TypeVar("E")
M = typing.TypeVar("M")
R = typing.TypeVar("R")
T = typing.TypeVar("T")


class DBTraceSpaceBased(ghidra.trace.util.TraceSpaceMixin):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def assertInSpace(self, addr: ghidra.program.model.address.Address) -> int:
        ...

    @typing.overload
    def assertInSpace(self, range: ghidra.program.model.address.AddressRange):
        ...

    def explainLanguages(self, space: ghidra.program.model.address.AddressSpace) -> str:
        ...

    def invalidateCache(self):
        ...

    def isMySpace(self, space: ghidra.program.model.address.AddressSpace) -> bool:
        ...

    def toAddress(self, offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        ...

    def toOverlay(self, physical: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        ...

    @property
    def mySpace(self) -> jpype.JBoolean:
        ...


class DBTraceDelegatingManager(java.lang.Object, typing.Generic[M]):

    class ExcFunction(java.lang.Object, typing.Generic[T, R, E]):

        class_: typing.ClassVar[java.lang.Class]

        def apply(self, t: T) -> R:
            ...


    class ExcConsumer(java.lang.Object, typing.Generic[T, E]):

        class_: typing.ClassVar[java.lang.Class]

        def accept(self, t: T):
            ...


    class ExcSupplier(java.lang.Object, typing.Generic[T, E]):

        class_: typing.ClassVar[java.lang.Class]

        def get(self) -> T:
            ...


    class ExcPredicate(java.lang.Object, typing.Generic[T, E]):

        class_: typing.ClassVar[java.lang.Class]

        def test(self, t: T) -> bool:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def checkIsInMemory(self, space: ghidra.program.model.address.AddressSpace):
        ...

    def delegateAddressSet(self, spaces: collections.abc.Sequence, func: DBTraceDelegatingManager.ExcFunction[M, ghidra.program.model.address.AddressSetView, E]) -> ghidra.program.model.address.AddressSetView:
        """
        Compose an address set, immediately, from address sets returned by delegates
        
        :param collections.abc.Sequence spaces: the delegates
        :param DBTraceDelegatingManager.ExcFunction[M, ghidra.program.model.address.AddressSetView, E] func: an address set getter for each delegate
        :return: the unioned results
        :rtype: ghidra.program.model.address.AddressSetView
        :raises E: if ``func`` throws and exception
        """

    def delegateAny(self, spaces: collections.abc.Sequence, func: DBTraceDelegatingManager.ExcPredicate[M, E]) -> bool:
        ...

    def delegateCollection(self, spaces: collections.abc.Sequence, func: java.util.function.Function[M, java.util.Collection[T]]) -> java.util.Collection[T]:
        """
        Compose a collection, lazily, from collections returned by delegates
        
        :param collections.abc.Sequence spaces: the delegates
        :param java.util.function.Function[M, java.util.Collection[T]] func: a collection getter for each delegate
        :return: the lazy catenated collection
        :rtype: java.util.Collection[T]
        """

    def delegateDeleteB(self, space: ghidra.program.model.address.AddressSpace, func: java.util.function.Predicate[M], ifNull: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    def delegateDeleteV(self, space: ghidra.program.model.address.AddressSpace, func: DBTraceDelegatingManager.ExcConsumer[M, E]):
        ...

    def delegateFirst(self, spaces: collections.abc.Sequence, func: java.util.function.Function[M, T]) -> T:
        ...

    def delegateHashSet(self, spaces: collections.abc.Sequence, func: java.util.function.Function[M, java.util.Collection[T]]) -> java.util.HashSet[T]:
        """
        Compose a set, immediately, from collections returned by delegates
        
        :param collections.abc.Sequence spaces: the delegates
        :param java.util.function.Function[M, java.util.Collection[T]] func: a collection (usually a set) getter for each delegate
        :return: the unioned results
        :rtype: java.util.HashSet[T]
        """

    @typing.overload
    def delegateRead(self, space: ghidra.program.model.address.AddressSpace, func: DBTraceDelegatingManager.ExcFunction[M, T, E]) -> T:
        ...

    @typing.overload
    def delegateRead(self, space: ghidra.program.model.address.AddressSpace, func: DBTraceDelegatingManager.ExcFunction[M, T, E], ifNull: T) -> T:
        ...

    def delegateReadB(self, space: ghidra.program.model.address.AddressSpace, func: java.util.function.Predicate[M], ifNull: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    @typing.overload
    def delegateReadI(self, space: ghidra.program.model.address.AddressSpace, func: java.util.function.ToIntFunction[M], ifNull: typing.Union[jpype.JInt, int]) -> int:
        ...

    @typing.overload
    def delegateReadI(self, space: ghidra.program.model.address.AddressSpace, func: java.util.function.ToIntFunction[M], ifNull: java.util.function.IntSupplier) -> int:
        ...

    def delegateReadOr(self, space: ghidra.program.model.address.AddressSpace, func: DBTraceDelegatingManager.ExcFunction[M, T, E], ifNull: DBTraceDelegatingManager.ExcSupplier[T, E]) -> T:
        ...

    def delegateWrite(self, space: ghidra.program.model.address.AddressSpace, func: DBTraceDelegatingManager.ExcFunction[M, T, E]) -> T:
        ...

    def delegateWriteAll(self, spaces: collections.abc.Sequence, func: DBTraceDelegatingManager.ExcConsumer[M, E]):
        ...

    def delegateWriteI(self, space: ghidra.program.model.address.AddressSpace, func: java.util.function.ToIntFunction[M]) -> int:
        ...

    def delegateWriteV(self, space: ghidra.program.model.address.AddressSpace, func: DBTraceDelegatingManager.ExcConsumer[M, E]):
        ...

    def getForSpace(self, space: ghidra.program.model.address.AddressSpace, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> M:
        ...

    def readLock(self) -> java.util.concurrent.locks.Lock:
        ...

    def writeLock(self) -> java.util.concurrent.locks.Lock:
        ...


class AbstractDBTraceSpaceBasedManager(ghidra.trace.database.DBTraceManager, typing.Generic[M]):

    class DBTraceSpaceEntry(ghidra.util.database.DBAnnotatedObject):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
            ...


    @typing.type_check_only
    class TabledSpace(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def entry(self) -> AbstractDBTraceSpaceBasedManager.DBTraceSpaceEntry:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def space(self) -> ghidra.program.model.address.AddressSpace:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, baseLanguage: ghidra.program.model.lang.Language, trace: ghidra.trace.database.DBTrace, threadManager: ghidra.trace.database.thread.DBTraceThreadManager):
        ...

    def get(self, space: ghidra.program.model.address.AddressSpace, createIfAbsent: typing.Union[jpype.JBoolean, bool]) -> M:
        ...

    def getActiveSpaces(self) -> java.util.Collection[M]:
        ...

    def getBaseLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    def getLock(self) -> java.util.concurrent.locks.ReadWriteLock:
        ...

    def getTrace(self) -> ghidra.trace.database.DBTrace:
        ...

    @property
    def activeSpaces(self) -> java.util.Collection[M]:
        ...

    @property
    def trace(self) -> ghidra.trace.database.DBTrace:
        ...

    @property
    def lock(self) -> java.util.concurrent.locks.ReadWriteLock:
        ...

    @property
    def baseLanguage(self) -> ghidra.program.model.lang.Language:
        ...



__all__ = ["DBTraceSpaceBased", "DBTraceDelegatingManager", "AbstractDBTraceSpaceBasedManager"]
