from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.framework.data
import ghidra.program.database
import ghidra.program.database.map
import ghidra.program.model.reloc
import ghidra.util
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


@typing.type_check_only
class RelocationDBAdapterNoTable(RelocationDBAdapter):
    """
    A stub for a time when we did not produce these tables.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RelocationDBAdapterV3(RelocationDBAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RelocationDBAdapterV1(RelocationDBAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class RelocationDBAdapterV5(RelocationDBAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class RelocationManager(ghidra.program.model.reloc.RelocationTable, ghidra.program.database.ManagerDB):
    """
    An implementation of the relocation table interface.
    """

    @typing.type_check_only
    class RelocationIterator(java.util.Iterator[ghidra.program.model.reloc.Relocation]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handle: db.DBHandle, addrMap: ghidra.program.database.map.AddressMap, openMode: ghidra.framework.data.OpenMode, lock: ghidra.util.Lock, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructs a new relocation manager.
        
        :param db.DBHandle handle: the database handle
        :param ghidra.program.database.map.AddressMap addrMap: the address map
        :param ghidra.framework.data.OpenMode openMode: the open mode; CREATE, UPDATE, READONLY, UPGRADE
        :param ghidra.util.Lock lock: the program synchronization lock
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises VersionException: 
        :raises IOException:
        """


@typing.type_check_only
class RelocationDBAdapterV2(RelocationDBAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


class RelocationDBAdapterV6(RelocationDBAdapter):
    """
    Relocation Adapter (v6) introduced a stored status and length value.  The byte-length value
    is  only stored/used when stored bytes are not used and the original bytes are obtained from 
    the underlying :obj:`FileBytes` via associated :obj:`Memory`.  Older program's may 
    have a stored bytes array but is unneccessary when original FileBytes are available. 
     
    
    During the transition of older relocation records we are unable to determine a proper status 
    without comparing current memory to the original bytes.  It may also be neccessary to reconcile
    overlapping relocations when the stored bytes value is null to obtain a valid length.  This
    transition is too complicated for a low-level record translation so it must be deferred to 
    a higher-level program upgrade (see :obj:`ProgramDB`).  This also holds true for establishing
    a reasonable status for existing relocation records.  During the initial record migration a
    status of :obj:`Status.UNKNOWN` and default length will be used.  After the program is 
    ready another high-level upgrade, based on Program version, will then attempt to refine these 
    records further.
    """

    class_: typing.ClassVar[java.lang.Class]


class RelocationDBAdapterV4(RelocationDBAdapter):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class RelocationDBAdapter(java.lang.Object):

    @typing.type_check_only
    class RecordIteratorAdapter(db.RecordIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]



__all__ = ["RelocationDBAdapterNoTable", "RelocationDBAdapterV3", "RelocationDBAdapterV1", "RelocationDBAdapterV5", "RelocationManager", "RelocationDBAdapterV2", "RelocationDBAdapterV6", "RelocationDBAdapterV4", "RelocationDBAdapter"]
