from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.framework.data
import ghidra.trace.database
import ghidra.trace.database.address
import ghidra.trace.database.target
import ghidra.trace.model.modules
import ghidra.util.database
import ghidra.util.task
import java.lang # type: ignore
import java.util.concurrent.locks # type: ignore


class DBTraceSection(ghidra.trace.model.modules.TraceSection, ghidra.trace.database.target.DBTraceObjectInterface):

    @typing.type_check_only
    class SectionTranslator(ghidra.trace.database.target.DBTraceObjectInterface.Translator[ghidra.trace.model.modules.TraceSection]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceModule(ghidra.trace.model.modules.TraceModule, ghidra.trace.database.target.DBTraceObjectInterface):

    @typing.type_check_only
    class ModuleChangeTranslator(ghidra.trace.database.target.DBTraceObjectInterface.Translator[ghidra.trace.model.modules.TraceModule]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, object: ghidra.trace.database.target.DBTraceObject):
        ...


class DBTraceModuleManager(ghidra.trace.model.modules.TraceModuleManager, ghidra.trace.database.DBTraceManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, trace: ghidra.trace.database.DBTrace, objectManager: ghidra.trace.database.target.DBTraceObjectManager):
        ...


class DBTraceStaticMapping(ghidra.util.database.DBAnnotatedObject, ghidra.trace.model.modules.TraceStaticMapping, ghidra.trace.database.address.DBTraceOverlaySpaceAdapter.DecodesAddresses):
    """
    The implementation of a static mapping, directly via a database object
    
     
    
    Version history:
     
    * 1: Change :obj:`.traceAddress` to 10-byte fixed encoding
    * 0: Initial version and previous unversioned implementation
    """

    class_: typing.ClassVar[java.lang.Class]
    TABLE_NAME: typing.Final = "StaticMappings"

    def __init__(self, manager: DBTraceStaticMappingManager, store: ghidra.util.database.DBCachedObjectStore[typing.Any], record: db.DBRecord):
        ...


class DBTraceStaticMappingManager(ghidra.trace.model.modules.TraceStaticMappingManager, ghidra.trace.database.DBTraceManager):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dbh: db.DBHandle, openMode: ghidra.framework.data.OpenMode, lock: java.util.concurrent.locks.ReadWriteLock, monitor: ghidra.util.task.TaskMonitor, trace: ghidra.trace.database.DBTrace, overlayAdapter: ghidra.trace.database.address.DBTraceOverlaySpaceAdapter):
        ...

    def delete(self, mapping: DBTraceStaticMapping):
        ...



__all__ = ["DBTraceSection", "DBTraceModule", "DBTraceModuleManager", "DBTraceStaticMapping", "DBTraceStaticMappingManager"]
