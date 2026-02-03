from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db
import ghidra.app.plugin.core.debug.service.target
import ghidra.app.services
import ghidra.debug.api.progress
import ghidra.debug.api.target
import ghidra.debug.api.tracermi
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.target
import ghidra.trace.model.target.path
import ghidra.trace.model.target.schema
import ghidra.trace.model.time
import ghidra.trace.model.time.schedule
import ghidra.util.task
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class AbstractTraceRmiConnection(ghidra.debug.api.tracermi.TraceRmiConnection):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class TraceRmiServer(AbstractTraceRmiListener):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: TraceRmiPlugin, address: java.net.SocketAddress):
        ...


class AbstractTraceRmiListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: TraceRmiPlugin, address: java.net.SocketAddress):
        ...

    def close(self):
        ...

    def getAddress(self) -> java.net.SocketAddress:
        ...

    def setTimeout(self, millis: typing.Union[jpype.JInt, int]):
        ...

    def start(self):
        ...

    @property
    def address(self) -> java.net.SocketAddress:
        ...


@typing.type_check_only
class OpenTrace(ValueDecoder):

    @typing.type_check_only
    class CurrentTxListener(ghidra.framework.model.TransactionListener):

        class_: typing.ClassVar[java.lang.Class]

        def markNotUndoable(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def createSnapshot(self, snap: typing.Union[jpype.JLong, int]) -> ghidra.trace.model.time.TraceSnapshot:
        ...

    @typing.overload
    def createSnapshot(self, schedule: ghidra.trace.model.time.schedule.TraceSchedule) -> ghidra.trace.model.time.TraceSnapshot:
        ...

    def dispose(self, consumer: TraceRmiHandler):
        ...

    @typing.overload
    def getObject(self, id: typing.Union[jpype.JLong, int], required: typing.Union[jpype.JBoolean, bool]) -> ghidra.trace.model.target.TraceObject:
        ...

    @typing.overload
    def getObject(self, path: ghidra.rmi.trace.TraceRmi.ObjPath, required: typing.Union[jpype.JBoolean, bool]) -> ghidra.trace.model.target.TraceObject:
        ...

    def getRegister(self, name: typing.Union[java.lang.String, str], required: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.lang.Register:
        ...

    def getSpace(self, name: typing.Union[java.lang.String, str], required: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSpace:
        ...


class ValueSupplier(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def get(self, decoder: ValueDecoder) -> java.lang.Object:
        ...


class TraceRmiTarget(ghidra.app.plugin.core.debug.service.target.AbstractTarget):

    @typing.type_check_only
    class TraceRmiActionEntry(ghidra.debug.api.target.Target.ActionEntry):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, method: ghidra.debug.api.tracermi.RemoteMethod, args: collections.abc.Mapping):
            ...


    class Missing(java.lang.Enum[TraceRmiTarget.Missing]):
        """
        A singleton to indicate missing arguments
        """

        class_: typing.ClassVar[java.lang.Class]
        MISSING: typing.Final[TraceRmiTarget.Missing]
        """
        The argument requires a prompt
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> TraceRmiTarget.Missing:
            ...

        @staticmethod
        def values() -> jpype.JArray[TraceRmiTarget.Missing]:
            ...


    @typing.type_check_only
    class ParamAndObjectArg(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def obj(self) -> ghidra.trace.model.target.TraceObject:
            ...

        def param(self) -> ghidra.debug.api.tracermi.RemoteParameter:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class MethodMatcher(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def match(self, method: ghidra.debug.api.tracermi.RemoteMethod, rootSchema: ghidra.trace.model.target.schema.TraceObjectSchema, path: ghidra.trace.model.target.path.KeyPath) -> TraceRmiTarget.MatchedMethod:
            ...

        @staticmethod
        def matchPreferredForm(method: ghidra.debug.api.tracermi.RemoteMethod, rootSchema: ghidra.trace.model.target.schema.TraceObjectSchema, path: ghidra.trace.model.target.path.KeyPath, preferred: java.util.List[TraceRmiTarget.MethodMatcher]) -> TraceRmiTarget.MatchedMethod:
            ...

        def score(self) -> int:
            ...

        def spec(self) -> java.util.List[TraceRmiTarget.ParamSpec]:
            ...


    @typing.type_check_only
    class MatchedMethod(java.lang.Record, java.lang.Comparable[TraceRmiTarget.MatchedMethod]):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def method(self) -> ghidra.debug.api.tracermi.RemoteMethod:
            ...

        def params(self) -> java.util.Map[java.lang.String, ghidra.debug.api.tracermi.RemoteParameter]:
            ...

        def score(self) -> int:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class ParamSpec(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def find(self, method: ghidra.debug.api.tracermi.RemoteMethod, rootSchema: ghidra.trace.model.target.schema.TraceObjectSchema, path: ghidra.trace.model.target.path.KeyPath) -> ghidra.debug.api.tracermi.RemoteParameter:
            ...

        def name(self) -> str:
            ...


    @typing.type_check_only
    class SchemaParamSpec(java.lang.Record, TraceRmiTarget.ParamSpec):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def schema(self) -> ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class TypeParamSpec(java.lang.Record, TraceRmiTarget.ParamSpec):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> java.lang.Class[typing.Any]:
            ...


    @typing.type_check_only
    class NameParamSpec(java.lang.Record, TraceRmiTarget.ParamSpec):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def name(self) -> str:
            ...

        def toString(self) -> str:
            ...

        def type(self) -> java.lang.Class[typing.Any]:
            ...


    @typing.type_check_only
    class ActivateMatcher(java.lang.Record, TraceRmiTarget.MethodMatcher):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def score(self) -> int:
            ...

        def spec(self) -> java.util.List[TraceRmiTarget.ParamSpec]:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class ExecuteMatcher(java.lang.Record, TraceRmiTarget.MethodMatcher):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def score(self) -> int:
            ...

        def spec(self) -> java.util.List[TraceRmiTarget.ParamSpec]:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class ReadMemMatcher(java.lang.Record, TraceRmiTarget.MethodMatcher):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def score(self) -> int:
            ...

        def spec(self) -> java.util.List[TraceRmiTarget.ParamSpec]:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class WriteMemMatcher(java.lang.Record, TraceRmiTarget.MethodMatcher):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def score(self) -> int:
            ...

        def spec(self) -> java.util.List[TraceRmiTarget.ParamSpec]:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class ReadRegsMatcher(java.lang.Record, TraceRmiTarget.MethodMatcher):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def score(self) -> int:
            ...

        def spec(self) -> java.util.List[TraceRmiTarget.ParamSpec]:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class WriteRegMatcher(java.lang.Record, TraceRmiTarget.MethodMatcher):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def score(self) -> int:
            ...

        def spec(self) -> java.util.List[TraceRmiTarget.ParamSpec]:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class BreakExecMatcher(java.lang.Record, TraceRmiTarget.MethodMatcher):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def score(self) -> int:
            ...

        def spec(self) -> java.util.List[TraceRmiTarget.ParamSpec]:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class BreakAccMatcher(java.lang.Record, TraceRmiTarget.MethodMatcher):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def score(self) -> int:
            ...

        def spec(self) -> java.util.List[TraceRmiTarget.ParamSpec]:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class DelBreakMatcher(java.lang.Record, TraceRmiTarget.MethodMatcher):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def score(self) -> int:
            ...

        def spec(self) -> java.util.List[TraceRmiTarget.ParamSpec]:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class ToggleBreakMatcher(java.lang.Record, TraceRmiTarget.MethodMatcher):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def score(self) -> int:
            ...

        def spec(self) -> java.util.List[TraceRmiTarget.ParamSpec]:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class MatchKey(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def action(self) -> ghidra.debug.api.target.ActionName:
            ...

        def cls(self) -> java.lang.Class[TraceRmiTarget.MethodMatcher]:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def sch(self) -> ghidra.trace.model.target.schema.TraceObjectSchema:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class Matches(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def getBest(self, cls: java.lang.Class[T], path: ghidra.trace.model.target.path.KeyPath, action: ghidra.debug.api.target.ActionName, preferredSupplier: java.util.function.Supplier[java.util.List[T]]) -> TraceRmiTarget.MatchedMethod:
            ...

        @typing.overload
        def getBest(self, cls: java.lang.Class[T], path: ghidra.trace.model.target.path.KeyPath, action: ghidra.debug.api.target.ActionName, preferred: java.util.List[T]) -> TraceRmiTarget.MatchedMethod:
            """
            Search for the most preferred method for a given operation, with respect to a given path
             
             
            
            A given path should be given as a point of reference, usually the current object or the
            object from the UI action context. If given, parameters that require a certain
            :obj:`TraceObjectInterface` will seek a suitable schema from that path and require it.
            Otherwise, any parameter whose schema includes the interface will be accepted.
            
            :param T: the matcher class representing the desired operation:param java.lang.Class[T] cls: the matcher class representing the desired operation
            :param ghidra.trace.model.target.path.KeyPath path: a path as a point of reference, or null for "any" point of reference.
            :param ghidra.debug.api.target.ActionName action: the required action name for a matching method
            :param java.util.List[T] preferred: the list of matchers (signatures) in preferred order
            :return: the best method, or null
            :rtype: TraceRmiTarget.MatchedMethod
            """

        def makeKey(self, cls: java.lang.Class[TraceRmiTarget.MethodMatcher], action: ghidra.debug.api.target.ActionName, path: ghidra.trace.model.target.path.KeyPath) -> TraceRmiTarget.MatchKey:
            ...


    @typing.type_check_only
    class RequestCaches(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def invalidate(self):
            ...

        def invalidateMemory(self):
            ...

        def readBlock(self, min: ghidra.program.model.address.Address, method: ghidra.debug.api.tracermi.RemoteMethod, args: collections.abc.Mapping) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
            ...

        def readRegs(self, obj: ghidra.trace.model.target.TraceObject, method: ghidra.debug.api.tracermi.RemoteMethod, args: collections.abc.Mapping) -> java.util.concurrent.CompletableFuture[java.lang.Void]:
            ...


    @typing.type_check_only
    class DefaultRequestCaches(TraceRmiTarget.RequestCaches):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DorkedRequestCaches(TraceRmiTarget.RequestCaches):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FoundRegister(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def register(self) -> ghidra.program.model.lang.Register:
            ...

        def toString(self) -> str:
            ...

        def value(self) -> ghidra.trace.model.target.TraceObjectValue:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, connection: ghidra.debug.api.tracermi.TraceRmiConnection, trace: ghidra.trace.model.Trace):
        ...


class TraceRmiPlugin(ghidra.framework.plugintool.Plugin, ghidra.app.services.InternalTraceRmiService):

    @typing.type_check_only
    class FallbackTaskMonitor(ghidra.util.task.ConsoleTaskMonitor, ghidra.debug.api.progress.CloseableTaskMonitor):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        ...

    def setTargetService(self, targetService: ghidra.app.services.DebuggerTargetService):
        ...


class DefaultTraceRmiAcceptor(AbstractTraceRmiListener, ghidra.debug.api.tracermi.TraceRmiAcceptor):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: TraceRmiPlugin, address: java.net.SocketAddress):
        ...


class RecordRemoteMethod(java.lang.Record, ghidra.debug.api.tracermi.RemoteMethod):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handler: TraceRmiHandler, name: typing.Union[java.lang.String, str], action: ghidra.debug.api.target.ActionName, display: typing.Union[java.lang.String, str], icon: javax.swing.Icon, okText: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], parameters: collections.abc.Mapping, retType: ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName):
        ...

    def action(self) -> ghidra.debug.api.target.ActionName:
        ...

    def description(self) -> str:
        ...

    def display(self) -> str:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def handler(self) -> TraceRmiHandler:
        ...

    def hashCode(self) -> int:
        ...

    def icon(self) -> javax.swing.Icon:
        ...

    def name(self) -> str:
        ...

    def okText(self) -> str:
        ...

    def parameters(self) -> java.util.Map[java.lang.String, ghidra.debug.api.tracermi.RemoteParameter]:
        ...

    def retType(self) -> ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName:
        ...

    def toString(self) -> str:
        ...


class ValueDecoder(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT: typing.Final[ValueDecoder]
    DISPLAY: typing.Final[ValueDecoder]

    @typing.overload
    def getObject(self, spec: ghidra.rmi.trace.TraceRmi.ObjSpec, required: typing.Union[jpype.JBoolean, bool]) -> java.lang.Object:
        ...

    @typing.overload
    def getObject(self, desc: ghidra.rmi.trace.TraceRmi.ObjDesc, required: typing.Union[jpype.JBoolean, bool]) -> java.lang.Object:
        ...

    def toAddress(self, addr: ghidra.rmi.trace.TraceRmi.Addr, required: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.Address:
        ...

    def toRange(self, range: ghidra.rmi.trace.TraceRmi.AddrRange, required: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressRange:
        ...

    def toValue(self, value: ghidra.rmi.trace.TraceRmi.Value) -> java.lang.Object:
        ...


class DefaultRemoteAsyncResult(java.util.concurrent.CompletableFuture[java.lang.Object], ghidra.debug.api.tracermi.RemoteAsyncResult):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, open: OpenTrace):
        ...


class RecordRemoteParameter(java.lang.Record, ghidra.debug.api.tracermi.RemoteParameter):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, handler: TraceRmiHandler, name: typing.Union[java.lang.String, str], type: ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName, required: typing.Union[jpype.JBoolean, bool], defaultValue: ValueSupplier, display: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str]):
        ...

    def defaultValue(self) -> ValueSupplier:
        ...

    def description(self) -> str:
        ...

    def display(self) -> str:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def getDefaultValue(self, trace: ghidra.trace.model.Trace) -> java.lang.Object:
        ...

    def handler(self) -> TraceRmiHandler:
        ...

    def hashCode(self) -> int:
        ...

    def name(self) -> str:
        ...

    def required(self) -> bool:
        ...

    def toString(self) -> str:
        ...

    def type(self) -> ghidra.trace.model.target.schema.TraceObjectSchema.SchemaName:
        ...


class TraceRmiHandler(AbstractTraceRmiConnection):

    @typing.type_check_only
    class VersionMismatchError(ghidra.debug.api.tracermi.TraceRmiError):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, remote: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class InvalidRequestError(ghidra.debug.api.tracermi.TraceRmiError):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, req: ghidra.rmi.trace.TraceRmi.RootMessage):
            ...


    @typing.type_check_only
    class InvalidDomObjIdError(ghidra.debug.api.tracermi.TraceRmiError):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DomObjIdInUseError(ghidra.debug.api.tracermi.TraceRmiError):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class InvalidObjIdError(ghidra.debug.api.tracermi.TraceRmiError):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class InvalidObjPathError(ghidra.debug.api.tracermi.TraceRmiError):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, path: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class NoSuchAddressSpaceError(ghidra.debug.api.tracermi.TraceRmiError):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class InvalidSchemaError(ghidra.debug.api.tracermi.TraceRmiError):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, cause: java.lang.Throwable):
            ...


    @typing.type_check_only
    class InvalidRegisterError(ghidra.debug.api.tracermi.TraceRmiError):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class InvalidTxIdError(ghidra.debug.api.tracermi.TraceRmiError):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, id: typing.Union[jpype.JInt, int]):
            ...


    @typing.type_check_only
    class TxIdInUseError(ghidra.debug.api.tracermi.TraceRmiError):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DoId(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, oid: ghidra.rmi.trace.TraceRmi.DomObjId):
            ...

        def domObjId(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toDomObjId(self) -> ghidra.rmi.trace.TraceRmi.DomObjId:
            ...

        def toString(self) -> str:
            ...


    @typing.type_check_only
    class Tid(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def doId(self) -> TraceRmiHandler.DoId:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def txId(self) -> int:
            ...


    @typing.type_check_only
    class OpenTx(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def toString(self) -> str:
            ...

        def tx(self) -> db.Transaction:
            ...

        def txId(self) -> TraceRmiHandler.Tid:
            ...

        def undoable(self) -> bool:
            ...


    @typing.type_check_only
    class OpenTraceMap(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def clearAll(self) -> java.util.List[OpenTrace]:
            """
            Call only for cleanup. Cannot be re-used after this
            
            :return: the open traces that were removed
            :rtype: java.util.List[OpenTrace]
            """

        def getById(self, doId: TraceRmiHandler.DoId) -> OpenTrace:
            ...

        def getByTrace(self, trace: ghidra.trace.model.Trace) -> OpenTrace:
            ...

        def getFirstAsync(self) -> java.util.concurrent.CompletableFuture[OpenTrace]:
            ...

        def getTargets(self) -> java.util.List[ghidra.debug.api.target.Target]:
            ...

        def idSet(self) -> java.util.Set[TraceRmiHandler.DoId]:
            ...

        def isEmpty(self) -> bool:
            ...

        def put(self, openTrace: OpenTrace):
            ...

        def removeById(self, id: TraceRmiHandler.DoId) -> OpenTrace:
            ...

        def removeByTrace(self, trace: ghidra.trace.model.Trace) -> OpenTrace:
            ...

        @property
        def byTrace(self) -> OpenTrace:
            ...

        @property
        def byId(self) -> OpenTrace:
            ...

        @property
        def targets(self) -> java.util.List[ghidra.debug.api.target.Target]:
            ...

        @property
        def empty(self) -> jpype.JBoolean:
            ...

        @property
        def firstAsync(self) -> java.util.concurrent.CompletableFuture[OpenTrace]:
            ...


    @typing.type_check_only
    class Dispatcher(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def dispatch(self, req: ghidra.rmi.trace.TraceRmi.RootMessage, rep: ghidra.rmi.trace.TraceRmi.RootMessage.Builder) -> ghidra.rmi.trace.TraceRmi.RootMessage.Builder:
            ...

        def exceptionMessage(self, exc: java.lang.Throwable) -> str:
            ...

        def handle(self, req: ghidra.rmi.trace.TraceRmi.RootMessage) -> ghidra.rmi.trace.TraceRmi.RootMessage:
            ...

        def toString(self, req: ghidra.rmi.trace.TraceRmi.RootMessage) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    VERSION: typing.Final = "12.0"
    """
    NOTE: This can't just be Application.getApplicationVersion(), because the Python client only
    specifies up to the minor, not patch, release.
    """


    def __init__(self, plugin: TraceRmiPlugin, socket: java.net.Socket):
        """
        Create a handler
         
         
        
        Note it is common for this to be constructed by a TCP *client*.
        
        :param TraceRmiPlugin plugin: the Trace RMI plugin
        :param java.net.Socket socket: the socket to the back-end debugger
        :raises IOException: if there is an issue with the I/O streams
        """

    def dispose(self):
        ...

    def receiveLoop(self):
        ...

    def registerTerminals(self, terminals: collections.abc.Sequence):
        ...

    def start(self):
        ...


class DefaultRemoteMethodRegistry(ghidra.debug.api.tracermi.RemoteMethodRegistry):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["AbstractTraceRmiConnection", "TraceRmiServer", "AbstractTraceRmiListener", "OpenTrace", "ValueSupplier", "TraceRmiTarget", "TraceRmiPlugin", "DefaultTraceRmiAcceptor", "RecordRemoteMethod", "ValueDecoder", "DefaultRemoteAsyncResult", "RecordRemoteParameter", "TraceRmiHandler", "DefaultRemoteMethodRegistry"]
