from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.address
import ghidra.program.model.lang
import ghidra.trace.model
import ghidra.trace.model.target.schema
import java.lang # type: ignore
import java.lang.annotation # type: ignore
import java.lang.reflect # type: ignore
import java.nio # type: ignore
import java.nio.channels # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore


T = typing.TypeVar("T")


class ProtobufSocket(java.lang.Object, typing.Generic[T]):

    class Decoder(java.lang.Object, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def decode(self, buf: java.nio.ByteBuffer) -> T:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, channel: java.nio.channels.SocketChannel, decoder: ProtobufSocket.Decoder[T]):
        ...

    def close(self):
        ...

    def getRemoteAddress(self) -> str:
        ...

    def recv(self) -> T:
        ...

    def send(self, msg: T):
        ...

    @property
    def remoteAddress(self) -> java.lang.String:
        ...


class RmiTransaction(java.lang.AutoCloseable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, trace: RmiTrace, id: typing.Union[jpype.JInt, int]):
        ...

    def abort(self):
        ...

    def commit(self):
        ...


class RmiRemoteMethodParameter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], schema: ghidra.trace.model.target.schema.TraceObjectSchema, required: typing.Union[jpype.JBoolean, bool], defaultValue: java.lang.Object, display: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str]):
        ...

    def getDefaultValue(self) -> java.lang.Object:
        ...

    def getDescription(self) -> str:
        ...

    def getDisplay(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def getType(self) -> ghidra.rmi.trace.TraceRmi.ValueType:
        ...

    def isRequired(self) -> bool:
        ...

    @property
    def defaultValue(self) -> java.lang.Object:
        ...

    @property
    def display(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def type(self) -> ghidra.rmi.trace.TraceRmi.ValueType:
        ...

    @property
    def required(self) -> jpype.JBoolean:
        ...


class DefaultRegisterMapper(RegisterMapper):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: ghidra.program.model.lang.LanguageID):
        ...


class MemoryMapper(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def genAddr(self, space: typing.Union[java.lang.String, str], offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        ...

    def map(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        ...

    def mapBack(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        ...


class RmiTrace(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    memoryMapper: MemoryMapper
    registerMapper: RegisterMapper

    def __init__(self, client: RmiClient, id: typing.Union[jpype.JInt, int], createResult: RmiClient.RequestResult):
        ...

    def activate(self, path: typing.Union[java.lang.String, str]):
        ...

    def checkResult(self, timeoutMs: typing.Union[jpype.JLong, int]):
        ...

    def close(self):
        ...

    def createAndInsertObject(self, path: typing.Union[java.lang.String, str]) -> RmiTraceObject:
        ...

    def createObject(self, path: typing.Union[java.lang.String, str]) -> RmiTraceObject:
        ...

    @typing.overload
    def createOverlaySpace(self, base: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def createOverlaySpace(self, repl: ghidra.program.model.address.Address, orig: ghidra.program.model.address.Address):
        ...

    def createRootObject(self, schemaContext: ghidra.trace.model.target.schema.SchemaContext, schema: typing.Union[java.lang.String, str]):
        ...

    def deleteBytes(self, range: ghidra.program.model.address.AddressRange, snap: typing.Union[java.lang.Long, int]):
        ...

    def deleteRegisters(self, ppath: typing.Union[java.lang.String, str], names: jpype.JArray[java.lang.String], snap: typing.Union[java.lang.Long, int]):
        ...

    def disassemble(self, start: ghidra.program.model.address.Address, snap: typing.Union[java.lang.Long, int]):
        ...

    def endTx(self, txid: typing.Union[jpype.JInt, int], abort: typing.Union[jpype.JBoolean, bool]):
        ...

    def getId(self) -> int:
        ...

    def getSnap(self) -> int:
        ...

    def getValues(self, pattern: typing.Union[java.lang.String, str]) -> java.util.List[RmiTraceObjectValue]:
        ...

    def getValuesAsync(self, pattern: typing.Union[java.lang.String, str]) -> RmiClient.RequestResult:
        ...

    def getValuesRng(self, start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int]) -> java.util.List[RmiTraceObjectValue]:
        ...

    def getValuesRngAsync(self, start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int]) -> RmiClient.RequestResult:
        ...

    def handleCreateTrace(self, reply: ghidra.rmi.trace.TraceRmi.ReplyCreateTrace) -> java.lang.Void:
        ...

    def handleDisassemble(self, reply: ghidra.rmi.trace.TraceRmi.ReplyDisassemble) -> int:
        ...

    def handleGetValues(self, reply: ghidra.rmi.trace.TraceRmi.ReplyGetValues) -> java.util.List[RmiTraceObjectValue]:
        ...

    def handleInvokeMethod(self, req: ghidra.rmi.trace.TraceRmi.XRequestInvokeMethod) -> ghidra.rmi.trace.TraceRmi.XReplyInvokeMethod:
        ...

    def insertObject(self, path: typing.Union[java.lang.String, str]):
        ...

    def nextSnap(self) -> int:
        ...

    def openTx(self, description: typing.Union[java.lang.String, str]) -> RmiTransaction:
        ...

    def proxyObjectId(self, objectId: typing.Union[java.lang.Long, int]) -> RmiTraceObject:
        ...

    @typing.overload
    def proxyObjectPath(self, path: typing.Union[java.lang.String, str]) -> RmiTraceObject:
        ...

    @typing.overload
    def proxyObjectPath(self, objectId: typing.Union[java.lang.Long, int], path: typing.Union[java.lang.String, str]) -> RmiTraceObject:
        ...

    def putBytes(self, addr: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte], snap: typing.Union[java.lang.Long, int]):
        ...

    def putRegisters(self, ppath: typing.Union[java.lang.String, str], values: jpype.JArray[ghidra.program.model.lang.RegisterValue], snap: typing.Union[java.lang.Long, int]):
        ...

    def retainValues(self, ppath: typing.Union[java.lang.String, str], keys: java.util.Set[java.lang.String], kinds: ghidra.rmi.trace.TraceRmi.ValueKinds):
        ...

    def save(self):
        ...

    def setMemoryState(self, range: ghidra.program.model.address.AddressRange, state: ghidra.rmi.trace.TraceRmi.MemoryState, snap: typing.Union[java.lang.Long, int]):
        ...

    def setSnap(self, snap: typing.Union[jpype.JLong, int]):
        ...

    def setValue(self, ppath: typing.Union[java.lang.String, str], key: typing.Union[java.lang.String, str], value: java.lang.Object):
        ...

    def snapOrCurrent(self, snap: typing.Union[java.lang.Long, int]) -> int:
        ...

    def snapshot(self, description: typing.Union[java.lang.String, str], datatime: typing.Union[java.lang.String, str], snap: typing.Union[java.lang.Long, int]) -> int:
        ...

    def startTx(self, description: typing.Union[java.lang.String, str], undoable: typing.Union[jpype.JBoolean, bool]) -> RmiTransaction:
        ...

    @property
    def values(self) -> java.util.List[RmiTraceObjectValue]:
        ...

    @property
    def valuesAsync(self) -> RmiClient.RequestResult:
        ...

    @property
    def id(self) -> jpype.JInt:
        ...

    @property
    def snap(self) -> jpype.JLong:
        ...

    @snap.setter
    def snap(self, value: jpype.JLong):
        ...


class RmiTraceObject(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, trace: RmiTrace, path: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, trace: RmiTrace, id: typing.Union[java.lang.Long, int], path: typing.Union[java.lang.String, str]):
        ...

    def activate(self):
        ...

    @staticmethod
    def fromId(trace: RmiTrace, id: typing.Union[jpype.JLong, int]) -> RmiTraceObject:
        ...

    @staticmethod
    def fromPath(trace: RmiTrace, path: typing.Union[java.lang.String, str]) -> RmiTraceObject:
        ...

    def getPath(self) -> str:
        ...

    def insert(self, snap: typing.Union[jpype.JLong, int], resolution: ghidra.rmi.trace.TraceRmi.Resolution) -> ghidra.trace.model.Lifespan:
        ...

    def remove(self, snap: typing.Union[jpype.JLong, int], tree: typing.Union[jpype.JBoolean, bool]) -> ghidra.trace.model.Lifespan:
        ...

    def retainValues(self, keys: java.util.Set[java.lang.String], snap: typing.Union[jpype.JLong, int], kinds: ghidra.rmi.trace.TraceRmi.ValueKinds):
        ...

    def setValue(self, key: typing.Union[java.lang.String, str], value: java.lang.Object, snap: typing.Union[jpype.JLong, int], resolution: typing.Union[java.lang.String, str]):
        ...

    @property
    def path(self) -> java.lang.String:
        ...


class RmiTraceObjectValue(java.lang.Record):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, parent: RmiTraceObject, span: ghidra.trace.model.Lifespan, key: typing.Union[java.lang.String, str], value: java.lang.Object, schema: ghidra.trace.model.target.schema.TraceObjectSchema):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def key(self) -> str:
        ...

    def parent(self) -> RmiTraceObject:
        ...

    def schema(self) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        ...

    def span(self) -> ghidra.trace.model.Lifespan:
        ...

    def toString(self) -> str:
        ...

    def value(self) -> java.lang.Object:
        ...


class RmiBatch(java.lang.AutoCloseable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, client: RmiClient):
        ...

    def append(self, f: RmiClient.RequestResult):
        ...

    def dec(self) -> int:
        ...

    def futures(self) -> java.util.List[RmiClient.RequestResult]:
        ...

    def inc(self):
        ...

    def results(self) -> java.util.List[java.lang.Object]:
        ...


class RmiClient(java.lang.Object):

    @typing.type_check_only
    class RequestResult(java.util.concurrent.CompletableFuture[java.lang.Object]):

        class_: typing.ClassVar[java.lang.Class]
        request: typing.Final[ghidra.rmi.trace.TraceRmi.RootMessage]

        def __init__(self, req: ghidra.rmi.trace.TraceRmi.RootMessage):
            ...


    class RmiException(java.lang.RuntimeException):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, message: typing.Union[java.lang.String, str]):
            ...


    class TraceRmiResolution(java.lang.Enum[RmiClient.TraceRmiResolution]):

        class_: typing.ClassVar[java.lang.Class]
        RES_ADJUST: typing.Final[RmiClient.TraceRmiResolution]
        RES_DENY: typing.Final[RmiClient.TraceRmiResolution]
        RES_TRUNCATE: typing.Final[RmiClient.TraceRmiResolution]
        val: typing.Final[java.lang.String]
        description: typing.Final[ghidra.rmi.trace.TraceRmi.Resolution]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> RmiClient.TraceRmiResolution:
            ...

        @staticmethod
        def values() -> jpype.JArray[RmiClient.TraceRmiResolution]:
            ...


    class TraceRmiValueKinds(java.lang.Enum[RmiClient.TraceRmiValueKinds]):

        class_: typing.ClassVar[java.lang.Class]
        ATTRIBUTES: typing.Final[RmiClient.TraceRmiValueKinds]
        ELEMENTS: typing.Final[RmiClient.TraceRmiValueKinds]
        BOTH: typing.Final[RmiClient.TraceRmiValueKinds]
        val: typing.Final[java.lang.String]
        description: typing.Final[ghidra.rmi.trace.TraceRmi.ValueKinds]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> RmiClient.TraceRmiValueKinds:
            ...

        @staticmethod
        def values() -> jpype.JArray[RmiClient.TraceRmiValueKinds]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, channel: java.nio.channels.SocketChannel, description: typing.Union[java.lang.String, str]):
        ...

    def activate(self, traceId: typing.Union[jpype.JInt, int], path: typing.Union[java.lang.String, str]):
        ...

    def close(self):
        ...

    def closeTrace(self, id: typing.Union[jpype.JInt, int]):
        ...

    def createOverlaySpace(self, traceId: typing.Union[jpype.JInt, int], base: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]):
        ...

    def createRootObject(self, traceId: typing.Union[jpype.JInt, int], schemContext: ghidra.trace.model.target.schema.SchemaContext, schema: typing.Union[java.lang.String, str]):
        ...

    def createTrace(self, path: typing.Union[java.lang.String, str], language: ghidra.program.model.lang.LanguageID, compiler: ghidra.program.model.lang.CompilerSpecID) -> RmiTrace:
        ...

    def deleteBytes(self, traceId: typing.Union[jpype.JInt, int], snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange):
        ...

    def deleteRegisters(self, traceId: typing.Union[jpype.JInt, int], snap: typing.Union[jpype.JLong, int], ppath: typing.Union[java.lang.String, str], names: jpype.JArray[java.lang.String]):
        ...

    def disassemble(self, traceId: typing.Union[jpype.JInt, int], snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address):
        ...

    def endTx(self, traceId: typing.Union[jpype.JInt, int], txId: typing.Union[jpype.JInt, int], abort: typing.Union[jpype.JBoolean, bool]):
        ...

    def getDescription(self) -> str:
        ...

    def getMethod(self, name: typing.Union[java.lang.String, str]) -> RmiRemoteMethod:
        ...

    def getObject(self, traceId: typing.Union[jpype.JInt, int], path: typing.Union[java.lang.String, str]):
        ...

    def getSchema(self, schema: typing.Union[java.lang.String, str]) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        ...

    def handleInvokeMethod(self, traceId: typing.Union[jpype.JInt, int], req: ghidra.rmi.trace.TraceRmi.XRequestInvokeMethod) -> ghidra.rmi.trace.TraceRmi.XReplyInvokeMethod:
        ...

    @typing.overload
    def insertObject(self, traceId: typing.Union[jpype.JInt, int], path: typing.Union[java.lang.String, str], span: ghidra.trace.model.Lifespan, r: ghidra.rmi.trace.TraceRmi.Resolution):
        ...

    @typing.overload
    def insertObject(self, traceId: typing.Union[jpype.JInt, int], id: typing.Union[jpype.JLong, int], span: ghidra.trace.model.Lifespan, r: ghidra.rmi.trace.TraceRmi.Resolution):
        ...

    @staticmethod
    def loadSchema(resourceName: typing.Union[java.lang.String, str], rootName: typing.Union[java.lang.String, str]) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        ...

    def negotiate(self, desc: typing.Union[java.lang.String, str]):
        ...

    def pollRequest(self) -> RmiClient.RequestResult:
        ...

    def proxyObjectId(self, traceId: typing.Union[jpype.JInt, int], id: typing.Union[java.lang.Long, int]) -> RmiTraceObject:
        ...

    @typing.overload
    def proxyObjectPath(self, traceId: typing.Union[jpype.JInt, int], path: typing.Union[java.lang.String, str]) -> RmiTraceObject:
        ...

    @typing.overload
    def proxyObjectPath(self, traceId: typing.Union[jpype.JInt, int], id: typing.Union[java.lang.Long, int], path: typing.Union[java.lang.String, str]) -> RmiTraceObject:
        ...

    def putBytes(self, traceId: typing.Union[jpype.JInt, int], snap: typing.Union[jpype.JLong, int], start: ghidra.program.model.address.Address, data: jpype.JArray[jpype.JByte]):
        ...

    def putRegisters(self, traceId: typing.Union[jpype.JInt, int], snap: typing.Union[jpype.JLong, int], ppath: typing.Union[java.lang.String, str], values: jpype.JArray[ghidra.program.model.lang.RegisterValue]):
        ...

    @typing.overload
    def removeObject(self, traceId: typing.Union[jpype.JInt, int], path: typing.Union[java.lang.String, str], span: ghidra.trace.model.Lifespan, tree: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def removeObject(self, traceId: typing.Union[jpype.JInt, int], id: typing.Union[jpype.JLong, int], span: ghidra.trace.model.Lifespan, tree: typing.Union[jpype.JBoolean, bool]):
        ...

    def retainValues(self, traceId: typing.Union[jpype.JInt, int], ppath: typing.Union[java.lang.String, str], span: ghidra.trace.model.Lifespan, kinds: ghidra.rmi.trace.TraceRmi.ValueKinds, keys: java.util.Set[java.lang.String]):
        ...

    def saveTrace(self, id: typing.Union[jpype.JInt, int]):
        ...

    def setMemoryState(self, traceId: typing.Union[jpype.JInt, int], snap: typing.Union[jpype.JLong, int], range: ghidra.program.model.address.AddressRange, state: ghidra.rmi.trace.TraceRmi.MemoryState):
        ...

    def setRegistry(self, methodRegistry: RmiMethodRegistry):
        ...

    def setValue(self, traceId: typing.Union[jpype.JInt, int], ppath: typing.Union[java.lang.String, str], span: ghidra.trace.model.Lifespan, key: typing.Union[java.lang.String, str], value: java.lang.Object, resolution: typing.Union[java.lang.String, str]):
        ...

    def snapshot(self, traceId: typing.Union[jpype.JInt, int], desc: typing.Union[java.lang.String, str], datetime: typing.Union[java.lang.String, str], snap: typing.Union[jpype.JLong, int]):
        ...

    def startBatch(self) -> RmiBatch:
        ...

    def startTx(self, traceId: typing.Union[jpype.JInt, int], desc: typing.Union[java.lang.String, str], undoable: typing.Union[jpype.JBoolean, bool], txId: typing.Union[jpype.JInt, int]):
        ...

    @property
    def schema(self) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        ...

    @property
    def method(self) -> RmiRemoteMethod:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class RmiMethods(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


class RegisterMapper(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def mapName(self, name: typing.Union[java.lang.String, str]) -> str:
        ...

    def mapNameBack(self, name: typing.Union[java.lang.String, str]) -> str:
        ...

    def mapValue(self, name: typing.Union[java.lang.String, str], rv: ghidra.program.model.lang.RegisterValue) -> ghidra.program.model.lang.RegisterValue:
        ...

    def mapValueBack(self, name: typing.Union[java.lang.String, str], rv: ghidra.program.model.lang.RegisterValue) -> ghidra.program.model.lang.RegisterValue:
        ...


class RmiRemoteMethod(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, schemaContext: ghidra.trace.model.target.schema.SchemaContext, name: typing.Union[java.lang.String, str], action: typing.Union[java.lang.String, str], display: typing.Union[java.lang.String, str], description: typing.Union[java.lang.String, str], okText: typing.Union[java.lang.String, str], icon: typing.Union[java.lang.String, str], schema: ghidra.trace.model.target.schema.TraceObjectSchema, instance: RmiMethods, m: java.lang.reflect.Method):
        ...

    def getAction(self) -> str:
        ...

    def getContainer(self) -> RmiMethods:
        ...

    def getDescription(self) -> str:
        ...

    def getDisplay(self) -> str:
        ...

    def getIcon(self) -> str:
        ...

    def getMethod(self) -> java.lang.reflect.Method:
        ...

    def getName(self) -> str:
        ...

    def getOkText(self) -> str:
        ...

    def getParameters(self) -> jpype.JArray[RmiRemoteMethodParameter]:
        ...

    def getSchema(self) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        ...

    @property
    def schema(self) -> ghidra.trace.model.target.schema.TraceObjectSchema:
        ...

    @property
    def container(self) -> RmiMethods:
        ...

    @property
    def method(self) -> java.lang.reflect.Method:
        ...

    @property
    def display(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def icon(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def action(self) -> java.lang.String:
        ...

    @property
    def okText(self) -> java.lang.String:
        ...

    @property
    def parameters(self) -> jpype.JArray[RmiRemoteMethodParameter]:
        ...


class RmiMethodRegistry(java.lang.Object):

    class TraceRmiMethod(java.lang.annotation.Annotation):
        """
        An annotation for marking remote methods.
        """

        class_: typing.ClassVar[java.lang.Class]

        def action(self) -> str:
            ...

        def description(self) -> str:
            ...

        def display(self) -> str:
            ...

        def icon(self) -> str:
            ...

        def okText(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getMap(self) -> java.util.Map[java.lang.String, RmiRemoteMethod]:
        ...

    def getMethod(self, key: typing.Union[java.lang.String, str]) -> RmiRemoteMethod:
        ...

    def putMethod(self, key: typing.Union[java.lang.String, str], value: RmiRemoteMethod):
        ...

    @property
    def method(self) -> RmiRemoteMethod:
        ...

    @property
    def map(self) -> java.util.Map[java.lang.String, RmiRemoteMethod]:
        ...


class RmiReplyHandlerThread(java.lang.Thread):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, client: RmiClient, socket: ProtobufSocket[ghidra.rmi.trace.TraceRmi.RootMessage]):
        ...

    def close(self):
        ...


class DefaultMemoryMapper(MemoryMapper):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: ghidra.program.model.lang.LanguageID):
        ...



__all__ = ["ProtobufSocket", "RmiTransaction", "RmiRemoteMethodParameter", "DefaultRegisterMapper", "MemoryMapper", "RmiTrace", "RmiTraceObject", "RmiTraceObjectValue", "RmiBatch", "RmiClient", "RmiMethods", "RegisterMapper", "RmiRemoteMethod", "RmiMethodRegistry", "RmiReplyHandlerThread", "DefaultMemoryMapper"]
