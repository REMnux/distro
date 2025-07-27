from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

CR_ADJUST: Resolution
CR_DENY: Resolution
CR_TRUNCATE: Resolution
DESCRIPTOR: _descriptor.FileDescriptor
MS_ERROR: MemoryState
MS_KNOWN: MemoryState
MS_UNKNOWN: MemoryState
VK_ATTRIBUTES: ValueKinds
VK_BOTH: ValueKinds
VK_ELEMENTS: ValueKinds

class Addr(_message.Message):
    __slots__ = ["offset", "space"]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    offset: int
    space: str
    def __init__(self, space: _Optional[str] = ..., offset: _Optional[int] = ...) -> None: ...

class AddrRange(_message.Message):
    __slots__ = ["extend", "offset", "space"]
    EXTEND_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    extend: int
    offset: int
    space: str
    def __init__(self, space: _Optional[str] = ..., offset: _Optional[int] = ..., extend: _Optional[int] = ...) -> None: ...

class BoolArr(_message.Message):
    __slots__ = ["arr"]
    ARR_FIELD_NUMBER: _ClassVar[int]
    arr: _containers.RepeatedScalarFieldContainer[bool]
    def __init__(self, arr: _Optional[_Iterable[bool]] = ...) -> None: ...

class Box(_message.Message):
    __slots__ = ["range", "span"]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    range: AddrRange
    span: Span
    def __init__(self, span: _Optional[_Union[Span, _Mapping]] = ..., range: _Optional[_Union[AddrRange, _Mapping]] = ...) -> None: ...

class Compiler(_message.Message):
    __slots__ = ["id"]
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class DomObjId(_message.Message):
    __slots__ = ["id"]
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class FilePath(_message.Message):
    __slots__ = ["path"]
    PATH_FIELD_NUMBER: _ClassVar[int]
    path: str
    def __init__(self, path: _Optional[str] = ...) -> None: ...

class IntArr(_message.Message):
    __slots__ = ["arr"]
    ARR_FIELD_NUMBER: _ClassVar[int]
    arr: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, arr: _Optional[_Iterable[int]] = ...) -> None: ...

class Language(_message.Message):
    __slots__ = ["id"]
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class LongArr(_message.Message):
    __slots__ = ["arr"]
    ARR_FIELD_NUMBER: _ClassVar[int]
    arr: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, arr: _Optional[_Iterable[int]] = ...) -> None: ...

class Method(_message.Message):
    __slots__ = ["action", "description", "display", "icon", "name", "ok_text", "parameters", "return_type"]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_FIELD_NUMBER: _ClassVar[int]
    ICON_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    OK_TEXT_FIELD_NUMBER: _ClassVar[int]
    PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    RETURN_TYPE_FIELD_NUMBER: _ClassVar[int]
    action: str
    description: str
    display: str
    icon: str
    name: str
    ok_text: str
    parameters: _containers.RepeatedCompositeFieldContainer[MethodParameter]
    return_type: ValueType
    def __init__(self, name: _Optional[str] = ..., action: _Optional[str] = ..., display: _Optional[str] = ..., description: _Optional[str] = ..., parameters: _Optional[_Iterable[_Union[MethodParameter, _Mapping]]] = ..., return_type: _Optional[_Union[ValueType, _Mapping]] = ..., ok_text: _Optional[str] = ..., icon: _Optional[str] = ...) -> None: ...

class MethodArgument(_message.Message):
    __slots__ = ["name", "value"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: Value
    def __init__(self, name: _Optional[str] = ..., value: _Optional[_Union[Value, _Mapping]] = ...) -> None: ...

class MethodParameter(_message.Message):
    __slots__ = ["default_value", "description", "display", "name", "required", "type"]
    DEFAULT_VALUE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    default_value: Value
    description: str
    display: str
    name: str
    required: bool
    type: ValueType
    def __init__(self, name: _Optional[str] = ..., type: _Optional[_Union[ValueType, _Mapping]] = ..., required: bool = ..., default_value: _Optional[_Union[Value, _Mapping]] = ..., display: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class Null(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ObjDesc(_message.Message):
    __slots__ = ["id", "path"]
    ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    id: int
    path: ObjPath
    def __init__(self, id: _Optional[int] = ..., path: _Optional[_Union[ObjPath, _Mapping]] = ...) -> None: ...

class ObjPath(_message.Message):
    __slots__ = ["path"]
    PATH_FIELD_NUMBER: _ClassVar[int]
    path: str
    def __init__(self, path: _Optional[str] = ...) -> None: ...

class ObjSpec(_message.Message):
    __slots__ = ["id", "path"]
    ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    id: int
    path: ObjPath
    def __init__(self, id: _Optional[int] = ..., path: _Optional[_Union[ObjPath, _Mapping]] = ...) -> None: ...

class RegVal(_message.Message):
    __slots__ = ["name", "value"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: bytes
    def __init__(self, name: _Optional[str] = ..., value: _Optional[bytes] = ...) -> None: ...

class ReplyActivate(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ReplyCloseTrace(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ReplyCreateObject(_message.Message):
    __slots__ = ["object"]
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    object: ObjSpec
    def __init__(self, object: _Optional[_Union[ObjSpec, _Mapping]] = ...) -> None: ...

class ReplyCreateOverlaySpace(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ReplyCreateTrace(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ReplyDeleteBytes(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ReplyDeleteRegisterValue(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ReplyDisassemble(_message.Message):
    __slots__ = ["length"]
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    length: int
    def __init__(self, length: _Optional[int] = ...) -> None: ...

class ReplyEndTx(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ReplyError(_message.Message):
    __slots__ = ["message"]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class ReplyGetObject(_message.Message):
    __slots__ = ["object"]
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    object: ObjDesc
    def __init__(self, object: _Optional[_Union[ObjDesc, _Mapping]] = ...) -> None: ...

class ReplyGetValues(_message.Message):
    __slots__ = ["values"]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    values: _containers.RepeatedCompositeFieldContainer[ValDesc]
    def __init__(self, values: _Optional[_Iterable[_Union[ValDesc, _Mapping]]] = ...) -> None: ...

class ReplyInsertObject(_message.Message):
    __slots__ = ["span"]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    span: Span
    def __init__(self, span: _Optional[_Union[Span, _Mapping]] = ...) -> None: ...

class ReplyNegotiate(_message.Message):
    __slots__ = ["description"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    description: str
    def __init__(self, description: _Optional[str] = ...) -> None: ...

class ReplyPutBytes(_message.Message):
    __slots__ = ["written"]
    WRITTEN_FIELD_NUMBER: _ClassVar[int]
    written: int
    def __init__(self, written: _Optional[int] = ...) -> None: ...

class ReplyPutRegisterValue(_message.Message):
    __slots__ = ["skipped_names"]
    SKIPPED_NAMES_FIELD_NUMBER: _ClassVar[int]
    skipped_names: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, skipped_names: _Optional[_Iterable[str]] = ...) -> None: ...

class ReplyRemoveObject(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ReplyRetainValues(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ReplySaveTrace(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ReplySetMemoryState(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class ReplySetValue(_message.Message):
    __slots__ = ["span"]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    span: Span
    def __init__(self, span: _Optional[_Union[Span, _Mapping]] = ...) -> None: ...

class ReplySnapshot(_message.Message):
    __slots__ = ["snap"]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    snap: Snap
    def __init__(self, snap: _Optional[_Union[Snap, _Mapping]] = ...) -> None: ...

class ReplyStartTx(_message.Message):
    __slots__ = []
    def __init__(self) -> None: ...

class RequestActivate(_message.Message):
    __slots__ = ["object", "oid"]
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    object: ObjSpec
    oid: DomObjId
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., object: _Optional[_Union[ObjSpec, _Mapping]] = ...) -> None: ...

class RequestCloseTrace(_message.Message):
    __slots__ = ["oid"]
    OID_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ...) -> None: ...

class RequestCreateObject(_message.Message):
    __slots__ = ["oid", "path"]
    OID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    path: ObjPath
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., path: _Optional[_Union[ObjPath, _Mapping]] = ...) -> None: ...

class RequestCreateOverlaySpace(_message.Message):
    __slots__ = ["baseSpace", "name", "oid"]
    BASESPACE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    baseSpace: str
    name: str
    oid: DomObjId
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., baseSpace: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class RequestCreateRootObject(_message.Message):
    __slots__ = ["oid", "root_schema", "schema_context"]
    OID_FIELD_NUMBER: _ClassVar[int]
    ROOT_SCHEMA_FIELD_NUMBER: _ClassVar[int]
    SCHEMA_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    root_schema: str
    schema_context: str
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., schema_context: _Optional[str] = ..., root_schema: _Optional[str] = ...) -> None: ...

class RequestCreateTrace(_message.Message):
    __slots__ = ["compiler", "language", "oid", "path"]
    COMPILER_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    compiler: Compiler
    language: Language
    oid: DomObjId
    path: FilePath
    def __init__(self, path: _Optional[_Union[FilePath, _Mapping]] = ..., language: _Optional[_Union[Language, _Mapping]] = ..., compiler: _Optional[_Union[Compiler, _Mapping]] = ..., oid: _Optional[_Union[DomObjId, _Mapping]] = ...) -> None: ...

class RequestDeleteBytes(_message.Message):
    __slots__ = ["oid", "range", "snap"]
    OID_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    range: AddrRange
    snap: Snap
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., range: _Optional[_Union[AddrRange, _Mapping]] = ...) -> None: ...

class RequestDeleteRegisterValue(_message.Message):
    __slots__ = ["names", "oid", "snap", "space"]
    NAMES_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    names: _containers.RepeatedScalarFieldContainer[str]
    oid: DomObjId
    snap: Snap
    space: str
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., space: _Optional[str] = ..., names: _Optional[_Iterable[str]] = ...) -> None: ...

class RequestDisassemble(_message.Message):
    __slots__ = ["oid", "snap", "start"]
    OID_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    snap: Snap
    start: Addr
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., start: _Optional[_Union[Addr, _Mapping]] = ...) -> None: ...

class RequestEndTx(_message.Message):
    __slots__ = ["abort", "oid", "txid"]
    ABORT_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    TXID_FIELD_NUMBER: _ClassVar[int]
    abort: bool
    oid: DomObjId
    txid: TxId
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., txid: _Optional[_Union[TxId, _Mapping]] = ..., abort: bool = ...) -> None: ...

class RequestGetObject(_message.Message):
    __slots__ = ["object", "oid"]
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    object: ObjSpec
    oid: DomObjId
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., object: _Optional[_Union[ObjSpec, _Mapping]] = ...) -> None: ...

class RequestGetValues(_message.Message):
    __slots__ = ["oid", "pattern", "span"]
    OID_FIELD_NUMBER: _ClassVar[int]
    PATTERN_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    pattern: ObjPath
    span: Span
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., span: _Optional[_Union[Span, _Mapping]] = ..., pattern: _Optional[_Union[ObjPath, _Mapping]] = ...) -> None: ...

class RequestGetValuesIntersecting(_message.Message):
    __slots__ = ["box", "key", "oid"]
    BOX_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    box: Box
    key: str
    oid: DomObjId
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., box: _Optional[_Union[Box, _Mapping]] = ..., key: _Optional[str] = ...) -> None: ...

class RequestInsertObject(_message.Message):
    __slots__ = ["object", "oid", "resolution", "span"]
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    RESOLUTION_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    object: ObjSpec
    oid: DomObjId
    resolution: Resolution
    span: Span
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., object: _Optional[_Union[ObjSpec, _Mapping]] = ..., span: _Optional[_Union[Span, _Mapping]] = ..., resolution: _Optional[_Union[Resolution, str]] = ...) -> None: ...

class RequestNegotiate(_message.Message):
    __slots__ = ["description", "methods", "version"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    METHODS_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    description: str
    methods: _containers.RepeatedCompositeFieldContainer[Method]
    version: str
    def __init__(self, version: _Optional[str] = ..., methods: _Optional[_Iterable[_Union[Method, _Mapping]]] = ..., description: _Optional[str] = ...) -> None: ...

class RequestPutBytes(_message.Message):
    __slots__ = ["data", "oid", "snap", "start"]
    DATA_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    oid: DomObjId
    snap: Snap
    start: Addr
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., start: _Optional[_Union[Addr, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class RequestPutRegisterValue(_message.Message):
    __slots__ = ["oid", "snap", "space", "values"]
    OID_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    snap: Snap
    space: str
    values: _containers.RepeatedCompositeFieldContainer[RegVal]
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., space: _Optional[str] = ..., values: _Optional[_Iterable[_Union[RegVal, _Mapping]]] = ...) -> None: ...

class RequestRemoveObject(_message.Message):
    __slots__ = ["object", "oid", "span", "tree"]
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    TREE_FIELD_NUMBER: _ClassVar[int]
    object: ObjSpec
    oid: DomObjId
    span: Span
    tree: bool
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., object: _Optional[_Union[ObjSpec, _Mapping]] = ..., span: _Optional[_Union[Span, _Mapping]] = ..., tree: bool = ...) -> None: ...

class RequestRetainValues(_message.Message):
    __slots__ = ["keys", "kinds", "object", "oid", "span"]
    KEYS_FIELD_NUMBER: _ClassVar[int]
    KINDS_FIELD_NUMBER: _ClassVar[int]
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    keys: _containers.RepeatedScalarFieldContainer[str]
    kinds: ValueKinds
    object: ObjSpec
    oid: DomObjId
    span: Span
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., object: _Optional[_Union[ObjSpec, _Mapping]] = ..., span: _Optional[_Union[Span, _Mapping]] = ..., kinds: _Optional[_Union[ValueKinds, str]] = ..., keys: _Optional[_Iterable[str]] = ...) -> None: ...

class RequestSaveTrace(_message.Message):
    __slots__ = ["oid"]
    OID_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ...) -> None: ...

class RequestSetMemoryState(_message.Message):
    __slots__ = ["oid", "range", "snap", "state"]
    OID_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    range: AddrRange
    snap: Snap
    state: MemoryState
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., range: _Optional[_Union[AddrRange, _Mapping]] = ..., state: _Optional[_Union[MemoryState, str]] = ...) -> None: ...

class RequestSetValue(_message.Message):
    __slots__ = ["oid", "resolution", "value"]
    OID_FIELD_NUMBER: _ClassVar[int]
    RESOLUTION_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    resolution: Resolution
    value: ValSpec
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., value: _Optional[_Union[ValSpec, _Mapping]] = ..., resolution: _Optional[_Union[Resolution, str]] = ...) -> None: ...

class RequestSnapshot(_message.Message):
    __slots__ = ["datetime", "description", "oid", "schedule", "snap"]
    DATETIME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    datetime: str
    description: str
    oid: DomObjId
    schedule: Schedule
    snap: Snap
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., description: _Optional[str] = ..., datetime: _Optional[str] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., schedule: _Optional[_Union[Schedule, _Mapping]] = ...) -> None: ...

class RequestStartTx(_message.Message):
    __slots__ = ["description", "oid", "txid", "undoable"]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    TXID_FIELD_NUMBER: _ClassVar[int]
    UNDOABLE_FIELD_NUMBER: _ClassVar[int]
    description: str
    oid: DomObjId
    txid: TxId
    undoable: bool
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., undoable: bool = ..., description: _Optional[str] = ..., txid: _Optional[_Union[TxId, _Mapping]] = ...) -> None: ...

class RootMessage(_message.Message):
    __slots__ = ["error", "reply_activate", "reply_close_trace", "reply_create_object", "reply_create_overlay", "reply_create_trace", "reply_delete_bytes", "reply_delete_register_value", "reply_disassemble", "reply_end_tx", "reply_get_object", "reply_get_values", "reply_insert_object", "reply_negotiate", "reply_put_bytes", "reply_put_register_value", "reply_remove_object", "reply_retain_values", "reply_save_trace", "reply_set_memory_state", "reply_set_value", "reply_snapshot", "reply_start_tx", "request_activate", "request_close_trace", "request_create_object", "request_create_overlay", "request_create_root_object", "request_create_trace", "request_delete_bytes", "request_delete_register_value", "request_disassemble", "request_end_tx", "request_get_object", "request_get_values", "request_get_values_intersecting", "request_insert_object", "request_negotiate", "request_put_bytes", "request_put_register_value", "request_remove_object", "request_retain_values", "request_save_trace", "request_set_memory_state", "request_set_value", "request_snapshot", "request_start_tx", "xreply_invoke_method", "xrequest_invoke_method"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    REPLY_ACTIVATE_FIELD_NUMBER: _ClassVar[int]
    REPLY_CLOSE_TRACE_FIELD_NUMBER: _ClassVar[int]
    REPLY_CREATE_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REPLY_CREATE_OVERLAY_FIELD_NUMBER: _ClassVar[int]
    REPLY_CREATE_TRACE_FIELD_NUMBER: _ClassVar[int]
    REPLY_DELETE_BYTES_FIELD_NUMBER: _ClassVar[int]
    REPLY_DELETE_REGISTER_VALUE_FIELD_NUMBER: _ClassVar[int]
    REPLY_DISASSEMBLE_FIELD_NUMBER: _ClassVar[int]
    REPLY_END_TX_FIELD_NUMBER: _ClassVar[int]
    REPLY_GET_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REPLY_GET_VALUES_FIELD_NUMBER: _ClassVar[int]
    REPLY_INSERT_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REPLY_NEGOTIATE_FIELD_NUMBER: _ClassVar[int]
    REPLY_PUT_BYTES_FIELD_NUMBER: _ClassVar[int]
    REPLY_PUT_REGISTER_VALUE_FIELD_NUMBER: _ClassVar[int]
    REPLY_REMOVE_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REPLY_RETAIN_VALUES_FIELD_NUMBER: _ClassVar[int]
    REPLY_SAVE_TRACE_FIELD_NUMBER: _ClassVar[int]
    REPLY_SET_MEMORY_STATE_FIELD_NUMBER: _ClassVar[int]
    REPLY_SET_VALUE_FIELD_NUMBER: _ClassVar[int]
    REPLY_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    REPLY_START_TX_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ACTIVATE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_CLOSE_TRACE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_CREATE_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_CREATE_OVERLAY_FIELD_NUMBER: _ClassVar[int]
    REQUEST_CREATE_ROOT_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_CREATE_TRACE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DELETE_BYTES_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DELETE_REGISTER_VALUE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DISASSEMBLE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_END_TX_FIELD_NUMBER: _ClassVar[int]
    REQUEST_GET_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_GET_VALUES_FIELD_NUMBER: _ClassVar[int]
    REQUEST_GET_VALUES_INTERSECTING_FIELD_NUMBER: _ClassVar[int]
    REQUEST_INSERT_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_NEGOTIATE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_PUT_BYTES_FIELD_NUMBER: _ClassVar[int]
    REQUEST_PUT_REGISTER_VALUE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_REMOVE_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_RETAIN_VALUES_FIELD_NUMBER: _ClassVar[int]
    REQUEST_SAVE_TRACE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_SET_MEMORY_STATE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_SET_VALUE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_START_TX_FIELD_NUMBER: _ClassVar[int]
    XREPLY_INVOKE_METHOD_FIELD_NUMBER: _ClassVar[int]
    XREQUEST_INVOKE_METHOD_FIELD_NUMBER: _ClassVar[int]
    error: ReplyError
    reply_activate: ReplyActivate
    reply_close_trace: ReplyCloseTrace
    reply_create_object: ReplyCreateObject
    reply_create_overlay: ReplyCreateOverlaySpace
    reply_create_trace: ReplyCreateTrace
    reply_delete_bytes: ReplyDeleteBytes
    reply_delete_register_value: ReplyDeleteRegisterValue
    reply_disassemble: ReplyDisassemble
    reply_end_tx: ReplyEndTx
    reply_get_object: ReplyGetObject
    reply_get_values: ReplyGetValues
    reply_insert_object: ReplyInsertObject
    reply_negotiate: ReplyNegotiate
    reply_put_bytes: ReplyPutBytes
    reply_put_register_value: ReplyPutRegisterValue
    reply_remove_object: ReplyRemoveObject
    reply_retain_values: ReplyRetainValues
    reply_save_trace: ReplySaveTrace
    reply_set_memory_state: ReplySetMemoryState
    reply_set_value: ReplySetValue
    reply_snapshot: ReplySnapshot
    reply_start_tx: ReplyStartTx
    request_activate: RequestActivate
    request_close_trace: RequestCloseTrace
    request_create_object: RequestCreateObject
    request_create_overlay: RequestCreateOverlaySpace
    request_create_root_object: RequestCreateRootObject
    request_create_trace: RequestCreateTrace
    request_delete_bytes: RequestDeleteBytes
    request_delete_register_value: RequestDeleteRegisterValue
    request_disassemble: RequestDisassemble
    request_end_tx: RequestEndTx
    request_get_object: RequestGetObject
    request_get_values: RequestGetValues
    request_get_values_intersecting: RequestGetValuesIntersecting
    request_insert_object: RequestInsertObject
    request_negotiate: RequestNegotiate
    request_put_bytes: RequestPutBytes
    request_put_register_value: RequestPutRegisterValue
    request_remove_object: RequestRemoveObject
    request_retain_values: RequestRetainValues
    request_save_trace: RequestSaveTrace
    request_set_memory_state: RequestSetMemoryState
    request_set_value: RequestSetValue
    request_snapshot: RequestSnapshot
    request_start_tx: RequestStartTx
    xreply_invoke_method: XReplyInvokeMethod
    xrequest_invoke_method: XRequestInvokeMethod
    def __init__(self, error: _Optional[_Union[ReplyError, _Mapping]] = ..., request_negotiate: _Optional[_Union[RequestNegotiate, _Mapping]] = ..., reply_negotiate: _Optional[_Union[ReplyNegotiate, _Mapping]] = ..., request_create_trace: _Optional[_Union[RequestCreateTrace, _Mapping]] = ..., reply_create_trace: _Optional[_Union[ReplyCreateTrace, _Mapping]] = ..., request_save_trace: _Optional[_Union[RequestSaveTrace, _Mapping]] = ..., reply_save_trace: _Optional[_Union[ReplySaveTrace, _Mapping]] = ..., request_close_trace: _Optional[_Union[RequestCloseTrace, _Mapping]] = ..., reply_close_trace: _Optional[_Union[ReplyCloseTrace, _Mapping]] = ..., request_start_tx: _Optional[_Union[RequestStartTx, _Mapping]] = ..., reply_start_tx: _Optional[_Union[ReplyStartTx, _Mapping]] = ..., request_end_tx: _Optional[_Union[RequestEndTx, _Mapping]] = ..., reply_end_tx: _Optional[_Union[ReplyEndTx, _Mapping]] = ..., request_create_overlay: _Optional[_Union[RequestCreateOverlaySpace, _Mapping]] = ..., reply_create_overlay: _Optional[_Union[ReplyCreateOverlaySpace, _Mapping]] = ..., request_set_memory_state: _Optional[_Union[RequestSetMemoryState, _Mapping]] = ..., reply_set_memory_state: _Optional[_Union[ReplySetMemoryState, _Mapping]] = ..., request_put_bytes: _Optional[_Union[RequestPutBytes, _Mapping]] = ..., reply_put_bytes: _Optional[_Union[ReplyPutBytes, _Mapping]] = ..., request_delete_bytes: _Optional[_Union[RequestDeleteBytes, _Mapping]] = ..., reply_delete_bytes: _Optional[_Union[ReplyDeleteBytes, _Mapping]] = ..., request_put_register_value: _Optional[_Union[RequestPutRegisterValue, _Mapping]] = ..., reply_put_register_value: _Optional[_Union[ReplyPutRegisterValue, _Mapping]] = ..., request_delete_register_value: _Optional[_Union[RequestDeleteRegisterValue, _Mapping]] = ..., reply_delete_register_value: _Optional[_Union[ReplyDeleteRegisterValue, _Mapping]] = ..., request_create_root_object: _Optional[_Union[RequestCreateRootObject, _Mapping]] = ..., request_create_object: _Optional[_Union[RequestCreateObject, _Mapping]] = ..., reply_create_object: _Optional[_Union[ReplyCreateObject, _Mapping]] = ..., request_insert_object: _Optional[_Union[RequestInsertObject, _Mapping]] = ..., reply_insert_object: _Optional[_Union[ReplyInsertObject, _Mapping]] = ..., request_remove_object: _Optional[_Union[RequestRemoveObject, _Mapping]] = ..., reply_remove_object: _Optional[_Union[ReplyRemoveObject, _Mapping]] = ..., request_set_value: _Optional[_Union[RequestSetValue, _Mapping]] = ..., reply_set_value: _Optional[_Union[ReplySetValue, _Mapping]] = ..., request_retain_values: _Optional[_Union[RequestRetainValues, _Mapping]] = ..., reply_retain_values: _Optional[_Union[ReplyRetainValues, _Mapping]] = ..., request_get_object: _Optional[_Union[RequestGetObject, _Mapping]] = ..., reply_get_object: _Optional[_Union[ReplyGetObject, _Mapping]] = ..., request_get_values: _Optional[_Union[RequestGetValues, _Mapping]] = ..., reply_get_values: _Optional[_Union[ReplyGetValues, _Mapping]] = ..., request_get_values_intersecting: _Optional[_Union[RequestGetValuesIntersecting, _Mapping]] = ..., request_disassemble: _Optional[_Union[RequestDisassemble, _Mapping]] = ..., reply_disassemble: _Optional[_Union[ReplyDisassemble, _Mapping]] = ..., request_activate: _Optional[_Union[RequestActivate, _Mapping]] = ..., reply_activate: _Optional[_Union[ReplyActivate, _Mapping]] = ..., request_snapshot: _Optional[_Union[RequestSnapshot, _Mapping]] = ..., reply_snapshot: _Optional[_Union[ReplySnapshot, _Mapping]] = ..., xrequest_invoke_method: _Optional[_Union[XRequestInvokeMethod, _Mapping]] = ..., xreply_invoke_method: _Optional[_Union[XReplyInvokeMethod, _Mapping]] = ...) -> None: ...

class Schedule(_message.Message):
    __slots__ = ["schedule"]
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    schedule: str
    def __init__(self, schedule: _Optional[str] = ...) -> None: ...

class ShortArr(_message.Message):
    __slots__ = ["arr"]
    ARR_FIELD_NUMBER: _ClassVar[int]
    arr: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, arr: _Optional[_Iterable[int]] = ...) -> None: ...

class Snap(_message.Message):
    __slots__ = ["snap"]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    snap: int
    def __init__(self, snap: _Optional[int] = ...) -> None: ...

class Span(_message.Message):
    __slots__ = ["max", "min"]
    MAX_FIELD_NUMBER: _ClassVar[int]
    MIN_FIELD_NUMBER: _ClassVar[int]
    max: int
    min: int
    def __init__(self, min: _Optional[int] = ..., max: _Optional[int] = ...) -> None: ...

class StringArr(_message.Message):
    __slots__ = ["arr"]
    ARR_FIELD_NUMBER: _ClassVar[int]
    arr: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, arr: _Optional[_Iterable[str]] = ...) -> None: ...

class TxId(_message.Message):
    __slots__ = ["id"]
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class ValDesc(_message.Message):
    __slots__ = ["key", "parent", "span", "value"]
    KEY_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    parent: ObjDesc
    span: Span
    value: Value
    def __init__(self, parent: _Optional[_Union[ObjDesc, _Mapping]] = ..., span: _Optional[_Union[Span, _Mapping]] = ..., key: _Optional[str] = ..., value: _Optional[_Union[Value, _Mapping]] = ...) -> None: ...

class ValSpec(_message.Message):
    __slots__ = ["key", "parent", "span", "value"]
    KEY_FIELD_NUMBER: _ClassVar[int]
    PARENT_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    key: str
    parent: ObjSpec
    span: Span
    value: Value
    def __init__(self, parent: _Optional[_Union[ObjSpec, _Mapping]] = ..., span: _Optional[_Union[Span, _Mapping]] = ..., key: _Optional[str] = ..., value: _Optional[_Union[Value, _Mapping]] = ...) -> None: ...

class Value(_message.Message):
    __slots__ = ["address_value", "bool_arr_value", "bool_value", "byte_value", "bytes_value", "char_arr_value", "char_value", "child_desc", "child_spec", "int_arr_value", "int_value", "long_arr_value", "long_value", "null_value", "range_value", "short_arr_value", "short_value", "string_arr_value", "string_value"]
    ADDRESS_VALUE_FIELD_NUMBER: _ClassVar[int]
    BOOL_ARR_VALUE_FIELD_NUMBER: _ClassVar[int]
    BOOL_VALUE_FIELD_NUMBER: _ClassVar[int]
    BYTES_VALUE_FIELD_NUMBER: _ClassVar[int]
    BYTE_VALUE_FIELD_NUMBER: _ClassVar[int]
    CHAR_ARR_VALUE_FIELD_NUMBER: _ClassVar[int]
    CHAR_VALUE_FIELD_NUMBER: _ClassVar[int]
    CHILD_DESC_FIELD_NUMBER: _ClassVar[int]
    CHILD_SPEC_FIELD_NUMBER: _ClassVar[int]
    INT_ARR_VALUE_FIELD_NUMBER: _ClassVar[int]
    INT_VALUE_FIELD_NUMBER: _ClassVar[int]
    LONG_ARR_VALUE_FIELD_NUMBER: _ClassVar[int]
    LONG_VALUE_FIELD_NUMBER: _ClassVar[int]
    NULL_VALUE_FIELD_NUMBER: _ClassVar[int]
    RANGE_VALUE_FIELD_NUMBER: _ClassVar[int]
    SHORT_ARR_VALUE_FIELD_NUMBER: _ClassVar[int]
    SHORT_VALUE_FIELD_NUMBER: _ClassVar[int]
    STRING_ARR_VALUE_FIELD_NUMBER: _ClassVar[int]
    STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
    address_value: Addr
    bool_arr_value: BoolArr
    bool_value: bool
    byte_value: int
    bytes_value: bytes
    char_arr_value: str
    char_value: int
    child_desc: ObjDesc
    child_spec: ObjSpec
    int_arr_value: IntArr
    int_value: int
    long_arr_value: LongArr
    long_value: int
    null_value: Null
    range_value: AddrRange
    short_arr_value: ShortArr
    short_value: int
    string_arr_value: StringArr
    string_value: str
    def __init__(self, null_value: _Optional[_Union[Null, _Mapping]] = ..., bool_value: bool = ..., byte_value: _Optional[int] = ..., char_value: _Optional[int] = ..., short_value: _Optional[int] = ..., int_value: _Optional[int] = ..., long_value: _Optional[int] = ..., string_value: _Optional[str] = ..., bool_arr_value: _Optional[_Union[BoolArr, _Mapping]] = ..., bytes_value: _Optional[bytes] = ..., char_arr_value: _Optional[str] = ..., short_arr_value: _Optional[_Union[ShortArr, _Mapping]] = ..., int_arr_value: _Optional[_Union[IntArr, _Mapping]] = ..., long_arr_value: _Optional[_Union[LongArr, _Mapping]] = ..., string_arr_value: _Optional[_Union[StringArr, _Mapping]] = ..., address_value: _Optional[_Union[Addr, _Mapping]] = ..., range_value: _Optional[_Union[AddrRange, _Mapping]] = ..., child_spec: _Optional[_Union[ObjSpec, _Mapping]] = ..., child_desc: _Optional[_Union[ObjDesc, _Mapping]] = ...) -> None: ...

class ValueType(_message.Message):
    __slots__ = ["name"]
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class XReplyInvokeMethod(_message.Message):
    __slots__ = ["error", "return_value"]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    RETURN_VALUE_FIELD_NUMBER: _ClassVar[int]
    error: str
    return_value: Value
    def __init__(self, error: _Optional[str] = ..., return_value: _Optional[_Union[Value, _Mapping]] = ...) -> None: ...

class XRequestInvokeMethod(_message.Message):
    __slots__ = ["arguments", "name", "oid"]
    ARGUMENTS_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    arguments: _containers.RepeatedCompositeFieldContainer[MethodArgument]
    name: str
    oid: DomObjId
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., name: _Optional[str] = ..., arguments: _Optional[_Iterable[_Union[MethodArgument, _Mapping]]] = ...) -> None: ...

class MemoryState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class Resolution(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []

class ValueKinds(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = []
