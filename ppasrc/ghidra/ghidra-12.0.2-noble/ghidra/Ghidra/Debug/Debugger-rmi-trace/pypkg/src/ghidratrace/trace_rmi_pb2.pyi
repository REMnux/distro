from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class MemoryState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    MS_UNKNOWN: _ClassVar[MemoryState]
    MS_KNOWN: _ClassVar[MemoryState]
    MS_ERROR: _ClassVar[MemoryState]

class Resolution(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CR_TRUNCATE: _ClassVar[Resolution]
    CR_DENY: _ClassVar[Resolution]
    CR_ADJUST: _ClassVar[Resolution]

class ValueKinds(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VK_ELEMENTS: _ClassVar[ValueKinds]
    VK_ATTRIBUTES: _ClassVar[ValueKinds]
    VK_BOTH: _ClassVar[ValueKinds]
MS_UNKNOWN: MemoryState
MS_KNOWN: MemoryState
MS_ERROR: MemoryState
CR_TRUNCATE: Resolution
CR_DENY: Resolution
CR_ADJUST: Resolution
VK_ELEMENTS: ValueKinds
VK_ATTRIBUTES: ValueKinds
VK_BOTH: ValueKinds

class FilePath(_message.Message):
    __slots__ = ("path",)
    PATH_FIELD_NUMBER: _ClassVar[int]
    path: str
    def __init__(self, path: _Optional[str] = ...) -> None: ...

class DomObjId(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class TxId(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: int
    def __init__(self, id: _Optional[int] = ...) -> None: ...

class ObjPath(_message.Message):
    __slots__ = ("path",)
    PATH_FIELD_NUMBER: _ClassVar[int]
    path: str
    def __init__(self, path: _Optional[str] = ...) -> None: ...

class Language(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class Compiler(_message.Message):
    __slots__ = ("id",)
    ID_FIELD_NUMBER: _ClassVar[int]
    id: str
    def __init__(self, id: _Optional[str] = ...) -> None: ...

class Addr(_message.Message):
    __slots__ = ("space", "offset")
    SPACE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    space: str
    offset: int
    def __init__(self, space: _Optional[str] = ..., offset: _Optional[int] = ...) -> None: ...

class AddrRange(_message.Message):
    __slots__ = ("space", "offset", "extend")
    SPACE_FIELD_NUMBER: _ClassVar[int]
    OFFSET_FIELD_NUMBER: _ClassVar[int]
    EXTEND_FIELD_NUMBER: _ClassVar[int]
    space: str
    offset: int
    extend: int
    def __init__(self, space: _Optional[str] = ..., offset: _Optional[int] = ..., extend: _Optional[int] = ...) -> None: ...

class Snap(_message.Message):
    __slots__ = ("snap",)
    SNAP_FIELD_NUMBER: _ClassVar[int]
    snap: int
    def __init__(self, snap: _Optional[int] = ...) -> None: ...

class Schedule(_message.Message):
    __slots__ = ("schedule",)
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    schedule: str
    def __init__(self, schedule: _Optional[str] = ...) -> None: ...

class Span(_message.Message):
    __slots__ = ("min", "max")
    MIN_FIELD_NUMBER: _ClassVar[int]
    MAX_FIELD_NUMBER: _ClassVar[int]
    min: int
    max: int
    def __init__(self, min: _Optional[int] = ..., max: _Optional[int] = ...) -> None: ...

class Box(_message.Message):
    __slots__ = ("span", "range")
    SPAN_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    span: Span
    range: AddrRange
    def __init__(self, span: _Optional[_Union[Span, _Mapping]] = ..., range: _Optional[_Union[AddrRange, _Mapping]] = ...) -> None: ...

class ReplyError(_message.Message):
    __slots__ = ("message",)
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    message: str
    def __init__(self, message: _Optional[str] = ...) -> None: ...

class RequestCreateTrace(_message.Message):
    __slots__ = ("path", "language", "compiler", "oid")
    PATH_FIELD_NUMBER: _ClassVar[int]
    LANGUAGE_FIELD_NUMBER: _ClassVar[int]
    COMPILER_FIELD_NUMBER: _ClassVar[int]
    OID_FIELD_NUMBER: _ClassVar[int]
    path: FilePath
    language: Language
    compiler: Compiler
    oid: DomObjId
    def __init__(self, path: _Optional[_Union[FilePath, _Mapping]] = ..., language: _Optional[_Union[Language, _Mapping]] = ..., compiler: _Optional[_Union[Compiler, _Mapping]] = ..., oid: _Optional[_Union[DomObjId, _Mapping]] = ...) -> None: ...

class ReplyCreateTrace(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RequestSaveTrace(_message.Message):
    __slots__ = ("oid",)
    OID_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ...) -> None: ...

class ReplySaveTrace(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RequestCloseTrace(_message.Message):
    __slots__ = ("oid",)
    OID_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ...) -> None: ...

class ReplyCloseTrace(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RequestStartTx(_message.Message):
    __slots__ = ("oid", "undoable", "description", "txid")
    OID_FIELD_NUMBER: _ClassVar[int]
    UNDOABLE_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    TXID_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    undoable: bool
    description: str
    txid: TxId
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., undoable: bool = ..., description: _Optional[str] = ..., txid: _Optional[_Union[TxId, _Mapping]] = ...) -> None: ...

class ReplyStartTx(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RequestEndTx(_message.Message):
    __slots__ = ("oid", "txid", "abort")
    OID_FIELD_NUMBER: _ClassVar[int]
    TXID_FIELD_NUMBER: _ClassVar[int]
    ABORT_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    txid: TxId
    abort: bool
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., txid: _Optional[_Union[TxId, _Mapping]] = ..., abort: bool = ...) -> None: ...

class ReplyEndTx(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RequestCreateOverlaySpace(_message.Message):
    __slots__ = ("oid", "baseSpace", "name")
    OID_FIELD_NUMBER: _ClassVar[int]
    BASESPACE_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    baseSpace: str
    name: str
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., baseSpace: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class ReplyCreateOverlaySpace(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RequestSetMemoryState(_message.Message):
    __slots__ = ("oid", "snap", "range", "state")
    OID_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    snap: Snap
    range: AddrRange
    state: MemoryState
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., range: _Optional[_Union[AddrRange, _Mapping]] = ..., state: _Optional[_Union[MemoryState, str]] = ...) -> None: ...

class ReplySetMemoryState(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RequestPutBytes(_message.Message):
    __slots__ = ("oid", "snap", "start", "data")
    OID_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    snap: Snap
    start: Addr
    data: bytes
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., start: _Optional[_Union[Addr, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class ReplyPutBytes(_message.Message):
    __slots__ = ("written",)
    WRITTEN_FIELD_NUMBER: _ClassVar[int]
    written: int
    def __init__(self, written: _Optional[int] = ...) -> None: ...

class RequestDeleteBytes(_message.Message):
    __slots__ = ("oid", "snap", "range")
    OID_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    RANGE_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    snap: Snap
    range: AddrRange
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., range: _Optional[_Union[AddrRange, _Mapping]] = ...) -> None: ...

class ReplyDeleteBytes(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RegVal(_message.Message):
    __slots__ = ("name", "value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: bytes
    def __init__(self, name: _Optional[str] = ..., value: _Optional[bytes] = ...) -> None: ...

class RequestPutRegisterValue(_message.Message):
    __slots__ = ("oid", "snap", "space", "values")
    OID_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    VALUES_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    snap: Snap
    space: str
    values: _containers.RepeatedCompositeFieldContainer[RegVal]
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., space: _Optional[str] = ..., values: _Optional[_Iterable[_Union[RegVal, _Mapping]]] = ...) -> None: ...

class ReplyPutRegisterValue(_message.Message):
    __slots__ = ("skipped_names",)
    SKIPPED_NAMES_FIELD_NUMBER: _ClassVar[int]
    skipped_names: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, skipped_names: _Optional[_Iterable[str]] = ...) -> None: ...

class RequestDeleteRegisterValue(_message.Message):
    __slots__ = ("oid", "snap", "space", "names")
    OID_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    SPACE_FIELD_NUMBER: _ClassVar[int]
    NAMES_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    snap: Snap
    space: str
    names: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., space: _Optional[str] = ..., names: _Optional[_Iterable[str]] = ...) -> None: ...

class ReplyDeleteRegisterValue(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ObjSpec(_message.Message):
    __slots__ = ("id", "path")
    ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    id: int
    path: ObjPath
    def __init__(self, id: _Optional[int] = ..., path: _Optional[_Union[ObjPath, _Mapping]] = ...) -> None: ...

class ObjDesc(_message.Message):
    __slots__ = ("id", "path")
    ID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    id: int
    path: ObjPath
    def __init__(self, id: _Optional[int] = ..., path: _Optional[_Union[ObjPath, _Mapping]] = ...) -> None: ...

class ValSpec(_message.Message):
    __slots__ = ("parent", "span", "key", "value")
    PARENT_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    parent: ObjSpec
    span: Span
    key: str
    value: Value
    def __init__(self, parent: _Optional[_Union[ObjSpec, _Mapping]] = ..., span: _Optional[_Union[Span, _Mapping]] = ..., key: _Optional[str] = ..., value: _Optional[_Union[Value, _Mapping]] = ...) -> None: ...

class ValDesc(_message.Message):
    __slots__ = ("parent", "span", "key", "value")
    PARENT_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    parent: ObjDesc
    span: Span
    key: str
    value: Value
    def __init__(self, parent: _Optional[_Union[ObjDesc, _Mapping]] = ..., span: _Optional[_Union[Span, _Mapping]] = ..., key: _Optional[str] = ..., value: _Optional[_Union[Value, _Mapping]] = ...) -> None: ...

class Null(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class BoolArr(_message.Message):
    __slots__ = ("arr",)
    ARR_FIELD_NUMBER: _ClassVar[int]
    arr: _containers.RepeatedScalarFieldContainer[bool]
    def __init__(self, arr: _Optional[_Iterable[bool]] = ...) -> None: ...

class ShortArr(_message.Message):
    __slots__ = ("arr",)
    ARR_FIELD_NUMBER: _ClassVar[int]
    arr: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, arr: _Optional[_Iterable[int]] = ...) -> None: ...

class IntArr(_message.Message):
    __slots__ = ("arr",)
    ARR_FIELD_NUMBER: _ClassVar[int]
    arr: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, arr: _Optional[_Iterable[int]] = ...) -> None: ...

class LongArr(_message.Message):
    __slots__ = ("arr",)
    ARR_FIELD_NUMBER: _ClassVar[int]
    arr: _containers.RepeatedScalarFieldContainer[int]
    def __init__(self, arr: _Optional[_Iterable[int]] = ...) -> None: ...

class StringArr(_message.Message):
    __slots__ = ("arr",)
    ARR_FIELD_NUMBER: _ClassVar[int]
    arr: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, arr: _Optional[_Iterable[str]] = ...) -> None: ...

class ValueType(_message.Message):
    __slots__ = ("name",)
    NAME_FIELD_NUMBER: _ClassVar[int]
    name: str
    def __init__(self, name: _Optional[str] = ...) -> None: ...

class Value(_message.Message):
    __slots__ = ("null_value", "bool_value", "byte_value", "char_value", "short_value", "int_value", "long_value", "string_value", "bool_arr_value", "bytes_value", "char_arr_value", "short_arr_value", "int_arr_value", "long_arr_value", "string_arr_value", "address_value", "range_value", "child_spec", "child_desc")
    NULL_VALUE_FIELD_NUMBER: _ClassVar[int]
    BOOL_VALUE_FIELD_NUMBER: _ClassVar[int]
    BYTE_VALUE_FIELD_NUMBER: _ClassVar[int]
    CHAR_VALUE_FIELD_NUMBER: _ClassVar[int]
    SHORT_VALUE_FIELD_NUMBER: _ClassVar[int]
    INT_VALUE_FIELD_NUMBER: _ClassVar[int]
    LONG_VALUE_FIELD_NUMBER: _ClassVar[int]
    STRING_VALUE_FIELD_NUMBER: _ClassVar[int]
    BOOL_ARR_VALUE_FIELD_NUMBER: _ClassVar[int]
    BYTES_VALUE_FIELD_NUMBER: _ClassVar[int]
    CHAR_ARR_VALUE_FIELD_NUMBER: _ClassVar[int]
    SHORT_ARR_VALUE_FIELD_NUMBER: _ClassVar[int]
    INT_ARR_VALUE_FIELD_NUMBER: _ClassVar[int]
    LONG_ARR_VALUE_FIELD_NUMBER: _ClassVar[int]
    STRING_ARR_VALUE_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_VALUE_FIELD_NUMBER: _ClassVar[int]
    RANGE_VALUE_FIELD_NUMBER: _ClassVar[int]
    CHILD_SPEC_FIELD_NUMBER: _ClassVar[int]
    CHILD_DESC_FIELD_NUMBER: _ClassVar[int]
    null_value: Null
    bool_value: bool
    byte_value: int
    char_value: int
    short_value: int
    int_value: int
    long_value: int
    string_value: str
    bool_arr_value: BoolArr
    bytes_value: bytes
    char_arr_value: str
    short_arr_value: ShortArr
    int_arr_value: IntArr
    long_arr_value: LongArr
    string_arr_value: StringArr
    address_value: Addr
    range_value: AddrRange
    child_spec: ObjSpec
    child_desc: ObjDesc
    def __init__(self, null_value: _Optional[_Union[Null, _Mapping]] = ..., bool_value: bool = ..., byte_value: _Optional[int] = ..., char_value: _Optional[int] = ..., short_value: _Optional[int] = ..., int_value: _Optional[int] = ..., long_value: _Optional[int] = ..., string_value: _Optional[str] = ..., bool_arr_value: _Optional[_Union[BoolArr, _Mapping]] = ..., bytes_value: _Optional[bytes] = ..., char_arr_value: _Optional[str] = ..., short_arr_value: _Optional[_Union[ShortArr, _Mapping]] = ..., int_arr_value: _Optional[_Union[IntArr, _Mapping]] = ..., long_arr_value: _Optional[_Union[LongArr, _Mapping]] = ..., string_arr_value: _Optional[_Union[StringArr, _Mapping]] = ..., address_value: _Optional[_Union[Addr, _Mapping]] = ..., range_value: _Optional[_Union[AddrRange, _Mapping]] = ..., child_spec: _Optional[_Union[ObjSpec, _Mapping]] = ..., child_desc: _Optional[_Union[ObjDesc, _Mapping]] = ...) -> None: ...

class RequestCreateRootObject(_message.Message):
    __slots__ = ("oid", "schema_context", "root_schema")
    OID_FIELD_NUMBER: _ClassVar[int]
    SCHEMA_CONTEXT_FIELD_NUMBER: _ClassVar[int]
    ROOT_SCHEMA_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    schema_context: str
    root_schema: str
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., schema_context: _Optional[str] = ..., root_schema: _Optional[str] = ...) -> None: ...

class RequestCreateObject(_message.Message):
    __slots__ = ("oid", "path")
    OID_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    path: ObjPath
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., path: _Optional[_Union[ObjPath, _Mapping]] = ...) -> None: ...

class ReplyCreateObject(_message.Message):
    __slots__ = ("object",)
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    object: ObjSpec
    def __init__(self, object: _Optional[_Union[ObjSpec, _Mapping]] = ...) -> None: ...

class RequestInsertObject(_message.Message):
    __slots__ = ("oid", "object", "span", "resolution")
    OID_FIELD_NUMBER: _ClassVar[int]
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    RESOLUTION_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    object: ObjSpec
    span: Span
    resolution: Resolution
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., object: _Optional[_Union[ObjSpec, _Mapping]] = ..., span: _Optional[_Union[Span, _Mapping]] = ..., resolution: _Optional[_Union[Resolution, str]] = ...) -> None: ...

class ReplyInsertObject(_message.Message):
    __slots__ = ("span",)
    SPAN_FIELD_NUMBER: _ClassVar[int]
    span: Span
    def __init__(self, span: _Optional[_Union[Span, _Mapping]] = ...) -> None: ...

class RequestRemoveObject(_message.Message):
    __slots__ = ("oid", "object", "span", "tree")
    OID_FIELD_NUMBER: _ClassVar[int]
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    TREE_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    object: ObjSpec
    span: Span
    tree: bool
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., object: _Optional[_Union[ObjSpec, _Mapping]] = ..., span: _Optional[_Union[Span, _Mapping]] = ..., tree: bool = ...) -> None: ...

class ReplyRemoveObject(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RequestSetValue(_message.Message):
    __slots__ = ("oid", "value", "resolution")
    OID_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    RESOLUTION_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    value: ValSpec
    resolution: Resolution
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., value: _Optional[_Union[ValSpec, _Mapping]] = ..., resolution: _Optional[_Union[Resolution, str]] = ...) -> None: ...

class ReplySetValue(_message.Message):
    __slots__ = ("span",)
    SPAN_FIELD_NUMBER: _ClassVar[int]
    span: Span
    def __init__(self, span: _Optional[_Union[Span, _Mapping]] = ...) -> None: ...

class RequestRetainValues(_message.Message):
    __slots__ = ("oid", "object", "span", "kinds", "keys")
    OID_FIELD_NUMBER: _ClassVar[int]
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    KINDS_FIELD_NUMBER: _ClassVar[int]
    KEYS_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    object: ObjSpec
    span: Span
    kinds: ValueKinds
    keys: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., object: _Optional[_Union[ObjSpec, _Mapping]] = ..., span: _Optional[_Union[Span, _Mapping]] = ..., kinds: _Optional[_Union[ValueKinds, str]] = ..., keys: _Optional[_Iterable[str]] = ...) -> None: ...

class ReplyRetainValues(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RequestGetObject(_message.Message):
    __slots__ = ("oid", "object")
    OID_FIELD_NUMBER: _ClassVar[int]
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    object: ObjSpec
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., object: _Optional[_Union[ObjSpec, _Mapping]] = ...) -> None: ...

class ReplyGetObject(_message.Message):
    __slots__ = ("object",)
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    object: ObjDesc
    def __init__(self, object: _Optional[_Union[ObjDesc, _Mapping]] = ...) -> None: ...

class RequestGetValues(_message.Message):
    __slots__ = ("oid", "span", "pattern")
    OID_FIELD_NUMBER: _ClassVar[int]
    SPAN_FIELD_NUMBER: _ClassVar[int]
    PATTERN_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    span: Span
    pattern: ObjPath
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., span: _Optional[_Union[Span, _Mapping]] = ..., pattern: _Optional[_Union[ObjPath, _Mapping]] = ...) -> None: ...

class ReplyGetValues(_message.Message):
    __slots__ = ("values",)
    VALUES_FIELD_NUMBER: _ClassVar[int]
    values: _containers.RepeatedCompositeFieldContainer[ValDesc]
    def __init__(self, values: _Optional[_Iterable[_Union[ValDesc, _Mapping]]] = ...) -> None: ...

class RequestGetValuesIntersecting(_message.Message):
    __slots__ = ("oid", "box", "key")
    OID_FIELD_NUMBER: _ClassVar[int]
    BOX_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    box: Box
    key: str
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., box: _Optional[_Union[Box, _Mapping]] = ..., key: _Optional[str] = ...) -> None: ...

class RequestDisassemble(_message.Message):
    __slots__ = ("oid", "snap", "start")
    OID_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    snap: Snap
    start: Addr
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., start: _Optional[_Union[Addr, _Mapping]] = ...) -> None: ...

class ReplyDisassemble(_message.Message):
    __slots__ = ("length",)
    LENGTH_FIELD_NUMBER: _ClassVar[int]
    length: int
    def __init__(self, length: _Optional[int] = ...) -> None: ...

class RequestActivate(_message.Message):
    __slots__ = ("oid", "object")
    OID_FIELD_NUMBER: _ClassVar[int]
    OBJECT_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    object: ObjSpec
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., object: _Optional[_Union[ObjSpec, _Mapping]] = ...) -> None: ...

class ReplyActivate(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RequestSnapshot(_message.Message):
    __slots__ = ("oid", "description", "datetime", "snap", "schedule")
    OID_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    DATETIME_FIELD_NUMBER: _ClassVar[int]
    SNAP_FIELD_NUMBER: _ClassVar[int]
    SCHEDULE_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    description: str
    datetime: str
    snap: Snap
    schedule: Schedule
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., description: _Optional[str] = ..., datetime: _Optional[str] = ..., snap: _Optional[_Union[Snap, _Mapping]] = ..., schedule: _Optional[_Union[Schedule, _Mapping]] = ...) -> None: ...

class ReplySnapshot(_message.Message):
    __slots__ = ("snap",)
    SNAP_FIELD_NUMBER: _ClassVar[int]
    snap: Snap
    def __init__(self, snap: _Optional[_Union[Snap, _Mapping]] = ...) -> None: ...

class MethodParameter(_message.Message):
    __slots__ = ("name", "type", "required", "default_value", "display", "description")
    NAME_FIELD_NUMBER: _ClassVar[int]
    TYPE_FIELD_NUMBER: _ClassVar[int]
    REQUIRED_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_VALUE_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    name: str
    type: ValueType
    required: bool
    default_value: Value
    display: str
    description: str
    def __init__(self, name: _Optional[str] = ..., type: _Optional[_Union[ValueType, _Mapping]] = ..., required: bool = ..., default_value: _Optional[_Union[Value, _Mapping]] = ..., display: _Optional[str] = ..., description: _Optional[str] = ...) -> None: ...

class MethodArgument(_message.Message):
    __slots__ = ("name", "value")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VALUE_FIELD_NUMBER: _ClassVar[int]
    name: str
    value: Value
    def __init__(self, name: _Optional[str] = ..., value: _Optional[_Union[Value, _Mapping]] = ...) -> None: ...

class Method(_message.Message):
    __slots__ = ("name", "action", "display", "description", "parameters", "return_type", "ok_text", "icon")
    NAME_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    DISPLAY_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    RETURN_TYPE_FIELD_NUMBER: _ClassVar[int]
    OK_TEXT_FIELD_NUMBER: _ClassVar[int]
    ICON_FIELD_NUMBER: _ClassVar[int]
    name: str
    action: str
    display: str
    description: str
    parameters: _containers.RepeatedCompositeFieldContainer[MethodParameter]
    return_type: ValueType
    ok_text: str
    icon: str
    def __init__(self, name: _Optional[str] = ..., action: _Optional[str] = ..., display: _Optional[str] = ..., description: _Optional[str] = ..., parameters: _Optional[_Iterable[_Union[MethodParameter, _Mapping]]] = ..., return_type: _Optional[_Union[ValueType, _Mapping]] = ..., ok_text: _Optional[str] = ..., icon: _Optional[str] = ...) -> None: ...

class RequestNegotiate(_message.Message):
    __slots__ = ("version", "methods", "description")
    VERSION_FIELD_NUMBER: _ClassVar[int]
    METHODS_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    version: str
    methods: _containers.RepeatedCompositeFieldContainer[Method]
    description: str
    def __init__(self, version: _Optional[str] = ..., methods: _Optional[_Iterable[_Union[Method, _Mapping]]] = ..., description: _Optional[str] = ...) -> None: ...

class ReplyNegotiate(_message.Message):
    __slots__ = ("description",)
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    description: str
    def __init__(self, description: _Optional[str] = ...) -> None: ...

class XRequestInvokeMethod(_message.Message):
    __slots__ = ("oid", "name", "arguments")
    OID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ARGUMENTS_FIELD_NUMBER: _ClassVar[int]
    oid: DomObjId
    name: str
    arguments: _containers.RepeatedCompositeFieldContainer[MethodArgument]
    def __init__(self, oid: _Optional[_Union[DomObjId, _Mapping]] = ..., name: _Optional[str] = ..., arguments: _Optional[_Iterable[_Union[MethodArgument, _Mapping]]] = ...) -> None: ...

class XReplyInvokeMethod(_message.Message):
    __slots__ = ("error", "return_value")
    ERROR_FIELD_NUMBER: _ClassVar[int]
    RETURN_VALUE_FIELD_NUMBER: _ClassVar[int]
    error: str
    return_value: Value
    def __init__(self, error: _Optional[str] = ..., return_value: _Optional[_Union[Value, _Mapping]] = ...) -> None: ...

class RootMessage(_message.Message):
    __slots__ = ("error", "request_negotiate", "reply_negotiate", "request_create_trace", "reply_create_trace", "request_save_trace", "reply_save_trace", "request_close_trace", "reply_close_trace", "request_start_tx", "reply_start_tx", "request_end_tx", "reply_end_tx", "request_create_overlay", "reply_create_overlay", "request_set_memory_state", "reply_set_memory_state", "request_put_bytes", "reply_put_bytes", "request_delete_bytes", "reply_delete_bytes", "request_put_register_value", "reply_put_register_value", "request_delete_register_value", "reply_delete_register_value", "request_create_root_object", "request_create_object", "reply_create_object", "request_insert_object", "reply_insert_object", "request_remove_object", "reply_remove_object", "request_set_value", "reply_set_value", "request_retain_values", "reply_retain_values", "request_get_object", "reply_get_object", "request_get_values", "reply_get_values", "request_get_values_intersecting", "request_disassemble", "reply_disassemble", "request_activate", "reply_activate", "request_snapshot", "reply_snapshot", "xrequest_invoke_method", "xreply_invoke_method")
    ERROR_FIELD_NUMBER: _ClassVar[int]
    REQUEST_NEGOTIATE_FIELD_NUMBER: _ClassVar[int]
    REPLY_NEGOTIATE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_CREATE_TRACE_FIELD_NUMBER: _ClassVar[int]
    REPLY_CREATE_TRACE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_SAVE_TRACE_FIELD_NUMBER: _ClassVar[int]
    REPLY_SAVE_TRACE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_CLOSE_TRACE_FIELD_NUMBER: _ClassVar[int]
    REPLY_CLOSE_TRACE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_START_TX_FIELD_NUMBER: _ClassVar[int]
    REPLY_START_TX_FIELD_NUMBER: _ClassVar[int]
    REQUEST_END_TX_FIELD_NUMBER: _ClassVar[int]
    REPLY_END_TX_FIELD_NUMBER: _ClassVar[int]
    REQUEST_CREATE_OVERLAY_FIELD_NUMBER: _ClassVar[int]
    REPLY_CREATE_OVERLAY_FIELD_NUMBER: _ClassVar[int]
    REQUEST_SET_MEMORY_STATE_FIELD_NUMBER: _ClassVar[int]
    REPLY_SET_MEMORY_STATE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_PUT_BYTES_FIELD_NUMBER: _ClassVar[int]
    REPLY_PUT_BYTES_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DELETE_BYTES_FIELD_NUMBER: _ClassVar[int]
    REPLY_DELETE_BYTES_FIELD_NUMBER: _ClassVar[int]
    REQUEST_PUT_REGISTER_VALUE_FIELD_NUMBER: _ClassVar[int]
    REPLY_PUT_REGISTER_VALUE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DELETE_REGISTER_VALUE_FIELD_NUMBER: _ClassVar[int]
    REPLY_DELETE_REGISTER_VALUE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_CREATE_ROOT_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_CREATE_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REPLY_CREATE_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_INSERT_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REPLY_INSERT_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_REMOVE_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REPLY_REMOVE_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_SET_VALUE_FIELD_NUMBER: _ClassVar[int]
    REPLY_SET_VALUE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_RETAIN_VALUES_FIELD_NUMBER: _ClassVar[int]
    REPLY_RETAIN_VALUES_FIELD_NUMBER: _ClassVar[int]
    REQUEST_GET_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REPLY_GET_OBJECT_FIELD_NUMBER: _ClassVar[int]
    REQUEST_GET_VALUES_FIELD_NUMBER: _ClassVar[int]
    REPLY_GET_VALUES_FIELD_NUMBER: _ClassVar[int]
    REQUEST_GET_VALUES_INTERSECTING_FIELD_NUMBER: _ClassVar[int]
    REQUEST_DISASSEMBLE_FIELD_NUMBER: _ClassVar[int]
    REPLY_DISASSEMBLE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ACTIVATE_FIELD_NUMBER: _ClassVar[int]
    REPLY_ACTIVATE_FIELD_NUMBER: _ClassVar[int]
    REQUEST_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    REPLY_SNAPSHOT_FIELD_NUMBER: _ClassVar[int]
    XREQUEST_INVOKE_METHOD_FIELD_NUMBER: _ClassVar[int]
    XREPLY_INVOKE_METHOD_FIELD_NUMBER: _ClassVar[int]
    error: ReplyError
    request_negotiate: RequestNegotiate
    reply_negotiate: ReplyNegotiate
    request_create_trace: RequestCreateTrace
    reply_create_trace: ReplyCreateTrace
    request_save_trace: RequestSaveTrace
    reply_save_trace: ReplySaveTrace
    request_close_trace: RequestCloseTrace
    reply_close_trace: ReplyCloseTrace
    request_start_tx: RequestStartTx
    reply_start_tx: ReplyStartTx
    request_end_tx: RequestEndTx
    reply_end_tx: ReplyEndTx
    request_create_overlay: RequestCreateOverlaySpace
    reply_create_overlay: ReplyCreateOverlaySpace
    request_set_memory_state: RequestSetMemoryState
    reply_set_memory_state: ReplySetMemoryState
    request_put_bytes: RequestPutBytes
    reply_put_bytes: ReplyPutBytes
    request_delete_bytes: RequestDeleteBytes
    reply_delete_bytes: ReplyDeleteBytes
    request_put_register_value: RequestPutRegisterValue
    reply_put_register_value: ReplyPutRegisterValue
    request_delete_register_value: RequestDeleteRegisterValue
    reply_delete_register_value: ReplyDeleteRegisterValue
    request_create_root_object: RequestCreateRootObject
    request_create_object: RequestCreateObject
    reply_create_object: ReplyCreateObject
    request_insert_object: RequestInsertObject
    reply_insert_object: ReplyInsertObject
    request_remove_object: RequestRemoveObject
    reply_remove_object: ReplyRemoveObject
    request_set_value: RequestSetValue
    reply_set_value: ReplySetValue
    request_retain_values: RequestRetainValues
    reply_retain_values: ReplyRetainValues
    request_get_object: RequestGetObject
    reply_get_object: ReplyGetObject
    request_get_values: RequestGetValues
    reply_get_values: ReplyGetValues
    request_get_values_intersecting: RequestGetValuesIntersecting
    request_disassemble: RequestDisassemble
    reply_disassemble: ReplyDisassemble
    request_activate: RequestActivate
    reply_activate: ReplyActivate
    request_snapshot: RequestSnapshot
    reply_snapshot: ReplySnapshot
    xrequest_invoke_method: XRequestInvokeMethod
    xreply_invoke_method: XReplyInvokeMethod
    def __init__(self, error: _Optional[_Union[ReplyError, _Mapping]] = ..., request_negotiate: _Optional[_Union[RequestNegotiate, _Mapping]] = ..., reply_negotiate: _Optional[_Union[ReplyNegotiate, _Mapping]] = ..., request_create_trace: _Optional[_Union[RequestCreateTrace, _Mapping]] = ..., reply_create_trace: _Optional[_Union[ReplyCreateTrace, _Mapping]] = ..., request_save_trace: _Optional[_Union[RequestSaveTrace, _Mapping]] = ..., reply_save_trace: _Optional[_Union[ReplySaveTrace, _Mapping]] = ..., request_close_trace: _Optional[_Union[RequestCloseTrace, _Mapping]] = ..., reply_close_trace: _Optional[_Union[ReplyCloseTrace, _Mapping]] = ..., request_start_tx: _Optional[_Union[RequestStartTx, _Mapping]] = ..., reply_start_tx: _Optional[_Union[ReplyStartTx, _Mapping]] = ..., request_end_tx: _Optional[_Union[RequestEndTx, _Mapping]] = ..., reply_end_tx: _Optional[_Union[ReplyEndTx, _Mapping]] = ..., request_create_overlay: _Optional[_Union[RequestCreateOverlaySpace, _Mapping]] = ..., reply_create_overlay: _Optional[_Union[ReplyCreateOverlaySpace, _Mapping]] = ..., request_set_memory_state: _Optional[_Union[RequestSetMemoryState, _Mapping]] = ..., reply_set_memory_state: _Optional[_Union[ReplySetMemoryState, _Mapping]] = ..., request_put_bytes: _Optional[_Union[RequestPutBytes, _Mapping]] = ..., reply_put_bytes: _Optional[_Union[ReplyPutBytes, _Mapping]] = ..., request_delete_bytes: _Optional[_Union[RequestDeleteBytes, _Mapping]] = ..., reply_delete_bytes: _Optional[_Union[ReplyDeleteBytes, _Mapping]] = ..., request_put_register_value: _Optional[_Union[RequestPutRegisterValue, _Mapping]] = ..., reply_put_register_value: _Optional[_Union[ReplyPutRegisterValue, _Mapping]] = ..., request_delete_register_value: _Optional[_Union[RequestDeleteRegisterValue, _Mapping]] = ..., reply_delete_register_value: _Optional[_Union[ReplyDeleteRegisterValue, _Mapping]] = ..., request_create_root_object: _Optional[_Union[RequestCreateRootObject, _Mapping]] = ..., request_create_object: _Optional[_Union[RequestCreateObject, _Mapping]] = ..., reply_create_object: _Optional[_Union[ReplyCreateObject, _Mapping]] = ..., request_insert_object: _Optional[_Union[RequestInsertObject, _Mapping]] = ..., reply_insert_object: _Optional[_Union[ReplyInsertObject, _Mapping]] = ..., request_remove_object: _Optional[_Union[RequestRemoveObject, _Mapping]] = ..., reply_remove_object: _Optional[_Union[ReplyRemoveObject, _Mapping]] = ..., request_set_value: _Optional[_Union[RequestSetValue, _Mapping]] = ..., reply_set_value: _Optional[_Union[ReplySetValue, _Mapping]] = ..., request_retain_values: _Optional[_Union[RequestRetainValues, _Mapping]] = ..., reply_retain_values: _Optional[_Union[ReplyRetainValues, _Mapping]] = ..., request_get_object: _Optional[_Union[RequestGetObject, _Mapping]] = ..., reply_get_object: _Optional[_Union[ReplyGetObject, _Mapping]] = ..., request_get_values: _Optional[_Union[RequestGetValues, _Mapping]] = ..., reply_get_values: _Optional[_Union[ReplyGetValues, _Mapping]] = ..., request_get_values_intersecting: _Optional[_Union[RequestGetValuesIntersecting, _Mapping]] = ..., request_disassemble: _Optional[_Union[RequestDisassemble, _Mapping]] = ..., reply_disassemble: _Optional[_Union[ReplyDisassemble, _Mapping]] = ..., request_activate: _Optional[_Union[RequestActivate, _Mapping]] = ..., reply_activate: _Optional[_Union[ReplyActivate, _Mapping]] = ..., request_snapshot: _Optional[_Union[RequestSnapshot, _Mapping]] = ..., reply_snapshot: _Optional[_Union[ReplySnapshot, _Mapping]] = ..., xrequest_invoke_method: _Optional[_Union[XRequestInvokeMethod, _Mapping]] = ..., xreply_invoke_method: _Optional[_Union[XReplyInvokeMethod, _Mapping]] = ...) -> None: ...
