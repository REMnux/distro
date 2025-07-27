from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.database.symbol
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.scalar
import ghidra.program.model.symbol
import ghidra.xml
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import org.xml.sax # type: ignore


T = typing.TypeVar("T")


class PcodeOverride(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getCallFixup(self, callDestAddr: ghidra.program.model.address.Address) -> ghidra.program.model.lang.InjectPayload:
        """
        Returns the call-fixup for a specified call destination.
        If the destination function has not be tagged or was tagged 
        with an unknown CallFixup name this method will return null.
        
        :param ghidra.program.model.address.Address callDestAddr: call destination address.  This address is used to 
        identify a function which may have been tagged with a CallFixup.
        :return: call fixup object or null
        :rtype: ghidra.program.model.lang.InjectPayload
        """

    def getFallThroughOverride(self) -> ghidra.program.model.address.Address:
        """
        Get the fall-through override address which may have been 
        applied to the current instruction.
        
        :return: fall-through override address or null
        :rtype: ghidra.program.model.address.Address
        """

    def getFlowOverride(self) -> ghidra.program.model.listing.FlowOverride:
        """
        Get the flow override which may have been applied
        to the current instruction.
        
        :return: flow override or null
        :rtype: ghidra.program.model.listing.FlowOverride
        """

    def getInstructionStart(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: current instruction address
        :rtype: ghidra.program.model.address.Address
        """

    def getOverridingReference(self, type: ghidra.program.model.symbol.RefType) -> ghidra.program.model.address.Address:
        """
        Get the primary overriding reference address of :obj:`RefType` ``type`` from 
        the current instruction
        
        :param ghidra.program.model.symbol.RefType type: type of reference
        :return: call reference address or null
        :rtype: ghidra.program.model.address.Address
        """

    def getPrimaryCallReference(self) -> ghidra.program.model.address.Address:
        """
        Get the primary call reference address from the current instruction
        
        :return: call reference address or null
        :rtype: ghidra.program.model.address.Address
        """

    def hasCallFixup(self, callDestAddr: ghidra.program.model.address.Address) -> bool:
        """
        Returns the call-fixup for a specified call destination.
        
        :param ghidra.program.model.address.Address callDestAddr: call destination address.  This address is used to 
        identify a function which may have been tagged with a CallFixup.
        :return: true if call destination function has been tagged with a call-fixup
        :rtype: bool
        """

    def hasPotentialOverride(self) -> bool:
        """
        Returns a boolean indicating whether there are any primary overriding references at the current 
        instruction
        
        :return: are there primary overriding references
        :rtype: bool
        """

    def isCallOtherCallOverrideRefApplied(self) -> bool:
        """
        Returns a boolean indicating whether a callother call override has been applied at the current
        instruction
        
        :return: has callother call override been applied
        :rtype: bool
        """

    def isCallOtherJumpOverrideApplied(self) -> bool:
        """
        Returns a boolean indicating whether a callother jump override has been applied at the current
        instruction
        
        :return: has callother jump override been applied
        :rtype: bool
        """

    def isCallOverrideRefApplied(self) -> bool:
        """
        Returns a boolean indicating whether a call override has been applied at the current instruction
        
        :return: has call override been applied
        :rtype: bool
        """

    def isJumpOverrideRefApplied(self) -> bool:
        """
        Returns a boolean indicating whether a jump override has been applied at the current instruction
        
        :return: has jump override been applied
        :rtype: bool
        """

    def setCallOtherCallOverrideRefApplied(self):
        """
        Register that a callother call override has been applied at the current instruction
        """

    def setCallOtherJumpOverrideRefApplied(self):
        """
        Register that a callother jump override has been applied at the current instruction
        """

    def setCallOverrideRefApplied(self):
        """
        Register that a call override has been applied at the current instruction.
        """

    def setJumpOverrideRefApplied(self):
        """
        Register that a jump override has been applied at the current instruction
        """

    @property
    def fallThroughOverride(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def callOverrideRefApplied(self) -> jpype.JBoolean:
        ...

    @property
    def callOtherCallOverrideRefApplied(self) -> jpype.JBoolean:
        ...

    @property
    def callFixup(self) -> ghidra.program.model.lang.InjectPayload:
        ...

    @property
    def instructionStart(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def flowOverride(self) -> ghidra.program.model.listing.FlowOverride:
        ...

    @property
    def jumpOverrideRefApplied(self) -> jpype.JBoolean:
        ...

    @property
    def callOtherJumpOverrideApplied(self) -> jpype.JBoolean:
        ...

    @property
    def overridingReference(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def primaryCallReference(self) -> ghidra.program.model.address.Address:
        ...


class ElementId(java.lang.Record):
    """
    An annotation for a specific collection of hierarchical data
    
    This record parallels the XML concept of an element.  An ElementId describes a collection of data, where each
    piece is annotated by a specific AttributeId.  In addition, each ElementId can contain zero or more child
    ElementId objects, forming a hierarchy of annotated data.  Each ElementId has a name, which is unique at least
    within the context of its parent ElementId. Internally this name is associated with an integer id. A special
    AttributeId ATTRIB_CONTENT is used to label the XML element's text content, which is traditionally not labeled
    as an attribute.
    """

    class_: typing.ClassVar[java.lang.Class]
    ELEM_DATA: typing.Final[ElementId]
    ELEM_INPUT: typing.Final[ElementId]
    ELEM_OFF: typing.Final[ElementId]
    ELEM_OUTPUT: typing.Final[ElementId]
    ELEM_RETURNADDRESS: typing.Final[ElementId]
    ELEM_SYMBOL: typing.Final[ElementId]
    ELEM_TARGET: typing.Final[ElementId]
    ELEM_VAL: typing.Final[ElementId]
    ELEM_VALUE: typing.Final[ElementId]
    ELEM_VOID: typing.Final[ElementId]
    ELEM_ADDR: typing.Final[ElementId]
    ELEM_RANGE: typing.Final[ElementId]
    ELEM_RANGELIST: typing.Final[ElementId]
    ELEM_REGISTER: typing.Final[ElementId]
    ELEM_SEQNUM: typing.Final[ElementId]
    ELEM_VARNODE: typing.Final[ElementId]
    ELEM_BREAK: typing.Final[ElementId]
    ELEM_CLANG_DOCUMENT: typing.Final[ElementId]
    ELEM_FUNCNAME: typing.Final[ElementId]
    ELEM_FUNCPROTO: typing.Final[ElementId]
    ELEM_LABEL: typing.Final[ElementId]
    ELEM_RETURN_TYPE: typing.Final[ElementId]
    ELEM_STATEMENT: typing.Final[ElementId]
    ELEM_SYNTAX: typing.Final[ElementId]
    ELEM_VARDECL: typing.Final[ElementId]
    ELEM_VARIABLE: typing.Final[ElementId]
    ELEM_OP: typing.Final[ElementId]
    ELEM_SLEIGH: typing.Final[ElementId]
    ELEM_SPACE: typing.Final[ElementId]
    ELEM_SPACEID: typing.Final[ElementId]
    ELEM_SPACES: typing.Final[ElementId]
    ELEM_SPACE_BASE: typing.Final[ElementId]
    ELEM_SPACE_OTHER: typing.Final[ElementId]
    ELEM_SPACE_OVERLAY: typing.Final[ElementId]
    ELEM_SPACE_UNIQUE: typing.Final[ElementId]
    ELEM_TRUNCATE_SPACE: typing.Final[ElementId]
    ELEM_ABSOLUTE_MAX_ALIGNMENT: typing.Final[ElementId]
    ELEM_BITFIELD_PACKING: typing.Final[ElementId]
    ELEM_CHAR_SIZE: typing.Final[ElementId]
    ELEM_CHAR_TYPE: typing.Final[ElementId]
    ELEM_CORETYPES: typing.Final[ElementId]
    ELEM_DATA_ORGANIZATION: typing.Final[ElementId]
    ELEM_DEF: typing.Final[ElementId]
    ELEM_DEFAULT_ALIGNMENT: typing.Final[ElementId]
    ELEM_DEFAULT_POINTER_ALIGNMENT: typing.Final[ElementId]
    ELEM_DOUBLE_SIZE: typing.Final[ElementId]
    ELEM_ENTRY: typing.Final[ElementId]
    ELEM_ENUM: typing.Final[ElementId]
    ELEM_FIELD: typing.Final[ElementId]
    ELEM_FLOAT_SIZE: typing.Final[ElementId]
    ELEM_INTEGER_SIZE: typing.Final[ElementId]
    ELEM_LONG_DOUBLE_SIZE: typing.Final[ElementId]
    ELEM_LONG_LONG_SIZE: typing.Final[ElementId]
    ELEM_LONG_SIZE: typing.Final[ElementId]
    ELEM_MACHINE_ALIGNMENT: typing.Final[ElementId]
    ELEM_POINTER_SHIFT: typing.Final[ElementId]
    ELEM_POINTER_SIZE: typing.Final[ElementId]
    ELEM_SHORT_SIZE: typing.Final[ElementId]
    ELEM_SIZE_ALIGNMENT_MAP: typing.Final[ElementId]
    ELEM_TYPE: typing.Final[ElementId]
    ELEM_TYPE_ALIGNMENT_ENABLED: typing.Final[ElementId]
    ELEM_TYPEGRP: typing.Final[ElementId]
    ELEM_TYPEREF: typing.Final[ElementId]
    ELEM_USE_MS_CONVENTION: typing.Final[ElementId]
    ELEM_WCHAR_SIZE: typing.Final[ElementId]
    ELEM_ZERO_LENGTH_BOUNDARY: typing.Final[ElementId]
    ELEM_COLLISION: typing.Final[ElementId]
    ELEM_DB: typing.Final[ElementId]
    ELEM_EQUATESYMBOL: typing.Final[ElementId]
    ELEM_EXTERNREFSYMBOL: typing.Final[ElementId]
    ELEM_FACETSYMBOL: typing.Final[ElementId]
    ELEM_FUNCTIONSHELL: typing.Final[ElementId]
    ELEM_HASH: typing.Final[ElementId]
    ELEM_HOLE: typing.Final[ElementId]
    ELEM_LABELSYM: typing.Final[ElementId]
    ELEM_MAPSYM: typing.Final[ElementId]
    ELEM_PARENT: typing.Final[ElementId]
    ELEM_PROPERTY_CHANGEPOINT: typing.Final[ElementId]
    ELEM_RANGEEQUALSSYMBOLS: typing.Final[ElementId]
    ELEM_SCOPE: typing.Final[ElementId]
    ELEM_SYMBOLLIST: typing.Final[ElementId]
    ELEM_HIGH: typing.Final[ElementId]
    ELEM_BYTES: typing.Final[ElementId]
    ELEM_STRING: typing.Final[ElementId]
    ELEM_STRINGMANAGE: typing.Final[ElementId]
    ELEM_COMMENT: typing.Final[ElementId]
    ELEM_COMMENTDB: typing.Final[ElementId]
    ELEM_TEXT: typing.Final[ElementId]
    ELEM_ADDR_PCODE: typing.Final[ElementId]
    ELEM_BODY: typing.Final[ElementId]
    ELEM_CALLFIXUP: typing.Final[ElementId]
    ELEM_CALLOTHERFIXUP: typing.Final[ElementId]
    ELEM_CASE_PCODE: typing.Final[ElementId]
    ELEM_CONTEXT: typing.Final[ElementId]
    ELEM_DEFAULT_PCODE: typing.Final[ElementId]
    ELEM_INJECT: typing.Final[ElementId]
    ELEM_INJECTDEBUG: typing.Final[ElementId]
    ELEM_INST: typing.Final[ElementId]
    ELEM_PAYLOAD: typing.Final[ElementId]
    ELEM_PCODE: typing.Final[ElementId]
    ELEM_SIZE_PCODE: typing.Final[ElementId]
    ELEM_BHEAD: typing.Final[ElementId]
    ELEM_BLOCK: typing.Final[ElementId]
    ELEM_BLOCKEDGE: typing.Final[ElementId]
    ELEM_EDGE: typing.Final[ElementId]
    ELEM_PARAMMEASURES: typing.Final[ElementId]
    ELEM_PROTO: typing.Final[ElementId]
    ELEM_RANK: typing.Final[ElementId]
    ELEM_CONSTANTPOOL: typing.Final[ElementId]
    ELEM_CPOOLREC: typing.Final[ElementId]
    ELEM_REF: typing.Final[ElementId]
    ELEM_TOKEN: typing.Final[ElementId]
    ELEM_IOP: typing.Final[ElementId]
    ELEM_UNIMPL: typing.Final[ElementId]
    ELEM_AST: typing.Final[ElementId]
    ELEM_FUNCTION: typing.Final[ElementId]
    ELEM_HIGHLIST: typing.Final[ElementId]
    ELEM_JUMPTABLELIST: typing.Final[ElementId]
    ELEM_VARNODES: typing.Final[ElementId]
    ELEM_CONTEXT_DATA: typing.Final[ElementId]
    ELEM_CONTEXT_POINTS: typing.Final[ElementId]
    ELEM_CONTEXT_POINTSET: typing.Final[ElementId]
    ELEM_CONTEXT_SET: typing.Final[ElementId]
    ELEM_SET: typing.Final[ElementId]
    ELEM_TRACKED_POINTSET: typing.Final[ElementId]
    ELEM_TRACKED_SET: typing.Final[ElementId]
    ELEM_CONSTRESOLVE: typing.Final[ElementId]
    ELEM_JUMPASSIST: typing.Final[ElementId]
    ELEM_SEGMENTOP: typing.Final[ElementId]
    ELEM_ADDRESS_SHIFT_AMOUNT: typing.Final[ElementId]
    ELEM_AGGRESSIVETRIM: typing.Final[ElementId]
    ELEM_COMPILER_SPEC: typing.Final[ElementId]
    ELEM_DATA_SPACE: typing.Final[ElementId]
    ELEM_DEFAULT_MEMORY_BLOCKS: typing.Final[ElementId]
    ELEM_DEFAULT_PROTO: typing.Final[ElementId]
    ELEM_DEFAULT_SYMBOLS: typing.Final[ElementId]
    ELEM_EVAL_CALLED_PROTOTYPE: typing.Final[ElementId]
    ELEM_EVAL_CURRENT_PROTOTYPE: typing.Final[ElementId]
    ELEM_EXPERIMENTAL_RULES: typing.Final[ElementId]
    ELEM_FLOWOVERRIDELIST: typing.Final[ElementId]
    ELEM_FUNCPTR: typing.Final[ElementId]
    ELEM_GLOBAL: typing.Final[ElementId]
    ELEM_INCIDENTALCOPY: typing.Final[ElementId]
    ELEM_INFERPTRBOUNDS: typing.Final[ElementId]
    ELEM_MODELALIAS: typing.Final[ElementId]
    ELEM_NOHIGHPTR: typing.Final[ElementId]
    ELEM_PROCESSOR_SPEC: typing.Final[ElementId]
    ELEM_PROGRAMCOUNTER: typing.Final[ElementId]
    ELEM_PROPERTIES: typing.Final[ElementId]
    ELEM_PROPERTY: typing.Final[ElementId]
    ELEM_READONLY: typing.Final[ElementId]
    ELEM_REGISTER_DATA: typing.Final[ElementId]
    ELEM_RULE: typing.Final[ElementId]
    ELEM_SAVE_STATE: typing.Final[ElementId]
    ELEM_SEGMENTED_ADDRESS: typing.Final[ElementId]
    ELEM_SPACEBASE: typing.Final[ElementId]
    ELEM_SPECEXTENSIONS: typing.Final[ElementId]
    ELEM_STACKPOINTER: typing.Final[ElementId]
    ELEM_VOLATILE: typing.Final[ElementId]
    ELEM_GROUP: typing.Final[ElementId]
    ELEM_INTERNALLIST: typing.Final[ElementId]
    ELEM_KILLEDBYCALL: typing.Final[ElementId]
    ELEM_LIKELYTRASH: typing.Final[ElementId]
    ELEM_LOCALRANGE: typing.Final[ElementId]
    ELEM_MODEL: typing.Final[ElementId]
    ELEM_PARAM: typing.Final[ElementId]
    ELEM_PARAMRANGE: typing.Final[ElementId]
    ELEM_PENTRY: typing.Final[ElementId]
    ELEM_PROTOTYPE: typing.Final[ElementId]
    ELEM_RESOLVEPROTOTYPE: typing.Final[ElementId]
    ELEM_RETPARAM: typing.Final[ElementId]
    ELEM_RETURNSYM: typing.Final[ElementId]
    ELEM_UNAFFECTED: typing.Final[ElementId]
    ELEM_INTERNAL_STORAGE: typing.Final[ElementId]
    ELEM_ALIASBLOCK: typing.Final[ElementId]
    ELEM_ALLOWCONTEXTSET: typing.Final[ElementId]
    ELEM_ANALYZEFORLOOPS: typing.Final[ElementId]
    ELEM_COMMENTHEADER: typing.Final[ElementId]
    ELEM_COMMENTINDENT: typing.Final[ElementId]
    ELEM_COMMENTINSTRUCTION: typing.Final[ElementId]
    ELEM_COMMENTSTYLE: typing.Final[ElementId]
    ELEM_CONVENTIONPRINTING: typing.Final[ElementId]
    ELEM_CURRENTACTION: typing.Final[ElementId]
    ELEM_DEFAULTPROTOTYPE: typing.Final[ElementId]
    ELEM_ERRORREINTERPRETED: typing.Final[ElementId]
    ELEM_ERRORTOOMANYINSTRUCTIONS: typing.Final[ElementId]
    ELEM_ERRORUNIMPLEMENTED: typing.Final[ElementId]
    ELEM_EXTRAPOP: typing.Final[ElementId]
    ELEM_IGNOREUNIMPLEMENTED: typing.Final[ElementId]
    ELEM_INDENTINCREMENT: typing.Final[ElementId]
    ELEM_INFERCONSTPTR: typing.Final[ElementId]
    ELEM_INLINE: typing.Final[ElementId]
    ELEM_INPLACEOPS: typing.Final[ElementId]
    ELEM_INTEGERFORMAT: typing.Final[ElementId]
    ELEM_JUMPLOAD: typing.Final[ElementId]
    ELEM_MAXINSTRUCTION: typing.Final[ElementId]
    ELEM_MAXLINEWIDTH: typing.Final[ElementId]
    ELEM_NAMESPACESTRATEGY: typing.Final[ElementId]
    ELEM_NOCASTPRINTING: typing.Final[ElementId]
    ELEM_NORETURN: typing.Final[ElementId]
    ELEM_NULLPRINTING: typing.Final[ElementId]
    ELEM_OPTIONSLIST: typing.Final[ElementId]
    ELEM_PARAM1: typing.Final[ElementId]
    ELEM_PARAM2: typing.Final[ElementId]
    ELEM_PARAM3: typing.Final[ElementId]
    ELEM_PROTOEVAL: typing.Final[ElementId]
    ELEM_SETACTION: typing.Final[ElementId]
    ELEM_SETLANGUAGE: typing.Final[ElementId]
    ELEM_STRUCTALIGN: typing.Final[ElementId]
    ELEM_TOGGLERULE: typing.Final[ElementId]
    ELEM_WARNING: typing.Final[ElementId]
    ELEM_BRACEFORMAT: typing.Final[ElementId]
    ELEM_BASICOVERRIDE: typing.Final[ElementId]
    ELEM_DEST: typing.Final[ElementId]
    ELEM_JUMPTABLE: typing.Final[ElementId]
    ELEM_LOADTABLE: typing.Final[ElementId]
    ELEM_NORMADDR: typing.Final[ElementId]
    ELEM_NORMHASH: typing.Final[ElementId]
    ELEM_STARTVAL: typing.Final[ElementId]
    ELEM_DEADCODEDELAY: typing.Final[ElementId]
    ELEM_FLOW: typing.Final[ElementId]
    ELEM_FORCEGOTO: typing.Final[ElementId]
    ELEM_INDIRECTOVERRIDE: typing.Final[ElementId]
    ELEM_MULTISTAGEJUMP: typing.Final[ElementId]
    ELEM_OVERRIDE: typing.Final[ElementId]
    ELEM_PROTOOVERRIDE: typing.Final[ElementId]
    ELEM_PREFERSPLIT: typing.Final[ElementId]
    ELEM_CALLGRAPH: typing.Final[ElementId]
    ELEM_NODE: typing.Final[ElementId]
    ELEM_LOCALDB: typing.Final[ElementId]
    ELEM_DOC: typing.Final[ElementId]
    COMMAND_ISNAMEUSED: typing.Final = 239
    ELEM_COMMAND_ISNAMEUSED: typing.Final[ElementId]
    COMMAND_GETBYTES: typing.Final = 240
    ELEM_COMMAND_GETBYTES: typing.Final[ElementId]
    COMMAND_GETCALLFIXUP: typing.Final = 241
    ELEM_COMMAND_GETCALLFIXUP: typing.Final[ElementId]
    COMMAND_GETCALLMECH: typing.Final = 242
    ELEM_COMMAND_GETCALLMECH: typing.Final[ElementId]
    COMMAND_GETCALLOTHERFIXUP: typing.Final = 243
    ELEM_COMMAND_GETCALLOTHERFIXUP: typing.Final[ElementId]
    COMMAND_GETCODELABEL: typing.Final = 244
    ELEM_COMMAND_GETCODELABEL: typing.Final[ElementId]
    COMMAND_GETCOMMENTS: typing.Final = 245
    ELEM_COMMAND_GETCOMMENTS: typing.Final[ElementId]
    COMMAND_GETCPOOLREF: typing.Final = 246
    ELEM_COMMAND_GETCPOOLREF: typing.Final[ElementId]
    COMMAND_GETDATATYPE: typing.Final = 247
    ELEM_COMMAND_GETDATATYPE: typing.Final[ElementId]
    COMMAND_GETEXTERNALREF: typing.Final = 248
    ELEM_COMMAND_GETEXTERNALREF: typing.Final[ElementId]
    COMMAND_GETMAPPEDSYMBOLS: typing.Final = 249
    ELEM_COMMAND_GETMAPPEDSYMBOLS: typing.Final[ElementId]
    COMMAND_GETNAMESPACEPATH: typing.Final = 250
    ELEM_COMMAND_GETNAMESPACEPATH: typing.Final[ElementId]
    COMMAND_GETPCODE: typing.Final = 251
    ELEM_COMMAND_GETPCODE: typing.Final[ElementId]
    COMMAND_GETPCODEEXECUTABLE: typing.Final = 252
    ELEM_COMMAND_GETPCODEEXECUTABLE: typing.Final[ElementId]
    COMMAND_GETREGISTER: typing.Final = 253
    ELEM_COMMAND_GETREGISTER: typing.Final[ElementId]
    COMMAND_GETREGISTERNAME: typing.Final = 254
    ELEM_COMMAND_GETREGISTERNAME: typing.Final[ElementId]
    COMMAND_GETSTRINGDATA: typing.Final = 255
    ELEM_COMMAND_GETSTRINGDATA: typing.Final[ElementId]
    COMMAND_GETTRACKEDREGISTERS: typing.Final = 256
    ELEM_COMMAND_GETTRACKEDREGISTERS: typing.Final[ElementId]
    COMMAND_GETUSEROPNAME: typing.Final = 257
    ELEM_COMMAND_GETUSEROPNAME: typing.Final[ElementId]
    ELEM_BLOCKSIG: typing.Final[ElementId]
    ELEM_CALL: typing.Final[ElementId]
    ELEM_GENSIG: typing.Final[ElementId]
    ELEM_MAJOR: typing.Final[ElementId]
    ELEM_MINOR: typing.Final[ElementId]
    ELEM_COPYSIG: typing.Final[ElementId]
    ELEM_SETTINGS: typing.Final[ElementId]
    ELEM_SIG: typing.Final[ElementId]
    ELEM_SIGNATUREDESC: typing.Final[ElementId]
    ELEM_SIGNATURES: typing.Final[ElementId]
    ELEM_SIGSETTINGS: typing.Final[ElementId]
    ELEM_VARSIG: typing.Final[ElementId]
    ELEM_SPLITDATATYPE: typing.Final[ElementId]
    ELEM_JUMPTABLEMAX: typing.Final[ElementId]
    ELEM_NANIGNORE: typing.Final[ElementId]
    ELEM_DATATYPE: typing.Final[ElementId]
    ELEM_CONSUME: typing.Final[ElementId]
    ELEM_CONSUME_EXTRA: typing.Final[ElementId]
    ELEM_CONVERT_TO_PTR: typing.Final[ElementId]
    ELEM_GOTO_STACK: typing.Final[ElementId]
    ELEM_JOIN: typing.Final[ElementId]
    ELEM_DATATYPE_AT: typing.Final[ElementId]
    ELEM_POSITION: typing.Final[ElementId]
    ELEM_VARARGS: typing.Final[ElementId]
    ELEM_HIDDEN_RETURN: typing.Final[ElementId]
    ELEM_JOIN_PER_PRIMITIVE: typing.Final[ElementId]
    ELEM_JOIN_DUAL_CLASS: typing.Final[ElementId]
    ELEM_EXTRA_STACK: typing.Final[ElementId]
    ELEM_UNKNOWN: typing.Final[ElementId]

    def __init__(self, name: typing.Union[java.lang.String, str], id: typing.Union[jpype.JInt, int]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def id(self) -> int:
        ...

    def name(self) -> str:
        ...

    def toString(self) -> str:
        ...


class PcodeFactory(java.lang.Object):
    """
    Interface for classes that build PcodeOps and Varnodes
    """

    class_: typing.ClassVar[java.lang.Class]

    def buildStorage(self, vn: Varnode) -> ghidra.program.model.listing.VariableStorage:
        """
        Build a storage object for a particular Varnode
        
        :param Varnode vn: is the Varnode
        :return: the storage object
        :rtype: ghidra.program.model.listing.VariableStorage
        :raises InvalidInputException: if valid storage cannot be created
        """

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        """
        
        
        :return: Address factory
        :rtype: ghidra.program.model.address.AddressFactory
        """

    def getDataTypeManager(self) -> PcodeDataTypeManager:
        """
        
        
        :return: pcode data type manager used to convert strings to Ghidra data types
        :rtype: PcodeDataTypeManager
        """

    def getJoinAddress(self, storage: ghidra.program.model.listing.VariableStorage) -> ghidra.program.model.address.Address:
        """
        Get the address (in the "join" space) corresponding to the given multi-piece storage.
        The storage must have been previously registered by a previous call to getJoinStorage().
        If the storage is not multi-piece or was not registered, null is returned.
        
        :param ghidra.program.model.listing.VariableStorage storage: is the multi-piece storage
        :return: the corresponding "join" address
        :rtype: ghidra.program.model.address.Address
        """

    def getJoinStorage(self, pieces: jpype.JArray[Varnode]) -> ghidra.program.model.listing.VariableStorage:
        """
        Create a storage object representing a value split across multiple physical locations.
        The sequence of physical locations are passed in as an array of Varnodes and the storage
        object is returned.  The storage is also assigned an Address in the join address space,
        which can be retrieved by calling the getJoinAddress() method.  The join Address can
        be used to create a Varnode that represents the logical whole created by concatenating
        the Varnode pieces.
        
        :param jpype.JArray[Varnode] pieces: is the array of Varnode pieces to join
        :return: the VariableStorage representing the whole
        :rtype: ghidra.program.model.listing.VariableStorage
        :raises InvalidInputException: if a valid storage object cannot be created
        """

    def getOpRef(self, refid: typing.Union[jpype.JInt, int]) -> PcodeOp:
        """
        Get a PcodeOp given a reference id.  The reference id corresponds to the op's
        SequenceNumber.getTime() field.  Return null if no op matching the id has been registered
        via newOp().
        
        :param jpype.JInt or int refid: is the reference id
        :return: the matching PcodeOp or null
        :rtype: PcodeOp
        """

    def getRef(self, refid: typing.Union[jpype.JInt, int]) -> Varnode:
        """
        Return a Varnode given its reference id, or null if the id is not registered.
        The id must have previously been registered via newVarnode().
        
        :param jpype.JInt or int refid: is the reference id
        :return: the matching Varnode or null
        :rtype: Varnode
        """

    def getSymbol(self, symbolId: typing.Union[jpype.JLong, int]) -> HighSymbol:
        """
        Get the high symbol matching the given id that has been registered with this object
        
        :param jpype.JLong or int symbolId: is the given id
        :return: the matching HighSymbol or null
        :rtype: HighSymbol
        """

    def newOp(self, sq: SequenceNumber, opc: typing.Union[jpype.JInt, int], inputs: java.util.ArrayList[Varnode], output: Varnode) -> PcodeOp:
        """
        Create a new PcodeOp given its opcode, sequence number, and input and output Varnodes
        
        :param SequenceNumber sq: is the sequence number
        :param jpype.JInt or int opc: is the opcode
        :param java.util.ArrayList[Varnode] inputs: is the array of input Varnodes, which may be empty
        :param Varnode output: is the output Varnode, which may be null
        :return: the new PcodeOp
        :rtype: PcodeOp
        """

    @typing.overload
    def newVarnode(self, sz: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address) -> Varnode:
        """
        Create a new Varnode with the given size and location
        
        :param jpype.JInt or int sz: size of the Varnode
        :param ghidra.program.model.address.Address addr: location of the Varnode
        :return: a new varnode
        :rtype: Varnode
        """

    @typing.overload
    def newVarnode(self, sz: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address, refId: typing.Union[jpype.JInt, int]) -> Varnode:
        """
        Create a new Varnode with the given size and location.
        Associate the Varnode with a specific reference id so that it can be retrieved,
        using just the id, via getRef();
        
        :param jpype.JInt or int sz: size of the Varnode
        :param ghidra.program.model.address.Address addr: location of the Varnode
        :param jpype.JInt or int refId: is the specific reference id
        :return: the new Varnode
        :rtype: Varnode
        """

    def setAddrTied(self, vn: Varnode, val: typing.Union[jpype.JBoolean, bool]):
        """
        Mark (or unmark) the given Varnode with the "address tied" property
        
        :param Varnode vn: is the given Varnode
        :param jpype.JBoolean or bool val: is true if the Varnode should be marked
        """

    def setDataType(self, vn: Varnode, type: ghidra.program.model.data.DataType):
        """
        Attach a data-type to the given Varnode
        
        :param Varnode vn: is the given Varnode
        :param ghidra.program.model.data.DataType type: is the data-type
        """

    def setInput(self, vn: Varnode, val: typing.Union[jpype.JBoolean, bool]) -> Varnode:
        """
        Mark (or unmark) the given Varnode as an input (to its function)
        
        :param Varnode vn: is the given Varnode
        :param jpype.JBoolean or bool val: is true if the Varnode should be marked
        :return: the altered Varnode, which may not be the same object passed in
        :rtype: Varnode
        """

    def setMergeGroup(self, vn: Varnode, val: typing.Union[jpype.JShort, int]):
        """
        Associate a specific merge group with the given Varnode
        
        :param Varnode vn: is the given Varnode
        :param jpype.JShort or int val: is the merge group
        """

    def setPersistent(self, vn: Varnode, val: typing.Union[jpype.JBoolean, bool]):
        """
        Mark (or unmark) the given Varnode with the "persistent" property
        
        :param Varnode vn: is the given Varnode
        :param jpype.JBoolean or bool val: is true if the Varnode should be marked
        """

    def setUnaffected(self, vn: Varnode, val: typing.Union[jpype.JBoolean, bool]):
        """
        Mark (or unmark) the given Varnode with the "unaffected" property
        
        :param Varnode vn: is the given Varnode
        :param jpype.JBoolean or bool val: is true if the Varnode should be marked
        """

    def setVolatile(self, vn: Varnode, val: typing.Union[jpype.JBoolean, bool]):
        """
        Mark (or unmark) the given Varnode with the "volatile" property
        
        :param Varnode vn: is the given Varnode
        :param jpype.JBoolean or bool val: is true if the Varnode should be marked volatile
        """

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    @property
    def symbol(self) -> HighSymbol:
        ...

    @property
    def ref(self) -> Varnode:
        ...

    @property
    def opRef(self) -> PcodeOp:
        ...

    @property
    def joinStorage(self) -> ghidra.program.model.listing.VariableStorage:
        ...

    @property
    def joinAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def dataTypeManager(self) -> PcodeDataTypeManager:
        ...


class Decoder(ByteIngest):
    """
    An interface for reading structured data from a stream
    
    All data is loosely structured as with an XML document.  A document contains a nested set
    of elements, with labels corresponding to the ElementId class. A single element can hold
    zero or more attributes and zero or more child elements.  An attribute holds a primitive
    data element (boolean, long, String) and is labeled by an AttributeId. The document is traversed
    using a sequence of openElement() and closeElement() calls, intermixed with read*() calls to extract
    the data. The elements are traversed in a depth first order.  Attributes within an element can
    be traversed in order using repeated calls to the getNextAttributeId() method, followed by a calls to
    one of the read*(void) methods to extract the data.  Alternately a read*(AttributeId) call can be used
    to extract data for an attribute known to be in the element.  There is a special content attribute
    whose data can be extracted using a read*(AttributeId) call that is passed the special ATTRIB_CONTENT id.
    This attribute will not be traversed by getNextAttributeId().
    """

    class_: typing.ClassVar[java.lang.Class]

    def closeElement(self, id: typing.Union[jpype.JInt, int]):
        """
        Close the current element
        The data for the current element is considered fully processed. If the element has additional
        children, an exception is thrown. The stream must indicate the end of the element in some way.
        
        :param jpype.JInt or int id: is the id of the element to close (which must be the current element)
        :raises DecoderException: if not at end of expected element
        """

    def closeElementSkipping(self, id: typing.Union[jpype.JInt, int]):
        """
        Close the current element, skipping any child elements that have not yet been parsed.
        This closes the given element, which must be current.  If there are child elements that have
        not been parsed, this is not considered an error, and they are skipped over in the parse.
        
        :param jpype.JInt or int id: is the id of the element to close (which must be the current element)
        :raises DecoderException: if the indicated element is not the current element
        """

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    def getIndexedAttributeId(self, attribId: AttributeId) -> int:
        """
        Get the id for the (current) attribute, assuming it is indexed.
        Assuming the previous call to getNextAttributeId() returned the id of ATTRIB_UNKNOWN,
        reinterpret the attribute as being an indexed form of the given attribute. If the attribute
        matches, return this indexed id, otherwise return ATTRIB_UNKNOWN.
        
        :param AttributeId attribId: is the attribute being indexed
        :return: the indexed id or ATTRIB_UNKNOWN
        :rtype: int
        :raises DecoderException: for unexpected end of stream
        """

    def getNextAttributeId(self) -> int:
        """
        Get the next attribute id for the current element
        Attributes are automatically set up for traversal using this method, when the element is
        opened. If all attributes have been traversed (or there are no attributes), 0 is returned.
        
        :return: the id of the next attribute or 0
        :rtype: int
        :raises DecoderException: for unexpected end of stream
        """

    @typing.overload
    def openElement(self) -> int:
        """
        Open (traverse into) the next child element of the current parent.
        The child becomes the current parent.
        The list of attributes is initialized for use with getNextAttributeId.
        
        :return: the id of the child element or 0 if there are no additional children
        :rtype: int
        :raises DecoderException: for an unexpected end of stream
        """

    @typing.overload
    def openElement(self, elemId: ElementId) -> int:
        """
        Open (traverse into) the next child element, which must be of a specific type
        The child becomes the current parent, and its attributes are initialized for use with
        getNextAttributeId. The child must match the given element id or an exception is thrown.
        
        :param ElementId elemId: is the given element id to match
        :return: the id of the child element
        :rtype: int
        :raises DecoderException: if the expected element is not the next element
        """

    def peekElement(self) -> int:
        """
        Peek at the next child element of the current parent, without traversing in (opening) it.
        The element id is returned, which can be compared to ElementId labels.
        If there are no remaining child elements to traverse, 0 is returned.
        
        :return: the element id or 0
        :rtype: int
        :raises DecoderException: for an unexpected end of stream
        """

    @typing.overload
    def readBool(self) -> bool:
        """
        Parse the current attribute as a boolean value
        The last attribute, as returned by getNextAttributeId, is treated as a boolean, and its
        value is returned.
        
        :return: the boolean value associated with the current attribute.
        :rtype: bool
        :raises DecoderException: if the expected value is not present
        """

    @typing.overload
    def readBool(self, attribId: AttributeId) -> bool:
        """
        Find and parse a specific attribute in the current element as a boolean value
        The set of attributes for the current element is searched for a match to the given attribute
        id. This attribute is then parsed as a boolean and its value returned.
        If there is no attribute matching the id, an exception is thrown.
        Parsing via getNextAttributeId is reset.
        
        :param AttributeId attribId: is the specific attribute id to match
        :return: the boolean value
        :rtype: bool
        :raises DecoderException: if the expected value is not present
        """

    @typing.overload
    def readOpcode(self) -> int:
        """
        Parse the current attribute is a p-code opcode
        The last attribute, as returned by getNextAttributeId, is returned as an opcode.
        The opcode is one of the constants specified in :obj:`PcodeOp`
        
        :return: the opcode associated with the current attribute
        :rtype: int
        :raises DecoderException: if the expected value is not present
        """

    @typing.overload
    def readOpcode(self, attribId: AttributeId) -> int:
        """
        Find the specific attribute in the current element and return it as an opcode
        Search attributes from the current element for a match to the given attribute id.
        Return this attribute as an opcode constant from :obj:`PcodeOp`. If there is no
        matching attribute id, an exception is thrown. Parse via getNextAttributeId is reset.
        
        :param AttributeId attribId: is the specific attribute id to match
        :return: the opcode associated with the attribute
        :rtype: int
        :raises DecoderException: if the expected value is not present
        """

    @typing.overload
    def readSignedInteger(self) -> int:
        """
        Parse the current attribute as a signed integer value
        The last attribute, as returned by getNextAttributeId, is treated as a signed integer,
        and its value is returned.
        
        :return: the signed integer value associated with the current attribute.
        :rtype: int
        :raises DecoderException: if the expected value is not present
        """

    @typing.overload
    def readSignedInteger(self, attribId: AttributeId) -> int:
        """
        Find and parse a specific attribute in the current element as a signed integer
        The set of attributes for the current element is searched for a match to the given attribute
        id. This attribute is then parsed as a signed integer and its value returned.
        If there is no attribute matching the id, an exception is thrown.
        Parsing via getNextAttributeId is reset.
        
        :param AttributeId attribId: is the specific attribute id to match
        :return: the signed integer value
        :rtype: int
        :raises DecoderException: if the expected value is not present
        """

    @typing.overload
    def readSignedIntegerExpectString(self, expect: typing.Union[java.lang.String, str], expectval: typing.Union[jpype.JLong, int]) -> int:
        """
        Parse the current attribute as either a signed integer value or a string.
        If the attribute is an integer, its value is returned.
        If the attribute is a string, it must match an expected string passed to the method,
        and a predetermined integer value associated with the string is returned.
        If the attribute string does not match, or the attribute is encoded as anything other than
        a string or signed integer, an exception is thrown.
        
        :param java.lang.String or str expect: is the string value to expect if the attribute is encoded as a string
        :param jpype.JLong or int expectval: is the integer value to return if the attribute matches the expected string
        :return: the encoded integer or the integer value associated with the expected string
        :rtype: int
        :raises DecoderException: is an integer value or expected string cannot be parsed
        """

    @typing.overload
    def readSignedIntegerExpectString(self, attribId: AttributeId, expect: typing.Union[java.lang.String, str], expectval: typing.Union[jpype.JLong, int]) -> int:
        """
        Find and parse a specific attribute in the current element as either a signed integer
        or a string. If the attribute is an integer, its value is returned.
        If the attribute is encoded as a string, it must match an expected string
        passed to this method. In this case, a predetermined integer value is passed back,
        indicating a matching string was parsed.  If the attribute string does not match, or
        the attribute is encoded as anything other than a string or signed integer, an exception
        is thrown.
        
        :param AttributeId attribId: is the specific attribute id to match
        :param java.lang.String or str expect: is the string to expect, if the attribute is not encoded as an integer
        :param jpype.JLong or int expectval: is the integer value to return if the attribute matches the expected string
        :return: the encoded integer or the integer value associated with the expected string
        :rtype: int
        :raises DecoderException: if an integer value or expected string cannot be parsed
        """

    @typing.overload
    def readSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        Parse the current attribute as an address space
        The last attribute, as returned by getNextAttributeId, is returned as an address space.
        
        :return: the address space associated with the current attribute.
        :rtype: ghidra.program.model.address.AddressSpace
        :raises DecoderException: if the expected value is not present
        """

    @typing.overload
    def readSpace(self, attribId: AttributeId) -> ghidra.program.model.address.AddressSpace:
        """
        Find the specific attribute in the current element and return it as an address space
        Search attributes from the current element for a match to the given attribute id.
        Return this attribute as an address space. If there is no attribute matching the id, an
        exception is thrown. Parse via getNextAttributeId is reset.
        
        :param AttributeId attribId: is the specific attribute id to match
        :return: the address space associated with the attribute
        :rtype: ghidra.program.model.address.AddressSpace
        :raises DecoderException: if the expected value is not present
        """

    @typing.overload
    def readString(self) -> str:
        """
        Parse the current attribute as a string
        The last attribute, as returned by getNextAttributeId, is returned as a string.
        
        :return: the string associated with the current attribute.
        :rtype: str
        :raises DecoderException: if the expected value is not present
        """

    @typing.overload
    def readString(self, attribId: AttributeId) -> str:
        """
        Find the specific attribute in the current element and return it as a string
        The set of attributes for the current element is searched for a match to the given attribute
        id. This attribute is then returned as a string.  If there is no attribute matching the id,
        and exception is thrown. Parse via getNextAttributeId is reset.
        
        :param AttributeId attribId: is the specific attribute id to match
        :return: the string associated with the attribute
        :rtype: str
        :raises DecoderException: if the expected value is not present
        """

    @typing.overload
    def readUnsignedInteger(self) -> int:
        """
        Parse the current attribute as an unsigned integer value
        The last attribute, as returned by getNextAttributeId, is treated as an unsigned integer,
        and its value is returned.
        
        :return: the unsigned integer value associated with the current attribute.
        :rtype: int
        :raises DecoderException: if the expected value is not present
        """

    @typing.overload
    def readUnsignedInteger(self, attribId: AttributeId) -> int:
        """
        Find and parse a specific attribute in the current element as an unsigned integer
        The set of attributes for the current element is searched for a match to the given attribute
        id. This attribute is then parsed as an unsigned integer and its value returned.
        If there is no attribute matching the id, an exception is thrown.
        Parsing via getNextAttributeId is reset.
        
        :param AttributeId attribId: is the specific attribute id to match
        :return: the unsigned integer value
        :rtype: int
        :raises DecoderException: if the expected value is not present
        """

    def rewindAttributes(self):
        """
        Reset attribute traversal for the current element
        Attributes for a single element can be traversed more than once using the getNextAttributeId
        method.
        """

    def setAddressFactory(self, addrFactory: ghidra.program.model.address.AddressFactory):
        ...

    def skipElement(self):
        """
        Skip parsing of the next element
        The element skipped is the one that would be opened by the next call to openElement.
        
        :raises DecoderException: if there is no new element
        """

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    @addressFactory.setter
    def addressFactory(self, value: ghidra.program.model.address.AddressFactory):
        ...

    @property
    def nextAttributeId(self) -> jpype.JInt:
        ...

    @property
    def indexedAttributeId(self) -> jpype.JInt:
        ...


class BlockSwitch(BlockGraph):
    """
    A block representing a switch construction
     
    possible multiple incoming edges
    1 outgoing edge representing all the interior control flow cases coming back together
       
    1 interior block representing the decision point with outgoing edges to the different cases (or the exit block)
    multiple interior blocks for each "case" of the switch
        cases must exactly 1 outgoing edge to the common exit block or have no outgoing edges
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PackedDecode(Decoder):

    class_: typing.ClassVar[java.lang.Class]
    HEADER_MASK: typing.Final = 192
    ELEMENT_START: typing.Final = 64
    ELEMENT_END: typing.Final = 128
    ATTRIBUTE: typing.Final = 192
    HEADEREXTEND_MASK: typing.Final = 32
    ELEMENTID_MASK: typing.Final = 31
    RAWDATA_MASK: typing.Final = 127
    RAWDATA_BITSPERBYTE: typing.Final = 7
    RAWDATA_MARKER: typing.Final = 128
    TYPECODE_SHIFT: typing.Final = 4
    LENGTHCODE_MASK: typing.Final = 15
    TYPECODE_BOOLEAN: typing.Final = 1
    TYPECODE_SIGNEDINT_POSITIVE: typing.Final = 2
    TYPECODE_SIGNEDINT_NEGATIVE: typing.Final = 3
    TYPECODE_UNSIGNEDINT: typing.Final = 4
    TYPECODE_ADDRESSSPACE: typing.Final = 5
    TYPECODE_SPECIALSPACE: typing.Final = 6
    TYPECODE_STRING: typing.Final = 7
    SPECIALSPACE_STACK: typing.Final = 0
    SPECIALSPACE_JOIN: typing.Final = 1
    SPECIALSPACE_FSPEC: typing.Final = 2
    SPECIALSPACE_IOP: typing.Final = 3
    SPECIALSPACE_SPACEBASE: typing.Final = 4

    @typing.overload
    def __init__(self):
        """
        Constructor for formats that do not use the readSpace() methods or use
        setAddressFactory() in the middle of decoding
        """

    @typing.overload
    def __init__(self, addrFactory: ghidra.program.model.address.AddressFactory):
        ...

    @typing.overload
    def __init__(self, stream: java.io.InputStream, desc: typing.Union[java.lang.String, str]):
        """
        Build a decoder for an input stream, where the decoder is set to read pages from the stream
        "as needed".  An initial page is read from the stream by this constructor. But then
        the stream must remain open and additional pages are read during the decoding process.
        Calling close() after decoding, will close the underlying stream.
        
        :param java.io.InputStream stream: is the stream
        :param java.lang.String or str desc: is a descriptive string for the stream used in error messages
        :raises IOException: for problems initially reading from the stream
        """

    def close(self):
        """
        Close stream cached by the ingestStreamAsNeeded method.
        
        :raises IOException: for low-level problems with the stream
        """


class DynamicEntry(SymbolEntry):
    """
    A HighSymbol mapping based on local hashing of the symbol's Varnode within a
    function's syntax tree.  The storage address of a temporary Varnode (a Varnode in
    the "unique" address space) is too ephemeral to use as a permanent way to identify it.
    This symbol stores a hash (generated by DynamicHash) that is better suited to
    identifying the Varnode.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, sym: HighSymbol):
        """
        Constructor for use with restoreXML
        
        :param HighSymbol sym: is the owning HighSymbol
        """

    @typing.overload
    def __init__(self, sym: HighSymbol, addr: ghidra.program.model.address.Address, h: typing.Union[jpype.JLong, int]):
        """
        Construct given the underlying symbol, defining Address of the Varnode, and the hash value
        
        :param HighSymbol sym: is the given symbol
        :param ghidra.program.model.address.Address addr: is the defining Address
        :param jpype.JLong or int h: is the hash value
        """

    @staticmethod
    def build(vn: Varnode) -> DynamicEntry:
        """
        Build a new DynamicEntry, given the underlying temporary
        Varnode attached to a symbol.  The hash is created from local information in the
        syntax tree near the Varnode.
        
        :param Varnode vn: is the underlying Varnode
        :return: the new DynamicEntry
        :rtype: DynamicEntry
        """

    def getHash(self) -> int:
        """
        
        
        :return: the hash value
        :rtype: int
        """

    @property
    def hash(self) -> jpype.JLong:
        ...


class HighGlobal(HighVariable):
    """
    All references (per function) to a single global variable
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, high: HighFunction):
        """
        Constructor for use with restoreXml
        
        :param HighFunction high: is the HighFunction this global is accessed by
        """

    @typing.overload
    def __init__(self, sym: HighSymbol, vn: Varnode, inst: jpype.JArray[Varnode]):
        ...


class ParamMeasure(java.lang.Object):
    """
    ParamMeasure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Constructs a ParamMeasure Object.
        **The ParamMeasure will be empty until :obj:`.decode` is invoked.**
        """

    def decode(self, decoder: Decoder, factory: PcodeFactory):
        """
        Decode a ParamMeasure object from the stream.
        
        :param Decoder decoder: is the stream decoder
        :param PcodeFactory factory: pcode factory
        :raises DecoderException: for an invalid encoding
        """

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getRank(self) -> int:
        ...

    def getVarnode(self) -> Varnode:
        ...

    def isEmpty(self) -> bool:
        ...

    @property
    def varnode(self) -> Varnode:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def rank(self) -> jpype.JInt:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class MappedEntry(SymbolEntry):
    """
    A normal mapping of a HighSymbol to a particular Address, consuming a set number of bytes
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, sym: HighSymbol):
        """
        For use with restoreXML
        
        :param HighSymbol sym: is the owning symbol
        """

    @typing.overload
    def __init__(self, sym: HighSymbol, store: ghidra.program.model.listing.VariableStorage, addr: ghidra.program.model.address.Address):
        """
        Construct given a symbol, storage, and first-use Address
        
        :param HighSymbol sym: is the given symbol
        :param ghidra.program.model.listing.VariableStorage store: is the given storage
        :param ghidra.program.model.address.Address addr: is the first-use Address (or null)
        """

    @staticmethod
    def getMutabilityOfAddress(addr: ghidra.program.model.address.Address, program: ghidra.program.model.listing.Program) -> int:
        """
        Get the underlying mutability setting of an Address based on the Program
        configuration and the MemoryBlock.  Ignore any overrides of Data at the address.
        
        :param ghidra.program.model.address.Address addr: is the Address
        :param ghidra.program.model.listing.Program program: is the Program containing the Address
        :return: the mutability
        :rtype: int
        """


class PcodeDataTypeManager(java.lang.Object):
    """
    Class for marshaling DataType objects to and from the Decompiler.
    """

    @typing.type_check_only
    class TypeMap(java.lang.Object):
        """
        A mapping between a DataType and its (name,id) on the decompiler side
        """

        class_: typing.ClassVar[java.lang.Class]
        dt: ghidra.program.model.data.DataType
        name: java.lang.String
        metatype: java.lang.String
        isChar: jpype.JBoolean
        isUtf: jpype.JBoolean
        id: jpype.JLong

        @typing.overload
        def __init__(self, lang: ghidra.program.model.lang.DecompilerLanguage, d: ghidra.program.model.data.BuiltIn, meta: typing.Union[java.lang.String, str], isChar: typing.Union[jpype.JBoolean, bool], isUtf: typing.Union[jpype.JBoolean, bool], manager: ghidra.program.model.data.DataTypeManager):
            ...

        @typing.overload
        def __init__(self, d: ghidra.program.model.data.DataType, nm: typing.Union[java.lang.String, str], meta: typing.Union[java.lang.String, str], isChar: typing.Union[jpype.JBoolean, bool], isUtf: typing.Union[jpype.JBoolean, bool], id: typing.Union[jpype.JLong, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    TYPE_VOID: typing.Final = 14
    TYPE_UNKNOWN: typing.Final = 12
    TYPE_INT: typing.Final = 11
    TYPE_UINT: typing.Final = 10
    TYPE_BOOL: typing.Final = 9
    TYPE_CODE: typing.Final = 8
    TYPE_FLOAT: typing.Final = 7
    TYPE_PTR: typing.Final = 6
    TYPE_PTRREL: typing.Final = 5
    TYPE_ARRAY: typing.Final = 4
    TYPE_STRUCT: typing.Final = 3
    TYPE_UNION: typing.Final = 2

    def __init__(self, prog: ghidra.program.model.listing.Program, simplifier: ghidra.program.model.symbol.NameTransformer):
        ...

    def clearTemporaryIds(self):
        """
        Throw out any temporary ids (from previous function decompilation) and
        reset the counter.
        """

    def decodeDataType(self, decoder: Decoder) -> ghidra.program.model.data.DataType:
        """
        Decode a data-type from the stream
        
        :param Decoder decoder: is the stream decoder
        :return: the decoded data-type object
        :rtype: ghidra.program.model.data.DataType
        :raises DecoderException: for invalid encodings
        """

    def encodeCompositePlaceholder(self, encoder: Encoder, type: ghidra.program.model.data.DataType):
        """
        Encode a Structure/Union to the stream without listing its fields
        
        :param Encoder encoder: is the stream encoder
        :param ghidra.program.model.data.DataType type: data type to encode
        :raises IOException: for errors in the underlying stream
        """

    def encodeCoreTypes(self, encoder: Encoder):
        """
        Encode the core data-types to the stream
        
        :param Encoder encoder: is the stream encoder
        :raises IOException: for errors in the underlying stream
        """

    def encodeType(self, encoder: Encoder, type: ghidra.program.model.data.DataType, size: typing.Union[jpype.JInt, int]):
        """
        Encode information for a data-type to the stream
        
        :param Encoder encoder: is the stream encoder
        :param ghidra.program.model.data.DataType type: is the data-type to encode
        :param jpype.JInt or int size: is the size of the data-type
        :raises IOException: for errors in the underlying stream
        """

    def encodeTypeRef(self, encoder: Encoder, type: ghidra.program.model.data.DataType, size: typing.Union[jpype.JInt, int]):
        """
        Encode a reference to the given data-type to stream. Most data-types produce a
        ``<type>`` element, fully describing the data-type. Where possible a ``<typeref>``
        element is produced, which just encodes the name of the data-type, deferring a full
        description of the data-type. For certain simple or nameless data-types, a ``<type>``
        element is emitted giving a full description.
        
        :param Encoder encoder: is the stream encoder
        :param ghidra.program.model.data.DataType type: is the data-type to be converted
        :param jpype.JInt or int size: is the size in bytes of the specific instance of the data-type
        :raises IOException: for errors in the underlying stream
        """

    def encodeUnion(self, encoder: Encoder, unionType: ghidra.program.model.data.Union):
        """
        Encode a Union data-type to the stream
        
        :param Encoder encoder: is the stream encoder
        :param ghidra.program.model.data.Union unionType: is the Union data-type
        :raises IOException: for errors in the underlying stream
        """

    def findBaseType(self, nm: typing.Union[java.lang.String, str], id: typing.Union[jpype.JLong, int]) -> ghidra.program.model.data.DataType:
        """
        Find a base/built-in data-type with the given name and/or id.  If an id is provided and
        a corresponding data-type exists, this data-type is returned. Otherwise the first
        built-in data-type with a matching name is returned
        
        :param java.lang.String or str nm: name of data-type
        :param jpype.JLong or int id: is an optional data-type id number
        :return: the data-type object or null if no matching data-type exists
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def findPointerRelativeInner(base: ghidra.program.model.data.DataType, offset: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.DataType:
        """
        Get the inner data-type being referred to by an offset from a relative/shifted pointer.
        Generally we expect the base of the relative pointer to be a structure and the offset
        refers to a (possibly nested) field. In this case, we return the data-type of the field.
        Otherwise return an "undefined" data-type.
        
        :param ghidra.program.model.data.DataType base: is the base data-type of the relative pointer
        :param jpype.JInt or int offset: is the offset into the base data-type
        :return: the inner data-type
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    @typing.overload
    def getMetatype(tp: ghidra.program.model.data.DataType) -> int:
        """
        Get the decompiler meta-type associated with a data-type.
        
        :param ghidra.program.model.data.DataType tp: is the data-type
        :return: the meta-type
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def getMetatype(metaString: typing.Union[java.lang.String, str]) -> int:
        """
        Convert an XML marshaling string to a metatype code
        
        :param java.lang.String or str metaString: is the string
        :return: the metatype code
        :rtype: int
        :raises XmlParseException: if the string does not represent a valid metatype
        """

    @staticmethod
    def getMetatypeString(meta: typing.Union[jpype.JInt, int]) -> str:
        """
        Convert a decompiler metatype code to a string for XML marshaling
        
        :param jpype.JInt or int meta: is the metatype
        :return: the marshaling string
        :rtype: str
        :raises IOException: is the metatype is invalid
        """

    def getNameTransformer(self) -> ghidra.program.model.symbol.NameTransformer:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def setNameTransformer(self, newTransformer: ghidra.program.model.symbol.NameTransformer):
        ...

    @property
    def nameTransformer(self) -> ghidra.program.model.symbol.NameTransformer:
        ...

    @nameTransformer.setter
    def nameTransformer(self, value: ghidra.program.model.symbol.NameTransformer):
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class PatchPackedEncode(PackedEncode, PatchEncoder):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BlockProperIf(BlockGraph):
    """
    A block containing condition control flow
     
    possible multiple incoming edges
    1 outgoing edge representing rejoined control flow
     
    2 interior blocks
        one "condition" block representing the decision point on whether to take the conditional flow
        one "body" block representing the conditional flow that may be followed or may be skipped
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ByteIngest(java.lang.Object):
    """
    An object that can ingest bytes from a stream in preparation for decoding
    """

    class_: typing.ClassVar[java.lang.Class]

    def clear(self):
        """
        Clear any previous cached bytes.
        """

    def endIngest(self):
        """
        Formal indicator that ingesting of bytes is complete and processing can begin
        
        :raises IOException: for errors processing the underlying stream
        """

    def ingestBytes(self, byteArray: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], sz: typing.Union[jpype.JInt, int]):
        """
        Ingest bytes directly from a byte array.
        If these bytes would cause the total number of bytes ingested to exceed
        the maximum (as set by the call to open()), an exception is thrown.
        This can be called multiple times to read in different chunks.
        
        :param jpype.JArray[jpype.JByte] byteArray: is the array of bytes
        :param jpype.JInt or int off: is the index of the first byte to ingest
        :param jpype.JInt or int sz: is the number of bytes to ingest
        :raises IOException: if the max number of bytes to ingest is exceeded
        """

    def ingestStream(self, inStream: java.io.InputStream):
        """
        Ingest bytes from the stream until the end of stream is encountered.
        An absolute limit is set on the number of bytes that can be ingested via the max parameter
        to a previous call to open(). If this limit is exceeded, an exception is thrown.
        
        :param java.io.InputStream inStream: is the input stream to read from
        :raises IOException: for errors reading from the stream
        """

    def ingestStreamToNextTerminator(self, inStream: java.io.InputStream):
        """
        Ingest bytes from the stream up to (and including) the first 0 byte.  This can be called
        multiple times to read in bytes in different chunks.
        An absolute limit is set on the number of bytes that can be ingested via the max parameter
        to a previous call to open(). If this limit is exceeded, an exception is thrown.
        
        :param java.io.InputStream inStream: is the input stream to read from
        :raises IOException: for errors reading from the stream
        """

    def isEmpty(self) -> bool:
        """
        
        
        :return: true if no bytes have yet been ingested via ingestStream()
        :rtype: bool
        """

    def open(self, max: typing.Union[jpype.JInt, int], desc: typing.Union[java.lang.String, str]):
        """
        Open the ingester for receiving bytes.  This establishes the description of the source of
        the bytes and maximum number of bytes that can be read
        
        :param jpype.JInt or int max: is the maximum number of bytes that can be read
        :param java.lang.String or str desc: is the description of the byte source
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class EquateSymbol(HighSymbol):

    class_: typing.ClassVar[java.lang.Class]
    FORMAT_DEFAULT: typing.Final = 0
    FORMAT_HEX: typing.Final = 1
    FORMAT_DEC: typing.Final = 2
    FORMAT_OCT: typing.Final = 3
    FORMAT_BIN: typing.Final = 4
    FORMAT_CHAR: typing.Final = 5
    FORMAT_FLOAT: typing.Final = 6
    FORMAT_DOUBLE: typing.Final = 7

    @typing.overload
    def __init__(self, func: HighFunction):
        ...

    @typing.overload
    def __init__(self, uniqueId: typing.Union[jpype.JLong, int], nm: typing.Union[java.lang.String, str], val: typing.Union[jpype.JLong, int], func: HighFunction, addr: ghidra.program.model.address.Address, hash: typing.Union[jpype.JLong, int]):
        ...

    @typing.overload
    def __init__(self, uniqueId: typing.Union[jpype.JLong, int], conv: typing.Union[jpype.JInt, int], val: typing.Union[jpype.JLong, int], func: HighFunction, addr: ghidra.program.model.address.Address, hash: typing.Union[jpype.JLong, int]):
        ...

    @staticmethod
    def convertName(nm: typing.Union[java.lang.String, str], val: typing.Union[jpype.JLong, int]) -> int:
        """
        Determine what format a given equate name is in.
        Integer format conversions are stored using an Equate object, where the name of the equate
        is the actual conversion String. So the only way to tell what kind of conversion is being performed
        is by examining the name of the equate.  The format code of the conversion is returned, or if
        the name is not a conversion,  FORMAT_DEFAULT is returned indicating a normal String equate.
        
        :param java.lang.String or str nm: is the name of the equate
        :param jpype.JLong or int val: is the value being equated
        :return: the format code for the conversion or FORMAT_DEFAULT if not a conversion
        :rtype: int
        """

    def getConvert(self) -> int:
        ...

    def getValue(self) -> int:
        ...

    @property
    def convert(self) -> jpype.JInt:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...


class HighLocal(HighVariable):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, high: HighFunction):
        """
        Constructor for use with restoreXml
        
        :param HighFunction high: is the HighFunction containing this local variable
        """

    @typing.overload
    def __init__(self, type: ghidra.program.model.data.DataType, vn: Varnode, inst: jpype.JArray[Varnode], pc: ghidra.program.model.address.Address, sym: HighSymbol):
        ...

    def getPCAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: instruction address the variable comes into scope within the function
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def pCAddress(self) -> ghidra.program.model.address.Address:
        ...


class PcodeOpBank(java.lang.Object):
    """
    Container for PcodeOpAST's
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def allAlive(self) -> java.util.Iterator[java.lang.Object]:
        """
        Returns iterator containing both PcodeOpAST and Iterator<PcodeOp> objects.
        """

    def allDead(self) -> java.util.Iterator[java.lang.Object]:
        """
        Returns iterator containing both PcodeOpAST and Iterator<PcodeOp> objects.
        """

    @typing.overload
    def allOrdered(self) -> java.util.Iterator[PcodeOpAST]:
        ...

    @typing.overload
    def allOrdered(self, pc: ghidra.program.model.address.Address) -> java.util.Iterator[PcodeOpAST]:
        ...

    def changeOpcode(self, op: PcodeOp, newopc: typing.Union[jpype.JInt, int]):
        ...

    def clear(self):
        ...

    @typing.overload
    def create(self, opcode: typing.Union[jpype.JInt, int], numinputs: typing.Union[jpype.JInt, int], pc: ghidra.program.model.address.Address) -> PcodeOp:
        ...

    @typing.overload
    def create(self, opcode: typing.Union[jpype.JInt, int], numinputs: typing.Union[jpype.JInt, int], sq: SequenceNumber) -> PcodeOp:
        ...

    def destroy(self, op: PcodeOp):
        ...

    def findOp(self, num: SequenceNumber) -> PcodeOp:
        ...

    def isEmpty(self) -> bool:
        ...

    def markAlive(self, op: PcodeOp):
        ...

    def markDead(self, op: PcodeOp):
        ...

    def size(self) -> int:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class BlockGoto(BlockGraph):
    """
    A "plain" goto block
        possible multiple incoming edges
        no outgoing edges
        1 (implied) outgoing edge representing the unstructured goto
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getGotoTarget(self) -> PcodeBlock:
        ...

    def getGotoType(self) -> int:
        ...

    def setGotoTarget(self, gt: PcodeBlock):
        ...

    @property
    def gotoTarget(self) -> PcodeBlock:
        ...

    @gotoTarget.setter
    def gotoTarget(self, value: PcodeBlock):
        ...

    @property
    def gotoType(self) -> jpype.JInt:
        ...


class PcodeBlockBasic(PcodeBlock):
    """
    A basic block constructed from PcodeOps
    """

    class_: typing.ClassVar[java.lang.Class]

    def contains(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Is the given address in the range of instructions represented by this basic block
        
        :param ghidra.program.model.address.Address addr: is the Address
        :return: true if the Address is contained
        :rtype: bool
        """

    def getFirstOp(self) -> PcodeOp:
        """
        
        
        :return: the first PcodeOp in this block (or null if the block is empty)
        :rtype: PcodeOp
        """

    def getIterator(self) -> java.util.Iterator[PcodeOp]:
        """
        
        
        :return: an iterator over the PcodeOps in this basic block
        :rtype: java.util.Iterator[PcodeOp]
        """

    def getLastOp(self) -> PcodeOp:
        """
        
        
        :return: the last PcodeOp in this block (or null if the block is empty)
        :rtype: PcodeOp
        """

    @property
    def iterator(self) -> java.util.Iterator[PcodeOp]:
        ...

    @property
    def firstOp(self) -> PcodeOp:
        ...

    @property
    def lastOp(self) -> PcodeOp:
        ...


class AttributeId(java.lang.Record):
    """
    An annotation for a data element being transferred to/from a stream
    
    This class parallels the XML concept of an attribute on an element. An AttributeId describes
    a particular piece of data associated with an ElementId.  The defining characteristic of the AttributeId is
    its name.  Internally this name is associated with an integer id.  The name (and id) uniquely determine
    the data being labeled, within the context of a specific ElementId.  Within this context, an AttributeId labels either
    - An unsigned integer
    - A signed integer
    - A boolean value
    - A string
    
    The same AttributeId can be used to label a different type of data when associated with a different ElementId.
    """

    class_: typing.ClassVar[java.lang.Class]
    ATTRIB_CONTENT: typing.Final[AttributeId]
    ATTRIB_ALIGN: typing.Final[AttributeId]
    ATTRIB_BIGENDIAN: typing.Final[AttributeId]
    ATTRIB_CONSTRUCTOR: typing.Final[AttributeId]
    ATTRIB_DESTRUCTOR: typing.Final[AttributeId]
    ATTRIB_EXTRAPOP: typing.Final[AttributeId]
    ATTRIB_FORMAT: typing.Final[AttributeId]
    ATTRIB_HIDDENRETPARM: typing.Final[AttributeId]
    ATTRIB_ID: typing.Final[AttributeId]
    ATTRIB_INDEX: typing.Final[AttributeId]
    ATTRIB_INDIRECTSTORAGE: typing.Final[AttributeId]
    ATTRIB_METATYPE: typing.Final[AttributeId]
    ATTRIB_MODEL: typing.Final[AttributeId]
    ATTRIB_NAME: typing.Final[AttributeId]
    ATTRIB_NAMELOCK: typing.Final[AttributeId]
    ATTRIB_OFFSET: typing.Final[AttributeId]
    ATTRIB_READONLY: typing.Final[AttributeId]
    ATTRIB_REF: typing.Final[AttributeId]
    ATTRIB_SIZE: typing.Final[AttributeId]
    ATTRIB_SPACE: typing.Final[AttributeId]
    ATTRIB_THISPTR: typing.Final[AttributeId]
    ATTRIB_TYPE: typing.Final[AttributeId]
    ATTRIB_TYPELOCK: typing.Final[AttributeId]
    ATTRIB_VAL: typing.Final[AttributeId]
    ATTRIB_VALUE: typing.Final[AttributeId]
    ATTRIB_WORDSIZE: typing.Final[AttributeId]
    ATTRIB_FIRST: typing.Final[AttributeId]
    ATTRIB_LAST: typing.Final[AttributeId]
    ATTRIB_UNIQ: typing.Final[AttributeId]
    ATTRIB_ADDRTIED: typing.Final[AttributeId]
    ATTRIB_GRP: typing.Final[AttributeId]
    ATTRIB_INPUT: typing.Final[AttributeId]
    ATTRIB_PERSISTS: typing.Final[AttributeId]
    ATTRIB_UNAFF: typing.Final[AttributeId]
    ATTRIB_BLOCKREF: typing.Final[AttributeId]
    ATTRIB_CLOSE: typing.Final[AttributeId]
    ATTRIB_COLOR: typing.Final[AttributeId]
    ATTRIB_INDENT: typing.Final[AttributeId]
    ATTRIB_OFF: typing.Final[AttributeId]
    ATTRIB_OPEN: typing.Final[AttributeId]
    ATTRIB_OPREF: typing.Final[AttributeId]
    ATTRIB_VARREF: typing.Final[AttributeId]
    ATTRIB_CODE: typing.Final[AttributeId]
    ATTRIB_CONTAIN: typing.Final[AttributeId]
    ATTRIB_DEFAULTSPACE: typing.Final[AttributeId]
    ATTRIB_UNIQBASE: typing.Final[AttributeId]
    ATTRIB_ALIGNMENT: typing.Final[AttributeId]
    ATTRIB_ARRAYSIZE: typing.Final[AttributeId]
    ATTRIB_CHAR: typing.Final[AttributeId]
    ATTRIB_CORE: typing.Final[AttributeId]
    ATTRIB_INCOMPLETE: typing.Final[AttributeId]
    ATTRIB_OPAQUESTRING: typing.Final[AttributeId]
    ATTRIB_SIGNED: typing.Final[AttributeId]
    ATTRIB_STRUCTALIGN: typing.Final[AttributeId]
    ATTRIB_UTF: typing.Final[AttributeId]
    ATTRIB_VARLENGTH: typing.Final[AttributeId]
    ATTRIB_CAT: typing.Final[AttributeId]
    ATTRIB_FIELD: typing.Final[AttributeId]
    ATTRIB_MERGE: typing.Final[AttributeId]
    ATTRIB_SCOPEIDBYNAME: typing.Final[AttributeId]
    ATTRIB_VOLATILE: typing.Final[AttributeId]
    ATTRIB_CLASS: typing.Final[AttributeId]
    ATTRIB_REPREF: typing.Final[AttributeId]
    ATTRIB_SYMREF: typing.Final[AttributeId]
    ATTRIB_TRUNC: typing.Final[AttributeId]
    ATTRIB_DYNAMIC: typing.Final[AttributeId]
    ATTRIB_INCIDENTALCOPY: typing.Final[AttributeId]
    ATTRIB_INJECT: typing.Final[AttributeId]
    ATTRIB_PARAMSHIFT: typing.Final[AttributeId]
    ATTRIB_TARGETOP: typing.Final[AttributeId]
    ATTRIB_ALTINDEX: typing.Final[AttributeId]
    ATTRIB_DEPTH: typing.Final[AttributeId]
    ATTRIB_END: typing.Final[AttributeId]
    ATTRIB_OPCODE: typing.Final[AttributeId]
    ATTRIB_REV: typing.Final[AttributeId]
    ATTRIB_A: typing.Final[AttributeId]
    ATTRIB_B: typing.Final[AttributeId]
    ATTRIB_LENGTH: typing.Final[AttributeId]
    ATTRIB_TAG: typing.Final[AttributeId]
    ATTRIB_NOCODE: typing.Final[AttributeId]
    ATTRIB_FARPOINTER: typing.Final[AttributeId]
    ATTRIB_INPUTOP: typing.Final[AttributeId]
    ATTRIB_OUTPUTOP: typing.Final[AttributeId]
    ATTRIB_USEROP: typing.Final[AttributeId]
    ATTRIB_BASE: typing.Final[AttributeId]
    ATTRIB_DELAY: typing.Final[AttributeId]
    ATTRIB_LOGICALSIZE: typing.Final[AttributeId]
    ATTRIB_PHYSICAL: typing.Final[AttributeId]
    ATTRIB_PIECE: typing.Final[AttributeId]
    ATTRIB_ADJUSTVMA: typing.Final[AttributeId]
    ATTRIB_ENABLE: typing.Final[AttributeId]
    ATTRIB_GROUP: typing.Final[AttributeId]
    ATTRIB_GROWTH: typing.Final[AttributeId]
    ATTRIB_KEY: typing.Final[AttributeId]
    ATTRIB_LOADERSYMBOLS: typing.Final[AttributeId]
    ATTRIB_PARENT: typing.Final[AttributeId]
    ATTRIB_REGISTER: typing.Final[AttributeId]
    ATTRIB_REVERSEJUSTIFY: typing.Final[AttributeId]
    ATTRIB_SIGNEXT: typing.Final[AttributeId]
    ATTRIB_STYLE: typing.Final[AttributeId]
    ATTRIB_CUSTOM: typing.Final[AttributeId]
    ATTRIB_DOTDOTDOT: typing.Final[AttributeId]
    ATTRIB_EXTENSION: typing.Final[AttributeId]
    ATTRIB_HASTHIS: typing.Final[AttributeId]
    ATTRIB_INLINE: typing.Final[AttributeId]
    ATTRIB_KILLEDBYCALL: typing.Final[AttributeId]
    ATTRIB_MAXSIZE: typing.Final[AttributeId]
    ATTRIB_MINSIZE: typing.Final[AttributeId]
    ATTRIB_MODELLOCK: typing.Final[AttributeId]
    ATTRIB_NORETURN: typing.Final[AttributeId]
    ATTRIB_POINTERMAX: typing.Final[AttributeId]
    ATTRIB_SEPARATEFLOAT: typing.Final[AttributeId]
    ATTRIB_STACKSHIFT: typing.Final[AttributeId]
    ATTRIB_STRATEGY: typing.Final[AttributeId]
    ATTRIB_THISBEFORERETPOINTER: typing.Final[AttributeId]
    ATTRIB_VOIDLOCK: typing.Final[AttributeId]
    ATTRIB_VECTOR_LANE_SIZES: typing.Final[AttributeId]
    ATTRIB_LABEL: typing.Final[AttributeId]
    ATTRIB_NUM: typing.Final[AttributeId]
    ATTRIB_LOCK: typing.Final[AttributeId]
    ATTRIB_MAIN: typing.Final[AttributeId]
    ATTRIB_BADDATA: typing.Final[AttributeId]
    ATTRIB_HASH: typing.Final[AttributeId]
    ATTRIB_UNIMPL: typing.Final[AttributeId]
    ATTRIB_STORAGE: typing.Final[AttributeId]
    ATTRIB_STACKSPILL: typing.Final[AttributeId]
    ATTRIB_SIZES: typing.Final[AttributeId]
    ATTRIB_BACKFILL: typing.Final[AttributeId]
    ATTRIB_UNKNOWN: typing.Final[AttributeId]

    def __init__(self, name: typing.Union[java.lang.String, str], id: typing.Union[jpype.JInt, int]):
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def hashCode(self) -> int:
        ...

    def id(self) -> int:
        ...

    def name(self) -> str:
        ...

    def toString(self) -> str:
        ...


class BlockCopy(PcodeBlock):
    """
    Placeholder for a basic block (BlockBasic) within a structured
    control-flow graph. It originally mirrors the in and out edges of
    the basic block, but edges may be modified during the structuring process.
    This copy holds a reference to the actual basic block
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, r: java.lang.Object, addr: ghidra.program.model.address.Address):
        ...

    def getAltIndex(self) -> int:
        """
        
        
        :return: the alternative index, used as an id for the original basic block Object
        :rtype: int
        """

    def getRef(self) -> java.lang.Object:
        """
        
        
        :return: the underlying basic block Object
        :rtype: java.lang.Object
        """

    @property
    def ref(self) -> java.lang.Object:
        ...

    @property
    def altIndex(self) -> jpype.JInt:
        ...


class BlockCondition(BlockGraph):
    """
    Block representing and '&&' or '||' control flow path within a conditional expression
        possible multiple incoming edges
        2 outgoing edges,  one for true control flow, one for false control flow
         
        one "initial" condition block, with 2 outgoing edges
        one "secondary" condition block, with 2 outgoing edges, exactly 1 incoming edge from "initial"
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getOpcode(self) -> int:
        ...

    @property
    def opcode(self) -> jpype.JInt:
        ...


class PcodeOp(java.lang.Object):
    """
    Pcode Op describes a generic machine operation.  You can think of
    it as the microcode for a specific processor's instruction set.  There
    are a finite number of PcodeOp's that theoretically can define the
    operations for any given processor.
     
    Pcode have
        An operation code
        Some number of input parameter varnodes
        possible output varnode
    """

    class_: typing.ClassVar[java.lang.Class]
    UNIMPLEMENTED: typing.Final = 0
    COPY: typing.Final = 1
    LOAD: typing.Final = 2
    STORE: typing.Final = 3
    BRANCH: typing.Final = 4
    CBRANCH: typing.Final = 5
    BRANCHIND: typing.Final = 6
    CALL: typing.Final = 7
    CALLIND: typing.Final = 8
    CALLOTHER: typing.Final = 9
    RETURN: typing.Final = 10
    INT_EQUAL: typing.Final = 11
    INT_NOTEQUAL: typing.Final = 12
    INT_SLESS: typing.Final = 13
    INT_SLESSEQUAL: typing.Final = 14
    INT_LESS: typing.Final = 15
    INT_LESSEQUAL: typing.Final = 16
    INT_ZEXT: typing.Final = 17
    INT_SEXT: typing.Final = 18
    INT_ADD: typing.Final = 19
    INT_SUB: typing.Final = 20
    INT_CARRY: typing.Final = 21
    INT_SCARRY: typing.Final = 22
    INT_SBORROW: typing.Final = 23
    INT_2COMP: typing.Final = 24
    INT_NEGATE: typing.Final = 25
    INT_XOR: typing.Final = 26
    INT_AND: typing.Final = 27
    INT_OR: typing.Final = 28
    INT_LEFT: typing.Final = 29
    INT_RIGHT: typing.Final = 30
    INT_SRIGHT: typing.Final = 31
    INT_MULT: typing.Final = 32
    INT_DIV: typing.Final = 33
    INT_SDIV: typing.Final = 34
    INT_REM: typing.Final = 35
    INT_SREM: typing.Final = 36
    BOOL_NEGATE: typing.Final = 37
    BOOL_XOR: typing.Final = 38
    BOOL_AND: typing.Final = 39
    BOOL_OR: typing.Final = 40
    FLOAT_EQUAL: typing.Final = 41
    FLOAT_NOTEQUAL: typing.Final = 42
    FLOAT_LESS: typing.Final = 43
    FLOAT_LESSEQUAL: typing.Final = 44
    FLOAT_NAN: typing.Final = 46
    FLOAT_ADD: typing.Final = 47
    FLOAT_DIV: typing.Final = 48
    FLOAT_MULT: typing.Final = 49
    FLOAT_SUB: typing.Final = 50
    FLOAT_NEG: typing.Final = 51
    FLOAT_ABS: typing.Final = 52
    FLOAT_SQRT: typing.Final = 53
    FLOAT_INT2FLOAT: typing.Final = 54
    FLOAT_FLOAT2FLOAT: typing.Final = 55
    FLOAT_TRUNC: typing.Final = 56
    FLOAT_CEIL: typing.Final = 57
    FLOAT_FLOOR: typing.Final = 58
    FLOAT_ROUND: typing.Final = 59
    MULTIEQUAL: typing.Final = 60
    INDIRECT: typing.Final = 61
    PIECE: typing.Final = 62
    SUBPIECE: typing.Final = 63
    CAST: typing.Final = 64
    PTRADD: typing.Final = 65
    PTRSUB: typing.Final = 66
    SEGMENTOP: typing.Final = 67
    CPOOLREF: typing.Final = 68
    NEW: typing.Final = 69
    INSERT: typing.Final = 70
    EXTRACT: typing.Final = 71
    POPCOUNT: typing.Final = 72
    LZCOUNT: typing.Final = 73
    PCODE_MAX: typing.Final = 74

    @typing.overload
    def __init__(self, sq: SequenceNumber, op: typing.Union[jpype.JInt, int], numinputs: typing.Union[jpype.JInt, int], out: Varnode):
        """
        Constructor - pcode part of sequence of pcodes, some number of inputs, output
        
        :param SequenceNumber sq: place in sequence of pcode
        :param jpype.JInt or int op: pcode operation
        :param jpype.JInt or int numinputs: number of inputs to operation, actual inputs not defined yet.
        :param Varnode out: output from operation
        """

    @typing.overload
    def __init__(self, sq: SequenceNumber, op: typing.Union[jpype.JInt, int], in_: jpype.JArray[Varnode], out: Varnode):
        """
        Constructor - pcode part of sequence of pcodes, inputs, outputs
        
        :param SequenceNumber sq: place in sequence of pcode
        :param jpype.JInt or int op: pcode operation
        :param jpype.JArray[Varnode] in: inputs to operation
        :param Varnode out: output from operation
        """

    @typing.overload
    def __init__(self, a: ghidra.program.model.address.Address, sequencenumber: typing.Union[jpype.JInt, int], op: typing.Union[jpype.JInt, int], in_: jpype.JArray[Varnode], out: Varnode):
        """
        Constructor - inputs and outputs
        
        :param ghidra.program.model.address.Address a: address pcode is attached to
        :param jpype.JInt or int sequencenumber: unique sequence number for the specified address.
        :param jpype.JInt or int op: pcode operation
        :param jpype.JArray[Varnode] in: inputs to operation
        :param Varnode out: output from operation
        """

    @typing.overload
    def __init__(self, a: ghidra.program.model.address.Address, sequencenumber: typing.Union[jpype.JInt, int], op: typing.Union[jpype.JInt, int], in_: jpype.JArray[Varnode]):
        """
        Constructor - no output
        
        :param ghidra.program.model.address.Address a: address pcode is attached to
        :param jpype.JInt or int sequencenumber: id within a single address
        :param jpype.JInt or int op: operation pcode performs
        :param jpype.JArray[Varnode] in: inputs from pcode operation
        """

    @typing.overload
    def __init__(self, a: ghidra.program.model.address.Address, sequencenumber: typing.Union[jpype.JInt, int], op: typing.Union[jpype.JInt, int]):
        """
        Constructor - no inputs, output
        
        :param ghidra.program.model.address.Address a: address pcode is attached to
        :param jpype.JInt or int sequencenumber: id within a single address
        :param jpype.JInt or int op: pcode operation
        """

    @staticmethod
    def decode(decoder: Decoder, pfact: PcodeFactory) -> PcodeOp:
        """
        Decode p-code from a stream
        
        :param Decoder decoder: is the stream decoder
        :param PcodeFactory pfact: factory used to create p-code correctly
        :return: new PcodeOp
        :rtype: PcodeOp
        :raises DecoderException: if encodings are invalid
        """

    def encodeRaw(self, encoder: Encoder, addrFactory: ghidra.program.model.address.AddressFactory):
        """
        Encode just the opcode and input/output Varnode data for this PcodeOp to a stream
        as an ``<op>`` element
        
        :param Encoder encoder: is the stream encoder
        :param ghidra.program.model.address.AddressFactory addrFactory: is a factory for looking up encoded address spaces
        :raises IOException: for errors in the underlying stream
        """

    def getBasicIter(self) -> java.util.Iterator[PcodeOp]:
        ...

    def getInput(self, i: typing.Union[jpype.JInt, int]) -> Varnode:
        """
        
        
        :param jpype.JInt or int i: the i'th input varnode
        :return: the i'th input varnode
        :rtype: Varnode
        """

    def getInputs(self) -> jpype.JArray[Varnode]:
        """
        
        
        :return: get input varnodes
        :rtype: jpype.JArray[Varnode]
        """

    def getInsertIter(self) -> java.util.Iterator[java.lang.Object]:
        ...

    @typing.overload
    def getMnemonic(self) -> str:
        """
        
        
        :return: get the string representation for the pcode operation
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getMnemonic(op: typing.Union[jpype.JInt, int]) -> str:
        """
        Get string representation for p-code operation
        
        :param jpype.JInt or int op: operation code
        :return: String representation of p-code operation
        :rtype: str
        """

    def getNumInputs(self) -> int:
        """
        
        
        :return: number of input varnodes
        :rtype: int
        """

    @typing.overload
    def getOpcode(self) -> int:
        """
        
        
        :return: pcode operation code
        :rtype: int
        """

    @staticmethod
    @typing.overload
    def getOpcode(s: typing.Union[java.lang.String, str]) -> int:
        """
        Get the p-code op code for the given mnemonic string.
        
        :param java.lang.String or str s: is the mnemonic string
        :return: the op code
        :rtype: int
        :raises UnknownInstructionException: if there is no matching mnemonic
        """

    def getOutput(self) -> Varnode:
        """
        
        
        :return: get output varnodes
        :rtype: Varnode
        """

    def getParent(self) -> PcodeBlockBasic:
        """
        
        
        :return: the pcode basic block this pcode belongs to
        :rtype: PcodeBlockBasic
        """

    def getSeqnum(self) -> SequenceNumber:
        """
        
        
        :return: the sequence number this pcode is within some number of pcode
        :rtype: SequenceNumber
        """

    def getSlot(self, vn: Varnode) -> int:
        """
        Assuming vn is an input to this op, return its input slot number
        
        :param Varnode vn: is the input varnode
        :return: the slot number
        :rtype: int
        """

    def insertInput(self, vn: Varnode, slot: typing.Union[jpype.JInt, int]):
        """
        Insert an input varnode at the given index of input varnodes
        
        :param Varnode vn: varnode to insert
        :param jpype.JInt or int slot: insert index in input varnode list
        """

    def isAssignment(self) -> bool:
        """
        
        
        :return: true if the pcode assigns a value to an output varnode
        :rtype: bool
        """

    @typing.overload
    def isCommutative(self) -> bool:
        """
        Return true if the PcodeOp is commutative.
        If true, the operation has exactly two inputs that can be switched without affecting the output.
        
        :return: true if the operation is commutative
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isCommutative(opcode: typing.Union[jpype.JInt, int]) -> bool:
        """
        Return true if the given opcode represents a commutative operation.
        If true, the operation has exactly two inputs that can be switched without affecting the output.
        
        :param jpype.JInt or int opcode: is the opcode
        :return: true if the operation is commutative
        :rtype: bool
        """

    def isDead(self) -> bool:
        """
        Check if the pcode has been determined to be a dead operation.
        
        :return: true if the pcode has been determined to have no effect in the context it is used
        :rtype: bool
        """

    def removeInput(self, slot: typing.Union[jpype.JInt, int]):
        """
        Remove a varnode at the given slot from the list of input varnodes
        
        :param jpype.JInt or int slot: index of input varnode to remove
        """

    def setInput(self, vn: Varnode, slot: typing.Union[jpype.JInt, int]):
        """
        Set/Replace an input varnode at the given slot.
        
        :param Varnode vn: varnode to replace
        :param jpype.JInt or int slot: index of input varnode to be replaced
        """

    def setOpcode(self, o: typing.Union[jpype.JInt, int]):
        """
        Set the pcode operation code
        
        :param jpype.JInt or int o: pcode operation code
        """

    def setOrder(self, ord: typing.Union[jpype.JInt, int]):
        """
        Set relative position information of PcodeOps within
        a basic block, may change as basic block is edited.
        
        :param jpype.JInt or int ord: relative position of pcode op in basic block
        """

    def setOutput(self, vn: Varnode):
        """
        Set the output varnode for the pcode operation.
        
        :param Varnode vn: new output varnode
        """

    def setTime(self, t: typing.Union[jpype.JInt, int]):
        """
        Set a unique number for pcode ops that are attached to the same address
        
        :param jpype.JInt or int t: unique id
        """

    @property
    def insertIter(self) -> java.util.Iterator[java.lang.Object]:
        ...

    @property
    def parent(self) -> PcodeBlockBasic:
        ...

    @property
    def numInputs(self) -> jpype.JInt:
        ...

    @property
    def assignment(self) -> jpype.JBoolean:
        ...

    @property
    def seqnum(self) -> SequenceNumber:
        ...

    @property
    def inputs(self) -> jpype.JArray[Varnode]:
        ...

    @property
    def dead(self) -> jpype.JBoolean:
        ...

    @property
    def slot(self) -> jpype.JInt:
        ...

    @property
    def opcode(self) -> jpype.JInt:
        ...

    @opcode.setter
    def opcode(self, value: jpype.JInt):
        ...

    @property
    def output(self) -> Varnode:
        ...

    @output.setter
    def output(self, value: Varnode):
        ...

    @property
    def input(self) -> Varnode:
        ...

    @property
    def basicIter(self) -> java.util.Iterator[PcodeOp]:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...

    @property
    def commutative(self) -> jpype.JBoolean:
        ...


class BlockDoWhile(BlockGraph):
    """
    Do-while block:
        possible multiple incoming edges
        1 (implied) edge outgoing back to itself
        1 edge outgoing (the loop exit)
        
        1 block representing the body of the loop
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class HighParamID(PcodeSyntaxTree):
    """
    High-level abstraction associated with a low level function made up of assembly instructions.
    Based on information the decompiler has produced after working on a function.
    """

    class_: typing.ClassVar[java.lang.Class]
    DECOMPILER_TAG_MAP: typing.Final = "decompiler_tags"

    def __init__(self, function: ghidra.program.model.listing.Function, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, dtManager: PcodeDataTypeManager):
        """
        
        
        :param ghidra.program.model.listing.Function function: function associated with the higher level function abstraction.
        :param ghidra.program.model.lang.Language language: language parser used to disassemble/get info on the language.
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: the compiler spec.
        :param PcodeDataTypeManager dtManager: data type manager.
        """

    @staticmethod
    def getErrorHandler(errOriginator: java.lang.Object, targetName: typing.Union[java.lang.String, str]) -> org.xml.sax.ErrorHandler:
        ...

    def getFunction(self) -> ghidra.program.model.listing.Function:
        """
        
        
        :return: get the associated low level function
        :rtype: ghidra.program.model.listing.Function
        """

    def getFunctionAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: get the Address of the function
        :rtype: ghidra.program.model.address.Address
        """

    def getFunctionName(self) -> str:
        """
        
        
        :return: get the name of the function
        :rtype: str
        """

    def getInput(self, i: typing.Union[jpype.JInt, int]) -> ParamMeasure:
        """
        
        
        :param jpype.JInt or int i: is the specific index to return
        :return: the specific input for functionparams
        :rtype: ParamMeasure
        """

    def getModelName(self) -> str:
        """
        
        
        :return: get the name of the model
        :rtype: str
        """

    def getNumInputs(self) -> int:
        """
        
        
        :return: the number of inputs for functionparams
        :rtype: int
        """

    def getNumOutputs(self) -> int:
        """
        
        
        :return: the number of outputs for functionparams
        :rtype: int
        """

    def getOutput(self, i: typing.Union[jpype.JInt, int]) -> ParamMeasure:
        """
        
        
        :param jpype.JInt or int i: is the index of the specific output
        :return: the specific of output for functionparams
        :rtype: ParamMeasure
        """

    def getProtoExtraPop(self) -> int:
        """
        
        
        :return: get the prototype extrapop information
        :rtype: int
        """

    def storeParametersToDatabase(self, storeDataTypes: typing.Union[jpype.JBoolean, bool], srctype: ghidra.program.model.symbol.SourceType):
        """
        Update any parameters for this Function from parameters defined in this map.
        Originally from LocalSymbolMap, but being modified.
        
        :param jpype.JBoolean or bool storeDataTypes: is true if data-types are being stored
        :param ghidra.program.model.symbol.SourceType srctype: function signature source
        """

    def storeReturnToDatabase(self, storeDataTypes: typing.Union[jpype.JBoolean, bool], srctype: ghidra.program.model.symbol.SourceType):
        """
        Update any parameters for this Function from parameters defined in this map.
        
        :param jpype.JBoolean or bool storeDataTypes: is true if data-types are getting stored
        :param ghidra.program.model.symbol.SourceType srctype: function signature source
        """

    @property
    def output(self) -> ParamMeasure:
        ...

    @property
    def modelName(self) -> java.lang.String:
        ...

    @property
    def input(self) -> ParamMeasure:
        ...

    @property
    def numInputs(self) -> jpype.JInt:
        ...

    @property
    def functionName(self) -> java.lang.String:
        ...

    @property
    def protoExtraPop(self) -> jpype.JInt:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def functionAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def numOutputs(self) -> jpype.JInt:
        ...


class BlockMap(java.lang.Object):

    @typing.type_check_only
    class GotoReference(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        gotoblock: PcodeBlock
        rootindex: jpype.JInt
        depth: jpype.JInt

        def __init__(self, gblock: PcodeBlock, root: typing.Union[jpype.JInt, int], d: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, fac: ghidra.program.model.address.AddressFactory):
        ...

    @typing.overload
    def __init__(self, op2: BlockMap):
        ...

    def addGotoRef(self, gblock: PcodeBlock, root: typing.Union[jpype.JInt, int], depth: typing.Union[jpype.JInt, int]):
        ...

    def createBlock(self, name: typing.Union[java.lang.String, str], index: typing.Union[jpype.JInt, int]) -> PcodeBlock:
        ...

    def findLevelBlock(self, ind: typing.Union[jpype.JInt, int]) -> PcodeBlock:
        """
        Assume blocks are in index order, find the block with index -ind-
        
        :param jpype.JInt or int ind: is the block index to match
        :return: the matching PcodeBlock
        :rtype: PcodeBlock
        """

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    def resolveGotoReferences(self):
        ...

    def sortLevelList(self):
        ...

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...


class BlockList(BlockGraph):
    """
    Block representing a sequence of other blocks
     
    possible multiple incoming edges
    1 outgoing edge
     
    1 or more interior blocks that are executed in sequence
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BlockGraph(PcodeBlock):
    """
    A block (with in edges and out edges) that contains other blocks
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addBlock(self, bl: PcodeBlock):
        """
        Add a block to this container. There are (initially) no edges between
        it and any other block in the container.
        
        :param PcodeBlock bl: is the new block to add
        """

    def addEdge(self, begin: PcodeBlock, end: PcodeBlock):
        """
        Add a directed edge between two blocks in this container
        
        :param PcodeBlock begin: is the "from" block of the edge
        :param PcodeBlock end: is the "to" block of the edge
        """

    def decode(self, decoder: Decoder):
        """
        Decode all blocks and edges in this container from a stream.
        
        :param Decoder decoder: is the stream decoder
        :raises DecoderException: if there are invalid encodings
        """

    def getBlock(self, i: typing.Union[jpype.JInt, int]) -> PcodeBlock:
        """
        Retrieve the i-th block from this container
        
        :param jpype.JInt or int i: is the index of the block to fetch
        :return: the block
        :rtype: PcodeBlock
        """

    def getSize(self) -> int:
        """
        
        
        :return: the number of blocks in this container
        :rtype: int
        """

    def setIndices(self):
        """
        Assign a unique index to all blocks in this container. After this call,
        getBlock(i) will return the block that satisfies block.getIndex() == i
        """

    def transferObjectRef(self, ingraph: BlockGraph):
        """
        Recursively run through this structured BlockGraph finding the BlockCopy leaves.
        Using the BlockCopy altindex, lookup the original BlockCopy in -ingraph- and
        transfer the Object ref and Address into the leaf
        
        :param BlockGraph ingraph: is the original flow graph
        """

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def block(self) -> PcodeBlock:
        ...


class LocalSymbolMap(java.lang.Object):
    """
    A container for local symbols within the decompiler's model of a function. It contains HighSymbol
    objects for any symbol within the scope of the function, including parameters. The container is populated
    either from the underlying Function object (when sending information to the decompiler) or read in from
    an XML description (when receiving a function model from the decompiler). HighSymbols can be obtained
    via Address using findLocal() or by id using getSymbol().  Parameters can be accessed specifically
    using getParamSymbol().
    """

    @typing.type_check_only
    class MappedVarKey(java.lang.Object):
        """
        Hashing keys for Local variables
        """

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, addr: ghidra.program.model.address.Address, pcad: ghidra.program.model.address.Address):
            ...

        @typing.overload
        def __init__(self, store: ghidra.program.model.listing.VariableStorage, pcad: ghidra.program.model.address.Address):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, highFunc: HighFunction, spc: ghidra.program.model.address.AddressSpace):
        """
        
        
        :param HighFunction highFunc: HighFunction the local variables are defined within.
        :param ghidra.program.model.address.AddressSpace spc: the address space the local variables are defined within.
        """

    def decodeScope(self, decoder: Decoder):
        """
        Decode a local symbol scope from the stream
        
        :param Decoder decoder: is the stream decoder
        :raises DecoderException: for invalid encodings
        """

    def decodeSymbolList(self, decoder: Decoder):
        """
        Add mapped symbols to this LocalVariableMap, by decoding the <symbollist> and <mapsym> elements
        
        :param Decoder decoder: is the stream decoder
        :raises DecoderException: for invalid encodings
        """

    def encodeLocalDb(self, encoder: Encoder, namespace: ghidra.program.model.symbol.Namespace, transformer: ghidra.program.model.symbol.NameTransformer):
        """
        Encode all the variables in this local variable map to the stream
        
        :param Encoder encoder: is the stream encoder
        :param ghidra.program.model.symbol.Namespace namespace: if the namespace of the function
        :param ghidra.program.model.symbol.NameTransformer transformer: is used to compute a simplified version of the namespace name
        :raises IOException: for errors in the underlying stream
        """

    @typing.overload
    def findLocal(self, store: ghidra.program.model.listing.VariableStorage, pc: ghidra.program.model.address.Address) -> HighSymbol:
        """
        Find any local variable (including input params) by address
        
        :param ghidra.program.model.listing.VariableStorage store: - variable storage
        :param ghidra.program.model.address.Address pc: = Address of first use, or null if address
                    is valid throughout the entire scope
        :return: HighLocal or null
        :rtype: HighSymbol
        """

    @typing.overload
    def findLocal(self, addr: ghidra.program.model.address.Address, pc: ghidra.program.model.address.Address) -> HighSymbol:
        """
        Find any local variable (including input params) by address
        
        :param ghidra.program.model.address.Address addr: - variable storage address
        :param ghidra.program.model.address.Address pc: = Address of first use, or null if address
                    is valid throughout the entire scope
        :return: HighLocal or null
        :rtype: HighSymbol
        """

    def getHighFunction(self) -> HighFunction:
        """
        Get the decompiler's function model owning this container
        
        :return: the owning HighFunction
        :rtype: HighFunction
        """

    def getNameToSymbolMap(self) -> java.util.Map[java.lang.String, HighSymbol]:
        """
        Construct and return a map from a HighSymbol's name to the HighSymbol object
        
        :return: the new name to symbol map
        :rtype: java.util.Map[java.lang.String, HighSymbol]
        """

    def getNumParams(self) -> int:
        """
        Get the number of parameter symbols in this scope
        
        :return: the number of parameters
        :rtype: int
        """

    def getParam(self, i: typing.Union[jpype.JInt, int]) -> HighParam:
        """
        
        
        :param jpype.JInt or int i: is the desired parameter position
        :return: the i-th parameter variable
        :rtype: HighParam
        """

    def getParamSymbol(self, i: typing.Union[jpype.JInt, int]) -> HighSymbol:
        """
        
        
        :param jpype.JInt or int i: is the desired parameter position
        :return: the i-th parameter HighSymbol
        :rtype: HighSymbol
        """

    def getSymbol(self, id: typing.Union[jpype.JLong, int]) -> HighSymbol:
        """
        Lookup high variable based upon its symbol-id
        
        :param jpype.JLong or int id: symbol-id
        :return: variable or null if not found
        :rtype: HighSymbol
        """

    def getSymbols(self) -> java.util.Iterator[HighSymbol]:
        """
        Get all the symbols mapped for this program, Param, Locals.
        The HighSymbol can either be a HighParam, or HighLocal
        
        :return: an iterator over all mapped symbols.
        :rtype: java.util.Iterator[HighSymbol]
        """

    def grabFromFunction(self, includeDefaultNames: typing.Union[jpype.JBoolean, bool]):
        """
        Populate the local variable map from information attached to the Program DB's function.
        
        :param jpype.JBoolean or bool includeDefaultNames: is true if default symbol names should be considered locked
        """

    @property
    def symbol(self) -> HighSymbol:
        ...

    @property
    def highFunction(self) -> HighFunction:
        ...

    @property
    def numParams(self) -> jpype.JInt:
        ...

    @property
    def param(self) -> HighParam:
        ...

    @property
    def paramSymbol(self) -> HighSymbol:
        ...

    @property
    def nameToSymbolMap(self) -> java.util.Map[java.lang.String, HighSymbol]:
        ...

    @property
    def symbols(self) -> java.util.Iterator[HighSymbol]:
        ...


class BlockIfElse(BlockGraph):
    """
    A standard if/else control flow block
        possible multiple incoming edges
        1 outgoing edge - going to the common out block rejoining the 2 control flows
         
        1 "condition" block with exactly 2 outputs
        1 "true" block representing the control flow if the condition is true
        1 "false" block representing the control flow if the condition is false
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class PackedDecodeOverlay(PackedDecode):
    """
    Alter address space decoding for a specific overlay space.
    Any decoded space that matches the overlayed space is replaced with the overlay itself.
    This causes addresses in the overlayed space to be converted into overlay addresses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addrFactory: ghidra.program.model.address.AddressFactory, spc: ghidra.program.model.address.OverlayAddressSpace):
        ...

    def setOverlay(self, spc: ghidra.program.model.address.OverlayAddressSpace):
        ...


class VarnodeBank(java.lang.Object):
    """
    Container class for VarnodeAST's
    """

    class LocComparator(java.util.Comparator[VarnodeAST]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class DefComparator(java.util.Comparator[VarnodeAST]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def clear(self):
        ...

    def create(self, s: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address, id: typing.Union[jpype.JInt, int]) -> Varnode:
        ...

    def destroy(self, vn: Varnode):
        ...

    def find(self, sz: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address, pc: ghidra.program.model.address.Address, uniq: typing.Union[jpype.JInt, int]) -> Varnode:
        ...

    def findInput(self, sz: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address) -> Varnode:
        ...

    def isEmpty(self) -> bool:
        ...

    @typing.overload
    def locRange(self) -> java.util.Iterator[VarnodeAST]:
        ...

    @typing.overload
    def locRange(self, spaceid: ghidra.program.model.address.AddressSpace) -> java.util.Iterator[VarnodeAST]:
        ...

    @typing.overload
    def locRange(self, addr: ghidra.program.model.address.Address) -> java.util.Iterator[VarnodeAST]:
        ...

    @typing.overload
    def locRange(self, min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address) -> java.util.Iterator[VarnodeAST]:
        ...

    @typing.overload
    def locRange(self, sz: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address) -> java.util.Iterator[VarnodeAST]:
        ...

    def makeFree(self, vn: Varnode):
        ...

    def setDef(self, vn: Varnode, op: PcodeOp) -> Varnode:
        ...

    def setInput(self, vn: Varnode) -> Varnode:
        ...

    def size(self) -> int:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class PackedEncodeOverlay(PatchPackedEncode):
    """
    Alter address space encoding for a specific overlay space.
    Any space that matches the overlay space is encoded as the overlayed space.
    This causes addresses in the overlay space to be converted into the underlying space.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, spc: ghidra.program.model.address.OverlayAddressSpace):
        ...

    def setOverlay(self, spc: ghidra.program.model.address.OverlayAddressSpace):
        ...


class DynamicHash(java.lang.Object):
    """
    A hash utility to uniquely identify a temporary Varnode in data-flow
    
    Most Varnodes can be identified within the data-flow graph by their storage address
    and the address of the PcodeOp that defines them.  For temporary registers,
    this does not work because the storage address is ephemeral. This class allows
    Varnodes like temporary registers (and constants) to be robustly identified
    by hashing details of the local data-flow.
    
    This class, when presented with a Varnode (via constructor), calculates a hash (getHash())
    and an address (getAddress()) of the PcodeOp most closely associated with the Varnode,
    either the defining op or the op directly reading the Varnode.
    There are actually four hash variants that can be calculated, labeled 0, 1, 2, or 3,
    which incrementally hash in a larger portion of data-flow.
    """

    @typing.type_check_only
    class ToOpEdge(java.lang.Comparable[DynamicHash.ToOpEdge]):
        """
        An edge between a Varnode and a PcodeOp
         
        A DynamicHash is defined on a sub-graph of the data-flow, and this defines an edge
        in the sub-graph.  The edge can either be from an input Varnode to the PcodeOp
        that reads it, or from a PcodeOp to the Varnode it defines.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, o: PcodeOp, s: typing.Union[jpype.JInt, int]):
            ...

        def getOp(self) -> PcodeOp:
            ...

        def getSlot(self) -> int:
            ...

        def hash(self, reg: typing.Union[jpype.JInt, int]) -> int:
            ...

        @property
        def op(self) -> PcodeOp:
            ...

        @property
        def slot(self) -> jpype.JInt:
            ...


    class_: typing.ClassVar[java.lang.Class]
    transtable: typing.Final[jpype.JArray[jpype.JInt]]

    @typing.overload
    def __init__(self, root: Varnode, method: typing.Union[jpype.JInt, int]):
        """
        Construct a hash of the given Varnode with a specific hash method.
        
        :param Varnode root: is the given Varnode
        :param jpype.JInt or int method: is the method (0, 1, 2, 3)
        """

    @typing.overload
    def __init__(self, root: Varnode, fd: PcodeSyntaxTree):
        """
        Construct a unique hash for the given Varnode, which must be in
        a syntax tree.  The hash method is cycled until a uniquely identifying one is found.
        
        :param Varnode root: is the given Varnode
        :param PcodeSyntaxTree fd: is the PcodeSyntaxTree containing the Varnode
        """

    @typing.overload
    def __init__(self, op: PcodeOp, slot: typing.Union[jpype.JInt, int], fd: PcodeSyntaxTree):
        """
        Construct a unique hash that allows recovery of a specific PcodeOp and slot from the
        syntax tree.  The hash method is cycled until a uniquely identifying one is found.
        
        :param PcodeOp op: is the specific PcodeOp to hash
        :param jpype.JInt or int slot: is the specific slot (-1 is the output, >=0 is an input)
        :param PcodeSyntaxTree fd: is the PcodeSyntaxTree containing the PcodeOp
        """

    @typing.overload
    def __init__(self, op: PcodeOp, inputIndex: typing.Union[jpype.JInt, int]):
        """
        Construct a level 0 hash on the input Varnode to the given PcodeOp
         
        The PcodeOp can be raw, no linked into a PcodeSyntaxTree
        
        :param PcodeOp op: is the given PcodeOp
        :param jpype.JInt or int inputIndex: is the index of the input Varnode to hash
        """

    @staticmethod
    def calcConstantHash(instr: ghidra.program.model.listing.Instruction, value: typing.Union[jpype.JLong, int]) -> jpype.JArray[jpype.JLong]:
        """
        Given a constant value accessed as an operand by a particular instruction,
        calculate a (level 0) hash for (any) corresponding constant varnode
        
        :param ghidra.program.model.listing.Instruction instr: is the instruction referencing the constant
        :param jpype.JLong or int value: of the constant
        :return: array of hash values (may be zero length)
        :rtype: jpype.JArray[jpype.JLong]
        """

    @staticmethod
    def clearTotalPosition(h: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def findOp(fd: PcodeSyntaxTree, addr: ghidra.program.model.address.Address, h: typing.Union[jpype.JLong, int]) -> PcodeOp:
        ...

    @staticmethod
    def findVarnode(fd: PcodeSyntaxTree, addr: ghidra.program.model.address.Address, h: typing.Union[jpype.JLong, int]) -> Varnode:
        ...

    @staticmethod
    def gatherFirstLevelVars(varlist: java.util.ArrayList[Varnode], fd: PcodeSyntaxTree, addr: ghidra.program.model.address.Address, h: typing.Union[jpype.JLong, int]):
        ...

    @staticmethod
    def gatherOpsAtAddress(oplist: java.util.ArrayList[PcodeOp], fd: PcodeSyntaxTree, addr: ghidra.program.model.address.Address):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    @staticmethod
    def getComparable(h: typing.Union[jpype.JLong, int]) -> int:
        ...

    def getHash(self) -> int:
        ...

    @staticmethod
    def getIsNotAttached(h: typing.Union[jpype.JLong, int]) -> bool:
        ...

    @staticmethod
    def getMethodFromHash(h: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def getOpCodeFromHash(h: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def getPositionFromHash(h: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def getSlotFromHash(h: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    def getTotalFromHash(h: typing.Union[jpype.JLong, int]) -> int:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def hash(self) -> jpype.JLong:
        ...


class StringIngest(ByteIngest):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class HighFunctionDBUtil(java.lang.Object):
    """
    ``HighFunctionDBUtil`` provides various methods for updating the state of a
    function contained within a program database.  It is important to note that the decompiler
    result state (e.g., HighFunction, HighParam, HighLocal, etc.) is not altered by any of
    these methods.  A new decompiler result will need to be generated to reflect any
    changes made to the database.  Care must be taken when making incremental changes
    to multiple elements (e.g., Variables)
    """

    class ReturnCommitOption(java.lang.Enum[HighFunctionDBUtil.ReturnCommitOption]):

        class_: typing.ClassVar[java.lang.Class]
        NO_COMMIT: typing.Final[HighFunctionDBUtil.ReturnCommitOption]
        """
        :obj:`.NO_COMMIT` - keep functions existing return parameter
        """

        COMMIT: typing.Final[HighFunctionDBUtil.ReturnCommitOption]
        """
        :obj:`.COMMIT` - commit return parameter as defined by :obj:`HighFunction`
        """

        COMMIT_NO_VOID: typing.Final[HighFunctionDBUtil.ReturnCommitOption]
        """
        :obj:`.COMMIT_NO_VOID` - commit return parameter as defined by :obj:`HighFunction`
        unless it is :obj:`VoidDataType` in which case keep existing function return parameter.
        """


        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> HighFunctionDBUtil.ReturnCommitOption:
            ...

        @staticmethod
        def values() -> jpype.JArray[HighFunctionDBUtil.ReturnCommitOption]:
            ...


    class_: typing.ClassVar[java.lang.Class]
    AUTO_CAT: typing.Final = "/auto_proto"

    def __init__(self):
        ...

    @staticmethod
    def commitLocalNamesToDatabase(highFunction: HighFunction, source: ghidra.program.model.symbol.SourceType):
        """
        Commit local variables from the decompiler's model of the function to the database.
        This does NOT include formal function parameters.
        
        :param HighFunction highFunction: is the decompiler's model of the function
        :param ghidra.program.model.symbol.SourceType source: is the desired SourceType for the commit
        """

    @staticmethod
    def commitParamsToDatabase(highFunction: HighFunction, useDataTypes: typing.Union[jpype.JBoolean, bool], returnCommit: HighFunctionDBUtil.ReturnCommitOption, source: ghidra.program.model.symbol.SourceType):
        """
        Commit all parameters, including optional return, associated with HighFunction to the 
        underlying database.
        
        :param HighFunction highFunction: is the associated HighFunction
        :param jpype.JBoolean or bool useDataTypes: is true if the HighFunction's parameter data-types should be committed
        :param HighFunctionDBUtil.ReturnCommitOption returnCommit: controls optional commit of return parameter
        :param ghidra.program.model.symbol.SourceType source: is the signature source type to set
        :raises DuplicateNameException: if commit of parameters caused conflict with other
        local variable/label.
        :raises InvalidInputException: if specified storage is invalid
        """

    @staticmethod
    def getFirstVarArg(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address) -> int:
        """
        If there is a call to a function at the given address, and the function takes variable arguments,
        return the index of the first variable argument. Return -1 otherwise.
        
        :param ghidra.program.model.listing.Program program: is the Program
        :param ghidra.program.model.address.Address addr: is the given address of the call
        :return: the index of the first variable argument or -1
        :rtype: int
        """

    @staticmethod
    def getFunctionVariable(highSymbol: HighSymbol) -> ghidra.program.model.listing.Variable:
        ...

    @staticmethod
    def getSpacebaseReferenceAddress(addrFactory: ghidra.program.model.address.AddressFactory, op: PcodeOp) -> ghidra.program.model.address.Address:
        """
        Get the Address referred to by a spacebase reference. Address-of references are encoded in
        the p-code syntax tree as: ``vn = PTRSUB(<spacebase>, #const)``.  This decodes the reference and
        returns the Address
        
        :param ghidra.program.model.address.AddressFactory addrFactory: is the factory used to construct the Address
        :param PcodeOp op: is the PTRSUB op encoding the reference
        :return: the recovered Address (or null if not correct form)
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def readOverride(sym: ghidra.program.model.symbol.Symbol) -> DataTypeSymbol:
        """
        Read a call prototype override which corresponds to the specified override code symbol
        
        :param ghidra.program.model.symbol.Symbol sym: special call override code symbol whose address corresponds to a call site
        :return: call prototype override DataTypeSymbol or null if associated function signature
        data-type could not be found
        :rtype: DataTypeSymbol
        """

    @staticmethod
    def updateDBVariable(highSymbol: HighSymbol, name: typing.Union[java.lang.String, str], dataType: ghidra.program.model.data.DataType, source: ghidra.program.model.symbol.SourceType):
        """
        Rename and/or retype the specified variable in the database.  All parameters may be flushed
        to the database if typed parameter inconsistency detected.
        
        :param HighSymbol highSymbol: is the symbol being updated
        :param java.lang.String or str name: new variable name or null to use retain current variable name
        :param ghidra.program.model.data.DataType dataType: newly assigned data type or null to retain current variable datatype.
        Only a fixed-length data type may be specified.  If size varies from the current size,
        an attempt will be made to grow/shrink the storage.
        :param ghidra.program.model.symbol.SourceType source: source type
        :raises InvalidInputException: if suitable data type was not specified, or unable to
        resize storage, or invalid name specified
        :raises DuplicateNameException: if name was specified and conflicts with another
        variable/label within the function's namespace
        :raises UnsupportedOperationException: if unsupported variable type is specified
        """

    @staticmethod
    def writeOverride(function: ghidra.program.model.listing.Function, callsite: ghidra.program.model.address.Address, sig: ghidra.program.model.listing.FunctionSignature):
        """
        Commit an overriding prototype for a particular call site to the database. The override
        only applies to the function(s) containing the actual call site. Calls to the same function from
        other sites are unaffected.  This is used typically either for indirect calls are for calls to
        a function with a variable number of parameters.
        
        :param ghidra.program.model.listing.Function function: is the Function whose call site is being overridden
        :param ghidra.program.model.address.Address callsite: is the address of the calling instruction (the call site)
        :param ghidra.program.model.listing.FunctionSignature sig: is the overriding function signature
        :raises InvalidInputException: if there are problems committing the override symbol
        """

    @staticmethod
    def writeUnionFacet(function: ghidra.program.model.listing.Function, dt: ghidra.program.model.data.DataType, fieldNum: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address, hash: typing.Union[jpype.JLong, int], source: ghidra.program.model.symbol.SourceType):
        """
        Write a union facet to the database (UnionFacetSymbol).  Parameters provide the
        pieces for building the dynamic LocalVariable.  This method clears out any preexisting
        union facet with the same dynamic hash and firstUseOffset.
        
        :param ghidra.program.model.listing.Function function: is the function affected by the union facet
        :param ghidra.program.model.data.DataType dt: is the parent data-type; a union, a pointer to a union, or a partial union
        :param jpype.JInt or int fieldNum: is the ordinal of the desired union field
        :param ghidra.program.model.address.Address addr: is the first use address of the facet
        :param jpype.JLong or int hash: is the dynamic hash
        :param ghidra.program.model.symbol.SourceType source: is the SourceType for the LocalVariable
        :raises InvalidInputException: if the LocalVariable cannot be created
        :raises DuplicateNameException: if the (auto-generated) name is used elsewhere
        """


class HighFunctionShellSymbol(HighSymbol):
    """
    A function symbol that represents only a shell of (the name and address) the function,
    when no other information is available.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, id: typing.Union[jpype.JLong, int], nm: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, manage: PcodeDataTypeManager):
        """
        Construct the function shell given a name and address
        
        :param jpype.JLong or int id: is an id to associate with the new symbol
        :param java.lang.String or str nm: is the given name
        :param ghidra.program.model.address.Address addr: is the given address
        :param PcodeDataTypeManager manage: is PcodeDataTypeManager to facilitate XML marshaling
        """


class JumpTable(java.lang.Object):
    """
    JumpTable found as part of the decompilation of a function
    """

    class LoadTable(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def decode(self, decoder: Decoder):
            ...

        def getAddress(self) -> ghidra.program.model.address.Address:
            """
            
            
            :return: Starting address of table
            :rtype: ghidra.program.model.address.Address
            """

        def getNum(self) -> int:
            """
            
            
            :return: Number of entries in table
            :rtype: int
            """

        def getSize(self) -> int:
            """
            
            
            :return: Size of a table entry in bytes
            :rtype: int
            """

        @property
        def address(self) -> ghidra.program.model.address.Address:
            ...

        @property
        def size(self) -> jpype.JInt:
            ...

        @property
        def num(self) -> jpype.JInt:
            ...


    class BasicOverride(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, dlist: java.util.ArrayList[ghidra.program.model.address.Address]):
            ...

        def encode(self, encoder: Encoder):
            ...

        def getDestinations(self) -> jpype.JArray[ghidra.program.model.address.Address]:
            ...

        @property
        def destinations(self) -> jpype.JArray[ghidra.program.model.address.Address]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, preferredSpace: ghidra.program.model.address.AddressSpace):
        ...

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, destlist: java.util.ArrayList[ghidra.program.model.address.Address], override: typing.Union[jpype.JBoolean, bool]):
        ...

    def decode(self, decoder: Decoder):
        """
        Decode a JumpTable object from the stream.
        
        :param Decoder decoder: is the stream decoder
        :raises DecoderException: for invalid encodings
        """

    def encode(self, encoder: Encoder):
        ...

    def getCases(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    def getLabelValues(self) -> jpype.JArray[java.lang.Integer]:
        ...

    def getLoadTables(self) -> jpype.JArray[JumpTable.LoadTable]:
        ...

    def getSwitchAddress(self) -> ghidra.program.model.address.Address:
        ...

    def isEmpty(self) -> bool:
        ...

    @staticmethod
    def readOverride(space: ghidra.program.model.symbol.Namespace, symtab: ghidra.program.model.symbol.SymbolTable) -> JumpTable:
        ...

    def writeOverride(self, func: ghidra.program.model.listing.Function):
        ...

    @property
    def labelValues(self) -> jpype.JArray[java.lang.Integer]:
        ...

    @property
    def cases(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    @property
    def switchAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def loadTables(self) -> jpype.JArray[JumpTable.LoadTable]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class SequenceNumber(java.lang.Comparable[SequenceNumber]):
    """
    Basically a unique address for a PcodeOp
    It is unique, maintains original assembly instruction address, and is comparable
    within a basic block
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, instrAddr: ghidra.program.model.address.Address, sequenceNum: typing.Union[jpype.JInt, int]):
        """
        Construct a sequence number for an instruction at an address and sequence of pcode op within
        that instructions set of pcode.
        
        :param ghidra.program.model.address.Address instrAddr: address of instruction
        :param jpype.JInt or int sequenceNum: sequence of pcode op with an instructions pcode ops
        """

    @staticmethod
    def decode(decoder: Decoder) -> SequenceNumber:
        """
        Decode a new Sequence number from the stream
        
        :param Decoder decoder: is the stream decoder
        :return: new sequence number
        :rtype: SequenceNumber
        :raises DecoderException: for an invalid encoding
        """

    def encode(self, encoder: Encoder):
        """
        Encode this sequence number to the stream
        
        :param Encoder encoder: is the stream encoder
        :raises IOException: for errors in the underlying stream
        """

    def getOrder(self) -> int:
        """
        Get relative position information of PcodeOps within
        a basic block, may change as basic block is edited.
        
        :return: relative position of pcode in a basic block
        :rtype: int
        """

    def getTarget(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: get address of instruction this sequence belongs to
        :rtype: ghidra.program.model.address.Address
        """

    def getTime(self) -> int:
        """
        Get unique Sub-address for distinguishing multiple PcodeOps at one
        instruction address.
        Does not change over lifetime of PcodeOp
        
        :return: unique id for a pcode op within a given instruction
        :rtype: int
        """

    def setOrder(self, o: typing.Union[jpype.JInt, int]):
        """
        Set relative position information of PcodeOps within
        a basic block, may change as basic block is edited.
        
        :param jpype.JInt or int o: relative position of pcodeOp within a basic block
        """

    def setTime(self, t: typing.Union[jpype.JInt, int]):
        """
        Set unique Sub-address for distinguishing multiple PcodeOps at one
        instruction address.
        Does not change over lifetime of PcodeOp
        
        :param jpype.JInt or int t: unique id
        """

    @property
    def time(self) -> jpype.JInt:
        ...

    @time.setter
    def time(self, value: jpype.JInt):
        ...

    @property
    def target(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def order(self) -> jpype.JInt:
        ...

    @order.setter
    def order(self, value: jpype.JInt):
        ...


class UnionFacetSymbol(HighSymbol):
    """
    A specialized HighSymbol that directs the decompiler to use a specific field of a union,
    when interpreting a particular PcodeOp that accesses a Varnode whose data-type involves the
    union. The symbol is stored as a dynamic variable annotation.  The data-type must either be the
    union itself or a pointer to the union. The firstUseOffset and dynamic hash
    identify the particular PcodeOp and Varnode affected.  The field number is the ordinal
    of the desired field (DataTypeComponent) within the union.  It is currently stored by
    encoding it in the symbol name.
    """

    class_: typing.ClassVar[java.lang.Class]
    BASENAME: typing.ClassVar[java.lang.String]

    def __init__(self, uniqueId: typing.Union[jpype.JLong, int], nm: typing.Union[java.lang.String, str], dt: ghidra.program.model.data.DataType, fldNum: typing.Union[jpype.JInt, int], func: HighFunction):
        ...

    @staticmethod
    def buildSymbolName(fldNum: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address) -> str:
        """
        Generate an automatic symbol name, given a field number and address
        
        :param jpype.JInt or int fldNum: is the field number
        :param ghidra.program.model.address.Address addr: is the Address
        :return: the name
        :rtype: str
        """

    @staticmethod
    def extractFieldNumber(nm: typing.Union[java.lang.String, str]) -> int:
        """
        The actual field number is encoded in the symbol name
        
        :param java.lang.String or str nm: is the symbol name
        :return: the field number or -1 if we cannot parse
        :rtype: int
        """

    @staticmethod
    def isUnionType(dt: ghidra.program.model.data.DataType) -> bool:
        """
        Return true if the given data-type is either a union or a pointer to a union
        and is suitable for being the data-type of UnionFacetSymbol
        
        :param ghidra.program.model.data.DataType dt: is the given data-type
        :return: true if the data-type is a union or a pointer to a union
        :rtype: bool
        """


class HighConstant(HighVariable):
    """
    A constant that has been given a datatype (like a constant that is really a pointer)
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, func: HighFunction):
        """
        Constructor for use with restoreXml
        
        :param HighFunction func: is the HighFunction this constant belongs to
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], type: ghidra.program.model.data.DataType, vn: Varnode, pc: ghidra.program.model.address.Address, func: HighFunction):
        """
        Construct a constant NOT associated with a symbol
        
        :param java.lang.String or str name: name of variable
        :param ghidra.program.model.data.DataType type: data type of variable
        :param Varnode vn: constant varnode
        :param ghidra.program.model.address.Address pc: code unit address where constant is used
        :param HighFunction func: the associated high function
        """

    def getPCAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: instruction address the variable comes into scope within the function
        :rtype: ghidra.program.model.address.Address
        """

    def getScalar(self) -> ghidra.program.model.scalar.Scalar:
        """
        
        
        :return: constant as a scalar object
        :rtype: ghidra.program.model.scalar.Scalar
        """

    @property
    def scalar(self) -> ghidra.program.model.scalar.Scalar:
        ...

    @property
    def pCAddress(self) -> ghidra.program.model.address.Address:
        ...


class Encoder(java.lang.Object):
    """
    An interface for writing structured data to a stream
    
    The resulting encoded data is structured similarly to an XML document. The document contains a nested set
    of \elements, with labels corresponding to the ElementId class. A single element can hold
    zero or more attributes and zero or more child elements.  An attribute holds a primitive
    data element (boolean, long, String) and is labeled by an AttributeId. The document is written
    using a sequence of openElement() and closeElement() calls, intermixed with write*() calls to encode
    the data primitives.  All primitives written using a write*() call are associated with current open element,
    and all write*() calls for one element must come before opening any child element.
    The traditional XML element text content can be written using the special ATTRIB_CONTENT AttributeId, which
    must be the last write*() call associated with the specific element.
    """

    class_: typing.ClassVar[java.lang.Class]

    def closeElement(self, elemId: ElementId):
        """
        End the current element in the encoding
        The current element must match the given annotation or an exception is thrown.
        
        :param ElementId elemId: is the given (expected) annotation for the current element
        :raises IOException: for errors in the underlying stream
        """

    def openElement(self, elemId: ElementId):
        """
        Begin a new element in the encoding
        The element will have the given ElementId annotation and becomes the \e current element.
        
        :param ElementId elemId: is the given ElementId annotation
        :raises IOException: for errors in the underlying stream
        """

    def writeBool(self, attribId: AttributeId, val: typing.Union[jpype.JBoolean, bool]):
        """
        Write an annotated boolean value into the encoding
        The boolean data is associated with the given AttributeId annotation and the current open element.
        
        :param AttributeId attribId: is the given AttributeId annotation
        :param jpype.JBoolean or bool val: is boolean value to encode
        :raises IOException: for errors in the underlying stream
        """

    def writeOpcode(self, attribId: AttributeId, opcode: typing.Union[jpype.JInt, int]):
        """
        Write a p-code operation opcode into the encoding, associating it with the given
        annotation. The opcode is specified based on the constants defined in :obj:`PcodeOp`.
        
        :param AttributeId attribId: is the given annotation
        :param jpype.JInt or int opcode: is the opcode constant
        :raises IOException: for errors in the underlying stream
        """

    def writeSignedInteger(self, attribId: AttributeId, val: typing.Union[jpype.JLong, int]):
        """
        Write an annotated signed integer value into the encoding
        The integer is associated with the given AttributeId annotation and the current open element.
        
        :param AttributeId attribId: is the given AttributeId annotation
        :param jpype.JLong or int val: is the signed integer value to encode
        :raises IOException: for errors in the underlying stream
        """

    @typing.overload
    def writeSpace(self, attribId: AttributeId, spc: ghidra.program.model.address.AddressSpace):
        """
        Write an address space reference into the encoding
        The address space is associated with the given AttributeId annotation and the current open element.
        
        :param AttributeId attribId: is the given AttributeId annotation
        :param ghidra.program.model.address.AddressSpace spc: is the address space to encode
        :raises IOException: for errors in the underlying stream
        """

    @typing.overload
    def writeSpace(self, attribId: AttributeId, index: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str]):
        """
        Write an address space reference into the encoding.
        An address space identified by its name and unique index is associated with the given
        annotation and the current open element.
        
        :param AttributeId attribId: is the given annotation
        :param jpype.JInt or int index: is the unique index of the address space
        :param java.lang.String or str name: is the name of the address space
        :raises IOException: for errors in the underlying stream
        """

    def writeString(self, attribId: AttributeId, val: typing.Union[java.lang.String, str]):
        """
        Write an annotated string into the encoding
        The string is associated with the given AttributeId annotation and the current open element.
        
        :param AttributeId attribId: is the given AttributeId annotation
        :param java.lang.String or str val: is the string to encode
        :raises IOException: for errors in the underlying stream
        """

    def writeStringIndexed(self, attribId: AttributeId, index: typing.Union[jpype.JInt, int], val: typing.Union[java.lang.String, str]):
        """
        Write an annotated string, using an indexed attribute, into the encoding.
        Multiple attributes with a shared name can be written to the same element by calling this
        method multiple times with a different index value. The encoding will use attribute ids up
        to the base id plus the maximum index passed in.  Implementors must be careful to not use
        other attributes with ids bigger than the base id within the element taking the indexed attribute.
        
        :param AttributeId attribId: is the shared AttributeId
        :param jpype.JInt or int index: is the unique index to associated with the string
        :param java.lang.String or str val: is the string to encode
        :raises IOException: for errors in the underlying stream
        """

    def writeUnsignedInteger(self, attribId: AttributeId, val: typing.Union[jpype.JLong, int]):
        """
        Write an annotated unsigned integer value into the encoding
        The integer is associated with the given AttributeId annotation and the current open element.
        
        :param AttributeId attribId: is the given AttributeId annotation
        :param jpype.JLong or int val: is the unsigned integer value to encode
        :raises IOException: for errors in the underlying stream
        """


class HighOther(HighVariable):
    """
    Other forms of variable, these are typically compiler infrastructure
    like the stackpointer or saved registers
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, high: HighFunction):
        """
        Constructor for use with restoreXml
        
        :param HighFunction high: is the HighFunction containing the variable
        """

    @typing.overload
    def __init__(self, type: ghidra.program.model.data.DataType, vn: Varnode, inst: jpype.JArray[Varnode], pc: ghidra.program.model.address.Address, func: HighFunction):
        """
        Construct a unique high NOT associated with a symbol
        
        :param ghidra.program.model.data.DataType type: data type of variable
        :param Varnode vn: is the representative Varnode
        :param jpype.JArray[Varnode] inst: is the list of Varnodes making up the variable
        :param ghidra.program.model.address.Address pc: code unit address where unique is first assigned (first-use)
        :param HighFunction func: the associated high function
        """

    def getPCAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: instruction address the variable comes into scope within the function
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def pCAddress(self) -> ghidra.program.model.address.Address:
        ...


class HighFunctionSymbol(HighSymbol):
    """
    A function symbol that encapsulates detailed information about a particular function
    for the purposes of decompilation. The detailed model is provided by a backing HighFunction object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addr: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], function: HighFunction):
        """
        Construct given an Address, size, and decompiler function model for the symbol.
        The Address is typically the entry point of the function but may be different
        if the function is getting mapped from elsewhere (i.e. the EXTERNAL space). The size
        is given in bytes but generally isn't the true size of the function. The size needs to
        make the symbol just big enough to absorb any off-cut Address queries.
        
        :param ghidra.program.model.address.Address addr: is the starting Address of the symbol
        :param jpype.JInt or int size: is the pseudo-size of the function
        :param HighFunction function: is the decompiler model of the function
        """


class PcodeOpAST(PcodeOp):
    """
    Some extra things attached to PcodeOp for ease of walking the syntax tree
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, sq: SequenceNumber, op: typing.Union[jpype.JInt, int], numinputs: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, a: ghidra.program.model.address.Address, uq: typing.Union[jpype.JInt, int], op: typing.Union[jpype.JInt, int], numinputs: typing.Union[jpype.JInt, int]):
        ...

    def setBasicIter(self, iter: java.util.Iterator[PcodeOp]):
        """
        Set the iterator being used to iterate the pcode within a basic block.
        
        :param java.util.Iterator[PcodeOp] iter:
        """

    def setInsertIter(self, iter: java.util.Iterator[java.lang.Object]):
        """
        Set the iterator being used to iterate the pcode to insert within a block.
        
        :param java.util.Iterator[java.lang.Object] iter:
        """

    def setParent(self, par: PcodeBlockBasic):
        """
        Set the parent basic block this pcode is contained within.
        
        :param PcodeBlockBasic par: parent basic block.
        """


class MappedDataEntry(MappedEntry):
    """
    A normal address based HighSymbol mapping with an associated Data object
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, sym: HighSymbol):
        """
        Constructor for use with restoreXML
        
        :param HighSymbol sym: is the owning HighSymbol
        """

    @typing.overload
    def __init__(self, sym: HighSymbol, store: ghidra.program.model.listing.VariableStorage, d: ghidra.program.model.listing.Data):
        """
        Construct given a symbol, storage, and a backing Data object
        
        :param HighSymbol sym: the given symbol
        :param ghidra.program.model.listing.VariableStorage store: the given storage
        :param ghidra.program.model.listing.Data d: the backing Data object
        """

    def getData(self) -> ghidra.program.model.listing.Data:
        """
        
        
        :return: the backing Data object
        :rtype: ghidra.program.model.listing.Data
        """

    @property
    def data(self) -> ghidra.program.model.listing.Data:
        ...


class HighCodeSymbol(HighSymbol):
    """
    A global symbol as part of the decompiler's model of a function. This symbol can
    be backed by a formal CodeSymbol, obtained using getCodeSymbol(). This symbol can be backed
    by a formal Data object, obtained using getData(). If there is a backing CodeSymbol, this takes its name,
    otherwise the name is dynamically generated using SymbolUtilities. The data-type attached to this does
    not necessarily match the backing CodeSymbol or Data object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, sym: ghidra.program.database.symbol.CodeSymbol, func: HighFunction):
        """
        Construct with a backing CodeSymbol.  An attempt is made to also find a backing Data object.
        
        :param ghidra.program.database.symbol.CodeSymbol sym: is the backing CodeSymbol
        :param HighFunction func: is the decompiler function model owning the new HighSymbol
        """

    @typing.overload
    def __init__(self, id: typing.Union[jpype.JLong, int], addr: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType, sz: typing.Union[jpype.JInt, int], func: HighFunction):
        """
        Construct with just a (global) storage address and size. There will be no backing CodeSymbol.
        An attempt is made to find a backing Data object.
        
        :param jpype.JLong or int id: is the id to associate with the new HighSymbol
        :param ghidra.program.model.address.Address addr: is the starting Address of the symbol storage
        :param ghidra.program.model.data.DataType dataType: is the data-type associated with the new symbol
        :param jpype.JInt or int sz: is the size of the symbol storage in bytes
        :param HighFunction func: is the decompiler function model owning the new symbol
        """

    @typing.overload
    def __init__(self, id: typing.Union[jpype.JLong, int], nm: typing.Union[java.lang.String, str], data: ghidra.program.model.listing.Data, dtmanage: PcodeDataTypeManager):
        """
        Constructor for HighSymbol which is unattached to a HighFunction
        
        :param jpype.JLong or int id: is the unique id to assign
        :param java.lang.String or str nm: is the name of the symbol
        :param ghidra.program.model.listing.Data data: is an underlying Data object defining the storage and data-type
        :param PcodeDataTypeManager dtmanage: is the data-type manager for XML reference
        """

    def getCodeSymbol(self) -> ghidra.program.database.symbol.CodeSymbol:
        """
        Get the CodeSymbol backing this, if it exists
        
        :return: the CodeSymbol or null
        :rtype: ghidra.program.database.symbol.CodeSymbol
        """

    def getData(self) -> ghidra.program.model.listing.Data:
        """
        Get the Data object backing this, if it exists
        
        :return: the Data object or null
        :rtype: ghidra.program.model.listing.Data
        """

    @property
    def data(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def codeSymbol(self) -> ghidra.program.database.symbol.CodeSymbol:
        ...


class VarnodeAST(Varnode):
    """
    This type of Varnode is a node in an Abstract Syntax Tree
    It keeps track of its defining PcodeOp (in-edge) and PcodeOps which use it (out-edges)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, a: ghidra.program.model.address.Address, sz: typing.Union[jpype.JInt, int], id: typing.Union[jpype.JInt, int]):
        ...

    def addDescendant(self, op: PcodeOp):
        ...

    def descendReplace(self, vn: VarnodeAST):
        """
        Replace all of parameter vn's references with this
        
        :param VarnodeAST vn: Varnode whose references will get replaced
        """

    def getUniqueId(self) -> int:
        ...

    def removeDescendant(self, op: PcodeOp):
        ...

    def setAddrtied(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setDef(self, op: PcodeOp):
        ...

    def setFree(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setHigh(self, hi: HighVariable):
        ...

    def setInput(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setMergeGroup(self, val: typing.Union[jpype.JShort, int]):
        ...

    def setPersistent(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    def setUnaffected(self, val: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def uniqueId(self) -> jpype.JInt:
        ...


class PackedEncode(Encoder):
    """
    A byte-based encoder designed to marshal to the decompiler efficiently
    See ``PackedDecode`` for details of the encoding format
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, stream: java.io.OutputStream):
        ...

    def getOutputStream(self) -> java.io.OutputStream:
        """
        
        
        :return: the underlying stream
        :rtype: java.io.OutputStream
        """

    @property
    def outputStream(self) -> java.io.OutputStream:
        ...


class AddressXML(java.lang.Object):
    """
    Utility class for the myriad ways of marshaling/unmarshaling an address and an optional size,
    to/from XML for the various configuration files.
     
    
    An object of the class itself is the most general form, where the specified address
     
    * MAY have an associated size given in bytes
    * MAY be in the JOIN address space, with physical pieces making up the logical value explicitly provided
    
    The static buildXML methods write out an ``<addr>`` tag given component elements without allocating an object.
    The static readXML methods read XML tags (presented in different forms) and returns an Address object.
    The static appendAttributes methods write out attributes of an address to an arbitrary XML tag.
    The static restoreXML methods read an ``<addr>`` tag and produce a general AddressXML object.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_PIECES: typing.ClassVar[jpype.JInt]

    @typing.overload
    def __init__(self, spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], sz: typing.Union[jpype.JInt, int]):
        """
        Construct an Address range as a space/offset/size
        
        :param ghidra.program.model.address.AddressSpace spc: is the address space containing the range
        :param jpype.JLong or int off: is the starting byte offset of the range
        :param jpype.JInt or int sz: is the size of the range in bytes
        """

    @typing.overload
    def __init__(self, spc: ghidra.program.model.address.AddressSpace, off: typing.Union[jpype.JLong, int], sz: typing.Union[jpype.JInt, int], pieces: jpype.JArray[Varnode]):
        """
        Construct a logical memory range, representing multiple ranges pieced together.
        The logical range is assigned an address in the JOIN address space.
        The physical pieces making up the logical range are passed in as a sequence of
        Varnodes representing, in order, the most significant through the least significant
        portions of the value.
        
        :param ghidra.program.model.address.AddressSpace spc: is the JOIN address space (must have a type of AddressSpace.TYPE_JOIN)
        :param jpype.JLong or int off: is the offset of the logical value within the JOIN space
        :param jpype.JInt or int sz: is the number of bytes in the logical value
        :param jpype.JArray[Varnode] pieces: is the array of 1 or more physical pieces
        """

    @staticmethod
    def decode(decoder: Decoder) -> ghidra.program.model.address.Address:
        """
        Create an address from a stream encoding. This recognizes elements
         
        * ``<addr>``
        * ``<spaceid>``
        * ``<iop>`` or
        * any element with "space" and "offset" attributes
        
        An empty ``<addr>`` element, with no attributes, results in :obj:`Address.NO_ADDRESS`
        being returned.
        
        :param Decoder decoder: is the stream decoder
        :return: Address created from decode info
        :rtype: ghidra.program.model.address.Address
        :raises DecoderException: for any problems decoding the stream
        """

    @staticmethod
    def decodeFromAttributes(decoder: Decoder) -> ghidra.program.model.address.Address:
        """
        Create an address from "space" and "offset" attributes of the current element
        
        :param Decoder decoder: is the stream decoder
        :return: the decoded Address
        :rtype: ghidra.program.model.address.Address
        :raises DecoderException: for any problems decoding the stream
        """

    @staticmethod
    def decodeStorageFromAttributes(size: typing.Union[jpype.JInt, int], decoder: Decoder, pcodeFactory: PcodeFactory) -> ghidra.program.model.listing.VariableStorage:
        """
        Decode a VariableStorage object from the attributes in the current address element.
        The start of storage corresponds to the decoded address. The size is either passed
        in or is decoded from a size attribute.
        
        :param jpype.JInt or int size: is the desired size of storage or -1 to use the size attribute
        :param Decoder decoder: is the stream decoder
        :param PcodeFactory pcodeFactory: is used to resolve address spaces, etc.
        :return: the decoded VariableStorage
        :rtype: ghidra.program.model.listing.VariableStorage
        :raises DecoderException: for any errors in the encoding or problems creating the storage
        """

    @typing.overload
    def encode(self, encoder: Encoder):
        """
        Encode this sized address as an ``<addr>`` element to the stream
        
        :param Encoder encoder: is the stream encoder
        :raises IOException: for errors in the underlying stream
        """

    @staticmethod
    @typing.overload
    def encode(encoder: Encoder, addr: ghidra.program.model.address.Address):
        """
        Encode the given Address as an ``<addr>`` element to the stream
        
        :param Encoder encoder: is the stream encoder
        :param ghidra.program.model.address.Address addr: -- Address to encode
        :raises IOException: for errors in the underlying stream
        """

    @staticmethod
    @typing.overload
    def encode(encoder: Encoder, addr: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]):
        """
        Encode the given Address and a size as an ``<addr>`` element to the stream
        
        :param Encoder encoder: is the stream encoder
        :param ghidra.program.model.address.Address addr: is the given Address
        :param jpype.JInt or int size: is the given size
        :raises IOException: for errors in the underlying stream
        """

    @staticmethod
    @typing.overload
    def encode(encoder: Encoder, varnodes: jpype.JArray[Varnode], logicalsize: typing.Union[jpype.JLong, int]):
        """
        Encode a sequence of Varnodes as a single ``<addr>`` element to the stream.
        If there is more than one Varnode, or if the logical size is non-zero,
        the ``<addr>`` element will specify the address space as "join" and will have
        additional "piece" attributes.
        
        :param Encoder encoder: is the stream encoder
        :param jpype.JArray[Varnode] varnodes: is the sequence of storage varnodes
        :param jpype.JLong or int logicalsize: is the logical size value of the varnode
        :raises IOException: for errors in the underlying stream
        """

    @staticmethod
    @typing.overload
    def encodeAttributes(encoder: Encoder, addr: ghidra.program.model.address.Address):
        """
        Encode "space" and "offset" attributes for the current element, describing the
        given Address to the stream.
        
        :param Encoder encoder: is the stream encoder
        :param ghidra.program.model.address.Address addr: is the given Address
        :raises IOException: for errors in the underlying stream
        """

    @staticmethod
    @typing.overload
    def encodeAttributes(encoder: Encoder, addr: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]):
        """
        Encode "space" "offset" and "size" attributes for the current element, describing
        the given memory range to the stream.
        
        :param Encoder encoder: is the stream encoder
        :param ghidra.program.model.address.Address addr: is the starting Address of the memory range
        :param jpype.JInt or int size: is the size of the memory range
        :raises IOException: for errors in the underlying stream
        """

    @staticmethod
    @typing.overload
    def encodeAttributes(encoder: Encoder, startAddr: ghidra.program.model.address.Address, endAddr: ghidra.program.model.address.Address):
        """
        Encode a memory range, as "space", "first", and "last" attributes, for the current element,
        to the stream.
        
        :param Encoder encoder: is the stream encoder
        :param ghidra.program.model.address.Address startAddr: is the first address in the range
        :param ghidra.program.model.address.Address endAddr: is the last address in the range
        :raises IOException: for errors in the underlying stream
        """

    def getAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        """
        
        
        :return: the space associated of this address
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getFirstAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the first address in the range
        :rtype: ghidra.program.model.address.Address
        """

    def getJoinRecord(self) -> jpype.JArray[Varnode]:
        """
        Get the array of physical pieces making up this logical address range, if
        the range is in the JOIN address space. Otherwise return null.
        
        :return: the physical pieces or null
        :rtype: jpype.JArray[Varnode]
        """

    def getLastAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the last address in the range
        :rtype: ghidra.program.model.address.Address
        """

    def getOffset(self) -> int:
        """
        
        
        :return: the byte offset of this address
        :rtype: int
        """

    def getSize(self) -> int:
        """
        
        
        :return: the size in bytes associated with this address
        :rtype: int
        """

    def getVarnode(self) -> Varnode:
        """
        Build a raw Varnode from the Address and size
        
        :return: the new Varnode
        :rtype: Varnode
        """

    @staticmethod
    def restoreRangeXml(el: ghidra.xml.XmlElement, cspec: ghidra.program.model.lang.CompilerSpec) -> AddressXML:
        """
        A memory range is read from attributes of an XML tag. The tag must either have:
            - "name" attribute - indicating a register 
            - "space" attribute - with optional "first" and "last" attributes
         
        With the "space" attribute, "first" defaults to 0 and "last" defaults to the last offset in the space.
        
        :param ghidra.xml.XmlElement el: is the XML element
        :param ghidra.program.model.lang.CompilerSpec cspec: is a compiler spec to resolve address spaces and registers
        :return: an AddressXML object representing the range
        :rtype: AddressXML
        :raises XmlParseException: if the XML is badly formed
        """

    @staticmethod
    @typing.overload
    def restoreXml(el: ghidra.xml.XmlElement, cspec: ghidra.program.model.lang.CompilerSpec) -> AddressXML:
        """
        Restore an Address (as an AddressSpace and an offset) and an optional size from XML tag.
        The tag can have any name, but it must either have:
            - A "name" attribute, indicating a register name  OR
            - A "space" and "offset" attribute, indicating the address space and offset
            
        If a register name is given, size is obtained from the register.  If an offset is
        given, the size can optionally be specified using a "size" attribute.
        If not explicitly described, the size is set to zero.
         
        This method supports the "join" address space attached to the compiler specification
        
        :param ghidra.xml.XmlElement el: is the XML tag
        :param ghidra.program.model.lang.CompilerSpec cspec: is the compiler spec for looking up registers
        :return: an AddressXML object containing the recovered space,offset,size
        :rtype: AddressXML
        :raises XmlParseException: for problems parsing
        """

    @staticmethod
    @typing.overload
    def restoreXml(el: ghidra.xml.XmlElement, language: ghidra.program.model.lang.Language) -> AddressXML:
        """
        Restore an Address (as an AddressSpace and an offset) and an optional size from XML tag.
        The tag can have any name, but it must either have:
            - A "name" attribute, indicating a register name  OR
            - A "space" and "offset" attribute, indicating the address space and offset
            
        If a register name is given, size is obtained from the register.  If an offset is
        given, the size can optionally be specified using a "size" attribute.
        If not explicitly described, the size is set to zero.
        
        :param ghidra.xml.XmlElement el: is the XML tag
        :param ghidra.program.model.lang.Language language: is the processor language for looking up registers and address spaces
        :return: an AddressXML object containing the recovered space,offset,size
        :rtype: AddressXML
        :raises XmlParseException: for problems parsing
        """

    @property
    def joinRecord(self) -> jpype.JArray[Varnode]:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def varnode(self) -> Varnode:
        ...

    @property
    def addressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def lastAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def firstAddress(self) -> ghidra.program.model.address.Address:
        ...


class VarnodeTranslator(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, lang: ghidra.program.model.lang.Language):
        ...

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program):
        ...

    @typing.overload
    def getRegister(self, node: Varnode) -> ghidra.program.model.lang.Register:
        """
        Translate the Varnode into a register if possible
        
        :param Varnode node: varnode to translate
        :return: Register or null if node is not a register
        :rtype: ghidra.program.model.lang.Register
        """

    @typing.overload
    def getRegister(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.lang.Register:
        """
        Get register given a register name
        
        :param java.lang.String or str name: register name
        :return: register
        :rtype: ghidra.program.model.lang.Register
        """

    def getRegisters(self) -> java.util.List[ghidra.program.model.lang.Register]:
        """
        Get all defined registers for the program this translator was created
        with.
        
        :return: all defined registers as unmodifiable list
        :rtype: java.util.List[ghidra.program.model.lang.Register]
        """

    def getVarnode(self, register: ghidra.program.model.lang.Register) -> Varnode:
        """
        Get a varnode that maps to the given register
        
        :param ghidra.program.model.lang.Register register: register to translate into a varnode
        :return: varnode that reprents the register
        :rtype: Varnode
        """

    def supportsPcode(self) -> bool:
        """
        
        
        :return: true if this program's language supports pcode
        :rtype: bool
        """

    @property
    def varnode(self) -> Varnode:
        ...

    @property
    def registers(self) -> java.util.List[ghidra.program.model.lang.Register]:
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...


class CachedEncoder(Encoder):
    """
    An Encoder that holds its bytes in memory (where they can possibly be edited) and
    can then finally write them all to an OutputStream via a call to writeTo()
    """

    class_: typing.ClassVar[java.lang.Class]

    def clear(self):
        """
        Clear any state associated with the encoder
        The encoder should be ready to write a new document after this call.
        """

    def isEmpty(self) -> bool:
        """
        The encoder is considered empty if the writeTo() method would output zero bytes
        
        :return: true if there are no bytes in the encoder
        :rtype: bool
        """

    def writeTo(self, stream: java.io.OutputStream):
        """
        Dump all the accumulated bytes in this encoder to the stream.
        
        :param java.io.OutputStream stream: is the output stream
        :raises IOException: for errors during the write operation
        """

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class BlockMultiGoto(BlockGraph):
    """
    A block representing a 2-or-more control flow branchpoint
     
    possible multiple incoming edges
    1 or more outgoing edges (as in switch control flow)
    2 or more (implied) outgoing edges representing unstructured branch destinations   (switch case with goto statement)
     
    1 interior block representing the decision block of the switch
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def addGotoTarget(self, target: PcodeBlock):
        ...


class FunctionPrototype(java.lang.Object):
    """
    High-level prototype of a function based on Varnodes, describing the inputs and outputs
    of this function.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, ls: LocalSymbolMap, func: ghidra.program.model.listing.Function):
        """
        Construct a FunctionPrototype backed by a local symbolmap.
        This is only a partial initialization.  It is intended to be followed either by
        grabFromFunction() or readPrototypeXML()
        
        :param LocalSymbolMap ls: is the LocalSymbolMap backing the prototype
        :param ghidra.program.model.listing.Function func: is the function using the symbolmap
        """

    @typing.overload
    def __init__(self, proto: ghidra.program.model.listing.FunctionSignature, cspec: ghidra.program.model.lang.CompilerSpec, voidimpliesdotdotdot: typing.Union[jpype.JBoolean, bool]):
        """
        Construct an internally backed prototype based on a FunctionSignature prototype
        
        :param ghidra.program.model.listing.FunctionSignature proto: is the FunctionSignature used to internally back input parameters
        :param ghidra.program.model.lang.CompilerSpec cspec: is the compiler spec used to pick prototype model
        :param jpype.JBoolean or bool voidimpliesdotdotdot: set to true if a void prototype is interpreted as varargs
        """

    def decodePrototype(self, decoder: Decoder, pcodeFactory: PcodeFactory):
        """
        Decode the function prototype from a ``<prototype>`` element in the stream.
        
        :param Decoder decoder: is the stream decoder
        :param PcodeFactory pcodeFactory: is used to resolve data-type and address space references
        :raises DecoderException: for invalid encodings
        """

    def encodePrototype(self, encoder: Encoder, dtmanage: PcodeDataTypeManager, firstVarArg: typing.Union[jpype.JInt, int]):
        """
        Encode this function prototype to a stream.
        
        :param Encoder encoder: is the stream encoder
        :param PcodeDataTypeManager dtmanage: is the DataTypeManager for building type reference tags
        :param jpype.JInt or int firstVarArg: is index of first variable argument or -1
        :raises IOException: for errors in the underlying stream
        """

    def getExtraPop(self) -> int:
        """
        
        
        :return: the number of extra bytes popped off by this functions return
        :rtype: int
        """

    def getModelName(self) -> str:
        """
        
        
        :return: calling convention model name specific to the associated compiler spec
        :rtype: str
        """

    def getNumParams(self) -> int:
        """
        
        
        :return: the number of defined parameters for this function prototype
        :rtype: int
        """

    def getParam(self, i: typing.Union[jpype.JInt, int]) -> HighSymbol:
        """
        
        
        :param jpype.JInt or int i: i'th parameter index
        :return: the i'th HighParam to this function prototype or null
        if this prototype is not backed by a LocalSymbolMap
        :rtype: HighSymbol
        """

    def getParameterDefinitions(self) -> jpype.JArray[ghidra.program.model.data.ParameterDefinition]:
        """
        
        
        :return: parameter definitions if prototype was produced
        from a FunctionSignature or null if backed by a 
        LocalSymbolMap
        :rtype: jpype.JArray[ghidra.program.model.data.ParameterDefinition]
        """

    def getReturnStorage(self) -> ghidra.program.model.listing.VariableStorage:
        """
        
        
        :return: the return storage for the function
        :rtype: ghidra.program.model.listing.VariableStorage
        """

    def getReturnType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        :return: the return type for the function
        :rtype: ghidra.program.model.data.DataType
        """

    def hasNoReturn(self) -> bool:
        """
        
        
        :return: true if calls to this function do not return
        :rtype: bool
        """

    def hasThisPointer(self) -> bool:
        """
        
        
        :return: true if this function is a method taking a 'this' pointer as a parameter
        :rtype: bool
        """

    def isBackedByLocalSymbolMap(self) -> bool:
        """
        
        
        :return: true if this prototype is backed by a LocalSymbolMap, or 
        false if generated from a FunctionSignature.
        :rtype: bool
        """

    def isConstructor(self) -> bool:
        """
        
        
        :return: true if this function is an (object-oriented) constructor
        :rtype: bool
        """

    def isDestructor(self) -> bool:
        """
        
        
        :return: true if this function is an (object-oriented) destructor
        :rtype: bool
        """

    def isInline(self) -> bool:
        """
        
        
        :return: true if this function should be inlined by the decompile
        :rtype: bool
        """

    def isVarArg(self) -> bool:
        """
        
        
        :return: true if this function has variable arguments
        :rtype: bool
        """

    @property
    def modelName(self) -> java.lang.String:
        ...

    @property
    def inline(self) -> jpype.JBoolean:
        ...

    @property
    def numParams(self) -> jpype.JInt:
        ...

    @property
    def param(self) -> HighSymbol:
        ...

    @property
    def parameterDefinitions(self) -> jpype.JArray[ghidra.program.model.data.ParameterDefinition]:
        ...

    @property
    def varArg(self) -> jpype.JBoolean:
        ...

    @property
    def destructor(self) -> jpype.JBoolean:
        ...

    @property
    def constructor(self) -> jpype.JBoolean:
        ...

    @property
    def extraPop(self) -> jpype.JInt:
        ...

    @property
    def returnType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def backedByLocalSymbolMap(self) -> jpype.JBoolean:
        ...

    @property
    def returnStorage(self) -> ghidra.program.model.listing.VariableStorage:
        ...


class BlockIfGoto(BlockGraph):
    """
    Block representing an if () goto control flow
     
    possible multiple incoming edges
    1 output edge if the condition is false
    1 (implied) output edge representing the unstructured control flow if the condition is true
     
    1 block evaluating the condition
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getGotoTarget(self) -> PcodeBlock:
        ...

    def getGotoType(self) -> int:
        ...

    def setGotoTarget(self, bl: PcodeBlock):
        ...

    @property
    def gotoTarget(self) -> PcodeBlock:
        ...

    @gotoTarget.setter
    def gotoTarget(self, value: PcodeBlock):
        ...

    @property
    def gotoType(self) -> jpype.JInt:
        ...


class PackedBytes(java.io.OutputStream):
    """
    A class for dynamically collecting a stream of bytes and then later dumping those bytes to a stream
    It allows the bytes to be edited in the middle of collection
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, startlen: typing.Union[jpype.JInt, int]):
        ...

    def find(self, start: typing.Union[jpype.JInt, int], val: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getByte(self, streampos: typing.Union[jpype.JInt, int]) -> int:
        """
        Inspect the middle of the byte stream accumulated so far
        
        :param jpype.JInt or int streampos: is the index of the byte to inspect
        :return: a byte value from the stream
        :rtype: int
        """

    def insertByte(self, streampos: typing.Union[jpype.JInt, int], val: typing.Union[jpype.JInt, int]):
        """
        Overwrite bytes that have already been written into the stream
        
        :param jpype.JInt or int streampos: is the index of the byte to overwrite
        :param jpype.JInt or int val: is the value to overwrite with
        """

    def size(self) -> int:
        ...

    @typing.overload
    def write(self, val: typing.Union[jpype.JInt, int]):
        """
        Dump a single byte to the packed byte stream
        
        :param jpype.JInt or int val: is the byte to be written
        """

    @typing.overload
    def write(self, byteArray: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], len: typing.Union[jpype.JInt, int]):
        """
        Dump an array of bytes to the packed byte stream
        
        :param jpype.JArray[jpype.JByte] byteArray: is the byte array
        """

    def writeTo(self, s: java.io.OutputStream):
        """
        Write the accumulated packed byte stream onto the output stream
        
        :param java.io.OutputStream s: is the output stream receiving the bytes
        :raises IOException: for stream errors
        """

    @property
    def byte(self) -> jpype.JInt:
        ...


class HighFunction(PcodeSyntaxTree):
    """
    High-level abstraction associated with a low level function made up of assembly instructions.
    Based on information the decompiler has produced after working on a function.
    """

    class_: typing.ClassVar[java.lang.Class]
    DECOMPILER_TAG_MAP: typing.Final = "decompiler_tags"
    OVERRIDE_NAMESPACE_NAME: typing.Final = "override"

    def __init__(self, function: ghidra.program.model.listing.Function, language: ghidra.program.model.lang.Language, compilerSpec: ghidra.program.model.lang.CompilerSpec, dtManager: PcodeDataTypeManager):
        """
        
        
        :param ghidra.program.model.listing.Function function: function associated with the higher level function abstraction.
        :param ghidra.program.model.lang.Language language: description of the processor language of the function
        :param ghidra.program.model.lang.CompilerSpec compilerSpec: description of the compiler that produced the function
        :param PcodeDataTypeManager dtManager: data type manager
        """

    @staticmethod
    def clearNamespace(symtab: ghidra.program.model.symbol.SymbolTable, space: ghidra.program.model.symbol.Namespace) -> bool:
        ...

    @staticmethod
    def collapseToGlobal(namespace: ghidra.program.model.symbol.Namespace) -> bool:
        """
        The decompiler treats some namespaces as equivalent to the "global" namespace.
        Return true if the given namespace is treated as equivalent.
        
        :param ghidra.program.model.symbol.Namespace namespace: is the namespace
        :return: true if equivalent
        :rtype: bool
        """

    @staticmethod
    def createLabelSymbol(symtab: ghidra.program.model.symbol.SymbolTable, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace, source: ghidra.program.model.symbol.SourceType, useLocalNamespace: typing.Union[jpype.JBoolean, bool]):
        ...

    @staticmethod
    def deleteSymbol(symtab: ghidra.program.model.symbol.SymbolTable, addr: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], space: ghidra.program.model.symbol.Namespace):
        ...

    def encode(self, encoder: Encoder, id: typing.Union[jpype.JLong, int], namespace: ghidra.program.model.symbol.Namespace, entryPoint: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]):
        """
        Encode this HighFunction to a stream. The size describes how many bytes starting from the
        entry point are used by the function, but this doesn't need to be strictly accurate as it
        is only used to associate the function with addresses near its entry point.
        
        :param Encoder encoder: is the stream encoder
        :param jpype.JLong or int id: is the id associated with the function symbol
        :param ghidra.program.model.symbol.Namespace namespace: is the namespace containing the function symbol
        :param ghidra.program.model.address.Address entryPoint: pass null to use the function entryPoint, pass an address to force an entry point
        :param jpype.JInt or int size: describes how many bytes the function occupies as code
        :raises IOException: for errors in the underlying stream
        """

    @staticmethod
    def encodeNamespace(encoder: Encoder, namespace: ghidra.program.model.symbol.Namespace, transformer: ghidra.program.model.symbol.NameTransformer):
        """
        Encode <parent> element to the stream describing the formal path elements
        from the root (global) namespace up to the given namespace
        
        :param Encoder encoder: is the stream encoder
        :param ghidra.program.model.symbol.Namespace namespace: is the namespace being described
        :param ghidra.program.model.symbol.NameTransformer transformer: is used to computer the displayed version of each namespace
        :raises IOException: for errors in the underlying stream
        """

    @staticmethod
    def findCreateNamespace(symtab: ghidra.program.model.symbol.SymbolTable, parentspace: ghidra.program.model.symbol.Namespace, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Namespace:
        ...

    @staticmethod
    def findCreateOverrideSpace(func: ghidra.program.model.listing.Function) -> ghidra.program.model.symbol.Namespace:
        ...

    @staticmethod
    def findNamespace(symtab: ghidra.program.model.symbol.SymbolTable, parent: ghidra.program.model.symbol.Namespace, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Namespace:
        ...

    @staticmethod
    def findOverrideSpace(func: ghidra.program.model.listing.Function) -> ghidra.program.model.symbol.Namespace:
        ...

    def getCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...

    def getFunction(self) -> ghidra.program.model.listing.Function:
        """
        
        
        :return: get the associated low level function
        :rtype: ghidra.program.model.listing.Function
        """

    def getFunctionPrototype(self) -> FunctionPrototype:
        """
        
        
        :return: the function prototype for the function (how things are passed/returned)
        :rtype: FunctionPrototype
        """

    def getGlobalSymbolMap(self) -> GlobalSymbolMap:
        """
        
        
        :return: a map describing global variables accessed by this function
        :rtype: GlobalSymbolMap
        """

    def getID(self) -> int:
        """
        Get the id with the associated function symbol, if it exists.
        Otherwise return a dynamic id based on the entry point.
        
        :return: the symbol id, or possibly a dynamic id
        :rtype: int
        """

    def getJumpTables(self) -> jpype.JArray[JumpTable]:
        """
        
        
        :return: an array of jump table definitions found for this function decompilation
        :rtype: jpype.JArray[JumpTable]
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        
        
        :return: get the language parser used to disassemble
        :rtype: ghidra.program.model.lang.Language
        """

    def getLocalSymbolMap(self) -> LocalSymbolMap:
        """
        
        
        :return: the local variable map describing the defined local variables
        :rtype: LocalSymbolMap
        """

    def getMappedSymbol(self, addr: ghidra.program.model.address.Address, pcaddr: ghidra.program.model.address.Address) -> HighSymbol:
        ...

    def grabFromFunction(self, overrideExtrapop: typing.Union[jpype.JInt, int], includeDefaultNames: typing.Union[jpype.JBoolean, bool], doOverride: typing.Union[jpype.JBoolean, bool]):
        """
        Populate the information for the HighFunction from the information in the
        Function object.
        
        :param jpype.JInt or int overrideExtrapop: is the value to use if extrapop is overridden
        :param jpype.JBoolean or bool includeDefaultNames: is true if default symbol names should be considered locked
        :param jpype.JBoolean or bool doOverride: is true if extrapop is overridden
        """

    @staticmethod
    def isOverrideNamespace(namespace: ghidra.program.model.symbol.Namespace) -> bool:
        ...

    def splitOutMergeGroup(self, high: HighVariable, vn: Varnode) -> HighVariable:
        """
        If a HighVariable consists of more than one (forced) merge group, split out the group
        that contains vn as a separate HighVariable. Otherwise just return the original high.
        
        :param HighVariable high: is the HighVariable to split
        :param Varnode vn: is a representative of the merge group to split out
        :return: a HighVariable containing just the forced merge group of vn
        :rtype: HighVariable
        :raises PcodeException: if the split can't be performed
        """

    @staticmethod
    def tagFindExclude(tagname: typing.Union[java.lang.String, str], doc: typing.Union[java.lang.String, str]) -> str:
        """
        
        
        :param java.lang.String or str tagname: -- Name of tag to search for
        :param java.lang.String or str doc: -- String through which to search for tags
        :return: all characters between beginning and ending XML tags, excluding tags themselves
        :rtype: str
        """

    @property
    def functionPrototype(self) -> FunctionPrototype:
        ...

    @property
    def jumpTables(self) -> jpype.JArray[JumpTable]:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def iD(self) -> jpype.JLong:
        ...

    @property
    def globalSymbolMap(self) -> GlobalSymbolMap:
        ...

    @property
    def localSymbolMap(self) -> LocalSymbolMap:
        ...

    @property
    def compilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...


class BlockWhileDo(BlockGraph):
    """
    Block representing a while-do (exit from the top) loop construction
     
    possible multiple incoming edges
    1 outgoing exit edge
    1 (implied) loop edge
     
    1 interior block representing the top of the loop and the decision point for staying in the loop
    1 interior block representing the body of the loop, which always exits back to the top of the loop
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class XmlEncode(CachedEncoder):
    """
    An XML based encoder
    The underlying transfer encoding is an XML document.
    The encoder is initialized with a StringBuilder which will receive the XML document as calls
    are made on the encoder.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, doFormat: typing.Union[jpype.JBoolean, bool]):
        ...


class SymbolEntry(java.lang.Object):
    """
    A mapping from a HighSymbol object to the storage that holds the symbol's value.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sym: HighSymbol):
        """
        Constructor for use with restoreXML
        
        :param HighSymbol sym: is the symbol owning this entry
        """

    def decode(self, decoder: Decoder):
        """
        Decode this entry from the stream. Typically more than one element is consumed.
        
        :param Decoder decoder: is the stream decoder
        :raises DecoderException: for invalid encodings
        """

    def encode(self, encoder: Encoder):
        """
        Encode this entry as (a set of) elements to the given stream
        
        :param Encoder encoder: is the stream encoder
        :raises IOException: for errors in the underlying stream
        """

    def getMutability(self) -> int:
        """
        Return one of
            - MutabilitySettingsDefinition.NORMAL
            - MutabilitySettingsDefinition.VOLATILE
            - MutabilitySettingsDefinition.CONSTANT
        
        :return: the mutability setting
        :rtype: int
        """

    def getPCAdress(self) -> ghidra.program.model.address.Address:
        """
        The storage used to hold this Symbol may be used for other purposes at different points in
        the code.  This returns the earliest address in the code where this storage is used for this symbol
        
        :return: the starting address where the Symbol uses this storage
        :rtype: ghidra.program.model.address.Address
        """

    def getSize(self) -> int:
        """
        Get the number of bytes consumed by the symbol when using this storage
        
        :return: the size of this entry
        :rtype: int
        """

    def getStorage(self) -> ghidra.program.model.listing.VariableStorage:
        """
        Get the storage associated with this particular mapping of the Symbol
        
        :return: the storage object
        :rtype: ghidra.program.model.listing.VariableStorage
        """

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def storage(self) -> ghidra.program.model.listing.VariableStorage:
        ...

    @property
    def mutability(self) -> jpype.JInt:
        ...

    @property
    def pCAdress(self) -> ghidra.program.model.address.Address:
        ...


class Varnode(java.lang.Object):
    """
    Rawest possible Varnode.
    Just a variable location and size, not part of a syntax tree.
    A raw varnode is said to be free, it is not attached to any variable.
    """

    class Join(java.lang.Object):
        """
        Set of Varnode pieces referred to by a single Varnode in join space
        as returned by Varnode.decodePieces
        """

        class_: typing.ClassVar[java.lang.Class]
        pieces: jpype.JArray[Varnode]
        logicalSize: jpype.JInt

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, a: ghidra.program.model.address.Address, sz: typing.Union[jpype.JInt, int]):
        """
        
        
        :param ghidra.program.model.address.Address a: location varnode attached to
        :param jpype.JInt or int sz: size of varnode
        """

    @typing.overload
    def __init__(self, a: ghidra.program.model.address.Address, sz: typing.Union[jpype.JInt, int], symbolKey: typing.Union[jpype.JInt, int]):
        """
        
        
        :param ghidra.program.model.address.Address a: location varnode attached to
        :param jpype.JInt or int sz: size of varnode
        :param jpype.JInt or int symbolKey: associated symbol key
        """

    def contains(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Determine if this varnode contains the specified address
        
        :param ghidra.program.model.address.Address addr: the address for which to check
        :return: true if this varnode contains the specified address
        :rtype: bool
        """

    @staticmethod
    def decode(decoder: Decoder, factory: PcodeFactory) -> Varnode:
        """
        Decode a Varnode from a stream
        
        :param Decoder decoder: is the stream decoder
        :param PcodeFactory factory: pcode factory used to create valid pcode
        :return: the new Varnode
        :rtype: Varnode
        :raises DecoderException: if the Varnode is improperly encoded
        """

    @staticmethod
    def decodePieces(decoder: Decoder) -> Varnode.Join:
        """
        Decode a sequence of Varnodes from "piece" attributes for the current open element.
        The Varnodes are normally associated with an Address in the "join" space. In this virtual
        space, a contiguous sequence of bytes, at a specific Address, represent a logical value
        that may physically be split across multiple registers or other storage locations.
        
        :param Decoder decoder: is the stream decoder
        :return: an array of decoded Varnodes and the logical size
        :rtype: Varnode.Join
        :raises DecoderException: for any errors in the encoding
        """

    def encodePiece(self) -> str:
        """
        Encode details of the Varnode as a formatted string with three colon separated fields.
        space:offset:size
        The name of the address space, the offset of the address as a hex number, and
        the size field as a decimal number.
        
        :return: the formatted String
        :rtype: str
        """

    def encodeRaw(self, encoder: Encoder):
        """
        Encode just the raw storage info for this Varnode to stream
        
        :param Encoder encoder: is the stream encoder
        :raises IOException: for errors in the underlying stream
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the address this varnode is attached to
        :rtype: ghidra.program.model.address.Address
        """

    def getDef(self) -> PcodeOp:
        """
        
        
        :return: get the pcode op this varnode belongs to
        :rtype: PcodeOp
        """

    def getDescendants(self) -> java.util.Iterator[PcodeOp]:
        """
        
        
        :return: iterator to all PcodeOp s that take this as input
        :rtype: java.util.Iterator[PcodeOp]
        """

    def getHigh(self) -> HighVariable:
        """
        
        
        :return: the high level variable this varnode represents
        :rtype: HighVariable
        """

    def getLoneDescend(self) -> PcodeOp:
        """
        If there is only one PcodeOp taking this varnode as input, return it. Otherwise return null
        
        :return: the lone descendant PcodeOp
        :rtype: PcodeOp
        """

    def getMergeGroup(self) -> int:
        """
        
        
        :return: the index of the group, within the high containing this, that are forced merged with this
        :rtype: int
        """

    def getOffset(self) -> int:
        """
        
        
        :return: the offset into the address space varnode is defined within
        :rtype: int
        """

    def getPCAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the address where this varnode is defined or
        NO_ADDRESS if this varnode is an input
        
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    def getSize(self) -> int:
        """
        
        
        :return: size of the varnode in bytes
        :rtype: int
        """

    def getSpace(self) -> int:
        """
        
        
        :return: the space this varnode belongs to (ram, register, ...)
        :rtype: int
        """

    def getWordOffset(self) -> int:
        """
        Returns the word offset into the address space this is defined within
         
        The word size is defined in the Language's .slaspec file with the
        "WORDSIZE" argument when DEFINEing a memory SPACE (capitalization is
        for emphasis; the directives are actually lowercase).
        
        :return: the word offset into the address space this is defined within
        :rtype: int
        """

    def hasNoDescend(self) -> bool:
        """
        
        
        :return: false if the Varnode has a PcodeOp reading it that is part of function data-flow
        :rtype: bool
        """

    @typing.overload
    def intersects(self, varnode: Varnode) -> bool:
        """
        Determine if this varnode intersects another varnode.
        
        :param Varnode varnode: other varnode
        :return: true if this varnode intersects the specified varnode
        :rtype: bool
        """

    @typing.overload
    def intersects(self, set: ghidra.program.model.address.AddressSetView) -> bool:
        """
        Determine if this varnode intersects the specified address set
        
        :param ghidra.program.model.address.AddressSetView set: address set
        :return: true if this varnode intersects the specified address set
        :rtype: bool
        """

    def isAddrTied(self) -> bool:
        """
        
        
        :return: is mapped to an address
        :rtype: bool
        """

    def isAddress(self) -> bool:
        """
        
        
        :return: true if this varnode exists in a Memory space (vs. register etc...).
        Keep in mind this varnode may also correspond to a defined register 
        if true is returned and :meth:`isRegister() <.isRegister>` return false.  
        Memory-based registers may be indirectly addressed which leads to the 
        distinction with registers within the register space.
        :rtype: bool
        """

    def isConstant(self) -> bool:
        """
        
        
        :return: true if this varnode is just a constant number
        :rtype: bool
        """

    def isContiguous(self, lo: Varnode, bigEndian: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Is this contiguous (as the most significant piece) with the given Varnode
        
        :param Varnode lo: is the other Varnode to compare with
        :param jpype.JBoolean or bool bigEndian: is true for big endian significance ordering
        :return: true if the two byte ranges are contiguous and in order
        :rtype: bool
        """

    def isFree(self) -> bool:
        ...

    def isHash(self) -> bool:
        ...

    def isInput(self) -> bool:
        """
        
        
        :return: is input to a pcode op
        :rtype: bool
        """

    def isPersistent(self) -> bool:
        """
        
        
        :return: is persistent
        :rtype: bool
        """

    def isRegister(self) -> bool:
        """
        
        
        :return: true if this varnode exists in a Register type space.
        If false is returned, keep in mind this varnode may still correspond to a 
        defined register within a memory space.  Memory-based registers may be indirectly 
        addressed which leads to the distinction with registers within the register space.
        :rtype: bool
        """

    def isUnaffected(self) -> bool:
        ...

    def isUnique(self) -> bool:
        """
        
        
        :return: true if this varnode doesn't exist anywhere.  A temporary variable.
        :rtype: bool
        """

    def toString(self, language: ghidra.program.model.lang.Language) -> str:
        """
        Convert this varnode to an alternate String representation based on a specified language.
        
        :param ghidra.program.model.lang.Language language: is the specified Language
        :return: string representation
        :rtype: str
        """

    def trim(self):
        """
        Trim a varnode in a constant space to the correct starting offset.
         
        Constant handles may contain constants of indeterminate size.
        This is where the size gets fixed, i.e. we mask off the constant
        to its proper size.  A varnode that is ends up in pcode should
        call this method to ensure that varnodes always contains raw data.
        On the other hand, varnodes in handles are allowed to have offsets
        that violate size restrictions.
        """

    @property
    def constant(self) -> jpype.JBoolean:
        ...

    @property
    def mergeGroup(self) -> jpype.JShort:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def loneDescend(self) -> PcodeOp:
        ...

    @property
    def descendants(self) -> java.util.Iterator[PcodeOp]:
        ...

    @property
    def space(self) -> jpype.JInt:
        ...

    @property
    def pCAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def input(self) -> jpype.JBoolean:
        ...

    @property
    def addrTied(self) -> jpype.JBoolean:
        ...

    @property
    def high(self) -> HighVariable:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def def_(self) -> PcodeOp:
        ...

    @property
    def unique(self) -> jpype.JBoolean:
        ...

    @property
    def persistent(self) -> jpype.JBoolean:
        ...

    @property
    def free(self) -> jpype.JBoolean:
        ...

    @property
    def wordOffset(self) -> jpype.JLong:
        ...

    @property
    def hash(self) -> jpype.JBoolean:
        ...

    @property
    def unaffected(self) -> jpype.JBoolean:
        ...

    @property
    def register(self) -> jpype.JBoolean:
        ...


class HighVariable(java.lang.Object):
    """
    A High-level variable (as in a high-level language like C/C++)
    built out of Varnodes (low-level variables).  This is a base-class
    """

    class_: typing.ClassVar[java.lang.Class]

    def attachInstances(self, inst: jpype.JArray[Varnode], rep: Varnode):
        """
        Attach an instance or additional location the variable can be found in.
        
        :param jpype.JArray[Varnode] inst: varnode where variable can reside.
        :param Varnode rep: location that variable comes into scope.
        """

    def decode(self, decoder: Decoder):
        """
        Decode this HighVariable from a ``<high>`` element in the stream
        
        :param Decoder decoder: is the stream decoder
        :raises DecoderException: for invalid encodings
        """

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        :return: get the data type attached to the variable
        :rtype: ghidra.program.model.data.DataType
        """

    def getHighFunction(self) -> HighFunction:
        """
        
        
        :return: the high function associated with this variable.
        :rtype: HighFunction
        """

    def getInstances(self) -> jpype.JArray[Varnode]:
        """
        A variable can reside in different locations at various times.
        Get all the instances of the variable.
        
        :return: all the variables instances
        :rtype: jpype.JArray[Varnode]
        """

    def getName(self) -> str:
        """
        
        
        :return: get the name of the variable
        :rtype: str
        """

    def getOffset(self) -> int:
        """
        Get the offset of this variable into its containing HighSymbol.  If the value
        is -1, this indicates that this HighVariable matches the size and storage of the symbol.
        
        :return: the offset
        :rtype: int
        """

    def getRepresentative(self) -> Varnode:
        """
        
        
        :return: get the varnode that represents this variable
        :rtype: Varnode
        """

    def getSize(self) -> int:
        """
        
        
        :return: get the size of the variable
        :rtype: int
        """

    def getSymbol(self) -> HighSymbol:
        """
        Retrieve any underlying HighSymbol
        
        :return: the HighSymbol
        :rtype: HighSymbol
        """

    def requiresDynamicStorage(self) -> bool:
        """
        Return true in when the HighVariable should be recorded (in the database) using dynamic storage
        rather than using the actual address space and offset of the representative varnode.  Dynamic storage
        is typically needed if the actual storage is ephemeral (in the unique space).
        
        :return: true if this needs dynamic storage
        :rtype: bool
        """

    @property
    def symbol(self) -> HighSymbol:
        ...

    @property
    def highFunction(self) -> HighFunction:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def instances(self) -> jpype.JArray[Varnode]:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def representative(self) -> Varnode:
        ...


class DecoderException(PcodeException):
    """
    Exception thrown for errors decoding decompiler objects from stream
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


class PartialUnion(ghidra.program.model.data.AbstractDataType):
    """
    A data-type representing an unspecified piece of a parent Union data-type.  This is used
    internally by the decompiler to label Varnodes representing partial symbols, where the
    part is known to be contained in a Union data-type.  Within the isolated context of a Varnode,
    its not possible to resolve to a specific field of the Union because the Varnode may be used
    in multiple ways.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getOffset(self) -> int:
        """
        
        
        :return: the offset, in bytes, of this part within its parent Union
        :rtype: int
        """

    def getParent(self) -> ghidra.program.model.data.DataType:
        """
        
        
        :return: the Union data-type of which this is a part
        :rtype: ghidra.program.model.data.DataType
        """

    def getStrippedDataType(self) -> ghidra.program.model.data.DataType:
        """
        Get a data-type that can be used as a formal replacement for this (internal) data-type
        
        :return: a replacement data-type
        :rtype: ghidra.program.model.data.DataType
        """

    @property
    def parent(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def offset(self) -> jpype.JInt:
        ...

    @property
    def strippedDataType(self) -> ghidra.program.model.data.DataType:
        ...


class HighParam(HighLocal):
    """
    High-level function parameter
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, high: HighFunction):
        """
        Constructor for use with restoreXml
        
        :param HighFunction high: is the HighFunction containing this parameter
        """

    @typing.overload
    def __init__(self, tp: ghidra.program.model.data.DataType, rep: Varnode, pc: ghidra.program.model.address.Address, slot: typing.Union[jpype.JInt, int], sym: HighSymbol):
        """
        
        
        :param ghidra.program.model.data.DataType tp: data type of variable
        :param Varnode rep: is the representative input Varnode
        :param ghidra.program.model.address.Address pc: null or Address of PcodeOp which defines the representative
        :param jpype.JInt or int slot: parameter index starting at 0
        :param HighSymbol sym: associated symbol
        """

    def getSlot(self) -> int:
        """
        
        
        :return: get the slot or parameter index
        :rtype: int
        """

    @property
    def slot(self) -> jpype.JInt:
        ...


class LinkedByteBuffer(java.lang.Object):
    """
    A byte buffer that is stored as a linked list of pages.  Each page holds BUFFER_SIZE bytes.
    A Position object acts as an iterator over the whole buffer.  The buffer can be populated
    from a stream, either all at once or "as needed" when a Position object iterates past
    the current cached set of bytes.
    """

    class Position(java.lang.Object):
        """
        An iterator into the byte buffer
        """

        class_: typing.ClassVar[java.lang.Class]
        buffer: LinkedByteBuffer
        seqIter: LinkedByteBuffer.ArrayIter
        array: jpype.JArray[jpype.JByte]
        current: jpype.JInt

        def __init__(self):
            ...

        def advancePosition(self, skip: typing.Union[jpype.JInt, int]):
            """
            Advance this Position by the specified number of bytes
            
            :param jpype.JInt or int skip: is the specified number of bytes to advance
            :raises DecoderException: if the end of stream is reached
            """

        def copy(self, pos: LinkedByteBuffer.Position):
            """
            Set this to be a copy of another Position
            
            :param LinkedByteBuffer.Position pos: is the Position being copied
            """

        def getByte(self) -> int:
            """
            Return the byte at the current Position. Do not advance the Position.
            
            :return: the byte at this Position
            :rtype: int
            """

        def getBytePlus1(self) -> int:
            """
            Lookahead exactly one byte, without advancing this Position
            
            :return: the byte after the one at this Position
            :rtype: int
            :raises DecoderException: if the end of stream is reached
            """

        def getNextByte(self) -> int:
            """
            Advance this Position by exactly one byte and return the next byte.
            
            :return: the next byte
            :rtype: int
            :raises DecoderException: if the end of stream is reached
            """

        @property
        def nextByte(self) -> jpype.JByte:
            ...

        @property
        def byte(self) -> jpype.JByte:
            ...

        @property
        def bytePlus1(self) -> jpype.JByte:
            ...


    class ArrayIter(java.lang.Object):
        """
        A linked-list page node
        """

        class_: typing.ClassVar[java.lang.Class]
        next: LinkedByteBuffer.ArrayIter
        array: jpype.JArray[jpype.JByte]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    BUFFER_SIZE: typing.Final = 1024

    def __init__(self, max: typing.Union[jpype.JInt, int], pad: typing.Union[jpype.JInt, int], desc: typing.Union[java.lang.String, str]):
        ...

    def close(self):
        """
        Close the "as needed" stream, if configure.
        
        :raises IOException: for problems closing the stream
        """

    def getStartPosition(self, position: LinkedByteBuffer.Position):
        ...

    def ingestBytes(self, byteArray: jpype.JArray[jpype.JByte], off: typing.Union[jpype.JInt, int], sz: typing.Union[jpype.JInt, int]):
        """
        Ingest bytes directly from a byte array.
        If these bytes would cause the total number of bytes ingested to exceed
        the maximum (maxCount) bytes set for this buffer, an exception is thrown.
        This can be called multiple times to read in different chunks.
        
        :param jpype.JArray[jpype.JByte] byteArray: is the array of bytes
        :param jpype.JInt or int off: is the index of the first byte to ingest
        :param jpype.JInt or int sz: is the number of bytes to ingest
        :raises IOException: if the max number of bytes to ingest is exceeded
        """

    def ingestStream(self, stream: java.io.InputStream):
        """
        Read the stream until the end of stream is encountered or until maxCount bytes is reached.
        Store the bytes on the heap in BUFFER_SIZE chunks.
        
        :param java.io.InputStream stream: is the input
        :raises IOException: for errors reading from the stream
        """

    def ingestStreamAsNeeded(self, stream: java.io.InputStream, start: LinkedByteBuffer.Position):
        """
        Set up this buffer so that it reads in pages as needed.  The initial page is read
        immediately.  Additional pages are read via readNextPage() through the Position methods.
        
        :param java.io.InputStream stream: is the stream to read from
        :param LinkedByteBuffer.Position start: will hold the initial buffer
        :raises IOException: for problems reading data from the stream
        """

    def ingestStreamToNextTerminator(self, stream: java.io.InputStream):
        """
        Ingest stream up to the first 0 byte or until maxCount bytes is reached.
        Store the bytes on the heap in BUFFER_SIZE chunks.
        
        :param java.io.InputStream stream: is the input
        :raises IOException: for errors reading from the stream
        """

    def pad(self):
        """
        Add the padValue to the end of the buffer
        """


class PcodeBlock(java.lang.Object):
    """
    Blocks of PcodeOps
    """

    class BlockEdge(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        label: jpype.JInt
        point: PcodeBlock
        reverse_index: jpype.JInt

        @typing.overload
        def __init__(self, pt: PcodeBlock, lab: typing.Union[jpype.JInt, int], rev: typing.Union[jpype.JInt, int]):
            ...

        @typing.overload
        def __init__(self):
            """
            For use with restoreXml
            """

        @typing.overload
        def decode(self, decoder: Decoder, resolver: BlockMap):
            """
            Decode a single edge
            
            :param Decoder decoder: is the stream decoder
            :param BlockMap resolver: used to recover PcodeBlock reference
            :raises DecoderException: for invalid encodings
            """

        @typing.overload
        def decode(self, decoder: Decoder, blockList: java.util.ArrayList[PcodeBlock]):
            ...

        def encode(self, encoder: Encoder):
            """
            Encode edge to stream assuming we already know what block we are in
            
            :param Encoder encoder: is the stream encoder
            :raises IOException: for errors writing to underlying stream
            """


    class_: typing.ClassVar[java.lang.Class]
    PLAIN: typing.Final = 0
    BASIC: typing.Final = 1
    GRAPH: typing.Final = 2
    COPY: typing.Final = 3
    GOTO: typing.Final = 4
    MULTIGOTO: typing.Final = 5
    LIST: typing.Final = 6
    CONDITION: typing.Final = 7
    PROPERIF: typing.Final = 8
    IFELSE: typing.Final = 9
    IFGOTO: typing.Final = 10
    WHILEDO: typing.Final = 11
    DOWHILE: typing.Final = 12
    SWITCH: typing.Final = 13
    INFLOOP: typing.Final = 14

    def __init__(self):
        ...

    def calcDepth(self, leaf: PcodeBlock) -> int:
        ...

    def decode(self, decoder: Decoder, resolver: BlockMap):
        """
        Decode this block from a stream
        
        :param Decoder decoder: is the stream decoder
        :param BlockMap resolver: is the map from reference to block object
        :raises DecoderException: for errors in the encoding
        """

    def encode(self, encoder: Encoder):
        """
        Encode this block to a stream
        
        :param Encoder encoder: is the stream encoder
        :raises IOException: for errors writing to the underlying stream
        """

    def getFalseOut(self) -> PcodeBlock:
        """
        Assuming paths out of this block depend on a boolean condition
        
        :return: the PcodeBlock coming out of this if the condition is false
        :rtype: PcodeBlock
        """

    def getFrontLeaf(self) -> PcodeBlock:
        ...

    def getIn(self, i: typing.Union[jpype.JInt, int]) -> PcodeBlock:
        ...

    def getInRevIndex(self, i: typing.Union[jpype.JInt, int]) -> int:
        """
        Get reverse index of the i-th incoming block. I.e. this.getIn(i).getOut(reverse_index) == this
        
        :param jpype.JInt or int i: is the incoming block to request reverse index from
        :return: the reverse index
        :rtype: int
        """

    def getInSize(self) -> int:
        ...

    def getIndex(self) -> int:
        ...

    def getOut(self, i: typing.Union[jpype.JInt, int]) -> PcodeBlock:
        ...

    def getOutRevIndex(self, i: typing.Union[jpype.JInt, int]) -> int:
        """
        Get reverse index of the i-th outgoing block. I.e this.getOut(i).getIn(reverse_index) == this
        
        :param jpype.JInt or int i: is the outgoing block to request reverse index from
        :return: the reverse index
        :rtype: int
        """

    def getOutSize(self) -> int:
        ...

    def getParent(self) -> PcodeBlock:
        ...

    def getStart(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the first Address covered by this block
        :rtype: ghidra.program.model.address.Address
        """

    def getStop(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the last Address covered by this block
        :rtype: ghidra.program.model.address.Address
        """

    def getTrueOut(self) -> PcodeBlock:
        """
        Assuming paths out of this block depend on a boolean condition
        
        :return: the PcodeBlock coming out of this if the condition is true
        :rtype: PcodeBlock
        """

    def getType(self) -> int:
        ...

    @staticmethod
    def nameToType(name: typing.Union[java.lang.String, str]) -> int:
        ...

    def setIndex(self, i: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def typeToName(type: typing.Union[jpype.JInt, int]) -> str:
        ...

    @property
    def parent(self) -> PcodeBlock:
        ...

    @property
    def inSize(self) -> jpype.JInt:
        ...

    @property
    def inRevIndex(self) -> jpype.JInt:
        ...

    @property
    def start(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def falseOut(self) -> PcodeBlock:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...

    @index.setter
    def index(self, value: jpype.JInt):
        ...

    @property
    def outSize(self) -> jpype.JInt:
        ...

    @property
    def type(self) -> jpype.JInt:
        ...

    @property
    def out(self) -> PcodeBlock:
        ...

    @property
    def stop(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def trueOut(self) -> PcodeBlock:
        ...

    @property
    def outRevIndex(self) -> jpype.JInt:
        ...

    @property
    def in_(self) -> PcodeBlock:
        ...

    @property
    def frontLeaf(self) -> PcodeBlock:
        ...


class DataTypeSymbol(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dt: ghidra.program.model.data.DataType, nr: typing.Union[java.lang.String, str], cat: typing.Union[java.lang.String, str]):
        ...

    def cleanupUnusedOverride(self):
        ...

    @staticmethod
    def deleteSymbols(nmroot: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, symtab: ghidra.program.model.symbol.SymbolTable, space: ghidra.program.model.symbol.Namespace):
        ...

    @staticmethod
    def extractHash(symname: typing.Union[java.lang.String, str]) -> str:
        ...

    @staticmethod
    def extractNameRoot(symname: typing.Union[java.lang.String, str]) -> str:
        ...

    @staticmethod
    def generateHash(dt: ghidra.program.model.data.DataType) -> int:
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @staticmethod
    def readSymbol(cat: typing.Union[java.lang.String, str], s: ghidra.program.model.symbol.Symbol) -> DataTypeSymbol:
        ...

    def writeSymbol(self, symtab: ghidra.program.model.symbol.SymbolTable, addr: ghidra.program.model.address.Address, namespace: ghidra.program.model.symbol.Namespace, dtmanage: ghidra.program.model.data.DataTypeManager, clearold: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...


class HighLabelSymbol(HighSymbol):
    """
    A symbol with no underlying data-type. A label within code. This is used to
    model named jump targets within a function to the decompiler.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, nm: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, dtmanage: PcodeDataTypeManager):
        """
        Construct the label given a name and address
        
        :param java.lang.String or str nm: is the given name
        :param ghidra.program.model.address.Address addr: is the given Address
        :param PcodeDataTypeManager dtmanage: is a PcodeDataManager to facilitate XML marshaling
        """


class PcodeException(java.lang.Exception):
    """
    Exception generated from problems with Pcode.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        ...


class GlobalSymbolMap(java.lang.Object):
    """
    A container for global symbols in the decompiler's model of a function. It contains
    HighSymbol objects for any symbol accessed by the particular function that is in either
    the global scope or some other global namespace. Currently the container is populated
    indirectly from the HighGlobal objects marshaled back from the decompiler, using either
    the populateSymbol() or newSymbol() methods. HighSymbols are stored by Address and by id,
    which matches the formal SymbolDB id when it exists.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, f: HighFunction):
        """
        Construct a global symbol map attached to a particular function model.
        
        :param HighFunction f: is the decompiler function model
        """

    @typing.overload
    def getSymbol(self, id: typing.Union[jpype.JLong, int]) -> HighSymbol:
        """
        Retrieve a HighSymbol based on an id
        
        :param jpype.JLong or int id: is the id
        :return: the matching HighSymbol or null
        :rtype: HighSymbol
        """

    @typing.overload
    def getSymbol(self, addr: ghidra.program.model.address.Address) -> HighSymbol:
        """
        Retrieve a HighSymbol based on an Address
        
        :param ghidra.program.model.address.Address addr: is the given Address
        :return: the matching HighSymbol or null
        :rtype: HighSymbol
        """

    def getSymbols(self) -> java.util.Iterator[HighSymbol]:
        """
        Get an iterator over all HighSymbols in this container
        
        :return: the iterator
        :rtype: java.util.Iterator[HighSymbol]
        """

    def newSymbol(self, id: typing.Union[jpype.JLong, int], addr: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType, sz: typing.Union[jpype.JInt, int]) -> HighCodeSymbol:
        """
        Create a HighSymbol corresponding to an underlying Data object. The name of the symbol is
        generated dynamically. A symbol is always returned unless the address is invalid,
        in which case null is returned.
        
        :param jpype.JLong or int id: is the id to associate with the new symbol
        :param ghidra.program.model.address.Address addr: is the address of the Data object
        :param ghidra.program.model.data.DataType dataType: is the recovered data-type of the symbol
        :param jpype.JInt or int sz: is the size in bytes of the symbol
        :return: the new HighSymbol or null
        :rtype: HighCodeSymbol
        """

    def populateAnnotation(self, vn: Varnode):
        """
        Some Varnode annotations refer to global symbols.  Check if there is symbol at the
        Varnode address and, if there is, create a corresponding HighSymbol
        
        :param Varnode vn: is the annotation Varnode
        """

    def populateSymbol(self, id: typing.Union[jpype.JLong, int], dataType: ghidra.program.model.data.DataType, sz: typing.Union[jpype.JInt, int]) -> HighSymbol:
        """
        Create a HighSymbol based on the id of the underlying Ghidra Symbol. The Symbol
        is looked up in the SymbolTable and then a HighSymbol is created with the name and
        dataType associated with the Symbol. If a Symbol cannot be found, null is returned.
        
        :param jpype.JLong or int id: is the database id of the CodeSymbol
        :param ghidra.program.model.data.DataType dataType: is the recovered data-type of the symbol
        :param jpype.JInt or int sz: is the size in bytes of the desired symbol
        :return: the CodeSymbol wrapped as a HighSymbol or null
        :rtype: HighSymbol
        """

    @property
    def symbol(self) -> HighSymbol:
        ...

    @property
    def symbols(self) -> java.util.Iterator[HighSymbol]:
        ...


class HighExternalSymbol(HighSymbol):
    """
    A symbol, within a decompiler model, for a function without a body in the current Program.
    The Address of this symbol corresponds to the code location that CALL instructions refer to.
    In anticipation of a (not fully resolved) thunking mechanism, this symbol also has a separate
    resolve Address, which is where the decompiler expects to retrieve the detailed Function object.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, nm: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, resolveAddr: ghidra.program.model.address.Address, dtmanage: PcodeDataTypeManager):
        """
        Construct the external reference symbol given a name, the symbol Address, and a
        resolving Address.
        
        :param java.lang.String or str nm: is the given name
        :param ghidra.program.model.address.Address addr: is the symbol Address
        :param ghidra.program.model.address.Address resolveAddr: is the resolve Address
        :param PcodeDataTypeManager dtmanage: is a PcodeDataTypeManager for facilitating XML marshaling
        """


class BlockInfLoop(BlockGraph):
    """
    Block representing an infinite loop
     
    possible multiple incoming edges
    no outgoing edges
    1 (implied) outgoing edge representing loop to the top control flow
    
    1 interior block representing the body of the loop
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class ListLinked(java.lang.Object, typing.Generic[T]):
    """
    A better linked list implementation than provided by java.util.
     
    TODO: Looks like the main benefit is a non-failing iterator.  In JDK 1.5
    this may not be needed.  1.5 has better Iterators in the collections classes.
    """

    @typing.type_check_only
    class LinkedNode(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        previousNode: ListLinked.LinkedNode
        nextNode: ListLinked.LinkedNode
        data: T


    @typing.type_check_only
    class LinkedIterator(java.util.Iterator[T]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, cur: ListLinked.LinkedNode):
            ...

        def hasPrevious(self) -> bool:
            ...

        def previous(self) -> java.lang.Object:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def add(self, o: T) -> java.util.Iterator[T]:
        """
        Add object to end of the list, any existing iterators remain valid
        
        :param T o: -- Object to be added
        :return: Iterator to new object
        :rtype: java.util.Iterator[T]
        """

    def clear(self):
        """
        Get rid of all entries on the linked list.
        """

    def first(self) -> T:
        """
        
        
        :return: the first element in the list (or null)
        :rtype: T
        """

    def insertAfter(self, itr: java.util.Iterator[T], o: T) -> java.util.Iterator[T]:
        """
        Insert new object AFTER object pointed to by iterator, other Iterators remain valid
        
        :param java.util.Iterator[T] itr: Iterator to existing object
        :param T o: New object to add
        :return: Iterator to new object
        :rtype: java.util.Iterator[T]
        """

    def insertBefore(self, itr: java.util.Iterator[T], o: T) -> java.util.Iterator[T]:
        """
        Insert new object BEFORE object pointed to by iterator, other Iterators remain valid
        
        :param java.util.Iterator[T] itr: Iterator to existing object
        :param T o: New object to add
        :return: Iterator to new object
        :rtype: java.util.Iterator[T]
        """

    def iterator(self) -> java.util.Iterator[T]:
        """
        
        
        :return: an iterator over this linked list
        :rtype: java.util.Iterator[T]
        """

    def last(self) -> T:
        """
        
        
        :return: the last element in the list (or null)
        :rtype: T
        """

    def remove(self, itr: java.util.Iterator[T]):
        """
        Remove object from list indicated by Iterator, all iterators that point to objects other
        than this one remain valid
        
        :param java.util.Iterator[T] itr: Iterator to object to be removed
        """


class PatchEncoder(CachedEncoder):
    """
    This is an encoder that produces encodings that can be retroactively patched.
    The contained encoding is expected to be byte based.  The user can record a position
    in the encoding by calling the size() method in the middle of encoding, and then later
    use the returned offset to call the patchIntegerAttribute() method and modify the
    encoding at the recorded position.
    """

    class_: typing.ClassVar[java.lang.Class]

    def patchIntegerAttribute(self, pos: typing.Union[jpype.JInt, int], attribId: AttributeId, val: typing.Union[jpype.JLong, int]) -> bool:
        """
        Replace an integer attribute for the element at the given position.
        The position is assumed to be at an open directive for the element containing the
        attribute to be patched.
        
        :param jpype.JInt or int pos: is the given position
        :param AttributeId attribId: is the attribute to be patched
        :param jpype.JLong or int val: is the new value to insert
        :return: true if the attribute is successfully patched
        :rtype: bool
        """

    def size(self) -> int:
        """
        The returned value can be used as a position for later modification
        
        :return: the number of bytes written to this stream so far
        :rtype: int
        """

    def writeSpaceId(self, attribId: AttributeId, spaceId: typing.Union[jpype.JLong, int]):
        """
        Write a given raw spaceid (as returned by AddressSpace.getSpaceID()) as an attribute.
        The effect is the same as if writeSpace() was called with the AddressSpace matching
        the spaceid, i.e. the decoder will read this as just space attribute.
        
        :param AttributeId attribId: is the attribute
        :param jpype.JLong or int spaceId: is the given spaceid
        :raises IOException: for problems writing to the stream
        """


class PcodeSyntaxTree(PcodeFactory):
    """
    Varnodes and PcodeOps in a coherent graph structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, afact: ghidra.program.model.address.AddressFactory, dtmanage: PcodeDataTypeManager):
        ...

    def clear(self):
        ...

    def decode(self, decoder: Decoder):
        ...

    def delete(self, op: PcodeOp):
        ...

    def findInputVarnode(self, sz: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address) -> Varnode:
        """
        return Varnode of given size and starting Address, which is also an input
        
        :param jpype.JInt or int sz: -- size of Varnode
        :param ghidra.program.model.address.Address addr: -- starting Address of Varnode
        :return: -- the Varnode
        :rtype: Varnode
        """

    @typing.overload
    def findVarnode(self, sz: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address, pc: ghidra.program.model.address.Address) -> Varnode:
        """
        return first instance of a Varnode with given size, starting Address,
        and bound to an instruction at the given Address
        
        :param jpype.JInt or int sz: -- size of Varnode
        :param ghidra.program.model.address.Address addr: -- starting Address of Varnode
        :param ghidra.program.model.address.Address pc: -- Address of instruction writing to Varnode
        :return: -- the Varnode
        :rtype: Varnode
        """

    @typing.overload
    def findVarnode(self, sz: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address, sq: SequenceNumber) -> Varnode:
        """
        return Varnode of given size and starting Address defined by a PcodeOp
        with a given SequenceNumber
        
        :param jpype.JInt or int sz: -- size of Varnode
        :param ghidra.program.model.address.Address addr: -- starting Address of Varnode
        :param SequenceNumber sq: -- SequenceNumber of PcodeOp defining the Varnode
        :return: -- the Varnode
        :rtype: Varnode
        """

    def getBasicBlocks(self) -> java.util.ArrayList[PcodeBlockBasic]:
        ...

    def getNumVarnodes(self) -> int:
        ...

    def getPcodeOp(self, sq: SequenceNumber) -> PcodeOp:
        ...

    @typing.overload
    def getPcodeOps(self) -> java.util.Iterator[PcodeOpAST]:
        """
        return all PcodeOps (alive or dead) ordered by SequenceNumber
        
        :return: -- Iterator to PcodeOps
        :rtype: java.util.Iterator[PcodeOpAST]
        """

    @typing.overload
    def getPcodeOps(self, addr: ghidra.program.model.address.Address) -> java.util.Iterator[PcodeOpAST]:
        """
        return all PcodeOps associated with a particular instruction Address
        
        :param ghidra.program.model.address.Address addr: -- Address of instruction generating PcodeOps
        :return: -- Iterator to PcodeOps
        :rtype: java.util.Iterator[PcodeOpAST]
        """

    @typing.overload
    def getVarnodes(self, spc: ghidra.program.model.address.AddressSpace) -> java.util.Iterator[VarnodeAST]:
        """
        return Iterator to all Varnodes in the indicated AddressSpace
        
        :param ghidra.program.model.address.AddressSpace spc: -- AddressSpace to restrict Iterator to
        :return: -- Iterator to Varnodes
        :rtype: java.util.Iterator[VarnodeAST]
        """

    @typing.overload
    def getVarnodes(self, addr: ghidra.program.model.address.Address) -> java.util.Iterator[VarnodeAST]:
        """
        return all Varnodes that start at a given Address
        
        :param ghidra.program.model.address.Address addr: -- Address of Varnodes
        :return: -- Iterator to Varnodes
        :rtype: java.util.Iterator[VarnodeAST]
        """

    @typing.overload
    def getVarnodes(self, min: ghidra.program.model.address.Address, max: ghidra.program.model.address.Address) -> java.util.Iterator[VarnodeAST]:
        """
        return all Varnodes bounded between two Addresses
        
        :param ghidra.program.model.address.Address min: -- Minimum Address of Varnodes
        :param ghidra.program.model.address.Address max: -- Maximum Address of Varnodes
        :return: -- Iterator to Varnodes
        :rtype: java.util.Iterator[VarnodeAST]
        """

    @typing.overload
    def getVarnodes(self, sz: typing.Union[jpype.JInt, int], addr: ghidra.program.model.address.Address) -> java.util.Iterator[VarnodeAST]:
        """
        return all Varnodes of a given size that start at a given Address
        
        :param jpype.JInt or int sz: -- Size of Varnodes
        :param ghidra.program.model.address.Address addr: -- Starting Address of Varnodes
        :return: -- Iterator to Varnodes
        :rtype: java.util.Iterator[VarnodeAST]
        """

    def insertAfter(self, newop: PcodeOp, prev: PcodeOp):
        ...

    def insertBefore(self, newop: PcodeOp, follow: PcodeOp):
        ...

    def locRange(self) -> java.util.Iterator[VarnodeAST]:
        """
        
        
        :return: an iterator for all Varnodes in the tree ordered by Address
        :rtype: java.util.Iterator[VarnodeAST]
        """

    def setInput(self, op: PcodeOp, vn: Varnode, slot: typing.Union[jpype.JInt, int]):
        ...

    def setOpcode(self, op: PcodeOp, opc: typing.Union[jpype.JInt, int]):
        ...

    def setOutput(self, op: PcodeOp, vn: Varnode):
        ...

    def unInsert(self, op: PcodeOp):
        ...

    def unSetInput(self, op: PcodeOp, slot: typing.Union[jpype.JInt, int]):
        ...

    def unSetOutput(self, op: PcodeOp):
        ...

    def unlink(self, op: PcodeOpAST):
        ...

    @property
    def pcodeOps(self) -> java.util.Iterator[PcodeOpAST]:
        ...

    @property
    def numVarnodes(self) -> jpype.JInt:
        ...

    @property
    def pcodeOp(self) -> PcodeOp:
        ...

    @property
    def varnodes(self) -> java.util.Iterator[VarnodeAST]:
        ...

    @property
    def basicBlocks(self) -> java.util.ArrayList[PcodeBlockBasic]:
        ...


class HighSymbol(java.lang.Object):
    """
    A symbol within the decompiler's model of a particular function.  The symbol has a name and a data-type
    along with other properties. The symbol is mapped to one or more storage locations by attaching a
    SymbolEntry for each mapping.
    """

    class_: typing.ClassVar[java.lang.Class]
    ID_BASE: typing.Final = 4611686018427387904

    def decode(self, decoder: Decoder):
        """
        Decode this symbol object and its associated mappings from the stream.
        
        :param Decoder decoder: is the stream decoder
        :raises DecoderException: for invalid encodings
        """

    @staticmethod
    def decodeMapSym(decoder: Decoder, isGlobal: typing.Union[jpype.JBoolean, bool], high: HighFunction) -> HighSymbol:
        """
        Restore a full HighSymbol from the next <mapsym> element in the stream.
        This method acts as a HighSymbol factory, instantiating the correct class
        based on the particular elements.
        
        :param Decoder decoder: is the stream decoder
        :param jpype.JBoolean or bool isGlobal: is true if this symbol is being read into a global scope
        :param HighFunction high: is the function model that will own the new symbol
        :return: the new symbol
        :rtype: HighSymbol
        :raises DecoderException: for invalid encodings
        """

    def encode(self, encoder: Encoder):
        """
        Encode the symbol description as an element to the stream.  This does NOT save the mappings.
        
        :param Encoder encoder: is the stream encoder
        :raises IOException: for errors in the underlying stream
        """

    @staticmethod
    def encodeMapSym(encoder: Encoder, sym: HighSymbol):
        """
        Encode the given symbol with all its mapping as a <mapsym> element to the stream.
        
        :param Encoder encoder: is the stream encoder
        :param HighSymbol sym: is the given symbol
        :raises IOException: for errors in the underlying stream
        """

    def getCategoryIndex(self) -> int:
        """
        For parameters (category=0), this method returns the position of the parameter within the function prototype.
        
        :return: the category index for this symbol
        :rtype: int
        """

    def getDataType(self) -> ghidra.program.model.data.DataType:
        """
        
        
        :return: the data-type associate with this symbol
        :rtype: ghidra.program.model.data.DataType
        """

    def getFirstWholeMap(self) -> SymbolEntry:
        """
        
        
        :return: the first mapping object attached to this symbol
        :rtype: SymbolEntry
        """

    def getHighFunction(self) -> HighFunction:
        """
        Get the function model of which this symbol is a part.
        
        :return: the HighFunction owning this symbol
        :rtype: HighFunction
        """

    def getHighVariable(self) -> HighVariable:
        """
        Get the HighVariable associate with this symbol if any.  The symbol may have multiple
        partial HighVariables associated with it. This method returns the biggest one, which
        may not be the same size as the symbol itself.
        
        :return: the associated HighVariable or null
        :rtype: HighVariable
        """

    def getId(self) -> int:
        """
        Get id associated with this symbol.
        
        :return: the id
        :rtype: int
        """

    def getMutability(self) -> int:
        """
        Return one of
            - MutabilitySettingsDefinition.NORMAL
            - MutabilitySettingsDefinition.VOLATILE
            - MutabilitySettingsDefinition.CONSTANT
        
        :return: the mutability setting
        :rtype: int
        """

    def getName(self) -> str:
        """
        Get the base name of this symbol
        
        :return: the name
        :rtype: str
        """

    def getNamespace(self) -> ghidra.program.model.symbol.Namespace:
        """
        Fetch the namespace owning this symbol, if it exists.
        
        :return: the Namespace object or null
        :rtype: ghidra.program.model.symbol.Namespace
        """

    def getPCAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the first code Address, within the function, where this symbol's storage actually
        holds the value of the symbol.  If there is more than one mapping for the symbol, this
        returns the code Address for the first mapping.  A null value indicates that the storage
        is valid over the whole function (at least). If the value is non-null, the symbol storage
        may be used for other purposes at prior locations.
        
        :return: the first use code Address or null
        :rtype: ghidra.program.model.address.Address
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Get the Program object containing the function being modeled.
        
        :return: the Program
        :rtype: ghidra.program.model.listing.Program
        """

    def getSize(self) -> int:
        """
        
        
        :return: the number of bytes consumed by the storage for this symbol
        :rtype: int
        """

    def getStorage(self) -> ghidra.program.model.listing.VariableStorage:
        """
        
        
        :return: the storage associated with this symbol (associated with the first mapping)
        :rtype: ghidra.program.model.listing.VariableStorage
        """

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        Fetch the corresponding database Symbol if it exists.
        
        :return: the matching Symbol object or null
        :rtype: ghidra.program.model.symbol.Symbol
        """

    def isGlobal(self) -> bool:
        """
        Is this symbol in the global scope or some other global namespace
        
        :return: true if this is global
        :rtype: bool
        """

    def isHiddenReturn(self) -> bool:
        """
        
        
        :return: true is symbol holds a pointer to where a function's return value should be stored
        :rtype: bool
        """

    def isIsolated(self) -> bool:
        """
        If this returns true, the decompiler will not speculatively merge this with
        other variables.
        Currently, being isolated is equivalent to being typelocked.
        
        :return: true if this will not be merged with other variables
        :rtype: bool
        """

    def isNameLocked(self) -> bool:
        """
        If this returns true, this symbol's name is "locked". meaning the decompiler
        is forced to use the name when labeling the storage described by this symbol.
        
        :return: true if the name is considered "locked".
        :rtype: bool
        """

    def isParameter(self) -> bool:
        """
        Is this symbol a parameter for a function
        
        :return: true if this is a parameter
        :rtype: bool
        """

    def isThisPointer(self) -> bool:
        """
        
        
        :return: true if symbol is a "this" pointer for a class method
        :rtype: bool
        """

    def isTypeLocked(self) -> bool:
        """
        If this returns true, this symbol's data-type is "locked", meaning
        it is considered unchangeable during decompilation. The data-type
        will be forced into the decompiler's model of the function to the extent possible.
        
        :return: true if the data-type is considered "locked".
        :rtype: bool
        """

    def setNameLock(self, namelock: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether this symbol's name is considered "locked". If it is "locked", the decompiler
        will use the name when labeling the storage described by this symbol.
        
        :param jpype.JBoolean or bool namelock: is true if the name should be considered "locked".
        """

    def setTypeLock(self, typelock: typing.Union[jpype.JBoolean, bool]):
        """
        Set whether this symbol's data-type is considered "locked". If it is "locked",
        this symbol's data-type is considered unchangeable during decompilation. The data-type
        will be forced into the decompiler's model of the function to the extent possible.
        
        :param jpype.JBoolean or bool typelock: is true if the data-type should be considered "locked".
        """

    @property
    def hiddenReturn(self) -> jpype.JBoolean:
        ...

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def highFunction(self) -> HighFunction:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def isolated(self) -> jpype.JBoolean:
        ...

    @property
    def global_(self) -> jpype.JBoolean:
        ...

    @property
    def storage(self) -> ghidra.program.model.listing.VariableStorage:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def categoryIndex(self) -> jpype.JInt:
        ...

    @property
    def pCAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def highVariable(self) -> HighVariable:
        ...

    @property
    def size(self) -> jpype.JInt:
        ...

    @property
    def typeLocked(self) -> jpype.JBoolean:
        ...

    @property
    def parameter(self) -> jpype.JBoolean:
        ...

    @property
    def firstWholeMap(self) -> SymbolEntry:
        ...

    @property
    def thisPointer(self) -> jpype.JBoolean:
        ...

    @property
    def nameLocked(self) -> jpype.JBoolean:
        ...

    @property
    def namespace(self) -> ghidra.program.model.symbol.Namespace:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def mutability(self) -> jpype.JInt:
        ...

    @property
    def id(self) -> jpype.JLong:
        ...



__all__ = ["PcodeOverride", "ElementId", "PcodeFactory", "Decoder", "BlockSwitch", "PackedDecode", "DynamicEntry", "HighGlobal", "ParamMeasure", "MappedEntry", "PcodeDataTypeManager", "PatchPackedEncode", "BlockProperIf", "ByteIngest", "EquateSymbol", "HighLocal", "PcodeOpBank", "BlockGoto", "PcodeBlockBasic", "AttributeId", "BlockCopy", "BlockCondition", "PcodeOp", "BlockDoWhile", "HighParamID", "BlockMap", "BlockList", "BlockGraph", "LocalSymbolMap", "BlockIfElse", "PackedDecodeOverlay", "VarnodeBank", "PackedEncodeOverlay", "DynamicHash", "StringIngest", "HighFunctionDBUtil", "HighFunctionShellSymbol", "JumpTable", "SequenceNumber", "UnionFacetSymbol", "HighConstant", "Encoder", "HighOther", "HighFunctionSymbol", "PcodeOpAST", "MappedDataEntry", "HighCodeSymbol", "VarnodeAST", "PackedEncode", "AddressXML", "VarnodeTranslator", "CachedEncoder", "BlockMultiGoto", "FunctionPrototype", "BlockIfGoto", "PackedBytes", "HighFunction", "BlockWhileDo", "XmlEncode", "SymbolEntry", "Varnode", "HighVariable", "DecoderException", "PartialUnion", "HighParam", "LinkedByteBuffer", "PcodeBlock", "DataTypeSymbol", "HighLabelSymbol", "PcodeException", "GlobalSymbolMap", "HighExternalSymbol", "BlockInfLoop", "ListLinked", "PatchEncoder", "PcodeSyntaxTree", "HighSymbol"]
