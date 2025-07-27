from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.pcode
import ghidra.xml
import java.lang # type: ignore
import java.util # type: ignore


class HiddenReturnAssign(AssignAction):
    """
    Allocate the return value as an input parameter
     
    A pointer to where the return value is to be stored is passed in as an input parameter.
    This action signals this by returning one of
    - HIDDENRET_PTRPARAM         - indicating the pointer is allocated as a normal input parameter
    - HIDDENRET_SPECIALREG       - indicating the pointer is passed in a dedicated register
    - HIDDENRET_SPECIALREG_VOID
     
    Usually, if a hidden return input is present, the normal register used for return
    will also hold the pointer at the point(s) where the function returns.  A signal of
    HIDDENRET_SPECIALREG_VOID indicates the normal return register is not used to pass back
    the pointer.
    """

    class_: typing.ClassVar[java.lang.Class]
    STRATEGY_SPECIAL: typing.Final = "special"
    STRATEGY_NORMAL: typing.Final = "normalparam"

    def __init__(self, res: ghidra.program.model.lang.ParamListStandard, code: typing.Union[jpype.JInt, int]):
        ...


class MetaTypeFilter(SizeRestrictedFilter):
    """
    Filter on a single meta data-type. Filters on TYPE_STRUCT or TYPE_FLOAT etc.
    Additional filtering on size of the data-type can be configured.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, meta: typing.Union[jpype.JInt, int]):
        """
        Constructor for use with decode().
        
        :param jpype.JInt or int meta: is the data-type metatype to filter on
        """

    @typing.overload
    def __init__(self, meta: typing.Union[jpype.JInt, int], min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param jpype.JInt or int meta: is the data-type metatype to filter on
        :param jpype.JInt or int min: is the minimum size in bytes
        :param jpype.JInt or int max: is the maximum size in bytes
        """

    @typing.overload
    def __init__(self, op2: MetaTypeFilter):
        """
        Copy constructor
        
        :param MetaTypeFilter op2: is the filter to copy
        """


class PrimitiveExtractor(java.lang.Object):

    class Primitive(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        dt: ghidra.program.model.data.DataType
        offset: jpype.JInt

        def __init__(self, d: ghidra.program.model.data.DataType, off: typing.Union[jpype.JInt, int]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, dt: ghidra.program.model.data.DataType, unionIllegal: typing.Union[jpype.JBoolean, bool], offset: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]):
        """
        
        
        :param ghidra.program.model.data.DataType dt: is data-type extract from
        :param jpype.JBoolean or bool unionIllegal: is true if unions encountered during extraction are considered illegal
        :param jpype.JInt or int offset: is the starting offset to associate with the data-type
        :param jpype.JInt or int max: is the maximum number of primitives to extract before giving up
        """

    def containsHoles(self) -> bool:
        """
        
        
        :return: true if there is extra space in the data-type that is not alignment padding
        :rtype: bool
        """

    def containsUnknown(self) -> bool:
        """
        
        
        :return: true if any extracted element was unknown/undefined
        :rtype: bool
        """

    def get(self, i: typing.Union[jpype.JInt, int]) -> PrimitiveExtractor.Primitive:
        """
        Get the i-th extracted primitive and its offset
        
        :param jpype.JInt or int i: is the index
        :return: the primitive and offset
        :rtype: PrimitiveExtractor.Primitive
        """

    def isAligned(self) -> bool:
        """
        
        
        :return: true if all extracted elements are aligned
        :rtype: bool
        """

    def isValid(self) -> bool:
        """
        
        
        :return: true if all primitive elements were extracted
        :rtype: bool
        """

    def size(self) -> int:
        """
        
        
        :return: the number of primitives extracted
        :rtype: int
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def aligned(self) -> jpype.JBoolean:
        ...


class QualifierFilter(java.lang.Object):
    """
    A filter on some aspect of a specific function prototype.
    An instance is configured via the restoreXml() method, then a test of whether
    a function prototype meets its criteria can be performed by calling its filter() method.
    """

    class_: typing.ClassVar[java.lang.Class]

    def clone(self) -> QualifierFilter:
        """
        Make a copy of this qualifier
        
        :return: the copy
        :rtype: QualifierFilter
        """

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        """
        Save this filter and its configuration to a stream
        
        :param ghidra.program.model.pcode.Encoder encoder: is the stream encoder
        :raises IOException: for problems writing to the stream
        """

    def filter(self, proto: ghidra.program.model.lang.PrototypePieces, pos: typing.Union[jpype.JInt, int]) -> bool:
        """
        Test whether the given function prototype meets this filter's criteria
        
        :param ghidra.program.model.lang.PrototypePieces proto: is the high-level description of the function prototype to test
        :param jpype.JInt or int pos: is the position of a specific output (pos=-1) or input (pos >=0) in context
        :return: true if the prototype meets the criteria, false otherwise
        :rtype: bool
        """

    def isEquivalent(self, op: QualifierFilter) -> bool:
        """
        Test if the given filter is configured and performs identically to this
        
        :param QualifierFilter op: is the given filter
        :return: true if the two filters are equivalent
        :rtype: bool
        """

    @staticmethod
    def restoreFilterXml(parser: ghidra.xml.XmlPullParser) -> QualifierFilter:
        """
        Instantiate a qualifier from the stream. If the next element is not a qualifier,
        return null.
        
        :param ghidra.xml.XmlPullParser parser: is the given stream decoder
        :return: the new qualifier instance or null
        :rtype: QualifierFilter
        :raises XmlParseException: for problems decoding the stream
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        """
        Configure details of the criteria being filtered from the given stream
        
        :param ghidra.xml.XmlPullParser parser: is the given stream decoder
        :raises XmlParseException: if there are problems with the stream
        """

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...


class SizeRestrictedFilter(DatatypeFilter):
    """
    A base class for data-type filters that tests either for either a range or an enumerated list of sizes.
    Any filter that inherits from this, can use ATTRIB_MINSIZE, ATTRIB_MAXSIZE, or ATTRIB_SIZES
    to place bounds on the possible sizes of data-types.  The bounds are enforced
    by calling filterOnSize() within the inheriting classes filter() method.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "any"

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, op2: SizeRestrictedFilter):
        """
        Copy constructor
        
        :param SizeRestrictedFilter op2: is the filter to copy
        """

    def filterOnSize(self, dt: ghidra.program.model.data.DataType) -> bool:
        """
        Enforce any size bounds on a given data-type.
        If \b maxSize is not zero, the data-type is checked to see if its size in bytes
        falls between \b minSize and \b maxSize inclusive.  If enumerated sizes are present,
        also check that the particular size is in the enumerated set.
        
        :param ghidra.program.model.data.DataType dt: is the data-type to test
        :return: true if the data-type meets the size restrictions
        :rtype: bool
        """


class PositionMatchFilter(QualifierFilter):
    """
    Filter that selects for a particular parameter position.
    This matches if the position of the current parameter being assigned, within the data-type
    list, matches the position attribute of this filter.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, pos: typing.Union[jpype.JInt, int]):
        ...


class ExtraStack(AssignAction):
    """
    Consume stack resources as a side-effect
     
    This action is a side-effect and doesn't assign an address for the current parameter.
    If the current parameter has been assigned a address that is not on the stack, this action consumes
    stack resources as if the parameter were allocated to the stack.  If the current parameter was
    already assigned a stack address, no additional action is taken.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, res: ghidra.program.model.lang.ParamListStandard, val: typing.Union[jpype.JInt, int]):
        """
        Constructor for use with restoreXml
        
        :param ghidra.program.model.lang.ParamListStandard res: is the resource list
        :param jpype.JInt or int val: is a dummy variable
        """

    @typing.overload
    def __init__(self, res: ghidra.program.model.lang.ParamListStandard):
        ...


class HomogeneousAggregate(SizeRestrictedFilter):
    """
    Filter on a homogeneous aggregate data-type
    All primitive data-types must be the same.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME_FLOAT4: typing.Final = "homogeneous-float-aggregate"
    MAX_PRIMITIVES: typing.Final = 4

    @typing.overload
    def __init__(self, nm: typing.Union[java.lang.String, str], meta: typing.Union[jpype.JInt, int]):
        """
        Constructor for use with decode()
        
        :param java.lang.String or str nm: is the name attribute associated with the tag
        :param jpype.JInt or int meta: is the expected element meta-type
        """

    @typing.overload
    def __init__(self, nm: typing.Union[java.lang.String, str], meta: typing.Union[jpype.JInt, int], maxPrim: typing.Union[jpype.JInt, int], min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, op2: HomogeneousAggregate):
        """
        Copy constructor
        
        :param HomogeneousAggregate op2: is the filter to copy
        """


class ModelRule(java.lang.Object):
    """
    A rule controlling how parameters are assigned addresses
      
    Rules are applied to a parameter in the context of a full function prototype.
    A rule applies only for a specific class of data-type associated with the parameter, as
    determined by its DatatypeFilter, and may have other criteria limiting when it applies
    (via QualifierFilter).
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, op2: ModelRule, res: ghidra.program.model.lang.ParamListStandard):
        """
        Copy constructor
        
        :param ModelRule op2: is the ModelRule to copy from
        :param ghidra.program.model.lang.ParamListStandard res: is the new resource set to associate with the copy
        :raises InvalidInputException: if necessary resources are not present in the resource set
        """

    @typing.overload
    def __init__(self, typeFilter: DatatypeFilter, action: AssignAction, res: ghidra.program.model.lang.ParamListStandard):
        """
        Construct from components
         
        The provided components are cloned into the new object.
        
        :param DatatypeFilter typeFilter: is the data-type filter the rule applies before performing the action
        :param AssignAction action: is the action that will be applied
        :param ghidra.program.model.lang.ParamListStandard res: is the resource list to which this rule will be applied
        :raises InvalidInputException: if necessary resources are missing from the list
        """

    def assignAddress(self, dt: ghidra.program.model.data.DataType, proto: ghidra.program.model.lang.PrototypePieces, pos: typing.Union[jpype.JInt, int], dtManager: ghidra.program.model.data.DataTypeManager, status: jpype.JArray[jpype.JInt], res: ghidra.program.model.lang.ParameterPieces) -> int:
        """
        Assign an address and other details for a specific parameter or for return storage in context
         
        The Address is only assigned if the data-type filter and the optional qualifier filter
        pass, otherwise a FAIL response is returned.
        If the filters pass, the Address is assigned based on the AssignAction specific to
        this rule, and the action's response code is returned.
        
        :param ghidra.program.model.data.DataType dt: is the data-type of the parameter or return value
        :param ghidra.program.model.lang.PrototypePieces proto: is the high-level description of the function prototype
        :param jpype.JInt or int pos: is the position of the parameter (pos>=0) or return storage (pos=-1)
        :param ghidra.program.model.data.DataTypeManager dtManager: is a data-type manager for (possibly) transforming the data-type
        :param jpype.JArray[jpype.JInt] status: is the resource consumption array
        :param ghidra.program.model.lang.ParameterPieces res: will hold the resulting description of the parameter
        :return: the response code
        :rtype: int
        """

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        """
        Encode this rule to a stream
        
        :param ghidra.program.model.pcode.Encoder encoder: is the stream encode
        :raises IOException: for problems with the stream
        """

    def isEquivalent(self, op: ModelRule) -> bool:
        ...

    def restoreXml(self, parser: ghidra.xml.XmlPullParser, res: ghidra.program.model.lang.ParamListStandard):
        """
        Decode this rule from stream
        
        :param ghidra.xml.XmlPullParser parser: is the stream decoder
        :param ghidra.program.model.lang.ParamListStandard res: is the parameter resource list owning this rule
        :raises XmlParseException: if there are problems decoding are missing resources
        """

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...


class DatatypeMatchFilter(QualifierFilter):
    """
    Check if the function signature has a specific data-type in a specific position.
    This filter does not match against the data-type in the current position
    being assigned, but against a parameter at a fixed position.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GotoStack(AssignAction):
    """
    Action assigning a parameter Address from the next available stack location
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, res: ghidra.program.model.lang.ParamListStandard):
        ...


class MultiMemberAssign(AssignAction):
    """
    Consume a register per primitive member of an aggregate data-type
     
    The data-type is split up into its underlying primitive elements, and each one
    is assigned a register from the specific resource list.  There must be no padding between
    elements.  No packing of elements into a single register occurs.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: ghidra.program.model.lang.StorageClass, stack: typing.Union[jpype.JBoolean, bool], mostSig: typing.Union[jpype.JBoolean, bool], res: ghidra.program.model.lang.ParamListStandard):
        ...


class DatatypeFilter(java.lang.Object):
    """
    A filter selecting a specific class of data-type.
    A test of whether  data-type belongs to its class can be performed by calling
    the filter() method.
    """

    class_: typing.ClassVar[java.lang.Class]

    def clone(self) -> DatatypeFilter:
        """
        Make a copy of this filter
        
        :return: the new copy
        :rtype: DatatypeFilter
        """

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        """
        Encode this filter and its configuration to a stream
        
        :param ghidra.program.model.pcode.Encoder encoder: is the stream encoder
        :raises IOException: for problems writing to the stream
        """

    def filter(self, dt: ghidra.program.model.data.DataType) -> bool:
        """
        Test whether the given data-type belongs to this filter's data-type class
        
        :param ghidra.program.model.data.DataType dt: is the given data-type to test
        :return: true if the data-type is in the class, false otherwise
        :rtype: bool
        """

    def isEquivalent(self, op: DatatypeFilter) -> bool:
        """
        Test if the given filter is configured and performs identically to this
        
        :param DatatypeFilter op: is the given filter
        :return: true if the two filters are equivalent
        :rtype: bool
        """

    @staticmethod
    def restoreFilterXml(parser: ghidra.xml.XmlPullParser) -> DatatypeFilter:
        """
        Instantiate a filter from the given stream.
        
        :param ghidra.xml.XmlPullParser parser: is the given stream decoder
        :return: the new data-type filter instance
        :rtype: DatatypeFilter
        :raises XmlParseException: for problems reading the stream
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        """
        Configure details of the data-type class being filtered from the given stream
        
        :param ghidra.xml.XmlPullParser parser: is the given stream decoder
        :raises XmlParseException: if there are problems with the stream
        """

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...


class VarargsFilter(QualifierFilter):
    """
    A filter that selects a range of function parameters that are considered optional.
    If the underlying function prototype takes variable arguments, the first n
    parameters (as determined by PrototypePieces.firstVarArgSlot) are considered non-optional.
    If additional data-types are provided beyond the initial n, these are considered optional.
    By default this filter matches on all parameters in a prototype with variable arguments.
    Optionally, it can filter on a range of parameters that are specified relative to the
    first variable argument.
        ``<varargs first="0"/>``   - matches optional arguments but not non-optional ones.
        ``<varargs first="0" last="0"/>``  -  matches the first optional argument.
        ``<varargs first="-1"/>`` - matches the last non-optional argument and all optional ones.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, first: typing.Union[jpype.JInt, int], last: typing.Union[jpype.JInt, int]):
        ...


class ConsumeAs(AssignAction):
    """
    Consume a parameter from a specific resource list
     
    Normally the resource list is determined by the parameter data-type, but this
    action specifies an overriding resource list.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: ghidra.program.model.lang.StorageClass, res: ghidra.program.model.lang.ParamListStandard):
        ...


class ConvertToPointer(AssignAction):
    """
    Action converting the parameter's data-type to a pointer, and assigning storage for the pointer.
    This assumes the data-type is stored elsewhere and only the pointer is passed as a parameter.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, res: ghidra.program.model.lang.ParamListStandard):
        ...


class AndFilter(QualifierFilter):
    """
    Logically AND multiple QualifierFilters together into a single filter.
    An instances contains some number of other arbitrary filters.  In order for this filter to
    pass, all these contained filters must pass.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, qualifierList: java.util.ArrayList[QualifierFilter]):
        """
        The AndFilter assumes ownership of all the filters in the ArrayList
        
        :param java.util.ArrayList[QualifierFilter] qualifierList: is the list of filters pulled into this filter
        """

    @typing.overload
    def __init__(self, op: AndFilter):
        ...


class MultiSlotAssign(AssignAction):
    """
    Consume multiple registers to pass a data-type
     
    Available registers are consumed until the data-type is covered, and an appropriate
    join space address is assigned.  Registers can be consumed from a specific resource list.
    Consumption can spill over onto the stack if desired.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: ghidra.program.model.lang.StorageClass, stack: typing.Union[jpype.JBoolean, bool], mostSig: typing.Union[jpype.JBoolean, bool], align: typing.Union[jpype.JBoolean, bool], justRight: typing.Union[jpype.JBoolean, bool], backfill: typing.Union[jpype.JBoolean, bool], res: ghidra.program.model.lang.ParamListStandard):
        ...


class MultiSlotDualAssign(AssignAction):
    """
    Consume multiple registers from different storage classes to pass a data-type
     
    This action is for calling conventions that can use both floating-point and general purpose registers
    when assigning storage for a single composite data-type, such as the X86-64 System V ABI
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, baseStore: ghidra.program.model.lang.StorageClass, altStore: ghidra.program.model.lang.StorageClass, mostSig: typing.Union[jpype.JBoolean, bool], justRight: typing.Union[jpype.JBoolean, bool], res: ghidra.program.model.lang.ParamListStandard):
        ...


class AssignAction(java.lang.Object):
    """
    An action that assigns an Address to a function prototype parameter
     
    A request for the address of either return storage or an input parameter is made
    through the assignAddress() method, which is given full information about the function prototype.
    Details about how the action performs is configured through the restoreXml() method.
    """

    class_: typing.ClassVar[java.lang.Class]
    SUCCESS: typing.Final = 0
    FAIL: typing.Final = 1
    NO_ASSIGNMENT: typing.Final = 2
    HIDDENRET_PTRPARAM: typing.Final = 3
    HIDDENRET_SPECIALREG: typing.Final = 4
    HIDDENRET_SPECIALREG_VOID: typing.Final = 5

    def __init__(self, res: ghidra.program.model.lang.ParamListStandard):
        ...

    def assignAddress(self, dt: ghidra.program.model.data.DataType, proto: ghidra.program.model.lang.PrototypePieces, pos: typing.Union[jpype.JInt, int], dtManager: ghidra.program.model.data.DataTypeManager, status: jpype.JArray[jpype.JInt], res: ghidra.program.model.lang.ParameterPieces) -> int:
        """
        Assign an address and other meta-data for a specific parameter or for return storage in context
        The Address is assigned based on the data-type of the parameter, available register
        resources, and other details of the function prototype.  Consumed resources are marked.
        This method returns a response code:
        - SUCCESS            - indicating the Address was successfully assigned
        - FAIL               - if the Address could not be assigned
        - HIDDENRET_PTRPARAM - if an additional hidden return parameter is required
        
        :param ghidra.program.model.data.DataType dt: is the data-type of the parameter or return value
        :param ghidra.program.model.lang.PrototypePieces proto: is the high-level description of the function prototype
        :param jpype.JInt or int pos: is the position of the parameter (pos>=0) or return storage (pos=-1)
        :param ghidra.program.model.data.DataTypeManager dtManager: is a data-type manager for (possibly) transforming the data-type
        :param jpype.JArray[jpype.JInt] status: is the resource consumption array
        :param ghidra.program.model.lang.ParameterPieces res: will hold the resulting description of the parameter
        :return: the response code
        :rtype: int
        """

    def clone(self, newResource: ghidra.program.model.lang.ParamListStandard) -> AssignAction:
        """
        Make a copy of this action
        
        :param ghidra.program.model.lang.ParamListStandard newResource: is the new resource object that will own the clone
        :return: the newly allocated copy
        :rtype: AssignAction
        :raises InvalidInputException: if required configuration is not present in new resource object
        """

    def encode(self, encoder: ghidra.program.model.pcode.Encoder):
        """
        Save this action and its configuration to a stream
        
        :param ghidra.program.model.pcode.Encoder encoder: is the stream encoder
        :raises IOException: for problems writing to the stream
        """

    def isEquivalent(self, op: AssignAction) -> bool:
        """
        Test if the given action is configured and performs identically to this
        
        :param AssignAction op: is the given action
        :return: true if the two actions are equivalent
        :rtype: bool
        """

    @staticmethod
    def restoreActionXml(parser: ghidra.xml.XmlPullParser, res: ghidra.program.model.lang.ParamListStandard) -> AssignAction:
        """
        Read the next action element from the stream and return the new configured
        AssignAction object.  If the next element is not an action, throw an exception.
        
        :param ghidra.xml.XmlPullParser parser: is the stream parser
        :param ghidra.program.model.lang.ParamListStandard res: is the resource set for the new action
        :return: the new action
        :rtype: AssignAction
        :raises XmlParseException: for problems parsing the stream
        """

    @staticmethod
    def restoreSideeffectXml(parser: ghidra.xml.XmlPullParser, res: ghidra.program.model.lang.ParamListStandard) -> AssignAction:
        """
        Read the next sideeffect element from the stream and return the new configured
        AssignAction object.  If the next element is not a sideeffect, throw an exception.
        
        :param ghidra.xml.XmlPullParser parser: is the stream parser
        :param ghidra.program.model.lang.ParamListStandard res: is the resource set for the new sideeffect
        :return: the new sideeffect
        :rtype: AssignAction
        :raises XmlParseException: for problems parsing the stream
        """

    def restoreXml(self, parser: ghidra.xml.XmlPullParser):
        """
        Configure any details of how this action should behave from the stream
        
        :param ghidra.xml.XmlPullParser parser: is the given stream decoder
        :raises XmlParseException: is there are problems decoding the stream
        """

    @property
    def equivalent(self) -> jpype.JBoolean:
        ...


class ConsumeExtra(AssignAction):
    """
    Consume additional registers from an alternate resource list
     
    This action is a side-effect and doesn't assign an address for the current parameter.
    The resource list, resourceType, is specified. If the side-effect is triggered,
    register resources from this list are consumed.  If matchSize is true (the default),
    registers are consumed, until the number of bytes in the data-type is reached.  Otherwise,
    only a single register is consumed. If all registers are already consumed, no action is taken.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, store: ghidra.program.model.lang.StorageClass, match: typing.Union[jpype.JBoolean, bool], res: ghidra.program.model.lang.ParamListStandard):
        ...



__all__ = ["HiddenReturnAssign", "MetaTypeFilter", "PrimitiveExtractor", "QualifierFilter", "SizeRestrictedFilter", "PositionMatchFilter", "ExtraStack", "HomogeneousAggregate", "ModelRule", "DatatypeMatchFilter", "GotoStack", "MultiMemberAssign", "DatatypeFilter", "VarargsFilter", "ConsumeAs", "ConvertToPointer", "AndFilter", "MultiSlotAssign", "MultiSlotDualAssign", "AssignAction", "ConsumeExtra"]
