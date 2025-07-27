from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin.format.golang.rtti
import ghidra.app.util.bin.format.golang.structmapping
import ghidra.program.model.address
import ghidra.program.model.data
import java.lang # type: ignore
import java.util # type: ignore


class GoKind(java.lang.Enum[GoKind]):
    """
    Enum defining the various golang primitive types
    """

    class_: typing.ClassVar[java.lang.Class]
    invalid: typing.Final[GoKind]
    Bool: typing.Final[GoKind]
    Int: typing.Final[GoKind]
    Int8: typing.Final[GoKind]
    Int16: typing.Final[GoKind]
    Int32: typing.Final[GoKind]
    Int64: typing.Final[GoKind]
    Uint: typing.Final[GoKind]
    Uint8: typing.Final[GoKind]
    Uint16: typing.Final[GoKind]
    Uint32: typing.Final[GoKind]
    Uint64: typing.Final[GoKind]
    Uintptr: typing.Final[GoKind]
    Float32: typing.Final[GoKind]
    Float64: typing.Final[GoKind]
    Complex64: typing.Final[GoKind]
    Complex128: typing.Final[GoKind]
    Array: typing.Final[GoKind]
    Chan: typing.Final[GoKind]
    Func: typing.Final[GoKind]
    Interface: typing.Final[GoKind]
    Map: typing.Final[GoKind]
    Pointer: typing.Final[GoKind]
    Slice: typing.Final[GoKind]
    String: typing.Final[GoKind]
    Struct: typing.Final[GoKind]
    UnsafePointer: typing.Final[GoKind]
    KIND_MASK: typing.Final = 31
    GC_PROG: typing.Final = 64
    DIRECT_IFACE: typing.Final = 32

    @staticmethod
    def parseByte(b: typing.Union[jpype.JInt, int]) -> GoKind:
        """
        Parses the byte value read from the runtime._type kind field.
        
        :param jpype.JInt or int b: byte value
        :return: :obj:`GoKind` enum, or :obj:`.invalid` if bad value
        :rtype: GoKind
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> GoKind:
        ...

    @staticmethod
    def values() -> jpype.JArray[GoKind]:
        ...


class GoStructType(GoType):
    """
    Golang type information about a specific structure type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getFields(self) -> java.util.List[GoStructField]:
        """
        Returns the fields defined by this struct type.
        
        :return: list of fields defined by this struct type
        :rtype: java.util.List[GoStructField]
        :raises IOException: if error reading
        """

    def getPackagePathString(self) -> str:
        """
        Returns the package path of this structure type
        
        :return: package path of this structure type, as a string
        :rtype: str
        """

    def getPkgPath(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        """
        Returns the package path of this structure type.
        
        :return: package path of this structure type
        :rtype: ghidra.app.util.bin.format.golang.rtti.GoName
        :raises IOException: if error reading
        """

    def isClosureContextType(self) -> bool:
        ...

    def isMethodWrapperContextType(self) -> bool:
        ...

    @property
    def pkgPath(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        ...

    @property
    def packagePathString(self) -> java.lang.String:
        ...

    @property
    def closureContextType(self) -> jpype.JBoolean:
        ...

    @property
    def methodWrapperContextType(self) -> jpype.JBoolean:
        ...

    @property
    def fields(self) -> java.util.List[GoStructField]:
        ...


class GoSliceType(GoType):
    """
    Golang type information about a specific slice type.
     
    
    See :meth:`GoTypeManager.getGenericSliceDT() <GoTypeManager.getGenericSliceDT>` or the "runtime.slice" type for the definition of
    a instance of a slice variable in memory.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getElement(self) -> GoType:
        """
        Returns a reference to the element's type.
        
        :return: reference to the element's type
        :rtype: GoType
        :raises IOException: if error reading data
        """

    @property
    def element(self) -> GoType:
        ...


class GoInterfaceType(GoType):
    """
    A :obj:`GoType` structure that defines a golang interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getMethods(self) -> java.util.List[GoIMethod]:
        """
        Returns the methods defined by this interface
        
        :return: methods defined by this interface
        :rtype: java.util.List[GoIMethod]
        :raises IOException: if error reading data
        """

    def getMethodsSlice(self) -> ghidra.app.util.bin.format.golang.rtti.GoSlice:
        """
        Returns a slice containing the methods of this interface.
        
        :return: slice containing the methods of this interface
        :rtype: ghidra.app.util.bin.format.golang.rtti.GoSlice
        """

    def getPkgPath(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        """
        Returns the package path of this type, referenced via the pkgpath field's markup annotation
        
        :return: package path :obj:`GoName`a
        :rtype: ghidra.app.util.bin.format.golang.rtti.GoName
        :raises IOException: if error reading
        """

    def getSpecializedITabStruct(self, ifaceCP: ghidra.program.model.data.CategoryPath, ifaceName: typing.Union[java.lang.String, str], goTypes: ghidra.app.util.bin.format.golang.rtti.GoTypeManager) -> ghidra.program.model.data.Structure:
        ...

    @property
    def pkgPath(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        ...

    @property
    def methodsSlice(self) -> ghidra.app.util.bin.format.golang.rtti.GoSlice:
        ...

    @property
    def methods(self) -> java.util.List[GoIMethod]:
        ...


class GoFuncType(GoType):
    """
    A :obj:`GoType` structure that defines a function type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getFuncPrototypeString(self, funcName: typing.Union[java.lang.String, str]) -> str:
        """
        Returns a string that describes the function type as a golang-ish function decl.
        
        :param java.lang.String or str funcName: optional name of a function
        :return: golang func decl string
        :rtype: str
        """

    def getFunctionSignature(self, goTypes: ghidra.app.util.bin.format.golang.rtti.GoTypeManager) -> ghidra.program.model.data.FunctionDefinition:
        ...

    def getInCount(self) -> int:
        """
        Returns the number of inbound parameters
        
        :return: number of inbound parameters
        :rtype: int
        """

    @staticmethod
    def getMissingFuncPrototypeString(funcName: typing.Union[java.lang.String, str], genericsString: typing.Union[java.lang.String, str]) -> str:
        ...

    def getOutCount(self) -> int:
        """
        Returns the number of outbound result values
        
        :return: number of outbound result values
        :rtype: int
        """

    def getParamCount(self) -> int:
        """
        Returns the total number of in and out parameters
        
        :return: total number of in and out parameters
        :rtype: int
        """

    def getParamListString(self) -> str:
        ...

    def getParamTypes(self) -> java.util.List[GoType]:
        """
        Returns a list of :obj:`GoType`s for each parameter
        
        :return: list of :obj:`GoType`s for each parameter
        :rtype: java.util.List[GoType]
        :raises IOException: if error read type info
        """

    def isVarArg(self) -> bool:
        """
        Returns true if this function type is defined to be vararg
        
        :return: true if this function type is defined to be vararg
        :rtype: bool
        """

    @staticmethod
    def unwrapFunctionDefinitionPtrs(dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.FunctionDefinition:
        """
        Converts a ptr-to-ptr-to-funcdef to the base funcdef type.
        
        :param ghidra.program.model.data.DataType dt: ghidra :obj:`DataType`
        :return: :obj:`FunctionDefinition` that was pointed to by specified data type, or null
        :rtype: ghidra.program.model.data.FunctionDefinition
        """

    @property
    def outCount(self) -> jpype.JInt:
        ...

    @property
    def paramCount(self) -> jpype.JInt:
        ...

    @property
    def paramTypes(self) -> java.util.List[GoType]:
        ...

    @property
    def varArg(self) -> jpype.JBoolean:
        ...

    @property
    def functionSignature(self) -> ghidra.program.model.data.FunctionDefinition:
        ...

    @property
    def funcPrototypeString(self) -> java.lang.String:
        ...

    @property
    def inCount(self) -> jpype.JInt:
        ...

    @property
    def paramListString(self) -> java.lang.String:
        ...


class GoChanType(GoType):
    """
    A :obj:`GoType` structure that defines a go channel
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getElement(self) -> GoType:
        """
        Returns a reference to the :obj:`GoType` that defines the elements this channel uses
        
        :return: reference to the :obj:`GoType` that defines the elements this channel uses
        :rtype: GoType
        :raises IOException: if error reading type
        """

    @property
    def element(self) -> GoType:
        ...


class GoPointerType(GoType):
    """
    :obj:`GoType` structure that defines a pointer.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getElement(self) -> GoType:
        """
        Returns a reference to the element's type.
        
        :return: reference to the element's type
        :rtype: GoType
        :raises IOException: if error reading data
        """

    @property
    def element(self) -> GoType:
        ...


class GoArrayType(GoType):
    """
    :obj:`GoType` structure that defines an array.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getElement(self) -> GoType:
        """
        Returns a reference to the :obj:`GoType` of the elements of this array.
        
        :return: reference to the :obj:`GoType` of the elements of this array
        :rtype: GoType
        :raises IOException: if error reading data
        """

    def getSliceType(self) -> GoType:
        """
        Returns a reference to the :obj:`GoType` that defines the slice version of this array.
        
        :return: reference to the :obj:`GoType` that defines the slice version of this array
        :rtype: GoType
        :raises IOException: if error reading data
        """

    @property
    def sliceType(self) -> GoType:
        ...

    @property
    def element(self) -> GoType:
        ...


class GoTypeBridge(GoType):
    """
    A limited use wrapper/bridge between a GoType and a Ghidra DataType, this
    wrapper only supports the :meth:`recoverDataType(GoTypeManager) <.recoverDataType>` call.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, delegateGoType: GoType, ghidraType: ghidra.program.model.data.DataType, goBinary: ghidra.app.util.bin.format.golang.rtti.GoRttiMapper):
        ...

    @typing.overload
    def __init__(self, delegateGoTypeName: typing.Union[java.lang.String, str], ghidraType: ghidra.program.model.data.DataType, goBinary: ghidra.app.util.bin.format.golang.rtti.GoRttiMapper):
        ...


class GoUncommonType(java.lang.Object):
    """
    Structure found immediately after a :obj:`GoType` structure, if it has the uncommon flag
    set.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getEndOfTypeInfo(self) -> int:
        """
        Returns the location of where this object, and any known associated optional
        structures ends.
        
        :return: index location of end of this type object
        :rtype: int
        """

    def getMethods(self) -> java.util.List[GoMethod]:
        """
        Returns a list of the methods defined by the type.
        
        :return: list of the methods defined by the type
        :rtype: java.util.List[GoMethod]
        :raises IOException: if error reading data
        """

    def getMethodsSlice(self) -> ghidra.app.util.bin.format.golang.rtti.GoSlice:
        """
        Returns a slice containing the methods defined by the type.
        
        :return: slice containing the methods defined by the type
        :rtype: ghidra.app.util.bin.format.golang.rtti.GoSlice
        """

    def getPackagePathString(self) -> str:
        """
        Returns the package path of the type.
        
        :return: package path of the type, as a string
        :rtype: str
        :raises IOException: if error reading data
        """

    def getPkgPath(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        """
        Returns the package path of the type.
        
        :return: package path of the type
        :rtype: ghidra.app.util.bin.format.golang.rtti.GoName
        :raises IOException: if error reading data
        """

    @property
    def pkgPath(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        ...

    @property
    def packagePathString(self) -> java.lang.String:
        ...

    @property
    def methodsSlice(self) -> ghidra.app.util.bin.format.golang.rtti.GoSlice:
        ...

    @property
    def methods(self) -> java.util.List[GoMethod]:
        ...

    @property
    def endOfTypeInfo(self) -> jpype.JLong:
        ...


class GoStructField(java.lang.Object):
    """
    Structure used to define a field in a :obj:`struct type <GoStructType>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getGoName(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        """
        Returns the name of this field.
        
        :return: name of this field as it's raw GoName value
        :rtype: ghidra.app.util.bin.format.golang.rtti.GoName
        :raises IOException: if error reading
        """

    def getName(self) -> str:
        """
        Returns the name of this field.
        
        :return: name of this field
        :rtype: str
        """

    def getOffset(self) -> int:
        """
        Returns the offset of this field.
        
        :return: offset of this field
        :rtype: int
        """

    def getType(self) -> GoType:
        """
        Returns the type of this field.
        
        :return: type of this field
        :rtype: GoType
        :raises IOException: if error reading
        """

    def setOffsetAnon(self, offsetAnon: typing.Union[jpype.JLong, int]):
        """
        Setter called by offsetAnon field's serialization, referred by fieldmapping annotation.
        
        :param jpype.JLong or int offsetAnon: value
        """

    @property
    def offset(self) -> jpype.JLong:
        ...

    @property
    def goName(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def type(self) -> GoType:
        ...


class GoIMethod(ghidra.app.util.bin.format.golang.structmapping.StructureMarkup[GoIMethod]):

    class GoIMethodInfo(ghidra.app.util.bin.format.golang.rtti.MethodInfo):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, itab: ghidra.app.util.bin.format.golang.rtti.GoItab, imethod: GoIMethod, address: ghidra.program.model.address.Address):
            ...

        def getImethod(self) -> GoIMethod:
            ...

        def getItab(self) -> ghidra.app.util.bin.format.golang.rtti.GoItab:
            ...

        @property
        def itab(self) -> ghidra.app.util.bin.format.golang.rtti.GoItab:
            ...

        @property
        def imethod(self) -> GoIMethod:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getFunctionDefinition(self, isGeneric: typing.Union[jpype.JBoolean, bool], goTypes: ghidra.app.util.bin.format.golang.rtti.GoTypeManager) -> ghidra.program.model.data.FunctionDefinition:
        ...

    def getGoName(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        ...

    def getName(self) -> str:
        ...

    def getType(self) -> GoFuncType:
        ...

    @property
    def goName(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def type(self) -> GoFuncType:
        ...


class GoType(ghidra.app.util.bin.format.golang.structmapping.StructureMarkup[GoType], ghidra.app.util.bin.format.golang.structmapping.StructureVerifier):
    """
    Common abstract base class for GoType classes
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def discoverGoTypes(self, discoveredTypes: java.util.Set[java.lang.Long]) -> bool:
        """
        Iterates this type, and any types this type refers to, while registering the types with
        the :obj:`GoRttiMapper` context.
         
        
        This method should be overloaded by derived type classes to add any additional types 
        referenced by the derived type.
        
        :param java.util.Set[java.lang.Long] discoveredTypes: set of already iterated types
        :return: boolean boolean flag, if false the type has already been discovered, if true
        the type was encountered for the first time
        :rtype: bool
        :raises IOException: if error reading type info
        """

    def getDebugId(self) -> str:
        ...

    def getEndOfTypeInfo(self) -> int:
        """
        Returns the location of where this type object, and any known associated optional
        structures ends.
        
        :return: index location of end of this type object
        :rtype: int
        :raises IOException: if error reading
        """

    def getFullyQualifiedName(self) -> str:
        ...

    def getMethodInfoList(self) -> java.util.List[GoMethod.GoMethodInfo]:
        """
        Returns a list of all methods defined on this type.  Methods that specify both a
        "tfn" address as well as a "ifn" address will be represented twice.
        
        :return: list of MethodInfo's
        :rtype: java.util.List[GoMethod.GoMethodInfo]
        :raises IOException: if error reading
        """

    @typing.overload
    def getMethodPrototypeString(self, methodName: typing.Union[java.lang.String, str], funcdefType: GoFuncType) -> str:
        ...

    @typing.overload
    def getMethodPrototypeString(self, recvStr: typing.Union[java.lang.String, str], methodName: typing.Union[java.lang.String, str], funcdefType: GoFuncType) -> str:
        ...

    def getName(self) -> str:
        """
        Returns the name of this type.
        
        :return: name of this type
        :rtype: str
        """

    def getPackagePathString(self) -> str:
        """
        Returns the package path of this type.
        
        :return: package path of this type
        :rtype: str
        """

    @staticmethod
    def getSpecializedTypeClass(programContext: ghidra.app.util.bin.format.golang.rtti.GoRttiMapper, offset: typing.Union[jpype.JLong, int]) -> java.lang.Class[GoType]:
        """
        Returns the specific GoType derived class that will handle the go type located at the
        specified offset.
        
        :param ghidra.app.util.bin.format.golang.rtti.GoRttiMapper programContext: program-level mapper context
        :param jpype.JLong or int offset: absolute location of go type struct
        :return: GoType class that will best handle the type struct
        :rtype: java.lang.Class[GoType]
        :raises IOException: if error reading
        """

    def getSymbolName(self) -> ghidra.app.util.bin.format.golang.rtti.GoSymbolName:
        ...

    def getTypeOffset(self) -> int:
        """
        Returns the starting offset of this type, used as an identifier.
        
        :return: starting offset of this type
        :rtype: int
        """

    def getUncommonType(self) -> GoUncommonType:
        ...

    def recoverDataType(self, goTypes: ghidra.app.util.bin.format.golang.rtti.GoTypeManager) -> ghidra.program.model.data.DataType:
        """
        Converts a golang RTTI type structure into a Ghidra data type.
         
        
        This default implementation just creates an opaque blob of the appropriate size
        
        :param ghidra.app.util.bin.format.golang.rtti.GoTypeManager goTypes: :obj:`GoTypeManager`
        :return: :obj:`DataType` that represents the golang type
        :rtype: ghidra.program.model.data.DataType
        :raises IOException: if error getting name of the type
        """

    @property
    def methodInfoList(self) -> java.util.List[GoMethod.GoMethodInfo]:
        ...

    @property
    def uncommonType(self) -> GoUncommonType:
        ...

    @property
    def packagePathString(self) -> java.lang.String:
        ...

    @property
    def typeOffset(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def symbolName(self) -> ghidra.app.util.bin.format.golang.rtti.GoSymbolName:
        ...

    @property
    def endOfTypeInfo(self) -> jpype.JLong:
        ...

    @property
    def debugId(self) -> java.lang.String:
        ...

    @property
    def fullyQualifiedName(self) -> java.lang.String:
        ...


class GoPlainType(GoType, ghidra.app.util.bin.format.golang.structmapping.StructureReader[GoType]):
    """
    WARNING: tricky code / class layout here!
     
    
    To coerce java inheritance and structmapping features to match the layout of go rtti type structs,
    this class is constructed strangely.
     
    
    :obj:`GoType` structure that defines a built-in primitive type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class GoTypeFlag(java.lang.Enum[GoTypeFlag]):
    """
    Enum defining the various bitflags held in a GoType's tflag
    """

    class_: typing.ClassVar[java.lang.Class]
    Uncommon: typing.Final[GoTypeFlag]
    ExtraStar: typing.Final[GoTypeFlag]
    Named: typing.Final[GoTypeFlag]
    RegularMemory: typing.Final[GoTypeFlag]

    def getValue(self) -> int:
        ...

    def isSet(self, i: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @staticmethod
    def isValid(b: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @staticmethod
    def parseFlags(b: typing.Union[jpype.JInt, int]) -> java.util.Set[GoTypeFlag]:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> GoTypeFlag:
        ...

    @staticmethod
    def values() -> jpype.JArray[GoTypeFlag]:
        ...

    @property
    def set(self) -> jpype.JBoolean:
        ...

    @property
    def value(self) -> jpype.JInt:
        ...


class GoMethod(ghidra.app.util.bin.format.golang.structmapping.StructureMarkup[GoMethod]):
    """
    Structure that defines a method for a GoType, found in the type's :obj:`GoUncommonType` struct.
    """

    class GoMethodInfo(ghidra.app.util.bin.format.golang.rtti.MethodInfo):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, type: GoType, method: GoMethod, address: ghidra.program.model.address.Address):
            ...

        def getMethod(self) -> GoMethod:
            """
            :obj:`GoMethod` which contains the funcdef of this method
            
            :return: :obj:`GoMethod`
            :rtype: GoMethod
            """

        def getMethodFuncType(self) -> GoFuncType:
            ...

        def getType(self) -> GoType:
            """
            GoType that defined the method.  (eg. the receiver/"this" type of the method)
            
            :return: :obj:`GoType`
            :rtype: GoType
            """

        def isIfn(self, funcAddr: ghidra.program.model.address.Address) -> bool:
            ...

        def isTfn(self, funcAddr: ghidra.program.model.address.Address) -> bool:
            ...

        def toString(self) -> str:
            ...

        @property
        def ifn(self) -> jpype.JBoolean:
            ...

        @property
        def method(self) -> GoMethod:
            ...

        @property
        def methodFuncType(self) -> GoFuncType:
            ...

        @property
        def type(self) -> GoType:
            ...

        @property
        def tfn(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getGoName(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        """
        Returns the name of this method.
        
        :return: name of this method as a raw GoName value
        :rtype: ghidra.app.util.bin.format.golang.rtti.GoName
        :raises IOException: if error reading
        """

    def getIfn(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the version of the function that is called via the interface.
        
        :return: address of the version of the function that is called via the interface
        :rtype: ghidra.program.model.address.Address
        """

    def getMethodInfos(self, containingType: GoType) -> java.util.List[GoMethod.GoMethodInfo]:
        """
        Returns a list of :obj:`GoMethodInfo`s containing the ifn and tfn values (if present).
        
        :param GoType containingType: :obj:`GoType` that contains this method
        :return: list of :obj:`GoMethodInfo` instances representing the ifn and tfn values if present
        :rtype: java.util.List[GoMethod.GoMethodInfo]
        """

    def getName(self) -> str:
        """
        Returns the name of this method.
        
        :return: name of this method
        :rtype: str
        """

    def getTfn(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the version of the function that is called normally.
        
        :return: address of the version of the function that is called normally
        :rtype: ghidra.program.model.address.Address
        """

    def getType(self) -> GoType:
        """
        Return the :obj:`GoType` that defines the funcdef / func signature.
         
        
        Commonly will return ``null`` because the RTTI does not have any data for
        the method.
        
        :return: :obj:`GoType` that defines the funcdef / func signature
        :rtype: GoType
        :raises IOException: if error reading data
        """

    def isSignatureMissing(self) -> bool:
        """
        Returns true if the funcdef is missing for this method.
        
        :return: true if the funcdef is missing for this method
        :rtype: bool
        """

    @property
    def ifn(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def methodInfos(self) -> java.util.List[GoMethod.GoMethodInfo]:
        ...

    @property
    def goName(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        ...

    @property
    def signatureMissing(self) -> jpype.JBoolean:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def type(self) -> GoType:
        ...

    @property
    def tfn(self) -> ghidra.program.model.address.Address:
        ...


class GoBaseType(ghidra.app.util.bin.format.golang.structmapping.StructureVerifier):
    """
    Represents the fundamental golang rtti type information.
     
    
    The in-memory instance will typically be part of a specialized type structure, depending
    on the 'kind' of this type.
     
    
    Additionally, there can be an :obj:`GoUncommonType` structure immediately after this type, if
    the uncommon bit is set in tflag.
     
    struct specialized_type { basetype_struct; (various_fields)* } struct uncommon;
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getFlags(self) -> java.util.Set[GoTypeFlag]:
        """
        Returns the :obj:`GoTypeFlag`s assigned to this type definition.
        
        :return: :obj:`GoTypeFlag`s assigned to this type definition
        :rtype: java.util.Set[GoTypeFlag]
        """

    def getGoName(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        """
        Returns the name of this type.
        
        :return: name of this type, as a :obj:`GoName`
        :rtype: ghidra.app.util.bin.format.golang.rtti.GoName
        :raises IOException: if error reading data
        """

    def getKind(self) -> GoKind:
        """
        Returns the :obj:`GoKind` enum assigned to this type definition.
        
        :return: :obj:`GoKind` enum assigned to this type definition
        :rtype: GoKind
        """

    def getName(self) -> str:
        """
        Returns the name of this type.
        
        :return: String name of this type
        :rtype: str
        """

    def getPtrToThis(self) -> GoType:
        """
        Returns a reference to the :obj:`GoType` that represents a pointer to this type.
        
        :return: reference to the :obj:`GoType` that represents a pointer to this type
        :rtype: GoType
        :raises IOException: if error reading
        """

    def getSize(self) -> int:
        """
        Returns the size of the type being defined by this structure.
        
        :return: size of the type being defined
        :rtype: int
        """

    def getTflag(self) -> int:
        """
        Returns the raw flag value.
        
        :return: raw flag value
        :rtype: int
        """

    def hasUncommonType(self) -> bool:
        """
        Returns true if this type definition's flags indicate there is a following GoUncommon
        structure.
        
        :return: true if this type definition's flags indicate there is a following GoUncommon struct
        :rtype: bool
        """

    @property
    def tflag(self) -> jpype.JInt:
        ...

    @property
    def size(self) -> jpype.JLong:
        ...

    @property
    def kind(self) -> GoKind:
        ...

    @property
    def goName(self) -> ghidra.app.util.bin.format.golang.rtti.GoName:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def flags(self) -> java.util.Set[GoTypeFlag]:
        ...

    @property
    def ptrToThis(self) -> GoType:
        ...


class GoMapType(GoType):
    """
    Golang type info about a specific map type.
     
    
    See :meth:`GoTypeManager.getMapGoType() <GoTypeManager.getMapGoType>` or the "runtime.hmap" type for the definition of
    a instance of a map variable in memory.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getBucket(self) -> GoType:
        """
        Returns the GoType that defines the map's bucket, referenced by the bucket field's markup annotation
        
        :return: GoType that defines the map's bucket
        :rtype: GoType
        :raises IOException: if error reading data
        """

    def getElement(self) -> GoType:
        """
        Returns the GoType that defines the map's element, referenced by the element field's markup annotation
        
        :return: GoType that defines the map's element
        :rtype: GoType
        :raises IOException: if error reading data
        """

    def getKey(self) -> GoType:
        """
        Returns the GoType that defines the map's key, referenced by the key field's markup annotation
        
        :return: GoType that defines the map's key
        :rtype: GoType
        :raises IOException: if error reading data
        """

    @property
    def bucket(self) -> GoType:
        ...

    @property
    def key(self) -> GoType:
        ...

    @property
    def element(self) -> GoType:
        ...


class GoTypeDetector(java.lang.Object):
    """
    Small stub that is only used to fetch the "kind" field so that the real gotype can be detected
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def getKind(self) -> GoKind:
        ...

    @property
    def kind(self) -> GoKind:
        ...



__all__ = ["GoKind", "GoStructType", "GoSliceType", "GoInterfaceType", "GoFuncType", "GoChanType", "GoPointerType", "GoArrayType", "GoTypeBridge", "GoUncommonType", "GoStructField", "GoIMethod", "GoType", "GoPlainType", "GoTypeFlag", "GoMethod", "GoBaseType", "GoMapType", "GoTypeDetector"]
