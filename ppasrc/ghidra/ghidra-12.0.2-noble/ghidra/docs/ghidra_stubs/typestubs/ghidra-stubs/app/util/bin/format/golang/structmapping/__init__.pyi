from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.util.bin
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util
import ghidra.util.task
import java.lang # type: ignore
import java.lang.annotation # type: ignore
import java.lang.reflect # type: ignore
import java.util # type: ignore


CTX = typing.TypeVar("CTX")
R = typing.TypeVar("R")
T = typing.TypeVar("T")


class StructureVerifier(java.lang.Object):
    """
    Optional interface that allows a struct mapped object to verify itself after deserialization.
    """

    class_: typing.ClassVar[java.lang.Class]

    def isValid(self) -> bool:
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...


class FieldReadFunction(java.lang.Object, typing.Generic[T]):
    """
    Functional interface to read a structure field's value.
    
    
    .. seealso::
    
        | :obj:`.get(FieldContext)`
    """

    class_: typing.ClassVar[java.lang.Class]

    def get(self, context: FieldContext[T]) -> java.lang.Object:
        """
        Deserializes and returns a field's value.
        
        :param FieldContext[T] context: context for this field
        :return: value of the field
        :rtype: java.lang.Object
        :raises IOException: if error reading
        """


class MarkupSession(java.lang.Object):
    """
    State and methods needed for structure mapped objects to add markup, comments, labels, etc
    to a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, programContext: DataTypeMapper, monitor: ghidra.util.task.TaskMonitor):
        """
        Creates a new markup session
        
        :param DataTypeMapper programContext: program-level structure mapping context
        :param ghidra.util.task.TaskMonitor monitor: allows user to cancel
        """

    def addReference(self, fieldContext: FieldContext[typing.Any], refDest: ghidra.program.model.address.Address):
        """
        Creates a reference from the specified field to the specified address.
        
        :param FieldContext[typing.Any] fieldContext: field, is the source of the reference
        :param ghidra.program.model.address.Address refDest: destination address of the reference
        """

    @typing.overload
    def appendComment(self, fieldContext: FieldContext[typing.Any], commentType: ghidra.program.model.listing.CommentType, prefix: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], sep: typing.Union[java.lang.String, str]):
        """
        Adds a comment to the specified field, appending to any previous values
        already there.  If the existing comment already contains the specified comment value,
        the operation is skipped.
        
        :param FieldContext[typing.Any] fieldContext: the field
        :param ghidra.program.model.listing.CommentType commentType: :obj:`CommentType` enum
        :param java.lang.String or str prefix: String prefix to place in front of the comment string
        :param java.lang.String or str comment: String value to append
        :param java.lang.String or str sep: separator to use between existing comments (for example, "\n")
        :raises IOException: if error adding comment
        """

    @typing.overload
    def appendComment(self, structureContext: StructureContext[typing.Any], commentType: ghidra.program.model.listing.CommentType, prefix: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str], sep: typing.Union[java.lang.String, str]):
        """
        Adds a comment to the specified structure, appending to any previous values
        already there.  If the existing comment already contains the specified comment value,
        the operation is skipped.
        
        :param StructureContext[typing.Any] structureContext: the structure
        :param ghidra.program.model.listing.CommentType commentType: :obj:`CommentType` enum
        :param java.lang.String or str prefix: String prefix to place in front of the comment string
        :param java.lang.String or str comment: String value to append
        :param java.lang.String or str sep: separator to use between existing comments (for example, "\n")
        :raises IOException: if error adding comment
        """

    @typing.overload
    def appendComment(self, func: ghidra.program.model.listing.Function, prefix: typing.Union[java.lang.String, str], comment: typing.Union[java.lang.String, str]):
        ...

    def createFunctionIfMissing(self, name: typing.Union[java.lang.String, str], ns: ghidra.program.model.symbol.Namespace, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
        """
        Creates a default function at the specified address.
        
        :param java.lang.String or str name: name of the new function
        :param ghidra.program.model.symbol.Namespace ns: namespace function should be in
        :param ghidra.program.model.address.Address addr: address of the new function
        :return: :obj:`Function` that was created
        :rtype: ghidra.program.model.listing.Function
        """

    def getMappingContext(self) -> DataTypeMapper:
        """
        Returns the program level mapping context
        
        :return: :obj:`DataTypeMapper`
        :rtype: DataTypeMapper
        """

    def getMarkedupAddresses(self) -> ghidra.program.model.address.AddressSet:
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the Ghidra program
        
        :return: Ghidra :obj:`Program`
        :rtype: ghidra.program.model.listing.Program
        """

    @typing.overload
    def labelAddress(self, addr: ghidra.program.model.address.Address, symbolName: typing.Union[java.lang.String, str]):
        """
        Places a label at the specified address.
        
        :param ghidra.program.model.address.Address addr: :obj:`Address`
        :param java.lang.String or str symbolName: name
        :raises IOException: if error
        """

    @typing.overload
    def labelAddress(self, addr: ghidra.program.model.address.Address, symbolName: typing.Union[java.lang.String, str], namespaceName: typing.Union[java.lang.String, str]):
        """
        Places a label at the specified address.
        
        :param ghidra.program.model.address.Address addr: :obj:`Address`
        :param java.lang.String or str symbolName: name
        :param java.lang.String or str namespaceName: name of namespace to place the label symbol in, or null if root
        :raises IOException: if error
        """

    def labelStructure(self, obj: T, symbolName: typing.Union[java.lang.String, str], namespaceName: typing.Union[java.lang.String, str]):
        """
        Places a label at the specified structure mapped object's address.
        
        :param T: structure mapped object type:param T obj: structure mapped object
        :param java.lang.String or str symbolName: name
        :param java.lang.String or str namespaceName: name of namespace to place the label symbol in, or null if root
        :raises IOException: if error
        """

    @typing.overload
    def logWarningAt(self, addr: ghidra.program.model.address.Address, msg: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    @typing.overload
    def logWarningAt(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, msg: typing.Union[java.lang.String, str]):
        ...

    def markup(self, obj: T, nested: typing.Union[jpype.JBoolean, bool]):
        """
        Decorates the specified object's memory using the various structure mapping tags that 
        were applied the object's class definition.
         
        
        The object can be a structure mapped object, or a collection, array or iterator of structure
        mapped objects.
        
        :param T: structure mapped object type:param T obj: structure mapped object instance
        :param jpype.JBoolean or bool nested: boolean flag, if true the specified object is contained inside another object
        who's data type has already been laid down in memory, removing the need for this object's
        data type to be applied to memory
        :raises IOException: if error or cancelled
        :raises CancelledException: if cancelled
        :raises IllegalArgumentException: if object instance is not a supported type
        """

    @typing.overload
    def markupAddress(self, addr: ghidra.program.model.address.Address, dt: ghidra.program.model.data.DataType):
        """
        Applies the specified :obj:`DataType` to the specified :obj:`Address`.
        
        :param ghidra.program.model.address.Address addr: location to place DataType
        :param ghidra.program.model.data.DataType dt: :obj:`DataType`
        :raises IOException: if error marking up address
        """

    @typing.overload
    def markupAddress(self, addr: ghidra.program.model.address.Address, dt: ghidra.program.model.data.DataType, length: typing.Union[jpype.JInt, int]):
        """
        Applies the specified :obj:`DataType` to the specified :obj:`Address`.
        
        :param ghidra.program.model.address.Address addr: location to place DataType
        :param ghidra.program.model.data.DataType dt: :obj:`DataType`
        :param jpype.JInt or int length: length of the data type instance, or -1 if the data type is fixed length
        :raises IOException: if error marking up address
        """

    def markupAddressIfUndefined(self, addr: ghidra.program.model.address.Address, dt: ghidra.program.model.data.DataType):
        """
        Applies the specified :obj:`DataType` to the specified :obj:`Address`.
        
        :param ghidra.program.model.address.Address addr: location to place DataType
        :param ghidra.program.model.data.DataType dt: :obj:`DataType`
        :raises IOException: if error marking up address
        """

    def markupArrayElementReferences(self, arrayAddr: ghidra.program.model.address.Address, elementSize: typing.Union[jpype.JInt, int], targetAddrs: java.util.List[ghidra.program.model.address.Address]):
        """
        Creates references from each element of an array to a list of target addresses.
        
        :param ghidra.program.model.address.Address arrayAddr: the address of the start of the array
        :param jpype.JInt or int elementSize: the size of each array element
        :param java.util.List[ghidra.program.model.address.Address] targetAddrs: list of addresses that will receive references from each array elements
        :raises IOException: if error
        """

    def markupStructure(self, structureContext: StructureContext[T], nested: typing.Union[jpype.JBoolean, bool]):
        """
        Decorates a structure mapped structure, and everything it contains.
        
        :param T: structure mapped type:param StructureContext[T] structureContext: :obj:`StructureContext`
        :param jpype.JBoolean or bool nested: if true, it is assumed that the Ghidra data types have already been
        placed and only markup needs to be performed.
        :raises IOException: if error marking up structure
        :raises CancelledException: if cancelled
        """

    @property
    def markedupAddresses(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def mappingContext(self) -> DataTypeMapper:
        ...


class ReflectionHelper(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def assignField(field: java.lang.reflect.Field, obj: java.lang.Object, value: java.lang.Object):
        """
        Write a value to a field in a java class.
        
        :param java.lang.reflect.Field field: reflection :obj:`Field`
        :param java.lang.Object obj: java instance that contains the field
        :param java.lang.Object value: value to write
        :raises IOException: if error accessing field or converting value
        """

    @staticmethod
    def callCtor(ctor: java.lang.reflect.Constructor[T], *params: java.lang.Object) -> T:
        ...

    @staticmethod
    @typing.overload
    def callGetter(getterMethod: java.lang.reflect.Method, obj: T) -> java.lang.Object:
        ...

    @staticmethod
    @typing.overload
    def callGetter(getterMethod: java.lang.reflect.Method, obj: T, expectedType: java.lang.Class[R]) -> R:
        ...

    @staticmethod
    def callSetter(obj: java.lang.Object, setterMethod: java.lang.reflect.Method, value: T):
        ...

    @staticmethod
    def createInstance(targetClass: java.lang.Class[T], optionalContext: CTX) -> T:
        """
        Creates an instance of the specified target class, using an optional context parameter
        to the constructor.
        
        :param T: type of the class to be created:param CTX: type of the context to be passed to the constructor:param java.lang.Class[T] targetClass: class to be created
        :param CTX optionalContext: anything, or null
        :return: new instance of type T
        :rtype: T
        :raises java.lang.IllegalArgumentException: if error creating instance
        """

    @staticmethod
    def findGetter(structClass: java.lang.Class[typing.Any], getterName: typing.Union[java.lang.String, str]) -> java.lang.reflect.Method:
        ...

    @staticmethod
    def findSetter(fieldName: typing.Union[java.lang.String, str], setterNameOverride: typing.Union[java.lang.String, str], structClass: java.lang.Class[typing.Any], valueClass: java.lang.Class[typing.Any]) -> java.lang.reflect.Method:
        ...

    @staticmethod
    def getAnnotations(targetClass: java.lang.Class[typing.Any], annotationClass: java.lang.Class[T], result: java.util.List[T]) -> java.util.List[T]:
        ...

    @staticmethod
    def getArrayOutputDataType(array_value: java.lang.Object, fieldType: java.lang.Class[typing.Any], length: typing.Union[jpype.JInt, int], signedness: Signedness, dataTypeMapper: DataTypeMapper) -> ghidra.program.model.data.DataType:
        """
        Return Ghidra data type representing an array of primitive values.
        
        :param java.lang.Object array_value: java array object
        :param java.lang.Class[typing.Any] fieldType: class representing the java array type
        :param jpype.JInt or int length: length of an element of the array, or -1
        :param Signedness signedness: :obj:`Signedness` enum
        :param DataTypeMapper dataTypeMapper: program level structure mapping context
        :return: Ghdira :obj:`ArrayDataType` representing the specified java array type
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getCommentMethod(clazz: java.lang.Class[typing.Any], commentGetterName: typing.Union[java.lang.String, str], defaultGetterName: typing.Union[java.lang.String, str]) -> java.lang.reflect.Method:
        ...

    @staticmethod
    def getCtor(clazz: java.lang.Class[T], *paramTypes: java.lang.Class[typing.Any]) -> java.lang.reflect.Constructor[T]:
        ...

    @staticmethod
    def getDataTypeSignedness(dt: ghidra.program.model.data.DataType) -> Signedness:
        ...

    @staticmethod
    def getFieldValue(obj: java.lang.Object, field: java.lang.reflect.Field, expectedType: java.lang.Class[R]) -> R:
        ...

    @staticmethod
    def getMarkedMethods(targetClass: java.lang.Class[typing.Any], annotationClass: java.lang.Class[java.lang.annotation.Annotation], methods: java.util.List[java.lang.reflect.Method], includeParentClasses: typing.Union[jpype.JBoolean, bool], *paramClasses: java.lang.Class[typing.Any]) -> java.util.List[java.lang.reflect.Method]:
        """
        Returns a list of methods that have been marked with a specific annotation.
        
        :param java.lang.Class[typing.Any] targetClass: class to query
        :param java.lang.Class[java.lang.annotation.Annotation] annotationClass: annotation to search for
        :param java.util.List[java.lang.reflect.Method] methods: list to accumulate results into, or null to allocate new list.  Also returned
        as the result of this function
        :param jpype.JBoolean or bool includeParentClasses: boolean flag, if true recurse into parent classes first
        :param jpype.JArray[java.lang.Class[typing.Any]] paramClasses: list of parameters that the tagged methods should declare.  Methods
        will be skipped if they don't match
        :return: list of found methods that match the annotation and param list
        :rtype: java.util.List[java.lang.reflect.Method]
        """

    @staticmethod
    def getPrimitiveOutputDataType(fieldType: java.lang.Class[typing.Any], length: typing.Union[jpype.JInt, int], signedness: Signedness, dataTypeMapper: DataTypeMapper) -> ghidra.program.model.data.DataType:
        ...

    @staticmethod
    def getPrimitiveSizeof(fieldType: java.lang.Class[typing.Any]) -> int:
        ...

    @staticmethod
    def getPrimitiveWrapper(primitiveType: java.lang.Class[typing.Any]) -> java.lang.Class[typing.Any]:
        ...

    @staticmethod
    def hasStructureMapping(clazz: java.lang.Class[typing.Any]) -> bool:
        ...

    @staticmethod
    def invokeMethods(methods: java.util.List[java.lang.reflect.Method], obj: java.lang.Object, *params: java.lang.Object):
        ...

    @staticmethod
    def isPrimitiveType(clazz: java.lang.Class[typing.Any]) -> bool:
        ...

    @staticmethod
    def requireGetter(clazz: java.lang.Class[typing.Any], getterName: typing.Union[java.lang.String, str]) -> java.lang.reflect.Method:
        ...


class StructureMarkupFunction(java.lang.Object, typing.Generic[T]):
    """
    Function that decorates a Ghidra structure
    """

    class_: typing.ClassVar[java.lang.Class]

    def markupStructure(self, context: StructureContext[T], markupSession: MarkupSession):
        """
        Decorates the specified structure.
        
        :param StructureContext[T] context: :obj:`StructureContext`
        :param MarkupSession markupSession: state and methods to assist marking up the program
        :raises IOException: thrown if error performing the markup
        :raises CancelledException: if cancelled
        """


class FieldOutputFunction(java.lang.Object, typing.Generic[T]):
    """
    A function that adds a field to a Ghidra structure using annotated field information
    found in a Java class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addFieldToStructure(self, context: StructureContext[T], structure: ghidra.program.model.data.Structure, fieldOutputInfo: FieldOutputInfo[T]):
        """
        Adds the specified field (in ``fieldOutputInfo``) to the structure.
        
        :param StructureContext[T] context: :obj:`StructureContext`
        :param ghidra.program.model.data.Structure structure: :obj:`Structure` data type
        :param FieldOutputInfo[T] fieldOutputInfo: :obj:`FieldOutputInfo` field info
        :raises IOException: if error
        """


class StructureContext(java.lang.Object, typing.Generic[T]):
    """
    Information about an instance of a structure that has been read from the memory of a 
    Ghidra program.
     
    
    All :obj:`StructureMapping` tagged classes must have a :obj:`ContextField` tagged
    StructureContext field for that class to be able to access meta-data about its self, and
    for other classes to reference it when performing markup:
     
    @StructureMapping(structureName = "mydatatype")
    class MyDataType {
        @ContextField
        private StructureContext<MyDataType> context;
     
        @FieldMapping
        private long someField;
    ...
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dataTypeMapper: DataTypeMapper, mappingInfo: StructureMappingInfo[T], reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates an instance of a :obj:`StructureContext`.
        
        :param DataTypeMapper dataTypeMapper: mapping context for the program
        :param StructureMappingInfo[T] mappingInfo: mapping information about this structure
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` positioned at the start of the structure to be read, or
        null if this is a limited-use context object
        """

    @typing.overload
    def __init__(self, dataTypeMapper: DataTypeMapper, mappingInfo: StructureMappingInfo[T], containingFieldDataType: ghidra.program.model.data.DataType, reader: ghidra.app.util.bin.BinaryReader):
        """
        Creates an instance of a :obj:`StructureContext`.
        
        :param DataTypeMapper dataTypeMapper: mapping context for the program
        :param StructureMappingInfo[T] mappingInfo: mapping information about this structure
        :param ghidra.program.model.data.DataType containingFieldDataType: optional, the DataType of the field that contained the
        instance being deserialized
        :param ghidra.app.util.bin.BinaryReader reader: :obj:`BinaryReader` positioned at the start of the structure to be read, or
        null if this is a limited-use context object
        """

    def createFieldContext(self, fmi: FieldMappingInfo[T], includeReader: typing.Union[jpype.JBoolean, bool]) -> FieldContext[T]:
        """
        Creates a new :obj:`FieldContext` for a specific field.
        
        :param FieldMappingInfo[T] fmi: :obj:`field <FieldMappingInfo>` of interest
        :param jpype.JBoolean or bool includeReader: boolean flag, if true create a BinaryReader for the field, if false no
        BinaryReader will be created
        :return: new :obj:`FieldContext`
        :rtype: FieldContext[T]
        """

    def getContainingFieldDataType(self) -> ghidra.program.model.data.DataType:
        """
        Returns the :obj:`DataType` of the field that this object instance was contained inside of,
        or null if this instance was not a field inside another structure.
         
        
        For instance, if a structure was being deserialized because it was a field inside 
        another structure, the actual Ghidra data type of the field may be slightly different
        than the structure data type defined at the top of the structmapped 
        class (ie. ``@StructureMapping(structureName='struct')``.  The containing field's
        data type could allow custom logic to enrich or modify this struct's behavior.
        
        :return: :obj:`DataType` of the field that this object instance was contained inside of
        :rtype: ghidra.program.model.data.DataType
        """

    def getDataTypeMapper(self) -> DataTypeMapper:
        """
        Returns a reference to the root :obj:`DataTypeMapper`, as a plain DataTypeMapper type.  If
        a more specific DataTypeMapper type is needed, either type-cast this value, or use
        a :obj:`ContextField` tag on a field in your class that specifies the correct 
        DataTypeMapper type.
        
        :return: the program mapping context that control's this structure instance
        :rtype: DataTypeMapper
        """

    def getFieldAddress(self, fieldOffset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Returns the address of an offset from the start of this structure instance.
        
        :param jpype.JLong or int fieldOffset: number of bytes from the beginning of this structure where a field (or
        other location of interest) starts
        :return: :obj:`Address` of specified offset
        :rtype: ghidra.program.model.address.Address
        """

    def getFieldLocation(self, fieldOffset: typing.Union[jpype.JLong, int]) -> int:
        """
        Returns the stream location of an offset from the start of this structure instance.
        
        :param jpype.JLong or int fieldOffset: number of bytes from the beginning of this structure where a field (or
        other location of interest) starts
        :return: absolute offset / position in the program / BinaryReader stream
        :rtype: int
        """

    def getFieldReader(self, fieldOffset: typing.Union[jpype.JLong, int]) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns an independent :obj:`BinaryReader` that is positioned at the start of the
        specified field.
        
        :param jpype.JLong or int fieldOffset: number of bytes from the beginning of this structure where a field (or
        other location of interest) starts
        :return: new :obj:`BinaryReader` positioned at the specified relative offset
        :rtype: ghidra.app.util.bin.BinaryReader
        """

    def getMappingInfo(self) -> StructureMappingInfo[T]:
        """
        Returns the :obj:`StructureMappingInfo` for this structure's class.
        
        :return: :obj:`StructureMappingInfo` for this structure's class
        :rtype: StructureMappingInfo[T]
        """

    def getReader(self) -> ghidra.app.util.bin.BinaryReader:
        """
        Returns the :obj:`BinaryReader` that is used to deserialize this structure.
        
        :return: :obj:`BinaryReader` that is used to deserialize this structure
        :rtype: ghidra.app.util.bin.BinaryReader
        """

    def getStructureAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address in the program of this structure instance.
        
        :return: :obj:`Address`
        :rtype: ghidra.program.model.address.Address
        """

    def getStructureDataType(self) -> ghidra.program.model.data.Structure:
        """
        Returns the Ghidra :obj:`structure data type <Structure>` that represents this object.
         
        
        If this is an instance of a variable length structure mapped class, a custom structure data
        type will be minted that exactly matches this instance's variable length fields.
        
        :return: Ghidra :obj:`structure data type <Structure>` that represents this object
        :rtype: ghidra.program.model.data.Structure
        :raises IOException: if error constructing new struct data type
        """

    def getStructureEnd(self) -> int:
        """
        Returns the stream location of the end of this structure instance.
        
        :return: absolute offset / position in the program / BinaryReader stream of the byte after
        this structure
        :rtype: int
        """

    def getStructureInstance(self) -> T:
        """
        Returns a reference to the object instance that was deserialized.
        
        :return: reference to deserialized structure mapped object
        :rtype: T
        """

    def getStructureLength(self) -> int:
        """
        Returns the length of this structure instance.
        
        :return: length of this structure, or 0 if this structure is a variable length structure
        that does not have a fixed length
        :rtype: int
        """

    def getStructureStart(self) -> int:
        """
        Returns the stream location of this structure instance.
        
        :return: absolute offset / position in the program / BinaryReader stream of this structure
        :rtype: int
        """

    def readNewInstance(self) -> T:
        """
        Creates a new instance of the structure by deserializing the structure's marked
        fields into java fields.
        
        :return: new instance of structure
        :rtype: T
        :raises IOException: if error reading
        """

    @property
    def fieldLocation(self) -> jpype.JLong:
        ...

    @property
    def containingFieldDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def structureStart(self) -> jpype.JLong:
        ...

    @property
    def structureEnd(self) -> jpype.JLong:
        ...

    @property
    def mappingInfo(self) -> StructureMappingInfo[T]:
        ...

    @property
    def reader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def structureInstance(self) -> T:
        ...

    @property
    def fieldAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def fieldReader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def structureDataType(self) -> ghidra.program.model.data.Structure:
        ...

    @property
    def structureAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def structureLength(self) -> jpype.JInt:
        ...

    @property
    def dataTypeMapper(self) -> DataTypeMapper:
        ...


class StructureReader(java.lang.Object, typing.Generic[T]):
    """
    Interface used by structure mapped classes that need to manually deserialize themselves from
    the raw data, required when the structure contains variable length fields.
    """

    class_: typing.ClassVar[java.lang.Class]

    def readStructure(self):
        """
        Called after an instance has been created and its context has been initialized, to give
        the struct a chance to deserialize itself using the BinaryReaders and such found in the
        context information.
        
        :raises IOException: if error deserializing data for this struct
        """


class StructureMappingInfo(java.lang.Object, typing.Generic[T]):
    """
    Contains immutable information about a structure mapped class needed to deserialize
    a new object from the data found in a Ghidra program.
    """

    @typing.type_check_only
    class ReadFromStructureFunction(java.lang.Object, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def readStructure(self, context: StructureContext[T]) -> T:
            ...


    @typing.type_check_only
    class ObjectInstanceCreator(java.lang.Object, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def get(self, context: StructureContext[T]) -> T:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def assignContextFieldValues(self, context: StructureContext[T]):
        """
        Initializes any :obj:`ContextField` fields in a new structure instance.
        
        :param StructureContext[T] context: :obj:`StructureContext`
        :raises IOException: if error assigning values to context fields in the structure mapped
        instance
        """

    def createStructureDataType(self, context: StructureContext[T]) -> ghidra.program.model.data.Structure:
        """
        Creates a new customized :obj:`structure data type <Structure>` for a variable length
        structure mapped class.
        
        :param StructureContext[T] context: :obj:`StructureContext` of a variable length structure mapped instance
        :return: new :obj:`structure data type <Structure>` with a name that encodes the size 
        information of the variable length fields
        :rtype: ghidra.program.model.data.Structure
        :raises IOException: if error creating the Ghidra data type
        """

    @staticmethod
    def fromClass(targetClass: java.lang.Class[T], structDataType: ghidra.program.model.data.Structure, context: DataTypeMapperContext) -> StructureMappingInfo[T]:
        """
        Returns the mapping info for a class, using annotations found in that class.
        
        :param T: structure mapped class:param java.lang.Class[T] targetClass: structure mapped class
        :param ghidra.program.model.data.Structure structDataType: Ghidra :obj:`DataType` that defines the binary layout of the mapped
        fields of the class, or null if this is a self-reading :obj:`StructureReader` class
        :param DataTypeMapperContext context: :obj:`DataTypeMapperContext`
        :return: new :obj:`StructureMappingInfo` for the specified class
        :rtype: StructureMappingInfo[T]
        :raises IllegalArgumentException: if targetClass isn't tagged as a structure mapped class
        """

    def getAfterMethods(self) -> java.util.List[java.lang.reflect.Method]:
        ...

    def getDescription(self) -> str:
        ...

    def getFieldInfo(self, javaFieldName: typing.Union[java.lang.String, str]) -> FieldMappingInfo[T]:
        ...

    def getFields(self) -> java.util.List[FieldMappingInfo[T]]:
        ...

    def getInstanceCreator(self) -> StructureMappingInfo.ObjectInstanceCreator[T]:
        ...

    def getMarkupFuncs(self) -> java.util.List[StructureMarkupFunction[T]]:
        ...

    def getStructureDataType(self) -> ghidra.program.model.data.Structure:
        ...

    def getStructureLength(self) -> int:
        ...

    def getStructureName(self) -> str:
        ...

    def getTargetClass(self) -> java.lang.Class[T]:
        ...

    def readStructure(self, context: StructureContext[T]):
        """
        Deserializes a structure mapped instance by assigning values to its 
        :obj:`@FieldMapping mapped <FieldMapping>` java fields.
        
        :param StructureContext[T] context: :obj:`StructureContext`
        :raises IOException: if error reading the structure
        """

    def recoverStructureContext(self, structureInstance: T) -> StructureContext[T]:
        """
        Reaches into a structure mapped instance and extracts its StructureContext field value.
        
        :param T structureInstance: instance to query
        :return: :obj:`StructureContext`, or null if error extracting value
        :rtype: StructureContext[T]
        """

    @property
    def markupFuncs(self) -> java.util.List[StructureMarkupFunction[T]]:
        ...

    @property
    def targetClass(self) -> java.lang.Class[T]:
        ...

    @property
    def structureName(self) -> java.lang.String:
        ...

    @property
    def instanceCreator(self) -> StructureMappingInfo.ObjectInstanceCreator[T]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def structureDataType(self) -> ghidra.program.model.data.Structure:
        ...

    @property
    def fields(self) -> java.util.List[FieldMappingInfo[T]]:
        ...

    @property
    def fieldInfo(self) -> FieldMappingInfo[T]:
        ...

    @property
    def structureLength(self) -> jpype.JInt:
        ...

    @property
    def afterMethods(self) -> java.util.List[java.lang.reflect.Method]:
        ...


class FieldOutputInfo(java.lang.Object, typing.Generic[T]):
    """
    Immutable information needed to create fields in a Ghidra structure data type, using information
    from a java field.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, fmi: FieldMappingInfo[T], dataTypeName: typing.Union[java.lang.String, str], isVariableLength: typing.Union[jpype.JBoolean, bool], ordinal: typing.Union[jpype.JInt, int], fieldOffset: typing.Union[jpype.JInt, int]):
        ...

    def getField(self) -> java.lang.reflect.Field:
        ...

    def getOrdinal(self) -> int:
        ...

    def getOutputFunc(self) -> FieldOutputFunction[T]:
        ...

    def getValue(self, structInstance: T, expectedType: java.lang.Class[R]) -> R:
        """
        Returns the value of this java field.
        
        :param R: type of the result value:param T structInstance: object containing the field
        :param java.lang.Class[R] expectedType: expected class of the value
        :return: value of the field, or null if the field's value is not of expected type
        :rtype: R
        :raises IOException: if error accessing java field
        """

    def isVariableLength(self) -> bool:
        ...

    def setOutputFuncClass(self, funcClass: java.lang.Class[FieldOutputFunction], getterName: typing.Union[java.lang.String, str]):
        ...

    @property
    def field(self) -> java.lang.reflect.Field:
        ...

    @property
    def variableLength(self) -> jpype.JBoolean:
        ...

    @property
    def outputFunc(self) -> FieldOutputFunction[T]:
        ...

    @property
    def ordinal(self) -> jpype.JInt:
        ...


class DataTypeMapperContext(java.lang.Object):
    """
    Context passed to StructureMapping logic when binding a structure's fields to a java class's
    fields.
    """

    class_: typing.ClassVar[java.lang.Class]

    def isFieldPresent(self, presentWhen: typing.Union[java.lang.String, str]) -> bool:
        """
        Tests if a field should be included when creating bindings between a structure and a class.
        
        :param java.lang.String or str presentWhen: free-form string that is interpreted by each :obj:`DataTypeMapper`
        :return: boolean true if field should be bound, false if field should not be bound
        :rtype: bool
        """

    @property
    def fieldPresent(self) -> jpype.JBoolean:
        ...


class FieldMappingInfo(java.lang.Object, typing.Generic[T]):
    """
    Immutable information needed to deserialize a field in a structure mapped class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addCommentMarkupFuncs(self):
        ...

    def addMarkupFunc(self, func: FieldMarkupFunction[T]):
        ...

    def addMarkupNestedFuncs(self):
        ...

    def addMarkupReferenceFunc(self):
        ...

    def assignField(self, fieldContext: FieldContext[T], value: java.lang.Object):
        ...

    @staticmethod
    def createEarlyBinding(field: java.lang.reflect.Field, dtc: ghidra.program.model.data.DataTypeComponent, signedness: Signedness, length: typing.Union[jpype.JInt, int]) -> FieldMappingInfo[T]:
        """
        Creates a FieldMappingInfo instance, used when the structure is not variable length.
        
        :param T: structure mapped class type:param java.lang.reflect.Field field: java field
        :param ghidra.program.model.data.DataTypeComponent dtc: Ghidra structure field
        :param Signedness signedness: :obj:`Signedness` enum
        :param jpype.JInt or int length: override of structure field, or -1
        :return: new :obj:`FieldMappingInfo` instance
        :rtype: FieldMappingInfo[T]
        """

    @staticmethod
    def createLateBinding(field: java.lang.reflect.Field, fieldName: typing.Union[java.lang.String, str], signedness: Signedness, length: typing.Union[jpype.JInt, int]) -> FieldMappingInfo[T]:
        """
        Creates a FieldMappingInfo instance, used when the structure is variable length and there is
        no pre-defined Ghidra Structure data type.
        
        :param T: structure mapped class type:param java.lang.reflect.Field field: java field
        :param java.lang.String or str fieldName: name of Ghidra structure field
        :param Signedness signedness: :obj:`Signedness` enum
        :param jpype.JInt or int length: override of structure field, or -1
        :return: new :obj:`FieldMappingInfo` instance
        :rtype: FieldMappingInfo[T]
        """

    def findDtc(self, struct: ghidra.program.model.data.Structure) -> ghidra.program.model.data.DataTypeComponent:
        ...

    @typing.overload
    def getDtc(self) -> ghidra.program.model.data.DataTypeComponent:
        ...

    @typing.overload
    def getDtc(self, structure: ghidra.program.model.data.Structure) -> ghidra.program.model.data.DataTypeComponent:
        ...

    def getField(self) -> java.lang.reflect.Field:
        ...

    def getFieldName(self) -> str:
        ...

    def getLength(self) -> int:
        ...

    def getMarkupFuncs(self) -> java.util.List[FieldMarkupFunction[T]]:
        ...

    def getReaderFunc(self) -> FieldReadFunction[T]:
        ...

    def getSignedness(self) -> Signedness:
        ...

    def getValue(self, structInstance: T, expectedType: java.lang.Class[R]) -> R:
        ...

    def isStructureMappedType(self) -> bool:
        ...

    def isUnsigned(self) -> bool:
        ...

    def setFieldValueDeserializationInfo(self, fieldReadValueClass: java.lang.Class[FieldReadFunction], structTargetClass: java.lang.Class[typing.Any], setterNameOverride: typing.Union[java.lang.String, str]):
        ...

    @property
    def readerFunc(self) -> FieldReadFunction[T]:
        ...

    @property
    def dtc(self) -> ghidra.program.model.data.DataTypeComponent:
        ...

    @property
    def markupFuncs(self) -> java.util.List[FieldMarkupFunction[T]]:
        ...

    @property
    def fieldName(self) -> java.lang.String:
        ...

    @property
    def field(self) -> java.lang.reflect.Field:
        ...

    @property
    def signedness(self) -> Signedness:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def unsigned(self) -> jpype.JBoolean:
        ...

    @property
    def structureMappedType(self) -> jpype.JBoolean:
        ...


class FieldMarkupFunction(java.lang.Object, typing.Generic[T]):
    """
    A function that decorates a field in a structure mapped class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def markupField(self, fieldContext: FieldContext[T], markupSession: MarkupSession):
        """
        Decorates the specified field.
        
        :param FieldContext[T] fieldContext: information about the field
        :param MarkupSession markupSession: state and methods to assist marking up the program
        :raises IOException: thrown if error performing the markup
        :raises CancelledException: if cancelled
        """


class StructureMarkup(java.lang.Object, typing.Generic[T]):
    """
    Optional interface that structure mapped classes can implement that allows them to control how
    their class is marked up.
     
    
    TODO: possibly refactor these methods to take a StructureContext parameter, which will
    allow removing the getStructureContext method.
    """

    class_: typing.ClassVar[java.lang.Class]

    def additionalMarkup(self, session: MarkupSession):
        """
        Called to allow the implementor to perform custom markup of itself.
        
        :param MarkupSession session: state and methods to assist marking up the program
        :raises IOException: if error during markup
        :raises CancelledException: if cancelled
        """

    def getExternalInstancesToMarkup(self) -> java.util.List[typing.Any]:
        """
        Returns a list of items that should be recursively marked up.
        
        :return: list of structure mapped object instances that should be marked up
        :rtype: java.util.List[typing.Any]
        :raises IOException: if error getting instances
        """

    def getStructureContext(self) -> StructureContext[T]:
        ...

    def getStructureLabel(self) -> str:
        """
        Returns a string that can be used to place a label on the instance.
         
        
        This default implementation will query the :meth:`getStructureName() <.getStructureName>` method, and if
        it provides a value, will produce a string that looks like "name___mappingstructname", where
        "mappingstructname" will be the ``structureName`` value in the ``@StructureMapping``
        annotation.
        
        :return: string to be used as a label, or null if there is not a valid label for the instance
        :rtype: str
        :raises IOException: if error getting label
        """

    def getStructureName(self) -> str:
        """
        Returns the name of the instance, typically retrieved from data found inside the instance.
        
        :return: string name, or null if this instance does not have a name
        :rtype: str
        :raises IOException: if error getting name
        """

    def getStructureNamespace(self) -> str:
        """
        Returns the namespace that any labels should be placed in.
        
        :return: name of namespace to place the label for this structure mapped type, or null
        :rtype: str
        :raises IOException: if error generating namespace name
        """

    @property
    def structureNamespace(self) -> java.lang.String:
        ...

    @property
    def structureLabel(self) -> java.lang.String:
        ...

    @property
    def structureContext(self) -> StructureContext[T]:
        ...

    @property
    def structureName(self) -> java.lang.String:
        ...

    @property
    def externalInstancesToMarkup(self) -> java.util.List[typing.Any]:
        ...


class FieldContext(java.lang.Record, typing.Generic[T]):
    """
    Context of an individual field that is being deserialized, or being markedup.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, structureContext: StructureContext[T], fieldInfo: FieldMappingInfo[T], dtc: ghidra.program.model.data.DataTypeComponent, reader: ghidra.app.util.bin.BinaryReader):
        ...

    def dtc(self) -> ghidra.program.model.data.DataTypeComponent:
        ...

    def equals(self, o: java.lang.Object) -> bool:
        ...

    def fieldInfo(self) -> FieldMappingInfo[T]:
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of this structure field.
        
        :return: the address of this field
        :rtype: ghidra.program.model.address.Address
        """

    def getStructureInstance(self) -> T:
        """
        Returns the structure instance that contains this field.
        
        :return: structure instance that contains this field
        :rtype: T
        """

    def getValue(self, expectedType: java.lang.Class[R]) -> R:
        """
        Returns the value of this java field.
        
        :param R: result type:param java.lang.Class[R] expectedType: class of expected result type
        :return: value of this java field, as type R
        :rtype: R
        :raises IOException: if error getting or converting value
        """

    def hashCode(self) -> int:
        ...

    def reader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    def structureContext(self) -> StructureContext[T]:
        ...

    def toString(self) -> str:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def structureInstance(self) -> T:
        ...

    @property
    def value(self) -> R:
        ...


class DataTypeMapper(java.lang.AutoCloseable):
    """
    Information about :obj:`StructureMapping` classes and their metadata.
     
    
    To use the full might and majesty of StructureMapping™, a DataTypeMapper must be created. It
    must be able to :meth:`find <.addArchiveSearchCategoryPath>` 
    (:meth:`more find <.addProgramSearchCategoryPath>`) the Ghidra structure data
    types being used, and it must :meth:`know <.registerStructure>` about
    all classes that are going to participate during deserialization and markup.
     
    
    Structure mapped classes can receive a reference to the specific DataTypeMapper type that 
    created them by declaring a ``DataTypeMapper`` field, and tagging it with 
    the @:obj:`ContextField` annotation:
     
     
    class MyDataTypeMapper extends DataTypeMapper {
    public MyDataTypeMapper() {
        ...
    registerStructure(MyDataType.class);
    }
    public void foo() { ... }
    }
     
    @StructureMapping(structureName = "mydatatype")
    class MyDataType {
     
    @ContextField
    private MyDataTypeMapper myDataTypeMapper;
      
    @ContextField
    private StructureContext<MyDataType> context;
     
    @FieldMapping
    private long someField;
     
    void bar() {
    context.getDataTypeMapper().getProgram(); // can only access methods defined on base DataTypeMapper type
    myDataTypeMapper.foo(); // same context as previous line, but typed correctly
    ...
    """

    class_: typing.ClassVar[java.lang.Class]

    def addArchiveSearchCategoryPath(self, *paths: ghidra.program.model.data.CategoryPath):
        """
        Adds category paths to a search list, used when looking for a data type.
         
        
        See :meth:`getType(String, Class) <.getType>`.
        
        :param jpype.JArray[ghidra.program.model.data.CategoryPath] paths: vararg list of :obj:`CategoryPath`s
        """

    def addProgramSearchCategoryPath(self, *paths: ghidra.program.model.data.CategoryPath):
        """
        Adds category paths to a search list, used when looking for a data type.
         
        
        See :meth:`getType(String, Class) <.getType>`.
        
        :param jpype.JArray[ghidra.program.model.data.CategoryPath] paths: vararg list of :obj:`CategoryPath`s
        """

    def createArtificialStructureContext(self, structureClass: java.lang.Class[T]) -> StructureContext[T]:
        """
        Creates an artificial structure context to be used in some limited situations.
        
        :param T: type of structure mapped object:param java.lang.Class[T] structureClass: class of structure mapped object
        :return: new :obj:`StructureContext`
        :rtype: StructureContext[T]
        """

    def createMarkupSession(self, monitor: ghidra.util.task.TaskMonitor) -> MarkupSession:
        """
        Creates a :obj:`MarkupSession` that is controlled by the specified :obj:`TaskMonitor`.
        
        :param ghidra.util.task.TaskMonitor monitor: :obj:`TaskMonitor`
        :return: new :obj:`MarkupSession`
        :rtype: MarkupSession
        """

    def getAddressOfStructure(self, structureInstance: T) -> ghidra.program.model.address.Address:
        """
        Attempts to convert an instance of an object (that represents a chunk of memory in
        the program) into its Address.
        
        :param T: type of the object:param T structureInstance: instance of an object that represents something in the program's
        memory
        :return: :obj:`Address` of the object, or null if not found or not a supported object
        :rtype: ghidra.program.model.address.Address
        """

    def getCodeAddress(self, offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Converts an offset into an Address.
        
        :param jpype.JLong or int offset: numeric offset
        :return: :obj:`Address`
        :rtype: ghidra.program.model.address.Address
        """

    def getDTM(self) -> ghidra.program.model.data.DataTypeManager:
        """
        Returns the program's data type manager.
        
        :return: program's :obj:`DataTypeManager`
        :rtype: ghidra.program.model.data.DataTypeManager
        """

    def getDataAddress(self, offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Converts an offset into an Address.
        
        :param jpype.JLong or int offset: numeric offset
        :return: :obj:`Address`
        :rtype: ghidra.program.model.address.Address
        """

    def getDataConverter(self) -> ghidra.util.DataConverter:
        """
        Returns a :obj:`DataConverter` appropriate for the current program.
        
        :return: :obj:`DataConverter`
        :rtype: ghidra.util.DataConverter
        """

    def getDefaultVariableLengthStructCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        """
        CategoryPath location (in the program) where new data types will be created to represent
        variable length structures.
        
        :return: :obj:`CategoryPath`, default is ROOT
        :rtype: ghidra.program.model.data.CategoryPath
        """

    def getMaxAddressOfStructure(self, structureInstance: T) -> ghidra.program.model.address.Address:
        """
        Returns the address of the last byte of a structure.
        
        :param T: type of object:param T structureInstance: instance of an object that represents something in the program's
        memory
        :return: :obj:`Address` of the last byte of the object, or null if not found 
        or not a supported object
        :rtype: ghidra.program.model.address.Address
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the program.
        
        :return: ghidra :obj:`Program`
        :rtype: ghidra.program.model.listing.Program
        """

    def getReader(self, position: typing.Union[jpype.JLong, int]) -> ghidra.app.util.bin.BinaryReader:
        """
        Creates a :obj:`BinaryReader`, at the specified position.
        
        :param jpype.JLong or int position: location in the program
        :return: new :obj:`BinaryReader`
        :rtype: ghidra.app.util.bin.BinaryReader
        """

    def getStructureContextOfInstance(self, structureInstance: T) -> StructureContext[T]:
        """
        Returns the :obj:`StructureContext` of a structure mapped instance.
        
        :param T: java type of a class that is structure mapped:param T structureInstance: an existing instance of type T
        :return: :obj:`StructureContext` of the instance, or null if instance was null or not
        a structure mapped object
        :rtype: StructureContext[T]
        """

    def getStructureDataType(self, clazz: java.lang.Class[typing.Any]) -> ghidra.program.model.data.Structure:
        """
        Returns a Ghidra structure data type representing the specified class.
        
        :param java.lang.Class[typing.Any] clazz: a structure mapped class
        :return: :obj:`Structure` data type, or null if the class was a struct with variable length
        fields
        :rtype: ghidra.program.model.data.Structure
        """

    def getStructureDataTypeName(self, clazz: java.lang.Class[typing.Any]) -> str:
        """
        Returns the name of the Ghidra structure that has been registered for the specified
        structure mapped class.
        
        :param java.lang.Class[typing.Any] clazz: a structure mapped class
        :return: name of the corresponding Ghidra structure data type, or null if class was not
        registered
        :rtype: str
        """

    @typing.overload
    def getStructureMappingInfo(self, clazz: java.lang.Class[T]) -> StructureMappingInfo[T]:
        """
        Returns the :obj:`StructureMappingInfo` for a class (that has already been registered).
        
        :param T: structure mapped class type:param java.lang.Class[T] clazz: the class
        :return: :obj:`StructureMappingInfo` for the specified class, or null if the class was
        not previously :meth:`registered <.registerStructure>`
        :rtype: StructureMappingInfo[T]
        """

    @typing.overload
    def getStructureMappingInfo(self, structureInstance: T) -> StructureMappingInfo[T]:
        """
        Returns the :obj:`StructureMappingInfo` for an object instance.
        
        :param T: structure mapped class type:param T structureInstance: an instance of a previously registered 
        :obj:`structure mapping <StructureMapping>` class, or null
        :return: :obj:`StructureMappingInfo` for the instance, or null if the class was
        not previously :meth:`registered <.registerStructure>`
        :rtype: StructureMappingInfo[T]
        """

    @typing.overload
    def getType(self, name: typing.Union[java.lang.String, str], clazz: java.lang.Class[T]) -> T:
        """
        Returns a named :obj:`DataType`, searching the registered 
        :meth:`program <.addProgramSearchCategoryPath>`
        and :meth:`archive <.addArchiveSearchCategoryPath>` category paths.
         
        
        DataTypes that were found in the attached archive gdt manager will be copied into the
        program's data type manager before being returned.
        
        :param T: DataType or derived type:param java.lang.String or str name: :obj:`DataType` name
        :param java.lang.Class[T] clazz: expected DataType class
        :return: DataType or null if not found
        :rtype: T
        """

    @typing.overload
    def getType(self, names: java.util.List[java.lang.String], clazz: java.lang.Class[T]) -> T:
        """
        Returns a named :obj:`DataType`, searching the registered
        :meth:`program <.addProgramSearchCategoryPath>`
        and :meth:`archive <.addArchiveSearchCategoryPath>` category paths.
         
        
        DataTypes that were found in the attached archive gdt manager will be copied into the
        program's data type manager before being returned.
        
        :param T: DataType or derived type:param java.util.List[java.lang.String] names: list containing the data type name and any alternates
        :param java.lang.Class[T] clazz: expected DataType class
        :return: DataType or null if not found
        :rtype: T
        """

    def getTypeOrDefault(self, name: typing.Union[java.lang.String, str], clazz: java.lang.Class[T], defaultValue: T) -> T:
        """
        Returns a named :obj:`DataType`, searching the registered
        :meth:`program <.addProgramSearchCategoryPath>`
        and :meth:`archive <.addArchiveSearchCategoryPath>` category paths.
         
        
        DataTypes that were found in the attached archive gdt manager will be copied into the
        program's data type manager before being returned.
        
        :param T: DataType or derived type:param java.lang.String or str name: :obj:`DataType` name
        :param java.lang.Class[T] clazz: expected DataType class
        :param T defaultValue: value to return if the requested data type was not found
        :return: DataType or ``defaultValue`` if not found
        :rtype: T
        """

    @typing.overload
    def readStructure(self, structureClass: java.lang.Class[T], structReader: ghidra.app.util.bin.BinaryReader) -> T:
        """
        Reads a structure mapped object from the current position of the specified BinaryReader.
        
        :param T: type of object:param java.lang.Class[T] structureClass: structure mapped object class
        :param ghidra.app.util.bin.BinaryReader structReader: :obj:`BinaryReader` positioned at the start of an object
        :return: new object instance of type T
        :rtype: T
        :raises IOException: if error reading
        :raises IllegalArgumentException: if specified structureClass is not valid
        """

    @typing.overload
    def readStructure(self, structureClass: java.lang.Class[T], containingFieldDataType: ghidra.program.model.data.DataType, structReader: ghidra.app.util.bin.BinaryReader) -> T:
        """
        Reads a structure mapped object from the current position of the specified BinaryReader.
        
        :param T: type of object:param java.lang.Class[T] structureClass: structure mapped object class
        :param ghidra.program.model.data.DataType containingFieldDataType: optional, data type of the structure field that contained the
        object instance that is being read (may be different than the data type that was specified in
        the matching :obj:`StructureMappingInfo`)
        :param ghidra.app.util.bin.BinaryReader structReader: :obj:`BinaryReader` positioned at the start of an object
        :return: new object instance of type T
        :rtype: T
        :raises IOException: if error reading
        :raises IllegalArgumentException: if specified structureClass is not valid
        """

    @typing.overload
    def readStructure(self, structureClass: java.lang.Class[T], position: typing.Union[jpype.JLong, int]) -> T:
        """
        Reads a structure mapped object from the specified position of the program.
        
        :param T: type of object:param java.lang.Class[T] structureClass: structure mapped object class
        :param jpype.JLong or int position: of object
        :return: new object instance of type T
        :rtype: T
        :raises IOException: if error reading
        :raises IllegalArgumentException: if specified structureClass is not valid
        """

    @typing.overload
    def readStructure(self, structureClass: java.lang.Class[T], address: ghidra.program.model.address.Address) -> T:
        """
        Reads a structure mapped object from the specified Address of the program.
        
        :param T: type of object:param java.lang.Class[T] structureClass: structure mapped object class
        :param ghidra.program.model.address.Address address: location of object
        :return: new object instance of type T
        :rtype: T
        :raises IOException: if error reading
        :raises IllegalArgumentException: if specified structureClass is not valid
        """

    def registerStructure(self, clazz: java.lang.Class[T], context: DataTypeMapperContext):
        """
        Registers a class that has :obj:`structure mapping <StructureMapping>` information.
        
        :param T: structure mapped class type:param java.lang.Class[T] clazz: class that represents a structure, marked with :obj:`StructureMapping` 
        annotation
        :param DataTypeMapperContext context: :obj:`DataTypeMapperContext`
        :raises IOException: if the class's Ghidra structure data type could not be found
        """

    def registerStructures(self, classes: java.util.List[java.lang.Class[typing.Any]], context: DataTypeMapperContext):
        """
        Registers the specified :obj:`structure mapping <StructureMapping>` classes.
        
        :param java.util.List[java.lang.Class[typing.Any]] classes: list of classes to register
        :param DataTypeMapperContext context: :obj:`DataTypeMapperContext`
        :raises IOException: if a class's Ghidra structure data type could not be found
        """

    @property
    def defaultVariableLengthStructCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        ...

    @property
    def dataAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def reader(self) -> ghidra.app.util.bin.BinaryReader:
        ...

    @property
    def addressOfStructure(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def structureMappingInfo(self) -> StructureMappingInfo[T]:
        ...

    @property
    def structureDataType(self) -> ghidra.program.model.data.Structure:
        ...

    @property
    def codeAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def structureDataTypeName(self) -> java.lang.String:
        ...

    @property
    def structureContextOfInstance(self) -> StructureContext[T]:
        ...

    @property
    def maxAddressOfStructure(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def dataConverter(self) -> ghidra.util.DataConverter:
        ...

    @property
    def dTM(self) -> ghidra.program.model.data.DataTypeManager:
        ...


class Signedness(java.lang.Enum[Signedness]):
    """
    Signedness attribute of a structure mapped field
    """

    class_: typing.ClassVar[java.lang.Class]
    Unspecified: typing.Final[Signedness]
    Signed: typing.Final[Signedness]
    Unsigned: typing.Final[Signedness]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> Signedness:
        ...

    @staticmethod
    def values() -> jpype.JArray[Signedness]:
        ...



__all__ = ["StructureVerifier", "FieldReadFunction", "MarkupSession", "ReflectionHelper", "StructureMarkupFunction", "FieldOutputFunction", "StructureContext", "StructureReader", "StructureMappingInfo", "FieldOutputInfo", "DataTypeMapperContext", "FieldMappingInfo", "FieldMarkupFunction", "StructureMarkup", "FieldContext", "DataTypeMapper", "Signedness"]
