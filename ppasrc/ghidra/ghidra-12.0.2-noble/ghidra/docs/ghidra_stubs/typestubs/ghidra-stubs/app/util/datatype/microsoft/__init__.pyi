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
import ghidra.program.model.mem
import ghidra.util
import java.lang # type: ignore


class WEVTResourceDataType(ghidra.program.model.data.DynamicDataType):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        ...


class VersionedGuidInfo(GuidInfo):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, guidString: typing.Union[java.lang.String, str], version: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], type: GuidUtil.GuidType):
        ...

    def getGuidVersionString(self) -> str:
        ...

    @property
    def guidVersionString(self) -> java.lang.String:
        ...


@deprecated("Use of this dynamic data type class is no longer recommended. Instead an \n array of either pointers or displacements to BaseClassDescriptor structures can be \n obtained using the Rtti2Model.")
class RTTI2DataType(RTTIDataType):
    """
    The RTTI2 data type represents an array of either pointers or displacements to the 
    BaseClassDescriptors (RTTI 1s) for a class.
     
    
    Fields for this RunTimeTypeInformation structure can be found on http://www.openrce.org
     
    
    RTTI_Base_Class_Array is the label for the RTTI2 data structure.
    
    
    .. deprecated::
    
    Use of this dynamic data type class is no longer recommended. Instead an 
    array of either pointers or displacements to BaseClassDescriptor structures can be 
    obtained using the Rtti2Model.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a dynamic Base Class Array data type.
        """

    @typing.overload
    def __init__(self, rtti1Count: typing.Union[jpype.JLong, int]):
        """
        Creates a dynamic Base Class Array data type.
        
        :param jpype.JLong or int rtti1Count: the number of rtti1 refs
        """

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        """
        Creates a dynamic Base Class Array data type.
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager for this data type.
        """

    @typing.overload
    def __init__(self, rtti1Count: typing.Union[jpype.JLong, int], dtm: ghidra.program.model.data.DataTypeManager):
        """
        Creates a dynamic Base Class Array data type.
        
        :param jpype.JLong or int rtti1Count: the number of rtti1 refs
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager for this data type.
        """

    def getLength(self, memory: ghidra.program.model.mem.Memory, address: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte]) -> int:
        """
        Gets the total length of the data created when this data type is placed at the indicated 
        address in memory.
        
        :param ghidra.program.model.mem.Memory memory: the program memory for this data.
        :param ghidra.program.model.address.Address address: the start address of the data.
        :param jpype.JArray[jpype.JByte] bytes: the bytes for this data.
        :return: the length of the data. zero is returned if valid data can't be created at the 
        indicated address using this data type.
        :rtype: int
        """

    @typing.overload
    def getRtti1Address(self, memory: ghidra.program.model.mem.Memory, rtti2Address: ghidra.program.model.address.Address, rtti1Index: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
        """
        Gets address referred to by the RTTI 1 pointer at the specified index in the RTTI2's 
        array that is at the rtti2Address.
        
        :param ghidra.program.model.mem.Memory memory: the program memory containing the RTTI 2
        :param ghidra.program.model.address.Address rtti2Address: the address of the RTTI 2
        :param jpype.JInt or int rtti1Index: the index of RTTI 1 entry in the RTTI 2 array
        :return: the address of the RTTI 1 referred to by the indexed array element.
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def getRtti1Address(self, program: ghidra.program.model.listing.Program, rtti2Address: ghidra.program.model.address.Address, rtti1Index: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
        """
        Gets address referred to by the RTTI 1 pointer at the specified index in the RTTI2's 
        array that is at the rtti2Address.
        
        :param ghidra.program.model.listing.Program program: the program containing the RTTI 2
        :param ghidra.program.model.address.Address rtti2Address: the address of the RTTI 2
        :param jpype.JInt or int rtti1Index: the index of RTTI 1 entry in the RTTI 2 array
        :return: the address of the RTTI 1 referred to by the indexed array element.
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def isValidRtti1Pointer(self, program: ghidra.program.model.listing.Program, startAddress: ghidra.program.model.address.Address, pointerIndex: typing.Union[jpype.JInt, int], overwriteInstructions: typing.Union[jpype.JBoolean, bool], overwriteDefinedData: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Determines if the RTTI 1 pointer in the RTTI2 structure is valid.
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address startAddress: the address of the RTTI 2 structure
        :param jpype.JInt or int pointerIndex: index of the element in the array that makes up the RTTI 2.
        :param jpype.JBoolean or bool overwriteInstructions: true indicates that existing instructions can be overwritten 
        by this data type.
        :param jpype.JBoolean or bool overwriteDefinedData: true indicates that existing defined data can be overwritten 
        by this data type.
        :return: true if the indicated RTTI1 pointer is valid.
        :rtype: bool
        """

    @typing.overload
    def isValidRtti1Pointer(self, program: ghidra.program.model.listing.Program, startAddress: ghidra.program.model.address.Address, pointerIndex: typing.Union[jpype.JInt, int], validationOptions: DataValidationOptions) -> bool:
        """
        Determines if the RTTI 1 pointer in the RTTI2 structure is valid.
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address startAddress: the address of the RTTI 2 structure
        :param jpype.JInt or int pointerIndex: index of the element in the array that makes up the RTTI 2.
        :param DataValidationOptions validationOptions: options indicating how to perform the validation
        :return: true if the indicated RTTI1 pointer is valid.
        :rtype: bool
        """


class DataValidationOptions(java.lang.Object):
    """
    Holds options for controlling how validation is performed when determining whether or not to 
    create data structures at a particular location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a DataValidationOptions object with the default values.
        """

    @typing.overload
    def __init__(self, validationOptions: DataValidationOptions):
        """
        Copy constructor
        
        :param DataValidationOptions validationOptions: the data validation options to copy
        """

    def setIgnoreDefinedData(self, ignoreDefinedData: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not existing defined data should invalidate the creation of new data.
        
        :param jpype.JBoolean or bool ignoreDefinedData: false indicates existing defined data, where the data would be 
        created, should cause validation to fail.
        """

    def setIgnoreInstructions(self, ignoreInstructions: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not existing instructions should invalidate the creation of new data.
        
        :param jpype.JBoolean or bool ignoreInstructions: false indicates existing instructions, where the data would be 
        created, should cause validation to fail.
        """

    def setValidateReferredToData(self, validateReferredToData: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not to validate follow on data that is referred to by the current 
        new structure.
        
        :param jpype.JBoolean or bool validateReferredToData: true indicates follow on data should be validated.
        """

    def shouldIgnoreDefinedData(self) -> bool:
        """
        An option indicating whether or not existing defined data should make the location invalid 
        for new data.
         
        Default is true.
        
        :return: false if existing defined data should cause the creation of new data to be invalid.
        :rtype: bool
        """

    def shouldIgnoreInstructions(self) -> bool:
        """
        An option indicating whether or not existing instructions should make the location invalid 
        for new data.
         
        Default is false.
        
        :return: false if existing instructions should cause the creation of new data to be invalid.
        :rtype: bool
        """

    def shouldValidateReferredToData(self) -> bool:
        """
        An option indicating whether or not to follow references to other data and validate those too.
        If this is set to true then the data is only valid if its referred to data is also valid.
         
        Default is true.
        
        :return: true if structures should be validated for referred to data.
        :rtype: bool
        """


@deprecated("Use of this dynamic data type class is no longer recommended. Instead a\n BaseClassDescriptor structure data type can be obtained using the Rtti1Model.")
class RTTI1DataType(RTTIDataType):
    """
    The RTTI1 data type represents a BaseClassDescriptor structure.
     
    
    Fields for this RunTimeTypeInformation structure can be found on http://www.openrce.org
     
    struct BaseClassDescriptor {
        4byte_ptr_or_disp pTypeDescriptor; // ref to TypeDescriptor (RTTI 0) for class
        dword numContainedBases;           // count of extended classes in BaseClassArray (RTTI 2)
        struct pmd where;                  // member displacement structure
        dword attributes;                  // bit flags
    }
     
     
    struct pmd {
        int mdisp; // member displacement
        int pdisp; // vbtable displacement
        int vdisp; // displacement within vbtable
    }
     
     
    
    RTTI_Base_Class_Descriptor is the label for the RTTI1 data structure.
    
    
    .. deprecated::
    
    Use of this dynamic data type class is no longer recommended. Instead a
    BaseClassDescriptor structure data type can be obtained using the Rtti1Model.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a dynamic Base Class Descriptor data type.
        """

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        """
        Creates a dynamic Base Class Descriptor data type.
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager for this data type.
        """

    def getLength(self, memory: ghidra.program.model.mem.Memory, address: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte]) -> int:
        """
        Gets the total length of the data created when this data type is placed at the indicated 
        address in memory.
        
        :param ghidra.program.model.mem.Memory memory: the program memory for this data.
        :param ghidra.program.model.address.Address address: the start address of the data.
        :param jpype.JArray[jpype.JByte] bytes: the bytes for this data.
        :return: the length of the data. zero is returned if valid data can't be created at the 
        indicated address using this data type.
        :rtype: int
        """

    @typing.overload
    def getRtti0Address(self, memory: ghidra.program.model.mem.Memory, rtti1Address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Gets the address of the RTTI 0 or null if one isn't indicated.
        
        :param ghidra.program.model.mem.Memory memory: the program memory containing the address
        :param ghidra.program.model.address.Address rtti1Address: the address for the RTTI 1 that refers to the RTTI 0
        :return: the address of the RTTI 0 or null.
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def getRtti0Address(self, program: ghidra.program.model.listing.Program, rtti1Address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Gets the address of the RTTI 0 or null if one isn't indicated.
        
        :param ghidra.program.model.listing.Program program: the program  containing the address
        :param ghidra.program.model.address.Address rtti1Address: the address for the RTTI 1 that refers to the RTTI 0
        :return: the address of the RTTI 0 or null.
        :rtype: ghidra.program.model.address.Address
        """


class GUID(java.lang.Object):
    """
    GUIDs identify objects such as interfaces, manager entry-point vectors (EPVs), 
    and class objects. A GUID is a 128-bit value consisting of one group 
    of 8 hexadecimal digits, followed by three groups of 4 hexadecimal 
    digits each, followed by one group of 12 hexadecimal digits. The 
    following example shows the groupings of hexadecimal digits in a GUID.
     
    
    ``6B29FC40-CA47-1067-B31D-00DD010662DA``
     
    
     
    typedef struct _GUID {
            DWORD Data1;
            WORD Data2;
            WORD Data3;
            BYTE Data4[8];
    } GUID;
     
    Data1 - Specifies the first 8 hexadecimal digits of the GUID.
     
    Data2 - Specifies the first group of 4 hexadecimal digits.
    
    Data3 - Specifies the second group of 4 hexadecimal digits.
    
    Data4 - Array of 8 bytes.
            The first 2 bytes contain the third group of 4 hexadecimal digits.
            The remaining 6 bytes contain the final 12 hexadecimal digits.
    """

    class_: typing.ClassVar[java.lang.Class]
    SIZEOF: typing.Final = 16

    @typing.overload
    def __init__(self, guidString: typing.Union[java.lang.String, str]):
        """
        Creates a GUID object using the GUID string form.
        
        :param java.lang.String or str guidString: - either with or without dashes between parts - 
        "6B29FC40-CA47-1067-B31D-00DD010662DA", or "6B29FC40CA471067B31D00DD010662DA", and
        with or without leading and trailing "{" "}" characters
        :raises java.lang.IllegalArgumentException: if string does not represent a valid GUID
        """

    @typing.overload
    def __init__(self, data1: typing.Union[jpype.JInt, int], data2: typing.Union[jpype.JShort, int], data3: typing.Union[jpype.JShort, int], data4: jpype.JArray[jpype.JByte]):
        """
        Constructs a GUID using the constitute pieces.
        """

    @typing.overload
    def __init__(self, reader: ghidra.app.util.bin.BinaryReader):
        """
        Reads a GUID from the given binary reader.
        
        :param ghidra.app.util.bin.BinaryReader reader: the binary reader to read the GUID
        :raises IOException: if an I/O error occurs while reading the GUID
        """

    @typing.overload
    def __init__(self, buf: ghidra.program.model.mem.MemBuffer):
        """
        Reads a GUID from the given memory buffer.
        
        :param ghidra.program.model.mem.MemBuffer buf: the memory buffer to read the GUID
        :raises MemoryAccessException: if an error occurs while reading the GUID
        """

    def getData1(self) -> int:
        """
        Specifies the first 8 hexadecimal digits of the GUID.
        
        :return: 
        :rtype: int
        """

    def getData2(self) -> int:
        """
        Specifies the first group of 4 hexadecimal digits.
        
        :return: 
        :rtype: int
        """

    def getData3(self) -> int:
        """
        Specifies the second group of 4 hexadecimal digits.
        
        :return: 
        :rtype: int
        """

    def getData4(self) -> jpype.JArray[jpype.JByte]:
        """
        Array of 8 bytes.
        The first 2 bytes contain the third group of 4 hexadecimal digits.
        The remaining 6 bytes contain the final 12 hexadecimal digits.
        
        :return: 
        :rtype: jpype.JArray[jpype.JByte]
        """

    @property
    def data4(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def data3(self) -> jpype.JShort:
        ...

    @property
    def data2(self) -> jpype.JShort:
        ...

    @property
    def data1(self) -> jpype.JInt:
        ...


class GuidInfo(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, guidString: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str], type: GuidUtil.GuidType):
        ...

    def getGuidString(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def getType(self) -> GuidUtil.GuidType:
        ...

    def getUniqueIdString(self) -> str:
        ...

    @property
    def guidString(self) -> java.lang.String:
        ...

    @property
    def uniqueIdString(self) -> java.lang.String:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def type(self) -> GuidUtil.GuidType:
        ...


class MUIResourceDataType(ghidra.program.model.data.DynamicDataType):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        ...


class GroupIconResourceDataType(ghidra.program.model.data.DynamicDataType):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        ...


class RTTIDataType(ghidra.program.model.data.DynamicDataType):
    """
    An abstract class that each RTTI data type should extend to get common functionality.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def isValid(self, program: ghidra.program.model.listing.Program, startAddress: ghidra.program.model.address.Address, overwriteInstructions: typing.Union[jpype.JBoolean, bool], overwriteDefinedData: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Determines if the data type is valid for placing at the indicated address in the program.
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address startAddress: the start address
        :param jpype.JBoolean or bool overwriteInstructions: true indicates that existing instructions can be overwritten 
        by this data type.
        :param jpype.JBoolean or bool overwriteDefinedData: true indicates that existing defined data can be overwritten 
        by this data type.
        :return: true if this data type can be laid down at the specified address.
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.isValid(Program program, Address address, DataValidationOptions validationOptions)`
        """

    @typing.overload
    def isValid(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, validationOptions: DataValidationOptions) -> bool:
        """
        Determines if the data type is valid for placing at the indicated address in the program.
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address address: the address where the validated data type will be used to create data
        :param DataValidationOptions validationOptions: options indicating how to perform the validation
        :return: true if this data type can be laid down at the specified address
        :rtype: bool
        """


class DataApplyOptions(java.lang.Object):
    """
    Holds options for the commands for creating new data structures.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates an DataApplyOptions object with the default values.
        """

    @typing.overload
    def __init__(self, dataApplyOptions: DataApplyOptions):
        """
        Copy constructor
        
        :param DataApplyOptions dataApplyOptions: the data apply options to copy
        """

    def setClearDefinedData(self, clearDefinedData: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not to clear existing defined data in order to create new data.
        
        :param jpype.JBoolean or bool clearDefinedData: true indicates existing defined data should be cleared to create 
        the new data.
        """

    def setClearInstructions(self, clearInstructions: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not to clear existing instructions in order to create new data.
        
        :param jpype.JBoolean or bool clearInstructions: true indicates existing instructions should be cleared to create 
        the new data.
        """

    def setCreateBookmarks(self, createBookmarks: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not to create bookmarks for problems encountered while trying to create
        an new structure or information associated with it.
        
        :param jpype.JBoolean or bool createBookmarks: true indicates error bookmarks should be created.
        """

    def setCreateComments(self, createComments: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not to create comments for problems encountered while trying to create
        a new structure or information associated with it.
        
        :param jpype.JBoolean or bool createComments: true indicates comments for the data should be created.
        """

    def setCreateFunction(self, createFunction: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not to disassemble and create a function that is referred to 
        by the current new structure.
        
        :param jpype.JBoolean or bool createFunction: true indicates a function should be created.
        """

    def setCreateLabel(self, createLabel: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not to create labels for follow on data or a function that is referred to 
        by the current new structure.
        
        :param jpype.JBoolean or bool createLabel: true indicates a label should be created.
        """

    def setFollowData(self, followData: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not to create follow on data that is referred to by the new structure.
        
        :param jpype.JBoolean or bool followData: true indicates follow on data should be created.
        """

    def shouldClearDefinedData(self) -> bool:
        """
        An option indicating whether or not to clear existing defined data in order to create 
        new data.
         
        Default is false.
        
        :return: true if existing defined data should be cleared to create the new data.
        :rtype: bool
        """

    def shouldClearInstructions(self) -> bool:
        """
        An option indicating whether or not to clear existing instructions in order to create 
        new data.
         
        Default is false.
        
        :return: true if existing instructions should be cleared to create the new data.
        :rtype: bool
        """

    def shouldCreateBookmarks(self) -> bool:
        """
        An option indicating whether or not to create bookmarks indicating any problems that
        occurred while creating the current structure or information associated with it.
         
        Default is true.
        
        :return: true if error bookmarks should be created.
        :rtype: bool
        """

    def shouldCreateComments(self) -> bool:
        """
        An option indicating whether or not to create comments indicating any problems that
        occurred while creating the data or information associated with it.
         
        Default is true.
        
        :return: true if error comments should be created.
        :rtype: bool
        """

    def shouldCreateFunction(self) -> bool:
        """
        An option indicating whether or not to disassemble and create a function that is referred
        to by your current structure.
         
        Default is true.
        
        :return: true if referred to functions should be created.
        :rtype: bool
        """

    def shouldCreateLabel(self) -> bool:
        """
        An option indicating whether or not to create a label for the new data or for a 
        referred to data or function.
         
        Default is true.
        
        :return: true if a label should be created for this data or for referred to structures 
        and functions.
        :rtype: bool
        """

    def shouldFollowData(self) -> bool:
        """
        An option indicating whether or not to create data that is referred to by the data structure.
         
        Default is true.
        
        :return: true if structures should be created for referred to data.
        :rtype: bool
        """


class MSDataTypeUtils(java.lang.Object):
    """
    An abstract class containing static utility methods for creating structure data types.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getAbsoluteAddress(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Extracts an absolute address from the bytes in memory at the indicated address in memory.
        
        :param ghidra.program.model.listing.Program program: the program containing the bytes
        :param ghidra.program.model.address.Address address: the address in memory where the address bytes should be obtained.
        :return: the absolute address or null if the address isn't in the program's memory.
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def getAlignedPack4Structure(dataTypeManager: ghidra.program.model.data.DataTypeManager, categoryPath: ghidra.program.model.data.CategoryPath, structureName: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.StructureDataType:
        """
        Gets an empty aligned structure with a packing value of 4 that can be use to create the 
        model's data type.
        
        :param ghidra.program.model.data.DataTypeManager dataTypeManager: the data type manager to associate with the structure.
        :param ghidra.program.model.data.CategoryPath categoryPath: the structure's category path.
        :param java.lang.String or str structureName: the structure's name.
        :return: the aligned pack(4) structure.
        :rtype: ghidra.program.model.data.StructureDataType
        """

    @staticmethod
    def getAlignedPack8Structure(dataTypeManager: ghidra.program.model.data.DataTypeManager, categoryPath: ghidra.program.model.data.CategoryPath, structureName: typing.Union[java.lang.String, str]) -> ghidra.program.model.data.StructureDataType:
        """
        Gets an empty aligned structure with a packing value of 8 that can be use to create the 
        model's data type.
        
        :param ghidra.program.model.data.DataTypeManager dataTypeManager: the data type manager to associate with the structure.
        :param ghidra.program.model.data.CategoryPath categoryPath: the structure's category path.
        :param java.lang.String or str structureName: the structure's name.
        :return: the aligned pack(8) structure.
        :rtype: ghidra.program.model.data.StructureDataType
        """

    @staticmethod
    def getBytes(memory: ghidra.program.model.mem.Memory, startAddress: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Gets bytes from ``memory`` at the indicated ``startAddress``. 
        The ``length`` indicates the number of bytes that must be read 
        from memory.
        
        :param ghidra.program.model.mem.Memory memory: the program memory for obtaining the bytes
        :param ghidra.program.model.address.Address startAddress: the address to begin reading bytes
        :param jpype.JInt or int length: the number of bytes to read
        :return: the bytes
        :rtype: jpype.JArray[jpype.JByte]
        :raises InvalidDataTypeException: if the ``length`` number of bytes couldn't 
        be read starting at the ``startAddress`` in ``memory``.
        """

    @staticmethod
    def getEHStateDataType(program: ghidra.program.model.listing.Program) -> ghidra.program.model.data.DataType:
        """
        Gets an exception handling state data type.
        
        :param ghidra.program.model.listing.Program program: the program for the data type.
        :return: the exception handling state data type.
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getMatchingDataType(program: ghidra.program.model.listing.Program, comparisonDt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        Gets the named data type from the program or the windows data type archive. If neither 
        the program or data type archive has an equivalent data type then the original data type 
        is returned.
        
        :param ghidra.program.model.listing.Program program: the program for the data type.
        :param ghidra.program.model.data.DataType comparisonDt: the data type it should match
        :return: the matching data type
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getPMDDataType(program: ghidra.program.model.listing.Program) -> ghidra.program.model.data.Structure:
        """
        Gets a PMD displacement structure data type.
        
        :param ghidra.program.model.listing.Program program: the program for the data type.
        :return: the PMD data type or null.
        :rtype: ghidra.program.model.data.Structure
        """

    @staticmethod
    def getPointerDisplacementDataType(program: ghidra.program.model.listing.Program) -> ghidra.program.model.data.DataType:
        """
        Gets a pointer displacement data type.
        
        :param ghidra.program.model.listing.Program program: the program for the data type.
        :return: the pointer displacement data type.
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getReferenceDataType(program: ghidra.program.model.listing.Program, referredToDataType: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        Gets the appropriate reference data type. If program is 64 bit, then a 32-bit image 
        base offset data type will be returned. Otherwise, a default pointer to the 
        referredToDataType will be returned.
        
        :param ghidra.program.model.listing.Program program: the program that will contain the returned data type
        :param ghidra.program.model.data.DataType referredToDataType: the data type that is at the address being referred to by the 
        pointer or image base offset. Otherwise, null.
        :return: the image base offset or pointer reference data type
        :rtype: ghidra.program.model.data.DataType
        """

    @staticmethod
    def getReferencedAddress(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Gets the referred to address from the bytes in the program at the indicated address.
        If the program has 64 bit pointers, then a 32 bit image base offset value is expected to 
        be found at the indicated address. 
        If the program has 32 bit pointers, then a 32 bit absolute pointer value is expected at the
        indicated address.
        
        :param ghidra.program.model.listing.Program program: the program whose memory is to be read.
        :param ghidra.program.model.address.Address address: the address to start reading the bytes for the referenced address.
        :return: the referred to address or null.
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def is64Bit(program: ghidra.program.model.listing.Program) -> bool:
        """
        Determines if the indicated program appears to be 64 bit (has 64 bit pointers).
        
        :param ghidra.program.model.listing.Program program: the program
        :return: true if 64 bit.
        :rtype: bool
        """


class GuidUtil(java.lang.Object):

    class GuidType(java.lang.Enum[GuidUtil.GuidType]):

        class_: typing.ClassVar[java.lang.Class]
        CLSID: typing.Final[GuidUtil.GuidType]
        IID: typing.Final[GuidUtil.GuidType]
        GUID: typing.Final[GuidUtil.GuidType]
        SYNTAX: typing.Final[GuidUtil.GuidType]

        def getFilename(self) -> str:
            ...

        def hasVersion(self) -> bool:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> GuidUtil.GuidType:
            ...

        @staticmethod
        def values() -> jpype.JArray[GuidUtil.GuidType]:
            ...

        @property
        def filename(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getGuidString(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, validate: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    @staticmethod
    @typing.overload
    def getKnownGuid(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> GuidInfo:
        ...

    @staticmethod
    @typing.overload
    def getKnownGuid(guidString: typing.Union[java.lang.String, str]) -> GuidInfo:
        ...

    @staticmethod
    def getKnownVersionedGuid(versionedGuidString: typing.Union[java.lang.String, str]) -> GuidInfo:
        ...

    @staticmethod
    def getVersionedGuidString(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, validate: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    @staticmethod
    def isGuidLabel(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address, label: typing.Union[java.lang.String, str]) -> bool:
        """
        Verify that the specified label correpsonds to a Microsoft symbol name 
        for the GUID stored at the specified address within program.
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address address: memory address
        :param java.lang.String or str label: symbol name to be checked
        :return: true if label is a valid GUID label which corresponds to the GUID
        stored at address within program
        :rtype: bool
        """

    @staticmethod
    def parseLine(guidNameLine: typing.Union[java.lang.String, str], delim: typing.Union[java.lang.String, str], guidType: GuidUtil.GuidType) -> GuidInfo:
        ...


class RTTI0DataType(RTTIDataType):
    """
    The RTTI0 data type represents a TypeDescriptor structure.
     
    
    Fields for this RunTimeTypeInformation structure can be found on http://www.openrce.org
     
    struct TypeDescriptor {
        Pointer vfTablePointer;
        Pointer dataPointer;
        NullTerminatedString name; // mangled version of class name
    }
     
     
    
    RTTI_Type_Descriptor is the label for the RTTI0 data structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a dynamic Type Descriptor data type.
        """

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        """
        Creates a dynamic Type Descriptor data type.
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager for this data type.
        """

    @typing.overload
    def getLength(self, memory: ghidra.program.model.mem.Memory, address: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte]) -> int:
        """
        Gets the total length of the data created when this data type is placed at the indicated
        address in memory.
        
        :param ghidra.program.model.mem.Memory memory: the program memory for this data.
        :param ghidra.program.model.address.Address address: the start address of the data.
        :param jpype.JArray[jpype.JByte] bytes: the bytes for this data.
        :return: the length of the data. zero is returned if valid data can't be created at the
        indicated address using this data type.
        :rtype: int
        """

    @typing.overload
    def getLength(self, memory: ghidra.program.model.mem.Memory, startAddress: ghidra.program.model.address.Address) -> int:
        """
        Gets the total length of the data created when this data type is placed at the indicated
        address in memory.
        
        :param ghidra.program.model.mem.Memory memory: the program memory for this data.
        :param ghidra.program.model.address.Address startAddress: the start address of the data.
        :return: the length of the data. zero is returned if valid data can't be created at the
        indicated address using this data type.
        :rtype: int
        """

    def getSpareDataAddress(self, memory: ghidra.program.model.mem.Memory, rtti0Address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Gets the address of the spare data, a 0 address if there is no spare data,
        or null.
        
        :param ghidra.program.model.mem.Memory memory: the program memory containing the address
        :param ghidra.program.model.address.Address rtti0Address: the address for the RTTI 0
        :return: the address of the spare data, a 0 value, or null.
        :rtype: ghidra.program.model.address.Address
        """

    def getVFTableAddress(self, memory: ghidra.program.model.mem.Memory, rtti0Address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Gets the address of the vf table or null if one isn't indicated.
        
        :param ghidra.program.model.mem.Memory memory: the program memory containing the address
        :param ghidra.program.model.address.Address rtti0Address: the address for the RTTI 0
        :return: the address of the vf table or null.
        :rtype: ghidra.program.model.address.Address
        """

    def getVFTableName(self, buf: ghidra.program.model.mem.MemBuffer) -> str:
        """
        Gets the type name for this descriptor.
        
        :param ghidra.program.model.mem.MemBuffer buf: the memory buffer where data has been created with this data type.
        :return: the name
        :rtype: str
        """

    @property
    def vFTableName(self) -> java.lang.String:
        ...


class ThreadEnvironmentBlock(java.lang.Object):
    """
    Class for creating a Ghidra memory block representing the TEB: Thread Environment Block.
    The class must be instantiated with the Program and the Windows OS version to control
    details of the TEB layout.  The user must call setAddress to provide the starting address
    of the block to create. Then they must call one of
        - createBlockAndStructure    or
        - createBlocksAndSymbols
     
    The TEB can be represented either by a single structure overlaying the
    block (createBlockAndStructure), or as a series of symbols and primitive
    data-types (createBlocksAndSymbols).
     
    Finally the user should call setRegisterValue. The TEB is accessed either through the FS segment
    (32-bit) or GS segment (64-bit), so this method sets a Register value for one these over
    the program.
    """

    class WinVersion(java.lang.Enum[ThreadEnvironmentBlock.WinVersion]):
        """
        An enumeration describing a Windows OS version by String and by ordinal.
        The most significant 1 or 2 digits of the ordinal specify the major Windows release.
        The least significant 4 digits provide the minor release.
        """

        class_: typing.ClassVar[java.lang.Class]
        WIN_3_10: typing.Final[ThreadEnvironmentBlock.WinVersion]
        WIN_3_50: typing.Final[ThreadEnvironmentBlock.WinVersion]
        WIN_95: typing.Final[ThreadEnvironmentBlock.WinVersion]
        WIN_2000: typing.Final[ThreadEnvironmentBlock.WinVersion]
        WIN_XP: typing.Final[ThreadEnvironmentBlock.WinVersion]
        WIN_VISTA: typing.Final[ThreadEnvironmentBlock.WinVersion]
        WIN_7: typing.Final[ThreadEnvironmentBlock.WinVersion]
        WIN_10: typing.Final[ThreadEnvironmentBlock.WinVersion]
        WIN_LATEST: typing.Final[ThreadEnvironmentBlock.WinVersion]

        def getOrder(self) -> int:
            ...

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ThreadEnvironmentBlock.WinVersion:
            ...

        @staticmethod
        def values() -> jpype.JArray[ThreadEnvironmentBlock.WinVersion]:
            ...

        @property
        def order(self) -> jpype.JInt:
            ...


    @typing.type_check_only
    class LayDown(java.lang.Object):
        """
        Class for creating specific fields of the TEB data structure
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, is64: typing.Union[jpype.JBoolean, bool]):
            ...

        def addEntry(self, off32: typing.Union[jpype.JInt, int], off64: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str], dat: ghidra.program.model.data.DataType):
            """
            Create a single field given an offset, name, and data-type
            
            :param jpype.JInt or int off32: is the offset for the 32-bit TEB (-1 means unused)
            :param jpype.JInt or int off64: is the offset for the 64-bit TEB (-1 means unused)
            :param java.lang.String or str name: is the name of the field
            :param ghidra.program.model.data.DataType dat: is the data-type of the field
            """


    @typing.type_check_only
    class LayDownStructure(ThreadEnvironmentBlock.LayDown):
        """
        Create TEB fields as components of a Structure data-type
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, is64: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class LayDownFlat(ThreadEnvironmentBlock.LayDown):
        """
        Create TEB fields as Symbols and CodeUnits on a MemoryBlock
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, is64: typing.Union[jpype.JBoolean, bool]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    BLOCK_NAME: typing.Final = "tdb"

    def __init__(self, prog: ghidra.program.model.listing.Program, version: ThreadEnvironmentBlock.WinVersion):
        ...

    def createBlockAndStructure(self):
        """
        Create TEB as a single uninitialized block.  A TEB structure is created and is
        placed on the block.
        
        :raises MemoryConflictException: if there are overlap problems with other blocks
        :raises AddressOverflowException: for problems with block's start Address
        :raises java.lang.IllegalArgumentException: for problems with the block name or the TEB data-type
        :raises LockException: if it cannot get an exclusive lock on the program
        :raises CodeUnitInsertionException: for problems laying down the structure on the block
        :raises InvalidInputException: for problems with the symbol name attached to the TEB
        """

    def createBlocksAndSymbols(self):
        """
        Create 2 blocks, one that is initialized to hold a proper value for the TEB Self reference field
        and another to hold the remainder of the TEB.  The data structure is layed down as a
        series of symbols on these blocks.
        
        :raises MemoryConflictException: if there are overlap problems with other blocks
        :raises CancelledException: if block creation is cancelled
        :raises AddressOverflowException: for problems with block's start Address
        :raises java.lang.IllegalArgumentException: for problems with the block name or the TEB data-type
        :raises LockException: if it cannot get an exclusive lock on the program
        """

    def getBlockSize(self) -> int:
        """
        
        
        :return: the number of bytes needed in the full TEB block being constructed
        :rtype: int
        """

    def is64(self) -> bool:
        """
        
        
        :return: true if a 64-bit TEB is being layed down.
        :rtype: bool
        """

    def setAddress(self, addr: ghidra.program.model.address.Address):
        """
        Set the starting address of the TEB
        
        :param ghidra.program.model.address.Address addr: is the Address to set
        """

    def setRegisterValue(self):
        """
        Set FS_OFFSET for 32-bit or GS_OFFSET for 64-bit to the address of the TEB across the program.
        """

    @property
    def blockSize(self) -> jpype.JInt:
        ...


@deprecated("Use of this dynamic data type class is no longer recommended. Instead a\n CompleteObjectLocator structure data type can be obtained using the Rtti4Model.")
class RTTI4DataType(RTTIDataType):
    """
    The RTTI4 data type represents a CompleteObjectLocator structure.
     
    
    Fields for this RunTimeTypeInformation structure can be found on http://www.openrce.org
     
    struct CompleteObjectLocator {
        dword signature;
        dword offset;             // offset of vbtable within class
        dword cdOffset;           // constructor displacement offset
        4byte_ptr_or_disp pRtti0; // ref to TypeDescriptor (RTTI 0) for class
        4byte_ptr_or_disp pRtti3; // ref to ClassHierarchyDescriptor (RTTI 3)
    }
     
     
    
    RTTI_Complete_Object_Locator is the label for the RTTI4 data structure.
    
    
    .. deprecated::
    
    Use of this dynamic data type class is no longer recommended. Instead a
    CompleteObjectLocator structure data type can be obtained using the Rtti4Model.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a dynamic Complete Object Locator data type.
        """

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        """
        Creates a dynamic Complete Object Locator data type.
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager for this data type.
        """

    def getLength(self, memory: ghidra.program.model.mem.Memory, address: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte]) -> int:
        """
        Gets the total length of the data created when this data type is placed at the indicated 
        address in memory.
        
        :param ghidra.program.model.mem.Memory memory: the program memory for this data.
        :param ghidra.program.model.address.Address address: the start address of the data.
        :param jpype.JArray[jpype.JByte] bytes: the bytes for this data.
        :return: the length of the data. zero is returned if valid data can't be created at the 
        indicated address using this data type.
        :rtype: int
        """

    def getRtti0Address(self, memory: ghidra.program.model.mem.Memory, rtti4Address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Gets the address of the RTTI0 that is referred to from an RTTI4 structure that is placed at 
        the indicated address.
        
        :param ghidra.program.model.mem.Memory memory: the memory with the data for the RTTI structures.
        :param ghidra.program.model.address.Address rtti4Address: address of an RTTI4 structure
        :return: the address of the RTTI0 structure or null.
        :rtype: ghidra.program.model.address.Address
        """

    def getRtti3Address(self, memory: ghidra.program.model.mem.Memory, rtti4Address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Gets the address of the RTTI3 that is referred to from an RTTI4 structure that is placed at 
        the indicated address.
        
        :param ghidra.program.model.mem.Memory memory: the memory with the data for the RTTI structures.
        :param ghidra.program.model.address.Address rtti4Address: address of an RTTI4 structure
        :return: the address of the RTTI3 structure or null.
        :rtype: ghidra.program.model.address.Address
        """


class GuidDataType(ghidra.program.model.data.BuiltIn):

    class_: typing.ClassVar[java.lang.Class]
    SIZE: typing.Final = 16
    KEY: typing.Final = "GUID_NAME"

    @typing.overload
    def __init__(self):
        """
        Creates a Double Word data type.
        """

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        ...


class NewGuid(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    size: typing.ClassVar[jpype.JInt]

    @typing.overload
    def __init__(self, conv: ghidra.util.DataConverter, GUID: typing.Union[java.lang.String, str], delim: typing.Union[java.lang.String, str], type: GuidUtil.GuidType, hasVersion: typing.Union[jpype.JBoolean, bool]):
        """
        Creates a GUID data type.
        """

    @typing.overload
    def __init__(self, conv: ghidra.util.DataConverter, bytes: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]):
        ...

    def getBytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    def getName(self) -> str:
        ...

    def getType(self) -> GuidUtil.GuidType:
        ...

    def getVersion(self) -> str:
        ...

    def isOK(self) -> bool:
        ...

    @staticmethod
    def isOKForGUID(bytes: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @staticmethod
    def isZeroGUID(bytes: jpype.JArray[jpype.JByte], offset: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def toString(self, delim: typing.Union[java.lang.String, str], useName: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    @property
    def bytes(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def oK(self) -> jpype.JBoolean:
        ...

    @property
    def type(self) -> GuidUtil.GuidType:
        ...

    @property
    def version(self) -> java.lang.String:
        ...


@deprecated("Use of this dynamic data type class is no longer recommended. Instead a \n ClassHierarchyDescriptor structure data type can be obtained using the Rtti3Model.")
class RTTI3DataType(RTTIDataType):
    """
    The RTTI3 data type represents a ClassHierarchyDescriptor structure.
     
    
    Fields for this RunTimeTypeInformation structure can be found on http://www.openrce.org
     
    struct ClassHierarchyDescriptor {
        dword signature;
        dword attributes;                  // bit flags
        dword numBaseClasses;              // count of RTTI 1 ref entries in RTTI 2 array
        4byte_ptr_or_disp pBaseClassArray; // ref to BaseClassArray (RTTI 2)
    }
     
     
    
    RTTI_Class_Hierarchy_Descriptor is the label for the RTTI3 data structure.
    
    
    .. deprecated::
    
    Use of this dynamic data type class is no longer recommended. Instead a 
    ClassHierarchyDescriptor structure data type can be obtained using the Rtti3Model.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a dynamic Class Hierarchy Descriptor data type.
        """

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        """
        Creates a dynamic Class Hierarchy Descriptor data type.
        
        :param ghidra.program.model.data.DataTypeManager dtm: the data type manager for this data type.
        """

    def getLength(self, memory: ghidra.program.model.mem.Memory, address: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte]) -> int:
        """
        Gets the total length of the data created when this data type is placed at the indicated 
        address in memory.
        
        :param ghidra.program.model.mem.Memory memory: the program memory for this data.
        :param ghidra.program.model.address.Address address: the start address of the data.
        :param jpype.JArray[jpype.JByte] bytes: the bytes for this data.
        :return: the length of the data. zero is returned if valid data can't be created at the 
        indicated address using this data type.
        :rtype: int
        """

    def getRtti1Count(self, memory: ghidra.program.model.mem.Memory, rtti3Address: ghidra.program.model.address.Address) -> int:
        """
        Gets the number of RTTI1 structures that are referred to by an RTTI3 structure being placed
        at the rtti3Address of the indicated memory.
        
        :param ghidra.program.model.mem.Memory memory: the memory with the data for the RTTI structures.
        :param ghidra.program.model.address.Address rtti3Address: address of an RTTI3 structure
        :return: the RTTI1 count or 0.
        :rtype: int
        """

    def getRtti2Address(self, memory: ghidra.program.model.mem.Memory, rtti3Address: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Gets the address of the RTTI2 that is referred to from an RTTI3 structure that is placed at 
        the indicated address.
        
        :param ghidra.program.model.mem.Memory memory: the memory with the data for the RTTI structures.
        :param ghidra.program.model.address.Address rtti3Address: address of an RTTI3 structure
        :return: the address of the RTTI2 structure or null.
        :rtype: ghidra.program.model.address.Address
        """


class HTMLResourceDataType(ghidra.program.model.data.BuiltIn, ghidra.program.model.data.Dynamic):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, dtm: ghidra.program.model.data.DataTypeManager):
        ...



__all__ = ["WEVTResourceDataType", "VersionedGuidInfo", "RTTI2DataType", "DataValidationOptions", "RTTI1DataType", "GUID", "GuidInfo", "MUIResourceDataType", "GroupIconResourceDataType", "RTTIDataType", "DataApplyOptions", "MSDataTypeUtils", "GuidUtil", "RTTI0DataType", "ThreadEnvironmentBlock", "RTTI4DataType", "GuidDataType", "NewGuid", "RTTI3DataType", "HTMLResourceDataType"]
