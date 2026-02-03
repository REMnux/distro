from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.cmd
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import java.lang # type: ignore


class CreateStructureInStructureCmd(AbstractCreateStructureCmd):
    """
    Command to create a structure inside of another structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, fromPath: jpype.JArray[jpype.JInt], toPath: jpype.JArray[jpype.JInt]):
        """
        Constructs a new command for creating structures inside other structures.
        
        :param ghidra.program.model.address.Address address: the address of the outer-most structure.
        :param jpype.JArray[jpype.JInt] fromPath: the componentPath of the first component to be consumed in 
        the new structure.
        :param jpype.JArray[jpype.JInt] toPath: the componentPath of the second component to be consumed in the
        the new structure.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], addr: ghidra.program.model.address.Address, fromPath: jpype.JArray[jpype.JInt], toPath: jpype.JArray[jpype.JInt]):
        """
        Constructs a new command for creating structures inside other structures.
        
        :param java.lang.String or str name: The name of the structure.
        :param ghidra.program.model.address.Address addr: the address of the outer-most structure.
        :param jpype.JArray[jpype.JInt] fromPath: the componentPath of the first component to be consumed in 
        the new structure.
        :param jpype.JArray[jpype.JInt] toPath: the componentPath of the second component to be consumed in the
        the new structure.
        """

    @typing.overload
    def __init__(self, newStructure: ghidra.program.model.data.Structure, address: ghidra.program.model.address.Address, fromPath: jpype.JArray[jpype.JInt], toPath: jpype.JArray[jpype.JInt]):
        ...


class CreateDataInStructureCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to Create data inside of a structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], dt: ghidra.program.model.data.DataType):
        """
        Constructs a new command for creating data inside a structure.
        Simple pointer conversion will NOT be performed.
        
        :param ghidra.program.model.address.Address addr: the address of the structure in which to apply the given datatype.
        :param jpype.JArray[jpype.JInt] componentPath: the component path of the component where the datatype
        will be applied.
        :param ghidra.program.model.data.DataType dt: the datatype to apply in the structure.
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], dt: ghidra.program.model.data.DataType, stackPointers: typing.Union[jpype.JBoolean, bool]):
        """
        This is the same as :meth:`CreateDataInStructureCmd(Address, int[], DataType) <.CreateDataInStructureCmd>` except that
        it allows the caller to control whether or not a pointer data type is created when a 
        non-pointer data type is applied at a location that previously contained a pointer data
        type.
        
        :param ghidra.program.model.address.Address addr: the address of the structure in which to apply the given datatype.
        :param jpype.JArray[jpype.JInt] componentPath: the component path of the component where the datatype
        will be applied.
        :param ghidra.program.model.data.DataType dt: the datatype to apply in the structure.
        :param jpype.JBoolean or bool stackPointers: if true simple pointer conversion is enabled 
        (see :meth:`DataUtilities.reconcileAppliedDataType(DataType, DataType, boolean) <DataUtilities.reconcileAppliedDataType>`).
        """


class AbstractCreateStructureCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    A base class to hold duplicate information for commands that create 
    structures.  This class implements the logic of the 
    :meth:`applyTo(Program) <.applyTo>` method so that child implementations need 
    only to implement the abstract methods.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getNewDataType(self) -> ghidra.program.model.data.DataType:
        """
        Get the new structure data type which was created.
        
        :return: new structure.
        :rtype: ghidra.program.model.data.DataType
        """

    @property
    def newDataType(self) -> ghidra.program.model.data.DataType:
        ...


class CreateArrayInStructureCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to create an array inside of a structure. All conflicting components
    within the targeted structure will be replaced with the new array component.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addr: ghidra.program.model.address.Address, numElements: typing.Union[jpype.JInt, int], dt: ghidra.program.model.data.DataType, compPath: jpype.JArray[jpype.JInt]):
        """
        Constructs a new command for creating arrays inside of structures.
        The specified component will be replaced as will subsequent components within 
        the structure required to make room for the new array component.
        NOTE: This is intended for replacing existing components and not for
        simply inserting an array component.
        
        :param ghidra.program.model.address.Address addr: The address of the structure that will contain the new array.
        :param jpype.JInt or int numElements: the number of elements in the array to be created.  A 0 element count is permitted.
        :param ghidra.program.model.data.DataType dt: the dataType of the elements in the array to be created.
        :param jpype.JArray[jpype.JInt] compPath: the target component path within the structure of an existing component where 
        the array should be created. The component path is an array of integers where each integer
        is a component index of the component above it.
        """


class CreateDataInStructureBackgroundCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Background command to create data across a selection inside of a structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, startPath: jpype.JArray[jpype.JInt], length: typing.Union[jpype.JInt, int], dt: ghidra.program.model.data.DataType):
        """
        Constructs a command for applying dataTypes within an existing structure
        across a range of components.
        Simple pointer conversion will NOT be performed.
        
        :param ghidra.program.model.address.Address addr: The address of the existing structure.
        :param jpype.JArray[jpype.JInt] startPath: the componentPath where to begin applying the datatype.
        :param jpype.JInt or int length: the number of bytes to apply the data type to.
        :param ghidra.program.model.data.DataType dt: the datatype to be applied to the range of components.
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, startPath: jpype.JArray[jpype.JInt], length: typing.Union[jpype.JInt, int], dt: ghidra.program.model.data.DataType, stackPointers: typing.Union[jpype.JBoolean, bool]):
        """
        This is the same as :meth:`CreateDataInStructureBackgroundCmd(Address, int[], int, DataType ) <.CreateDataInStructureBackgroundCmd>` except that
        it allows the caller to control whether or not a pointer data type is created when a 
        non-pointer data type is applied at a location that previously contained a pointer data
        type.
        
        :param ghidra.program.model.address.Address addr: The address of the existing structure.
        :param jpype.JArray[jpype.JInt] startPath: the componentPath where to begin applying the datatype.
        :param jpype.JInt or int length: the number of bytes to apply the data type to.
        :param ghidra.program.model.data.DataType dt: the datatype to be applied to the range of components.
        :param jpype.JBoolean or bool stackPointers: True will convert the given data type to a pointer if it is not one
        and the previous type was a pointer; false will not make this conversion
        """


class CreateDataCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    This command will create a data of type dataType at the given address.  This
    command will only work for fixed length dataTypes.  If there are any existing
    instructions in the area to be made into data, the command will fail.  Existing data
    in the area may be replaced with the new dataType (with optional pointer conversion).  
    If the existing dataType is a pointer, then
    the existing data will be changed into a pointer to the given dataType.  If the given dataType
    is a default-pointer, it will become a pointer to the existing type.
    
    
    .. seealso::
    
        | :obj:`DataUtilities.createData(Program, Address, DataType, int, boolean, DataUtilities.ClearDataMode)`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, force: typing.Union[jpype.JBoolean, bool], dataType: ghidra.program.model.data.DataType):
        """
        Constructs a command for creating data at an address.
        Simple pointer conversion will NOT be performed.
        Existing Undefined data will always be cleared even when force is false.
        
        :param ghidra.program.model.address.Address addr: the address at which to apply the datatype.  Offcut data
        address allowed, provided force==true.
        :param jpype.JBoolean or bool force: if true any existing conflicting data will be cleared
        :param ghidra.program.model.data.DataType dataType: the datatype to be applied at the given address.
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, force: typing.Union[jpype.JBoolean, bool], stackPointers: typing.Union[jpype.JBoolean, bool], dataType: ghidra.program.model.data.DataType):
        """
        This is the same as :meth:`CreateDataCmd(Address, boolean, DataType) <.CreateDataCmd>` except that
        it allows the caller to control whether or not pointer conversion should be handled.
        
        :param ghidra.program.model.address.Address addr: the address at which to apply the datatype.  Offcut data
        address allowed, provided force==true.
        :param jpype.JBoolean or bool force: if true any existing conflicting data will be cleared
        :param jpype.JBoolean or bool stackPointers: if true simple pointer conversion is enabled 
        (see :meth:`DataUtilities.reconcileAppliedDataType(DataType, DataType, boolean) <DataUtilities.reconcileAppliedDataType>`).
        :param ghidra.program.model.data.DataType dataType: the datatype to be applied at the given address.
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType):
        """
        Constructs a command for creating data at an address.
        Simple pointer conversion will NOT be performed and existing 
        defined data will not be cleared, however existing Undefined data will
        be cleared.
        
        :param ghidra.program.model.address.Address addr: the address at which to apply the datatype.
        :param ghidra.program.model.data.DataType dataType: the datatype to be applied at the given address.
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType, isCycle: typing.Union[jpype.JBoolean, bool], stackPointers: typing.Union[jpype.JBoolean, bool]):
        """
        This is the same as :meth:`CreateDataCmd(Address, DataType) <.CreateDataCmd>` except that
        it allows the caller to control whether or not pointer conversion should be handled.
        Existing Undefined data will always be cleared.
        
        :param ghidra.program.model.address.Address addr: the address at which to apply the datatype.
        :param ghidra.program.model.data.DataType dataType: the datatype to be applied at the given address.
        :param jpype.JBoolean or bool isCycle: true indicates this is from a cycle group action.
        :param jpype.JBoolean or bool stackPointers: if true simple pointer conversion is enabled 
        (see :meth:`DataUtilities.reconcileAppliedDataType(DataType, DataType, boolean) <DataUtilities.reconcileAppliedDataType>`).
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, dataType: ghidra.program.model.data.DataType, stackPointers: typing.Union[jpype.JBoolean, bool], clearMode: ghidra.program.model.data.DataUtilities.ClearDataMode):
        """
        This constructor provides the most flexibility when creating data, allowing optional pointer conversion and
        various clearing options for conflicting data.
        
        :param ghidra.program.model.address.Address addr: the address at which to apply the datatype.
        :param ghidra.program.model.data.DataType dataType: the datatype to be applied at the given address.
        :param jpype.JBoolean or bool stackPointers: if true simple pointer conversion is enabled 
        (see :meth:`DataUtilities.reconcileAppliedDataType(DataType, DataType, boolean) <DataUtilities.reconcileAppliedDataType>`).
        :param ghidra.program.model.data.DataUtilities.ClearDataMode clearMode: indicates how conflicting data should be cleared
        """


class CreateArrayCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to create an array.  All conflicting data will be cleared.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, addr: ghidra.program.model.address.Address, numElements: typing.Union[jpype.JInt, int], dt: ghidra.program.model.data.DataType, elementLength: typing.Union[jpype.JInt, int]):
        """
        Constructs a new command for creating arrays.
        
        :param ghidra.program.model.address.Address addr: The address at which to create an array.
        :param jpype.JInt or int numElements: the number of elements in the array to be created.  
        A 0 element count is permitted but a minimum length will apply for all array instances.
        :param ghidra.program.model.data.DataType dt: the dataType of the elements in the array to be created.
        :param jpype.JInt or int elementLength: the size of an element in the array.  Only used for Dynamic
        datatype ``dt`` when :meth:`Dynamic.canSpecifyLength() <Dynamic.canSpecifyLength>` returns true.
        """


class CreateDataBackgroundCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    This command will create a data of type dataType throughout an addressSet. 
    If there are any existing
    instructions in the area to be made into data, the command will fail.  Any data
    in the area will be replaced with the new dataType, except when the existing data
    or the given dataType is a pointer.  If the existing dataType is a pointer, then
    it will be changed into a pointer to the given dataType.  If the given dataType
    is a pointer and the existing data is >= to the size of a pointer, it will become
    a pointer to the existing type.  If the existing dataType is less than the size
    of a pointer, then a pointer to dataType will only be created if there are
    enough undefined bytes following to make a pointer.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addrSet: ghidra.program.model.address.AddressSetView, dataType: ghidra.program.model.data.DataType):
        """
        Constructs a command for applying a dataType to a set of addresses.
        Simple pointer conversion will NOT be performed.
        
        :param ghidra.program.model.address.AddressSetView addrSet: The address set to fill with the given dataType.
        :param ghidra.program.model.data.DataType dataType: the dataType to be applied to the address set.
        """

    @typing.overload
    def __init__(self, addrSet: ghidra.program.model.address.AddressSetView, dataType: ghidra.program.model.data.DataType, stackPointers: typing.Union[jpype.JBoolean, bool]):
        """
        This is the same as :meth:`CreateDataBackgroundCmd(AddressSetView, DataType) <.CreateDataBackgroundCmd>` except that
        it allows the caller to control whether or not a pointer data type is created when a 
        non-pointer data type is applied at a location that previously contained a pointer data
        type.
        
        :param ghidra.program.model.address.AddressSetView addrSet: The address set to fill with the given dataType.
        :param ghidra.program.model.data.DataType dataType: the dataType to be applied to the address set.
        :param jpype.JBoolean or bool stackPointers: if true simple pointer conversion is enabled 
        (see :meth:`DataUtilities.reconcileAppliedDataType(DataType, DataType, boolean) <DataUtilities.reconcileAppliedDataType>`).
        """


class CreateStructureCmd(AbstractCreateStructureCmd):
    """
    Command to create a structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]):
        """
        Constructs a new command for creating a new structure and applying it to
        the browser.  This method simply calls 
        :meth:`CreateStructureCmd(String, Address, int) <.CreateStructureCmd>` with 
        :obj:`ghidra.program.model.data.StructureFactory.DEFAULT_STRUCTURE_NAME` as the name of the structure.
        
        :param ghidra.program.model.address.Address address: the address at which to create the new structure.
        :param jpype.JInt or int length: the number of undefined bytes to consume in the new 
                structure.
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]):
        """
        Constructs a new command for creating a new structure and applying it to
        the browser.
        
        :param java.lang.String or str name: The name of the new structure to create.
        :param ghidra.program.model.address.Address address: the address at which to create the new structure.
        :param jpype.JInt or int length: the number of undefined bytes to consume in the new 
                structure.
        """

    @typing.overload
    def __init__(self, newStructure: ghidra.program.model.data.Structure, address: ghidra.program.model.address.Address):
        """
        Creates a new structure by using the provided structure and attaching
        it to the program passed in the :meth:`applyTo(Program) <.applyTo>` method.
        
        :param ghidra.program.model.data.Structure newStructure: The new structure to attach to the program 
                provided in the :meth:`applyTo(Program) <.applyTo>` method.
        :param ghidra.program.model.address.Address address: the address at which to create the new structure.
        """


class RenameDataFieldCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to rename a component in a data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, comp: ghidra.program.model.data.DataTypeComponent, newName: typing.Union[java.lang.String, str]):
        """
        Construct a new RenameDataFieldCmd.
        
        :param ghidra.program.model.data.DataTypeComponent comp: component in data type to be renamed
        :param java.lang.String or str newName: new name for the component
        """


class CreateStringCmd(ghidra.framework.cmd.Command[ghidra.program.model.listing.Program]):
    """
    Command to create a String and optionally label it.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, stringDataType: ghidra.program.model.data.AbstractStringDataType, length: typing.Union[jpype.JInt, int], clearMode: ghidra.program.model.data.DataUtilities.ClearDataMode):
        """
        Construct command for creating string Data
        
        :param ghidra.program.model.address.Address addr: address where string should be created.
        :param ghidra.program.model.data.AbstractStringDataType stringDataType: string datatype
        :param jpype.JInt or int length: maximum string length (treatment is specific to specified datatype).
        :param ghidra.program.model.data.DataUtilities.ClearDataMode clearMode: :obj:`ClearDataMode` which indicates how existing Data conflicts
        should be handled.
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], unicode: typing.Union[jpype.JBoolean, bool], clearMode: ghidra.program.model.data.DataUtilities.ClearDataMode):
        """
        Construct command for creating fixed-length ASCII or Unicode string Data
        
        :param ghidra.program.model.address.Address addr: address where string should be created.
        :param jpype.JInt or int length: byte-length of string
        :param jpype.JBoolean or bool unicode: if true Unicode string will be created, else ASCII
        :param ghidra.program.model.data.DataUtilities.ClearDataMode clearMode: :obj:`ClearDataMode` which indicates how existing Data conflicts
        should be handled.
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int], unicode: typing.Union[jpype.JBoolean, bool]):
        """
        Construct command for creating fixed-length ASCII or Unicode string Data.
        Current Data at addr will be cleared if it already exists.
        
        :param ghidra.program.model.address.Address addr: address where string should be created.
        :param jpype.JInt or int length: byte-length of string
        :param jpype.JBoolean or bool unicode: if true Unicode string will be created, else ASCII
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address):
        """
        Construct command for creating null-terminated ASCII string Data.
        Current Data at addr will be cleared if it already exists.
        
        :param ghidra.program.model.address.Address addr: address where string should be created.
        """

    @typing.overload
    def __init__(self, addr: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]):
        """
        Construct command for creating fixed-length ASCII string Data.
        Current Data at addr will be cleared if it already exists.
        
        :param ghidra.program.model.address.Address addr: address where string should be created.
        :param jpype.JInt or int length: byte-length of string
        """



__all__ = ["CreateStructureInStructureCmd", "CreateDataInStructureCmd", "AbstractCreateStructureCmd", "CreateArrayInStructureCmd", "CreateDataInStructureBackgroundCmd", "CreateDataCmd", "CreateArrayCmd", "CreateDataBackgroundCmd", "CreateStructureCmd", "RenameDataFieldCmd", "CreateStringCmd"]
