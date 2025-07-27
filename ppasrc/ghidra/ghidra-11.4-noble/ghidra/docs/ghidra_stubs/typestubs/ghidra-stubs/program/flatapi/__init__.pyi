from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.framework.model
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.symbol
import ghidra.program.util.string
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore


class FlatProgramAPI(java.lang.Object):
    """
    This class is a flattened version of the Program API.
     
    
    NOTE:
     
    1. NO METHODS *SHOULD* EVER BE REMOVED FROM THIS CLASS.
    2. NO METHOD SIGNATURES *SHOULD* EVER BE CHANGED IN THIS CLASS.
    
     
    
    This class is used by GhidraScript.
     
    
    Changing this class will break user scripts.
    """

    class_: typing.ClassVar[java.lang.Class]
    MAX_REFERENCES_TO: typing.Final = 4096

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Constructs a new flat program API.
        
        :param ghidra.program.model.listing.Program program: the program
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructs a new flat program API.
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        """

    def addEntryPoint(self, address: ghidra.program.model.address.Address):
        """
        Adds an entry point at the specified address.
        
        :param ghidra.program.model.address.Address address: address to create entry point
        """

    def addInstructionXref(self, from_: ghidra.program.model.address.Address, to: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], type: ghidra.program.model.symbol.FlowType) -> ghidra.program.model.symbol.Reference:
        """
        Adds a cross reference (XREF).
        
        :param ghidra.program.model.address.Address from: the source address of the reference
        :param ghidra.program.model.address.Address to: the destination address of the reference
        :param jpype.JInt or int opIndex: the operand index (-1 indicates the mnemonic)
        :param ghidra.program.model.symbol.FlowType type: the flow type
        :return: the newly created reference
        :rtype: ghidra.program.model.symbol.Reference
        
        .. seealso::
        
            | :obj:`ghidra.program.model.symbol.FlowType`
        
            | :obj:`ghidra.program.model.symbol.Reference`
        """

    @deprecated("the method analyzeAll or analyzeChanges should be invoked.\n These separate methods were created to clarify their true behavior since many times it is\n only necessary to analyze changes and not the entire program which can take much\n longer and affect more of the program than is necessary.")
    def analyze(self, program: ghidra.program.model.listing.Program):
        """
        Starts auto-analysis on the specified program and performs complete analysis
        of the entire program.  This is usually only necessary if full analysis was never
        performed. This method will block until analysis completes.
        
        :param ghidra.program.model.listing.Program program: the program to analyze
        
        .. deprecated::
        
        the method :obj:`.analyzeAll` or :obj:`.analyzeChanges` should be invoked.
        These separate methods were created to clarify their true behavior since many times it is
        only necessary to analyze changes and not the entire program which can take much
        longer and affect more of the program than is necessary.
        """

    def analyzeAll(self, program: ghidra.program.model.listing.Program):
        """
        Starts auto-analysis on the specified program and performs complete analysis
        of the entire program.  This is usually only necessary if full analysis was never
        performed. This method will block until analysis completes.
        
        :param ghidra.program.model.listing.Program program: the program to analyze
        """

    def analyzeChanges(self, program: ghidra.program.model.listing.Program):
        """
        Starts auto-analysis if not started and waits for pending analysis to complete.
        Only pending analysis on program changes is performed, including changes resulting
        from any analysis activity.  This method will block until analysis completes.
        NOTE: The auto-analysis manager will only detect program changes once it has been
        instantiated for a program (i.e, AutoAnalysisManager.getAnalysisManager(program) ).
        This is automatically done for the initial currentProgram, however, if a script is
        opening/instantiating its own programs it may be necessary to do this prior to
        making changes to the program.
        
        :param ghidra.program.model.listing.Program program: the program to analyze
        """

    @typing.overload
    def clearListing(self, address: ghidra.program.model.address.Address):
        """
        Clears the code unit (instruction or data) defined at the address.
        
        :param ghidra.program.model.address.Address address: the address to clear the code unit
        :raises CancelledException: if cancelled
        """

    @typing.overload
    def clearListing(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Clears the code units (instructions or data) in the specified range.
        
        :param ghidra.program.model.address.Address start: the start address
        :param ghidra.program.model.address.Address end: the end address (INCLUSIVE)
        :raises CancelledException: if cancelled
        """

    @typing.overload
    def clearListing(self, set: ghidra.program.model.address.AddressSetView):
        """
        Clears the code units (instructions or data) in the specified set
        
        :param ghidra.program.model.address.AddressSetView set: the set to clear
        :raises CancelledException: if cancelled
        """

    @typing.overload
    def clearListing(self, set: ghidra.program.model.address.AddressSetView, code: typing.Union[jpype.JBoolean, bool], symbols: typing.Union[jpype.JBoolean, bool], comments: typing.Union[jpype.JBoolean, bool], properties: typing.Union[jpype.JBoolean, bool], functions: typing.Union[jpype.JBoolean, bool], registers: typing.Union[jpype.JBoolean, bool], equates: typing.Union[jpype.JBoolean, bool], userReferences: typing.Union[jpype.JBoolean, bool], analysisReferences: typing.Union[jpype.JBoolean, bool], importReferences: typing.Union[jpype.JBoolean, bool], defaultReferences: typing.Union[jpype.JBoolean, bool], bookmarks: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Clears the listing in the specified address set.
        
        :param ghidra.program.model.address.AddressSetView set: the address set where to clear
        :param jpype.JBoolean or bool code: true if code units should be cleared (instructions and defined data)
        :param jpype.JBoolean or bool symbols: true if symbols should be cleared
        :param jpype.JBoolean or bool comments: true if comments should be cleared
        :param jpype.JBoolean or bool properties: true if properties should be cleared
        :param jpype.JBoolean or bool functions: true if functions should be cleared
        :param jpype.JBoolean or bool registers: true if registers should be cleared
        :param jpype.JBoolean or bool equates: true if equates should be cleared
        :param jpype.JBoolean or bool userReferences: true if user references should be cleared
        :param jpype.JBoolean or bool analysisReferences: true if analysis references should be cleared
        :param jpype.JBoolean or bool importReferences: true if import references should be cleared
        :param jpype.JBoolean or bool defaultReferences: true if default references should be cleared
        :param jpype.JBoolean or bool bookmarks: true if bookmarks should be cleared
        :return: true if the address set was successfully cleared
        :rtype: bool
        """

    @typing.overload
    def clearListing(self, set: ghidra.program.model.address.AddressSetView, instructions: typing.Union[jpype.JBoolean, bool], data: typing.Union[jpype.JBoolean, bool], symbols: typing.Union[jpype.JBoolean, bool], comments: typing.Union[jpype.JBoolean, bool], properties: typing.Union[jpype.JBoolean, bool], functions: typing.Union[jpype.JBoolean, bool], registers: typing.Union[jpype.JBoolean, bool], equates: typing.Union[jpype.JBoolean, bool], userReferences: typing.Union[jpype.JBoolean, bool], analysisReferences: typing.Union[jpype.JBoolean, bool], importReferences: typing.Union[jpype.JBoolean, bool], defaultReferences: typing.Union[jpype.JBoolean, bool], bookmarks: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Clears the listing in the specified address set.
        
        :param ghidra.program.model.address.AddressSetView set: the address set where to clear
        :param jpype.JBoolean or bool instructions: true if instructions should be cleared
        :param jpype.JBoolean or bool data: true if defined data should be cleared
        :param jpype.JBoolean or bool symbols: true if symbols should be cleared
        :param jpype.JBoolean or bool comments: true if comments should be cleared
        :param jpype.JBoolean or bool properties: true if properties should be cleared
        :param jpype.JBoolean or bool functions: true if functions should be cleared
        :param jpype.JBoolean or bool registers: true if registers should be cleared
        :param jpype.JBoolean or bool equates: true if equates should be cleared
        :param jpype.JBoolean or bool userReferences: true if user references should be cleared
        :param jpype.JBoolean or bool analysisReferences: true if analysis references should be cleared
        :param jpype.JBoolean or bool importReferences: true if import references should be cleared
        :param jpype.JBoolean or bool defaultReferences: true if default references should be cleared
        :param jpype.JBoolean or bool bookmarks: true if bookmarks should be cleared
        :return: true if the address set was successfully cleared
        :rtype: bool
        """

    def createAddressSet(self) -> ghidra.program.model.address.AddressSet:
        """
        Creates a new mutable address set.
        
        :return: a new mutable address set
        :rtype: ghidra.program.model.address.AddressSet
        """

    @typing.overload
    def createAsciiString(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Creates a null terminated ascii string starting
        at the specified address.
        
        :param ghidra.program.model.address.Address address: the address to create the string
        :return: the newly created Data object
        :rtype: ghidra.program.model.listing.Data
        :raises java.lang.Exception: if there is any exception
        """

    @typing.overload
    def createAsciiString(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> ghidra.program.model.listing.Data:
        """
        Create an ASCII string at the specified address.
        
        :param ghidra.program.model.address.Address address: the address
        :param jpype.JInt or int length: length of string (a value of 0 or negative will force use
        of dynamic null terminated string)
        :return: string data created
        :rtype: ghidra.program.model.listing.Data
        :raises CodeUnitInsertionException: if there is a data conflict
        """

    def createBookmark(self, address: ghidra.program.model.address.Address, category: typing.Union[java.lang.String, str], note: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Bookmark:
        """
        Creates a ``NOTE`` bookmark at the specified address
         
        
        NOTE: if a ``NOTE`` bookmark already exists at the address, it will be replaced.
        This is intentional and is done to match the behavior of setting bookmarks from the UI.
        
        :param ghidra.program.model.address.Address address: the address to create the bookmark
        :param java.lang.String or str category: the bookmark category (it may be null)
        :param java.lang.String or str note: the bookmark text
        :return: the newly created bookmark
        :rtype: ghidra.program.model.listing.Bookmark
        """

    def createByte(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Creates a byte datatype at the given address.
        
        :param ghidra.program.model.address.Address address: the address to create the byte
        :return: the newly created Data object
        :rtype: ghidra.program.model.listing.Data
        :raises java.lang.Exception: if there is any exception
        """

    def createChar(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Creates a char datatype at the given address.
        
        :param ghidra.program.model.address.Address address: the address to create the char
        :return: the newly created Data object
        :rtype: ghidra.program.model.listing.Data
        :raises java.lang.Exception: if there is any exception
        """

    def createClass(self, parent: ghidra.program.model.symbol.Namespace, className: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.GhidraClass:
        """
        Creates a new :obj:`GhidraClass` with the given name contained inside the
        specified parent namespace.
        Pass ``null`` for parent to indicate the global namespace.
        If a GhidraClass with the given name already exists, the existing one will be returned.
        
        :param ghidra.program.model.symbol.Namespace parent: the parent namespace, or null for global namespace
        :param java.lang.String or str className: the requested classes name
        :return: the GhidraClass with the given name
        :rtype: ghidra.program.model.listing.GhidraClass
        :raises InvalidInputException: if the name is invalid
        :raises DuplicateNameException: thrown if a :obj:`Library` or :obj:`Namespace`
        symbol already exists with the given name.
        Use :meth:`SymbolTable.convertNamespaceToClass(Namespace) <SymbolTable.convertNamespaceToClass>` for converting an
        existing Namespace to a GhidraClass.
        :raises IllegalArgumentException: if the given parent namespace is not from
        the :obj:`.currentProgram`.
        :raises ConcurrentModificationException: if the given parent has been deleted
        :raises IllegalArgumentException: if parent Namespace does not correspond to
        ``currerntProgram``
        
        .. seealso::
        
            | :obj:`SymbolTable.convertNamespaceToClass(Namespace)`
        """

    def createDWord(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Creates a dword datatype at the given address.
        
        :param ghidra.program.model.address.Address address: the address to create the dword
        :return: the newly created Data object
        :rtype: ghidra.program.model.listing.Data
        :raises java.lang.Exception: if there is any exception
        """

    def createData(self, address: ghidra.program.model.address.Address, datatype: ghidra.program.model.data.DataType) -> ghidra.program.model.listing.Data:
        """
        Creates a new defined Data object at the given address.
        
        :param ghidra.program.model.address.Address address: the address at which to create a new Data object.
        :param ghidra.program.model.data.DataType datatype: the Data Type that describes the type of Data object to create.
        :return: the newly created Data object
        :rtype: ghidra.program.model.listing.Data
        :raises CodeUnitInsertionException: if a conflicting code unit already exists
        """

    def createDouble(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Creates a double datatype at the given address.
        
        :param ghidra.program.model.address.Address address: the address to create the double
        :return: the newly created Data object
        :rtype: ghidra.program.model.listing.Data
        :raises java.lang.Exception: if there is any exception
        """

    def createDwords(self, start: ghidra.program.model.address.Address, count: typing.Union[jpype.JInt, int]):
        """
        Creates a list of dword datatypes starting at the given address.
        
        :param ghidra.program.model.address.Address start: the start address to create the dwords
        :param jpype.JInt or int count: the number of dwords to create
        :raises java.lang.Exception: if there is any exception
        """

    @typing.overload
    def createEquate(self, instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], equateName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Equate:
        """
        Creates a new equate on the scalar value
        at the operand index of the instruction.
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :param jpype.JInt or int operandIndex: the operand index on the instruction
        :param java.lang.String or str equateName: the name of the equate
        :return: the newly created equate
        :rtype: ghidra.program.model.symbol.Equate
        :raises java.lang.Exception: if a scalar does not exist of the specified
        operand index of the instruction
        """

    @typing.overload
    def createEquate(self, data: ghidra.program.model.listing.Data, equateName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Equate:
        """
        Creates a new equate on the scalar value
        at the value of the data.
        
        :param ghidra.program.model.listing.Data data: the data
        :param java.lang.String or str equateName: the name of the equate
        :return: the newly created equate
        :rtype: ghidra.program.model.symbol.Equate
        :raises InvalidInputException: if a scalar does not exist on the data
        :raises java.lang.Exception: if there is any exception
        """

    @typing.overload
    def createExternalReference(self, instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], libraryName: typing.Union[java.lang.String, str], externalLabel: typing.Union[java.lang.String, str], externalAddr: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Reference:
        """
        Creates an external reference from the given instruction.
        For instructions with flow, the FlowType will be assumed, otherwise
        :obj:`RefType.DATA` will be assumed.  To specify the appropriate
        RefType use the alternate form of this method.
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :param jpype.JInt or int operandIndex: the operand index on the instruction
        :param java.lang.String or str libraryName: the name of the library being referred
        :param java.lang.String or str externalLabel: the name of function in the library being referred
        :param ghidra.program.model.address.Address externalAddr: the address of the function in the library being referred
        :return: the newly created external reference
        :rtype: ghidra.program.model.symbol.Reference
        :raises java.lang.Exception: if an exception occurs
        """

    @typing.overload
    def createExternalReference(self, instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], libraryName: typing.Union[java.lang.String, str], externalLabel: typing.Union[java.lang.String, str], externalAddr: ghidra.program.model.address.Address, refType: ghidra.program.model.symbol.RefType) -> ghidra.program.model.symbol.Reference:
        """
        Creates an external reference from the given instruction.
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :param jpype.JInt or int operandIndex: the operand index on the instruction
        :param java.lang.String or str libraryName: the name of the library being referred
        :param java.lang.String or str externalLabel: the name of function in the library being referred
        :param ghidra.program.model.address.Address externalAddr: the address of the function in the library being referred
        :param ghidra.program.model.symbol.RefType refType: the appropriate external reference type (e.g., DATA, COMPUTED_CALL, etc.)
        :return: the newly created external reference
        :rtype: ghidra.program.model.symbol.Reference
        :raises java.lang.Exception: if an exception occurs
        """

    @typing.overload
    def createExternalReference(self, data: ghidra.program.model.listing.Data, libraryName: typing.Union[java.lang.String, str], externalLabel: typing.Union[java.lang.String, str], externalAddr: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Reference:
        """
        Creates an external reference from the given data.  The reference type :obj:`RefType.DATA`
        will be used.
        
        :param ghidra.program.model.listing.Data data: the data
        :param java.lang.String or str libraryName: the name of the library being referred
        :param java.lang.String or str externalLabel: the name of function in the library being referred
        :param ghidra.program.model.address.Address externalAddr: the address of the function in the library being referred
        :return: the newly created external reference
        :rtype: ghidra.program.model.symbol.Reference
        :raises java.lang.Exception: if an exception occurs
        """

    def createFloat(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Creates a float datatype at the given address.
        
        :param ghidra.program.model.address.Address address: the address to create the float
        :return: the newly created Data object
        :rtype: ghidra.program.model.listing.Data
        :raises java.lang.Exception: if there is any exception
        """

    @typing.overload
    @deprecated("This method is deprecated because it did not allow you to include the\n largest possible address.  Instead use the one that takes a start address and a length.")
    def createFragment(self, fragmentName: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.listing.ProgramFragment:
        """
        Creates a fragment in the root folder of the default program tree.
        
        :param java.lang.String or str fragmentName: the name of the fragment
        :param ghidra.program.model.address.Address start: the start address
        :param ghidra.program.model.address.Address end: the end address (NOT INCLUSIVE)
        :return: the newly created fragment
        :rtype: ghidra.program.model.listing.ProgramFragment
        :raises DuplicateNameException: if the given fragment name already exists
        :raises NotFoundException: if any address in the fragment would be outside of the program
        
        .. deprecated::
        
        This method is deprecated because it did not allow you to include the
        largest possible address.  Instead use the one that takes a start address and a length.
        """

    @typing.overload
    def createFragment(self, fragmentName: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int]) -> ghidra.program.model.listing.ProgramFragment:
        """
        Creates a fragment in the root folder of the default program tree.
        
        :param java.lang.String or str fragmentName: the name of the fragment
        :param ghidra.program.model.address.Address start: the start address
        :param jpype.JLong or int length: the length of the fragment
        :return: the newly created fragment
        :rtype: ghidra.program.model.listing.ProgramFragment
        :raises DuplicateNameException: if the given fragment name already exists
        :raises NotFoundException: if any address in the fragment would be outside of the program
        """

    @typing.overload
    @deprecated("This method is deprecated because it did not allow you to include the\n largest possible address.  Instead use the one that takes a start address and a length.")
    def createFragment(self, module: ghidra.program.model.listing.ProgramModule, fragmentName: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.listing.ProgramFragment:
        """
        Creates a fragment in the given folder of the default program tree.
        
        :param ghidra.program.model.listing.ProgramModule module: the parent module (or folder)
        :param java.lang.String or str fragmentName: the name of the fragment
        :param ghidra.program.model.address.Address start: the start address
        :param ghidra.program.model.address.Address end: the end address (NOT INCLUSIVE)
        :return: the newly created fragment
        :rtype: ghidra.program.model.listing.ProgramFragment
        :raises DuplicateNameException: if the given fragment name already exists
        :raises NotFoundException: if any address in the fragment would be outside of the program
        
        .. deprecated::
        
        This method is deprecated because it did not allow you to include the
        largest possible address.  Instead use the one that takes a start address and a length.
        """

    @typing.overload
    def createFragment(self, module: ghidra.program.model.listing.ProgramModule, fragmentName: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int]) -> ghidra.program.model.listing.ProgramFragment:
        """
        Creates a fragment in the given folder of the default program tree.
        
        :param ghidra.program.model.listing.ProgramModule module: the parent module (or folder)
        :param java.lang.String or str fragmentName: the name of the fragment
        :param ghidra.program.model.address.Address start: the start address
        :param jpype.JLong or int length: the length of the fragment
        :return: the newly created fragment
        :rtype: ghidra.program.model.listing.ProgramFragment
        :raises DuplicateNameException: if the given fragment name already exists
        :raises NotFoundException: if any address in the fragment would be outside of the program
        """

    def createFunction(self, entryPoint: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Function:
        """
        Creates a function at entry point with the specified name
        
        :param ghidra.program.model.address.Address entryPoint: the entry point of the function
        :param java.lang.String or str name: the name of the function or null for a default function
        :return: the new function or null if the function was not created
        :rtype: ghidra.program.model.listing.Function
        """

    @typing.overload
    def createLabel(self, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], makePrimary: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.symbol.Symbol:
        """
        Creates a label at the specified address in the global namespace.
        If makePrimary==true, then the new label is made primary.
        
        :param ghidra.program.model.address.Address address: the address to create the symbol
        :param java.lang.String or str name: the name of the symbol
        :param jpype.JBoolean or bool makePrimary: true if the symbol should be made primary
        :return: the newly created code or function symbol
        :rtype: ghidra.program.model.symbol.Symbol
        :raises java.lang.Exception: if there is any exception
        """

    @typing.overload
    def createLabel(self, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], makePrimary: typing.Union[jpype.JBoolean, bool], sourceType: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Symbol:
        """
        Creates a label at the specified address in the global namespace.
        If makePrimary==true, then the new label is made primary.
        If makeUnique==true, then if the name is a duplicate, the address
        will be concatenated to name to make it unique.
        
        :param ghidra.program.model.address.Address address: the address to create the symbol
        :param java.lang.String or str name: the name of the symbol
        :param jpype.JBoolean or bool makePrimary: true if the symbol should be made primary
        :param ghidra.program.model.symbol.SourceType sourceType: the source type.
        :return: the newly created code or function symbol
        :rtype: ghidra.program.model.symbol.Symbol
        :raises java.lang.Exception: if there is any exception
        """

    @typing.overload
    def createLabel(self, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace, makePrimary: typing.Union[jpype.JBoolean, bool], sourceType: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Symbol:
        """
        Creates a label at the specified address in the specified namespace.
        If makePrimary==true, then the new label is made primary if permitted.
        If makeUnique==true, then if the name is a duplicate, the address
        will be concatenated to name to make it unique.
        
        :param ghidra.program.model.address.Address address: the address to create the symbol
        :param java.lang.String or str name: the name of the symbol
        :param ghidra.program.model.symbol.Namespace namespace: label's parent namespace
        :param jpype.JBoolean or bool makePrimary: true if the symbol should be made primary
        :param ghidra.program.model.symbol.SourceType sourceType: the source type.
        :return: the newly created code or function symbol
        :rtype: ghidra.program.model.symbol.Symbol
        :raises java.lang.Exception: if there is any exception
        """

    @typing.overload
    def createMemoryBlock(self, name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, input: java.io.InputStream, length: typing.Union[jpype.JLong, int], overlay: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.mem.MemoryBlock:
        """
        Create a new memory block.
        If the input stream is null, then an uninitialized block will be created.
        
        :param java.lang.String or str name: the name of the block
        :param ghidra.program.model.address.Address start: start address of the block
        :param java.io.InputStream input: source of the data used to fill the block.
        :param jpype.JLong or int length: the size of the block
        :param jpype.JBoolean or bool overlay: true will create an overlay, false will not
        :return: the newly created memory block
        :rtype: ghidra.program.model.mem.MemoryBlock
        :raises java.lang.Exception: if there is any exception
        """

    @typing.overload
    def createMemoryBlock(self, name: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte], overlay: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.mem.MemoryBlock:
        """
        Create a new memory block.
        
        :param java.lang.String or str name: the name of the block
        :param ghidra.program.model.address.Address start: start address of the block
        :param jpype.JArray[jpype.JByte] bytes: the bytes of the memory block
        :param jpype.JBoolean or bool overlay: true will create an overlay, false will not
        :return: the newly created memory block
        :rtype: ghidra.program.model.mem.MemoryBlock
        :raises java.lang.Exception: if there is any exception
        """

    @typing.overload
    def createMemoryReference(self, instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], toAddress: ghidra.program.model.address.Address, flowType: ghidra.program.model.symbol.RefType) -> ghidra.program.model.symbol.Reference:
        """
        Creates a memory reference from the given instruction.
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :param jpype.JInt or int operandIndex: the operand index on the instruction
        :param ghidra.program.model.address.Address toAddress: the TO address
        :param ghidra.program.model.symbol.RefType flowType: the flow type of the reference
        :return: the newly created memory reference
        :rtype: ghidra.program.model.symbol.Reference
        """

    @typing.overload
    def createMemoryReference(self, data: ghidra.program.model.listing.Data, toAddress: ghidra.program.model.address.Address, dataRefType: ghidra.program.model.symbol.RefType) -> ghidra.program.model.symbol.Reference:
        """
        Creates a memory reference from the given data.
        
        :param ghidra.program.model.listing.Data data: the data
        :param ghidra.program.model.address.Address toAddress: the TO address
        :param ghidra.program.model.symbol.RefType dataRefType: the type of the reference
        :return: the newly created memory reference
        :rtype: ghidra.program.model.symbol.Reference
        """

    def createNamespace(self, parent: ghidra.program.model.symbol.Namespace, namespaceName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Namespace:
        """
        Creates a new :obj:`Namespace` with the given name contained inside the
        specified parent namespace.
        Pass ``null`` for parent to indicate the global namespace.
        If a :obj:`Namespace` or :obj:`GhidraClass` with the given name already exists, the
        existing one will be returned.
        
        :param ghidra.program.model.symbol.Namespace parent: the parent namespace, or null for global namespace
        :param java.lang.String or str namespaceName: the requested namespace's name
        :return: the namespace with the given name
        :rtype: ghidra.program.model.symbol.Namespace
        :raises DuplicateNameException: if a :obj:`Library` symbol exists with the given name
        :raises InvalidInputException: if the name is invalid
        :raises IllegalArgumentException: if parent Namespace does not correspond to
        ``currerntProgram``
        """

    def createQWord(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Creates a qword datatype at the given address.
        
        :param ghidra.program.model.address.Address address: the address to create the qword
        :return: the newly created Data object
        :rtype: ghidra.program.model.listing.Data
        :raises java.lang.Exception: if there is any exception
        """

    def createStackReference(self, instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], stackOffset: typing.Union[jpype.JInt, int], isWrite: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.symbol.Reference:
        """
        Create a stack reference from the given instruction
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :param jpype.JInt or int operandIndex: the operand index on the instruction
        :param jpype.JInt or int stackOffset: the stack offset of the reference
        :param jpype.JBoolean or bool isWrite: true if the reference is WRITE access or false if the
        reference is READ access
        :return: the newly created stack reference
        :rtype: ghidra.program.model.symbol.Reference
        """

    @typing.overload
    @deprecated("use createLabel(Address, String, boolean) instead.\n Deprecated in Ghidra 7.4")
    def createSymbol(self, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], makePrimary: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.symbol.Symbol:
        """
        
        
        
        .. deprecated::
        
        use :meth:`createLabel(Address, String, boolean) <.createLabel>` instead.
        Deprecated in Ghidra 7.4
        """

    @typing.overload
    @deprecated("use createLabel(Address, String, boolean, SourceType) instead. Deprecated in Ghidra 7.4")
    def createSymbol(self, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], makePrimary: typing.Union[jpype.JBoolean, bool], makeUnique: typing.Union[jpype.JBoolean, bool], sourceType: ghidra.program.model.symbol.SourceType) -> ghidra.program.model.symbol.Symbol:
        """
        
        
        
        .. deprecated::
        
        use :meth:`createLabel(Address, String, boolean, SourceType) <.createLabel>` instead. Deprecated in Ghidra 7.4
        """

    def createUnicodeString(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Creates a null terminated unicode string starting at the specified address.
        
        :param ghidra.program.model.address.Address address: the address to create the string
        :return: the newly created Data object
        :rtype: ghidra.program.model.listing.Data
        :raises java.lang.Exception: if there is any exception
        """

    def createWord(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Creates a word datatype at the given address.
        
        :param ghidra.program.model.address.Address address: the address to create the word
        :return: the newly created Data object
        :rtype: ghidra.program.model.listing.Data
        :raises java.lang.Exception: if there is any exception
        """

    def disassemble(self, address: ghidra.program.model.address.Address) -> bool:
        """
        Start disassembling at the specified address.
        The disassembler will follow code flows.
        
        :param ghidra.program.model.address.Address address: the address to begin disassembling
        :return: true if the program was successfully disassembled
        :rtype: bool
        """

    def end(self, commit: typing.Union[jpype.JBoolean, bool]):
        """
        Ends the transactions on the current program.
        
        :param jpype.JBoolean or bool commit: true if changes should be committed
        """

    @typing.overload
    def find(self, start: ghidra.program.model.address.Address, value: typing.Union[jpype.JByte, int]) -> ghidra.program.model.address.Address:
        """
        Finds the first occurrence of the byte
        starting from the address. If the start address
        is null, then the find will start from the minimum address
        of the program.
        
        :param ghidra.program.model.address.Address start: the address to start searching
        :param jpype.JByte or int value: the byte to search for
        :return: the first address where the byte was found
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def find(self, start: ghidra.program.model.address.Address, values: jpype.JArray[jpype.JByte]) -> ghidra.program.model.address.Address:
        """
        Finds the first occurrence of the byte array sequence
        starting from the address. If the start address
        is null, then the find will start from the minimum address
        of the program.
        
        :param ghidra.program.model.address.Address start: the address to start searching
        :param jpype.JArray[jpype.JByte] values: the byte array sequence to search for
        :return: the first address where the byte was found, or
        null if the bytes were not found
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def find(self, text: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        """
        Finds the first occurrence of 'text' in the program listing.
        The search order is defined as:
         
        1. PLATE comments
        2. PRE comments
        3. labels
        4. code unit mnemonics and operands
        5. EOL comments
        6. repeatable comments
        7. POST comments
        
        
        :param java.lang.String or str text: the text to search for
        :return: the first address where the 'text' was found, or null
        if the text was not found
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def findBytes(self, start: ghidra.program.model.address.Address, byteString: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        """
        Finds the first occurrence of the byte array sequence that matches the given byte string,
        starting from the address. If the start address is null, then the find will start
        from the minimum address of the program.
         
        
        The ``byteString`` may contain regular expressions.  The following
        highlights some example search strings (note the use of double backslashes ("\\")):
         
                    "\\x80" - A basic search pattern for a byte value of 0x80
        "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
                            followed by 0-10 occurrences of any byte value, followed
                            by the byte 0x55
         
        
        :param ghidra.program.model.address.Address start: the address to start searching.  If null, then the start of the program
                will be used.
        :param java.lang.String or str byteString: the byte pattern for which to search
        :return: the first address where the byte was found, or null if the bytes were not found
        :rtype: ghidra.program.model.address.Address
        :raises IllegalArgumentException: if the byteString is not a valid regular expression
        
        .. seealso::
        
            | :obj:`.findBytes(Address, String, int)`
        """

    @typing.overload
    def findBytes(self, start: ghidra.program.model.address.Address, byteString: typing.Union[java.lang.String, str], matchLimit: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Finds the first ``<matchLimit>`` occurrences of the byte array sequence that matches
        the given byte string, starting from the address. If the start address is null, then the
        find will start from the minimum address of the program.
         
        
        The ``byteString`` may contain regular expressions.  The following
        highlights some example search strings (note the use of double backslashes ("\\")):
         
                    "\\x80" - A basic search pattern for a byte value of 0x80
        "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
                            followed by 0-10 occurrences of any byte value, followed
                            by the byte 0x55
         
        
        :param ghidra.program.model.address.Address start: the address to start searching.  If null, then the start of the program
                will be used.
        :param java.lang.String or str byteString: the byte pattern for which to search
        :param jpype.JInt or int matchLimit: The number of matches to which the search should be restricted
        :return: the start addresses that contain byte patterns that match the given byteString
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        :raises IllegalArgumentException: if the byteString is not a valid regular expression
        
        .. seealso::
        
            | :obj:`.findBytes(Address, String)`
        """

    @typing.overload
    def findBytes(self, start: ghidra.program.model.address.Address, byteString: typing.Union[java.lang.String, str], matchLimit: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Finds the first ``<matchLimit>`` occurrences of the byte array sequence that matches
        the given byte string, starting from the address. If the start address is null, then the
        find will start from the minimum address of the program.
         
        
        The ``byteString`` may contain regular expressions.  The following
        highlights some example search strings (note the use of double backslashes ("\\")):
         
                    "\\x80" - A basic search pattern for a byte value of 0x80
        "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
                            followed by 0-10 occurrences of any byte value, followed
                            by the byte 0x55
         
        
        :param ghidra.program.model.address.Address start: the address to start searching.  If null, then the start of the program
                will be used.
        :param java.lang.String or str byteString: the byte pattern for which to search
        :param jpype.JInt or int matchLimit: The number of matches to which the search should be restricted
        :param jpype.JInt or int alignment: byte alignment to use for search starts. For example, a value of
            1 searches from every byte.  A value of 2 only matches runs that begin on a even
            address boundary.
        :return: the start addresses that contain byte patterns that match the given byteString
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        :raises IllegalArgumentException: if the byteString is not a valid regular expression
        
        .. seealso::
        
            | :obj:`.findBytes(Address, String)`
        """

    @typing.overload
    def findBytes(self, set: ghidra.program.model.address.AddressSetView, byteString: typing.Union[java.lang.String, str], matchLimit: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Finds a byte pattern within an addressSet.
        
        Note: The ranges within the addressSet are NOT treated as a contiguous set when searching
         
        
        The ``byteString`` may contain regular expressions.  The following
        highlights some example search strings (note the use of double backslashes ("\\")):
         
                    "\\x80" - A basic search pattern for a byte value of 0x80
        "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
                            followed by 0-10 occurrences of any byte value, followed
                            by the byte 0x55
         
        
        :param ghidra.program.model.address.AddressSetView set: the addressSet specifying which addresses to search.
        :param java.lang.String or str byteString: the byte pattern for which to search
        :param jpype.JInt or int matchLimit: The number of matches to which the search should be restricted
        :param jpype.JInt or int alignment: byte alignment to use for search starts. For example, a value of
            1 searches from every byte.  A value of 2 only matches runs that begin on a even
            address boundary.
        :return: the start addresses that contain byte patterns that match the given byteString
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        :raises IllegalArgumentException: if the byteString is not a valid regular expression
        
        .. seealso::
        
            | :obj:`.findBytes(Address, String)`
        """

    @typing.overload
    @deprecated("see description for details.")
    def findBytes(self, set: ghidra.program.model.address.AddressSetView, byteString: typing.Union[java.lang.String, str], matchLimit: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], searchAcrossAddressGaps: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        This method has been deprecated, use :meth:`findBytes(Address, String, int, int) <.findBytes>` instead.
        The concept of searching and finding matches that span gaps (address ranges where no memory
        blocks have been defined), is no longer supported. If this capability has value to anyone, 
        please contact the Ghidra team and let us know.
         
        
        Finds a byte pattern within an addressSet.
        
        Note: The ranges within the addressSet are NOT treated as a contiguous set when searching
         
        
        The ``byteString`` may contain regular expressions.  The following
        highlights some example search strings (note the use of double backslashes ("\\")):
         
                    "\\x80" - A basic search pattern for a byte value of 0x80
        "\\x50.{0,10}\\x55" - A regular expression string that searches for the byte 0x50
                            followed by 0-10 occurrences of any byte value, followed
                            by the byte 0x55
         
        
        :param ghidra.program.model.address.AddressSetView set: the addressSet specifying which addresses to search.
        :param java.lang.String or str byteString: the byte pattern for which to search
        :param jpype.JInt or int matchLimit: The number of matches to which the search should be restricted
        :param jpype.JInt or int alignment: byte alignment to use for search starts. For example, a value of
            1 searches from every byte.  A value of 2 only matches runs that begin on a even
            address boundary.
        :param jpype.JBoolean or bool searchAcrossAddressGaps: This parameter is no longer supported and its value is
        ignored. Previously, if true, match results were allowed to span non-continguous memory
        ranges.
        :return: the start addresses that contain byte patterns that match the given byteString
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        :raises IllegalArgumentException: if the byteString is not a valid regular expression
        
        .. deprecated::
        
        see description for details.
        
        .. seealso::
        
            | :obj:`.findBytes(Address, String)`
        """

    def findPascalStrings(self, addressSet: ghidra.program.model.address.AddressSetView, minimumStringLength: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], includePascalUnicode: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.program.util.string.FoundString]:
        """
        Search for sequences of Pascal Ascii strings in program memory.  See
        :obj:`AsciiCharSetRecognizer` to see exactly what chars are considered ASCII for purposes
        of this search.
        
        :param ghidra.program.model.address.AddressSetView addressSet: The address set to search. Use null to search all memory;
        :param jpype.JInt or int minimumStringLength: The smallest number of chars in a sequence to be considered a
        "string".
        :param jpype.JInt or int alignment: specifies any alignment requirements for the start of the string.  An
        alignment of 1, means the string can start at any address.  An alignment of 2 means the
        string must start on an even address and so on.  Only allowed values are 1,2, and 4.
        :param jpype.JBoolean or bool includePascalUnicode: if true, UTF16 size strings will be included in addition to UTF8.
        :return: a list of "FoundString" objects which contain the addresses, length, and type of
        possible strings.
        :rtype: java.util.List[ghidra.program.util.string.FoundString]
        """

    def findStrings(self, addressSet: ghidra.program.model.address.AddressSetView, minimumStringLength: typing.Union[jpype.JInt, int], alignment: typing.Union[jpype.JInt, int], requireNullTermination: typing.Union[jpype.JBoolean, bool], includeAllCharWidths: typing.Union[jpype.JBoolean, bool]) -> java.util.List[ghidra.program.util.string.FoundString]:
        """
        Search for sequences of Ascii strings in program memory.  See :obj:`AsciiCharSetRecognizer`
        to see exactly what chars are considered ASCII for purposes of this search.
        
        :param ghidra.program.model.address.AddressSetView addressSet: The address set to search. Use null to search all memory;
        :param jpype.JInt or int minimumStringLength: The smallest number of chars in a sequence to be considered a
        "string".
        :param jpype.JInt or int alignment: specifies any alignment requirements for the start of the string.  An
        alignment of 1, means the string can start at any address.  An alignment of 2 means the
        string must start on an even address and so on.  Only allowed values are 1,2, and 4.
        :param jpype.JBoolean or bool requireNullTermination: If true, only strings that end in a null will be returned.
        :param jpype.JBoolean or bool includeAllCharWidths: if true, UTF16 and UTF32 size strings will be included in
        addition to UTF8.
        :return: a list of "FoundString" objects which contain the addresses, length, and type of
        possible strings.
        :rtype: java.util.List[ghidra.program.util.string.FoundString]
        """

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    def getBookmarks(self, address: ghidra.program.model.address.Address) -> jpype.JArray[ghidra.program.model.listing.Bookmark]:
        """
        Returns all of the NOTE bookmarks defined at the specified address
        
        :param ghidra.program.model.address.Address address: the address to retrieve the bookmark
        :return: the bookmarks at the specified address
        :rtype: jpype.JArray[ghidra.program.model.listing.Bookmark]
        """

    def getByte(self, address: ghidra.program.model.address.Address) -> int:
        """
        Returns the signed 'byte' value at the specified address in memory.
        
        :param ghidra.program.model.address.Address address: the address
        :return: the signed 'byte' value at the specified address in memory
        :rtype: int
        :raises MemoryAccessException: if the memory is not readable
        """

    def getBytes(self, address: ghidra.program.model.address.Address, length: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Reads length number of signed bytes starting at the specified address.
        Note: this could be inefficient if length is large
        
        :param ghidra.program.model.address.Address address: the address to start reading
        :param jpype.JInt or int length: the number of bytes to read
        :return: an array of signed bytes
        :rtype: jpype.JArray[jpype.JByte]
        :raises MemoryAccessException: if memory does not exist or is uninitialized
        
        .. seealso::
        
            | :obj:`ghidra.program.model.mem.Memory`
        """

    def getCurrentProgram(self) -> ghidra.program.model.listing.Program:
        """
        Gets the current program.
        
        :return: the program
        :rtype: ghidra.program.model.listing.Program
        """

    @typing.overload
    def getDataAfter(self, data: ghidra.program.model.listing.Data) -> ghidra.program.model.listing.Data:
        """
        Returns the defined data after the specified data or null if no data exists.
        
        :param ghidra.program.model.listing.Data data: preceding data
        :return: the defined data after the specified data or null if no data exists
        :rtype: ghidra.program.model.listing.Data
        """

    @typing.overload
    def getDataAfter(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the defined data after the specified address or null if no data exists.
        
        :param ghidra.program.model.address.Address address: the data address
        :return: the defined data after the specified address or null if no data exists
        :rtype: ghidra.program.model.listing.Data
        """

    def getDataAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the defined data at the specified address or null if no data exists.
        
        :param ghidra.program.model.address.Address address: the data address
        :return: the data at the specified address or null if no data exists
        :rtype: ghidra.program.model.listing.Data
        """

    @typing.overload
    def getDataBefore(self, data: ghidra.program.model.listing.Data) -> ghidra.program.model.listing.Data:
        """
        Returns the defined data before the specified data or null if no data exists.
        
        :param ghidra.program.model.listing.Data data: the succeeding data
        :return: the defined data before the specified data or null if no data exists
        :rtype: ghidra.program.model.listing.Data
        """

    @typing.overload
    def getDataBefore(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the defined data before the specified address or null if no data exists.
        
        :param ghidra.program.model.address.Address address: the data address
        :return: the defined data before the specified address or null if no data exists
        :rtype: ghidra.program.model.listing.Data
        """

    def getDataContaining(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the defined data containing the specified address or null if no data exists.
        
        :param ghidra.program.model.address.Address address: the data address
        :return: the defined data containing the specified address or null if no data exists
        :rtype: ghidra.program.model.listing.Data
        """

    def getDataTypes(self, name: typing.Union[java.lang.String, str]) -> jpype.JArray[ghidra.program.model.data.DataType]:
        """
        Searches through the datatype manager of the current program and
        returns an array of datatypes that match the specified name.
        The datatype manager supports datatypes of the same name in different categories.
        A zero-length array indicates that no datatypes with the specified name exist.
        
        :param java.lang.String or str name: the name of the desired datatype
        :return: an array of datatypes that match the specified name
        :rtype: jpype.JArray[ghidra.program.model.data.DataType]
        """

    def getDouble(self, address: ghidra.program.model.address.Address) -> float:
        """
        Returns the 'double' value at the specified address in memory.
        
        :param ghidra.program.model.address.Address address: the address
        :return: the 'double' value at the specified address in memory
        :rtype: float
        :raises MemoryAccessException: if the memory is not readable
        """

    def getEOLComment(self, address: ghidra.program.model.address.Address) -> str:
        """
        Returns the EOL comment at the specified address.  The comment returned is the raw text
        of the comment.  Contrastingly, calling :meth:`GhidraScript.getEOLCommentAsRendered(Address) <GhidraScript.getEOLCommentAsRendered>` will
        return the text of the comment as it is rendered in the display.
        
        :param ghidra.program.model.address.Address address: the address to get the comment
        :return: the EOL comment at the specified address or null
        if one does not exist
        :rtype: str
        
        .. seealso::
        
            | :obj:`GhidraScript.getEOLCommentAsRendered(Address)`
        """

    @typing.overload
    def getEquate(self, instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]) -> ghidra.program.model.symbol.Equate:
        """
        Returns the equate defined at the operand index of the instruction with the given value.
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :param jpype.JInt or int operandIndex: the operand index
        :param jpype.JLong or int value: scalar equate value
        :return: the equate defined at the operand index of the instruction
        :rtype: ghidra.program.model.symbol.Equate
        """

    @typing.overload
    def getEquate(self, data: ghidra.program.model.listing.Data) -> ghidra.program.model.symbol.Equate:
        """
        Returns the equate defined on the data.
        
        :param ghidra.program.model.listing.Data data: the data
        :return: the equate defined on the data
        :rtype: ghidra.program.model.symbol.Equate
        """

    def getEquates(self, instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int]) -> java.util.List[ghidra.program.model.symbol.Equate]:
        """
        Returns the equates defined at the operand index of the instruction.
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :param jpype.JInt or int operandIndex: the operand index
        :return: the equate defined at the operand index of the instruction
        :rtype: java.util.List[ghidra.program.model.symbol.Equate]
        """

    def getFirstData(self) -> ghidra.program.model.listing.Data:
        """
        Returns the first defined data in the current program.
        
        :return: the first defined data in the current program
        :rtype: ghidra.program.model.listing.Data
        """

    def getFirstFunction(self) -> ghidra.program.model.listing.Function:
        """
        Returns the first function in the current program.
        
        :return: the first function in the current program
        :rtype: ghidra.program.model.listing.Function
        """

    @typing.overload
    def getFirstInstruction(self) -> ghidra.program.model.listing.Instruction:
        """
        Returns the first instruction in the current program.
        
        :return: the first instruction in the current program
        :rtype: ghidra.program.model.listing.Instruction
        """

    @typing.overload
    def getFirstInstruction(self, function: ghidra.program.model.listing.Function) -> ghidra.program.model.listing.Instruction:
        """
        Returns the first instruction in the function.
        
        :param ghidra.program.model.listing.Function function: the function
        :return: the first instruction in the function
        :rtype: ghidra.program.model.listing.Instruction
        """

    def getFloat(self, address: ghidra.program.model.address.Address) -> float:
        """
        Returns the 'float' value at the specified address in memory.
        
        :param ghidra.program.model.address.Address address: the address
        :return: the 'float' value at the specified address in memory
        :rtype: float
        :raises MemoryAccessException: if the memory is not readable
        """

    def getFragment(self, module: ghidra.program.model.listing.ProgramModule, fragmentName: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.ProgramFragment:
        """
        Returns the fragment with the specified name
        defined in the given module.
        
        :param ghidra.program.model.listing.ProgramModule module: the parent module
        :param java.lang.String or str fragmentName: the fragment name
        :return: the fragment or null if one does not exist
        :rtype: ghidra.program.model.listing.ProgramFragment
        """

    @deprecated("this method makes no sense in the new world order where function  names\n \t\t\t   no longer have to be unique. Use getGlobalFunctions(String)\n \t\t\t   Deprecated in Ghidra 7.4")
    def getFunction(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Function:
        """
        Returns the function with the specified name, or
        null if no function exists. (Now returns the first one it finds with that name)
        
        :param java.lang.String or str name: the name of the function
        :return: the function with the specified name, or
        null if no function exists
        :rtype: ghidra.program.model.listing.Function
        
        .. deprecated::
        
        this method makes no sense in the new world order where function  names
                        no longer have to be unique. Use :meth:`getGlobalFunctions(String) <.getGlobalFunctions>`
                        Deprecated in Ghidra 7.4
        """

    @typing.overload
    def getFunctionAfter(self, function: ghidra.program.model.listing.Function) -> ghidra.program.model.listing.Function:
        """
        Returns the function defined after the specified function in address order.
        
        :param ghidra.program.model.listing.Function function: the function
        :return: the function defined after the specified function
        :rtype: ghidra.program.model.listing.Function
        """

    @typing.overload
    def getFunctionAfter(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
        """
        Returns the function defined after the specified address.
        
        :param ghidra.program.model.address.Address address: the address
        :return: the function defined after the specified address
        :rtype: ghidra.program.model.listing.Function
        """

    def getFunctionAt(self, entryPoint: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
        """
        Returns the function with the specified entry point, or
        null if no function exists.
        
        :param ghidra.program.model.address.Address entryPoint: the function entry point address
        :return: the function with the specified entry point, or
        null if no function exists
        :rtype: ghidra.program.model.listing.Function
        """

    @typing.overload
    def getFunctionBefore(self, function: ghidra.program.model.listing.Function) -> ghidra.program.model.listing.Function:
        """
        Returns the function defined before the specified function in address order.
        
        :param ghidra.program.model.listing.Function function: the function
        :return: the function defined before the specified function
        :rtype: ghidra.program.model.listing.Function
        """

    @typing.overload
    def getFunctionBefore(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
        """
        Returns the function defined before the specified address.
        
        :param ghidra.program.model.address.Address address: the address
        :return: the function defined before the specified address
        :rtype: ghidra.program.model.listing.Function
        """

    def getFunctionContaining(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
        """
        Returns the function containing the specified address.
        
        :param ghidra.program.model.address.Address address: the address
        :return: the function containing the specified address
        :rtype: ghidra.program.model.listing.Function
        """

    def getGlobalFunctions(self, name: typing.Union[java.lang.String, str]) -> java.util.List[ghidra.program.model.listing.Function]:
        """
        Returns a list of all functions in the global namespace with the given name.
        
        :param java.lang.String or str name: the name of the function
        :return: the function with the specified name, or
        :rtype: java.util.List[ghidra.program.model.listing.Function]
        """

    @typing.overload
    def getInstructionAfter(self, instruction: ghidra.program.model.listing.Instruction) -> ghidra.program.model.listing.Instruction:
        """
        Returns the instruction defined after the specified instruction or null
        if no instruction exists.
        The instruction that is returned does not have to be contiguous.
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :return: the instruction defined after the specified instruction or null if no instruction exists
        :rtype: ghidra.program.model.listing.Instruction
        """

    @typing.overload
    def getInstructionAfter(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Returns the instruction defined after the specified address or null
        if no instruction exists.
        The instruction that is returned does not have to be contiguous.
        
        :param ghidra.program.model.address.Address address: the address of the prior instruction
        :return: the instruction defined after the specified address or null if no instruction exists
        :rtype: ghidra.program.model.listing.Instruction
        """

    def getInstructionAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Returns the instruction at the specified address or null if no instruction exists.
        
        :param ghidra.program.model.address.Address address: the instruction address
        :return: the instruction at the specified address or null if no instruction exists
        :rtype: ghidra.program.model.listing.Instruction
        """

    @typing.overload
    def getInstructionBefore(self, instruction: ghidra.program.model.listing.Instruction) -> ghidra.program.model.listing.Instruction:
        """
        Returns the instruction defined before the specified instruction or null
        if no instruction exists.
        The instruction that is returned does not have to be contiguous.
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :return: the instruction defined before the specified instruction or null if no instruction exists
        :rtype: ghidra.program.model.listing.Instruction
        """

    @typing.overload
    def getInstructionBefore(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Returns the instruction defined before the specified address or null
        if no instruction exists.
        The instruction that is returned does not have to be contiguous.
        
        :param ghidra.program.model.address.Address address: the address of the instruction
        :return: the instruction defined before the specified address or null if no instruction exists
        :rtype: ghidra.program.model.listing.Instruction
        """

    def getInstructionContaining(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        """
        Returns the instruction containing the specified address or null if no instruction exists.
        
        :param ghidra.program.model.address.Address address: the instruction address
        :return: the instruction containing the specified address or null if no instruction exists
        :rtype: ghidra.program.model.listing.Instruction
        """

    def getInt(self, address: ghidra.program.model.address.Address) -> int:
        """
        Returns the 'integer' value at the specified address in memory.
        
        :param ghidra.program.model.address.Address address: the address
        :return: the 'integer' value at the specified address in memory
        :rtype: int
        :raises MemoryAccessException: if the memory is not readable
        """

    def getLastData(self) -> ghidra.program.model.listing.Data:
        """
        Returns the last defined data in the current program.
        
        :return: the last defined data in the current program
        :rtype: ghidra.program.model.listing.Data
        """

    def getLastFunction(self) -> ghidra.program.model.listing.Function:
        """
        Returns the last function in the current program.
        
        :return: the last function in the current program
        :rtype: ghidra.program.model.listing.Function
        """

    def getLastInstruction(self) -> ghidra.program.model.listing.Instruction:
        """
        Returns the last instruction in the current program.
        
        :return: the last instruction in the current program
        :rtype: ghidra.program.model.listing.Instruction
        """

    def getLong(self, address: ghidra.program.model.address.Address) -> int:
        """
        Returns the 'long' value at the specified address in memory.
        
        :param ghidra.program.model.address.Address address: the address
        :return: the 'long' value at the specified address in memory
        :rtype: int
        :raises MemoryAccessException: if the memory is not readable
        """

    @typing.overload
    def getMemoryBlock(self, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.mem.MemoryBlock:
        """
        Returns the first memory block with the specified name.
        NOTE: if more than block exists with the same name, the first
        block with that name will be returned.
        
        :param java.lang.String or str name: the name of the requested block
        :return: the memory block with the specified name
        :rtype: ghidra.program.model.mem.MemoryBlock
        """

    @typing.overload
    def getMemoryBlock(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.mem.MemoryBlock:
        """
        Returns the memory block containing the specified address,
        or null if no memory block contains the address.
        
        :param ghidra.program.model.address.Address address: the address
        :return: the memory block containing the specified address
        :rtype: ghidra.program.model.mem.MemoryBlock
        """

    def getMemoryBlocks(self) -> jpype.JArray[ghidra.program.model.mem.MemoryBlock]:
        """
        Returns an array containing all the memory blocks
        in the current program.
        
        :return: an array containing all the memory blocks
        :rtype: jpype.JArray[ghidra.program.model.mem.MemoryBlock]
        """

    def getMonitor(self) -> ghidra.util.task.TaskMonitor:
        """
        Gets the current task monitor.
        
        :return: the task monitor
        :rtype: ghidra.util.task.TaskMonitor
        """

    def getNamespace(self, parent: ghidra.program.model.symbol.Namespace, namespaceName: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Namespace:
        """
        Returns the non-function namespace with the given name contained inside the
        specified parent namespace.
        Pass ``null`` for parent to indicate the global namespace.
        
        :param ghidra.program.model.symbol.Namespace parent: the parent namespace, or null for global namespace
        :param java.lang.String or str namespaceName: the requested namespace's name
        :return: the namespace with the given name or null if not found
        :rtype: ghidra.program.model.symbol.Namespace
        """

    def getPlateComment(self, address: ghidra.program.model.address.Address) -> str:
        """
        Returns the PLATE comment at the specified address.  The comment returned is the raw text
        of the comment.  Contrastingly, calling :meth:`GhidraScript.getPlateCommentAsRendered(Address) <GhidraScript.getPlateCommentAsRendered>` will
        return the text of the comment as it is rendered in the display.
        
        :param ghidra.program.model.address.Address address: the address to get the comment
        :return: the PLATE comment at the specified address or null
        if one does not exist
        :rtype: str
        
        .. seealso::
        
            | :obj:`GhidraScript.getPlateCommentAsRendered(Address)`
        """

    def getPostComment(self, address: ghidra.program.model.address.Address) -> str:
        """
        Returns the POST comment at the specified address.  The comment returned is the raw text
        of the comment.  Contrastingly, calling :meth:`GhidraScript.getPostCommentAsRendered(Address) <GhidraScript.getPostCommentAsRendered>` will
        return the text of the comment as it is rendered in the display.
        
        :param ghidra.program.model.address.Address address: the address to get the comment
        :return: the POST comment at the specified address or null
        if one does not exist
        :rtype: str
        
        .. seealso::
        
            | :obj:`GhidraScript.getPostCommentAsRendered(Address)`
        """

    def getPreComment(self, address: ghidra.program.model.address.Address) -> str:
        """
        Returns the PRE comment at the specified address.  The comment returned is the raw text
        of the comment.  Contrastingly, calling :meth:`GhidraScript.getPreCommentAsRendered(Address) <GhidraScript.getPreCommentAsRendered>` will
        return the text of the comment as it is rendered in the display.
        
        :param ghidra.program.model.address.Address address: the address to get the comment
        :return: the PRE comment at the specified address or null
        if one does not exist
        :rtype: str
        
        .. seealso::
        
            | :obj:`GhidraScript.getPreCommentAsRendered(Address)`
        """

    def getProgramFile(self) -> java.io.File:
        """
        Returns the :obj:`File` that the program was originally imported from.  It does not 
        necessarily still exist on the file system.
         
        
        For example, ``c:\temp\test.exe``.
        
        :return: the :obj:`File` that the program was originally imported from
        :rtype: java.io.File
        """

    def getProjectRootFolder(self) -> ghidra.framework.model.DomainFolder:
        """
        This method looks up the current project and returns
        the root domain folder.
        
        :return: the root domain folder of the current project
        :rtype: ghidra.framework.model.DomainFolder
        """

    @typing.overload
    def getReference(self, instruction: ghidra.program.model.listing.Instruction, toAddress: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Reference:
        """
        Returns the reference from the instruction to the given address.
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :param ghidra.program.model.address.Address toAddress: the destination address
        :return: the reference from the instruction to the given address
        :rtype: ghidra.program.model.symbol.Reference
        """

    @typing.overload
    def getReference(self, data: ghidra.program.model.listing.Data, toAddress: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Reference:
        """
        Returns the reference from the data to the given address.
        
        :param ghidra.program.model.listing.Data data: the data
        :param ghidra.program.model.address.Address toAddress: the destination address
        :return: the reference from the data to the given address
        :rtype: ghidra.program.model.symbol.Reference
        """

    def getReferencesFrom(self, address: ghidra.program.model.address.Address) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        """
        Returns an array of the references FROM the given address.
        
        :param ghidra.program.model.address.Address address: the from address of the references
        :return: an array of the references FROM the given address
        :rtype: jpype.JArray[ghidra.program.model.symbol.Reference]
        """

    def getReferencesTo(self, address: ghidra.program.model.address.Address) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        """
        Returns an array of the references TO the given address.
        Note: If more than 4096 references exists to this address,
        only the first 4096 will be returned.
        If you need to access all the references, please
        refer to the method ``ReferenceManager::getReferencesTo(Address)``.
        
        :param ghidra.program.model.address.Address address: the from address of the references
        :return: an array of the references TO the given address
        :rtype: jpype.JArray[ghidra.program.model.symbol.Reference]
        """

    def getRepeatableComment(self, address: ghidra.program.model.address.Address) -> str:
        """
        Returns the repeatable comment at the specified address.  The comment returned is the raw text
        of the comment.  Contrastingly, calling :meth:`GhidraScript.getRepeatableCommentAsRendered(Address) <GhidraScript.getRepeatableCommentAsRendered>` will
        return the text of the comment as it is rendered in the display.
        
        :param ghidra.program.model.address.Address address: the address to get the comment
        :return: the repeatable comment at the specified address or null
        if one does not exist
        :rtype: str
        
        .. seealso::
        
            | :obj:`GhidraScript.getRepeatableCommentAsRendered(Address)`
        """

    def getShort(self, address: ghidra.program.model.address.Address) -> int:
        """
        Returns the 'short' value at the specified address in memory.
        
        :param ghidra.program.model.address.Address address: the address
        :return: the 'short' value at the specified address in memory
        :rtype: int
        :raises MemoryAccessException: if the memory is not readable
        """

    @deprecated("use getSymbols(String, Namespace)")
    def getSymbol(self, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the symbol with the given name in the given namespace if there is only one.
        Pass ``null`` for namespace to indicate the global namespace.
        
        :param java.lang.String or str name: the name of the symbol
        :param ghidra.program.model.symbol.Namespace namespace: the parent namespace, or null for global namespace
        :return: the symbol with the given name in the given namespace
        :rtype: ghidra.program.model.symbol.Symbol
        :raises IllegalStateException: if there is more than one symbol with that name.
        
        .. deprecated::
        
        use :meth:`getSymbols(String, Namespace) <.getSymbols>`
        """

    @typing.overload
    def getSymbolAfter(self, symbol: ghidra.program.model.symbol.Symbol) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the next non-default primary symbol defined
        after the given symbol.
        
        :param ghidra.program.model.symbol.Symbol symbol: the symbol to use as a starting point
        :return: the next non-default primary symbol
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @typing.overload
    def getSymbolAfter(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the next non-default primary symbol defined
        after the given address.
        
        :param ghidra.program.model.address.Address address: the address to use as a starting point
        :return: the next non-default primary symbol
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @typing.overload
    @deprecated("Since the same label name can be at the same address if in a different namespace,\n this method is ambiguous. Use getSymbolAt(Address, String, Namespace) instead.")
    def getSymbolAt(self, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the symbol with the specified address and name, or
        null if no symbol exists.
        
        :param ghidra.program.model.address.Address address: the symbol address
        :param java.lang.String or str name: the symbol name
        :return: the symbol with the specified address and name, or
        null if no symbol exists
        :rtype: ghidra.program.model.symbol.Symbol
        
        .. deprecated::
        
        Since the same label name can be at the same address if in a different namespace,
        this method is ambiguous. Use :meth:`getSymbolAt(Address, String, Namespace) <.getSymbolAt>` instead.
        """

    @typing.overload
    def getSymbolAt(self, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the symbol with the specified address, name, and namespace
        
        :param ghidra.program.model.address.Address address: the symbol address
        :param java.lang.String or str name: the symbol name
        :param ghidra.program.model.symbol.Namespace namespace: the parent namespace for the symbol.
        :return: the symbol with the specified address, name, and namespace, or
        null if no symbol exists
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @typing.overload
    def getSymbolAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the PRIMARY symbol at the specified address, or
        null if no symbol exists.
        
        :param ghidra.program.model.address.Address address: the symbol address
        :return: the PRIMARY symbol at the specified address, or
        null if no symbol exists
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @typing.overload
    def getSymbolBefore(self, symbol: ghidra.program.model.symbol.Symbol) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the previous non-default primary symbol defined
        before the given symbol.
        
        :param ghidra.program.model.symbol.Symbol symbol: the symbol to use as a starting point
        :return: the previous non-default primary symbol
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @typing.overload
    def getSymbolBefore(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the previous non-default primary symbol defined
        after the previous address.
        
        :param ghidra.program.model.address.Address address: the address to use as a starting point
        :return: the next non-default primary symbol
        :rtype: ghidra.program.model.symbol.Symbol
        """

    def getSymbols(self, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace) -> java.util.List[ghidra.program.model.symbol.Symbol]:
        """
        Returns a list of all the symbols with the given name in the given namespace.
        
        :param java.lang.String or str name: the name of the symbols to retrieve.
        :param ghidra.program.model.symbol.Namespace namespace: the namespace containing the symbols, or null for the global namespace.
        :return: a list of all the symbols with the given name in the given namespace.
        :rtype: java.util.List[ghidra.program.model.symbol.Symbol]
        """

    def getUndefinedDataAfter(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the undefined data after the specified address or null if no undefined data exists.
        
        :param ghidra.program.model.address.Address address: the undefined data address
        :return: the undefined data after the specified address or null if no undefined data exists
        :rtype: ghidra.program.model.listing.Data
        """

    def getUndefinedDataAt(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the undefined data at the specified address or null if no undefined data exists.
        
        :param ghidra.program.model.address.Address address: the undefined data address
        :return: the undefined data at the specified address or null if no undefined data exists
        :rtype: ghidra.program.model.listing.Data
        """

    def getUndefinedDataBefore(self, address: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Data:
        """
        Returns the undefined data before the specified address or null if no undefined data exists.
        
        :param ghidra.program.model.address.Address address: the undefined data address
        :return: the undefined data before the specified address or null if no undefined data exists
        :rtype: ghidra.program.model.listing.Data
        """

    def openDataTypeArchive(self, archiveFile: jpype.protocol.SupportsPath, readOnly: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.data.FileDataTypeManager:
        """
        Opens an existing File Data Type Archive.
         
        
        **NOTE:** If archive has an assigned architecture, issues may arise due to a revised or
        missing :obj:`Language`/:obj:`CompilerSpec` which will result in a warning but not
        prevent the archive from being opened.  Such a warning condition will be logged and may 
        result in missing or stale information for existing datatypes which have architecture related
        data.  In some case it may be appropriate to 
        :meth:`check for warnings <FileDataTypeManager.getWarning>` on the returned archive
        object prior to its use.
        
        :param jpype.protocol.SupportsPath archiveFile: the archive file to open
        :param jpype.JBoolean or bool readOnly: should file be opened read only
        :return: the data type manager
        :rtype: ghidra.program.model.data.FileDataTypeManager
        :raises java.lang.Exception: if there is any exception
        """

    def removeBookmark(self, bookmark: ghidra.program.model.listing.Bookmark):
        """
        Removes the specified bookmark.
        
        :param ghidra.program.model.listing.Bookmark bookmark: the bookmark to remove
        """

    def removeData(self, data: ghidra.program.model.listing.Data):
        """
        Removes the given data from the current program.
        
        :param ghidra.program.model.listing.Data data: the data to remove
        :raises java.lang.Exception: if there is any exception
        """

    def removeDataAt(self, address: ghidra.program.model.address.Address):
        """
        Removes the data containing the given address from the current program.
        
        :param ghidra.program.model.address.Address address: the address to remove data
        :raises java.lang.Exception: if there is any exception
        """

    def removeEntryPoint(self, address: ghidra.program.model.address.Address):
        """
        Removes the entry point at the specified address.
        
        :param ghidra.program.model.address.Address address: address of entry point to remove
        """

    @typing.overload
    def removeEquate(self, instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
        """
        Removes the equate defined at the operand index of the instruction with the given value.
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :param jpype.JInt or int operandIndex: the operand index
        :param jpype.JLong or int value: scalar value corresponding to equate
        """

    @typing.overload
    def removeEquate(self, data: ghidra.program.model.listing.Data):
        """
        Removes the equate defined on the data.
        
        :param ghidra.program.model.listing.Data data: the data
        """

    def removeEquates(self, instruction: ghidra.program.model.listing.Instruction, operandIndex: typing.Union[jpype.JInt, int]):
        """
        Removes the equates defined at the operand index of the instruction.
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction
        :param jpype.JInt or int operandIndex: the operand index
        """

    def removeFunction(self, function: ghidra.program.model.listing.Function):
        """
        Removes the function from the current program.
        
        :param ghidra.program.model.listing.Function function: the function to remove
        """

    def removeFunctionAt(self, entryPoint: ghidra.program.model.address.Address):
        """
        Removes the function with the given entry point.
        
        :param ghidra.program.model.address.Address entryPoint: the entry point of the function to remove
        """

    def removeInstruction(self, instruction: ghidra.program.model.listing.Instruction):
        """
        Removes the given instruction from the current program.
        
        :param ghidra.program.model.listing.Instruction instruction: the instruction to remove
        :raises java.lang.Exception: if there is any exception
        """

    def removeInstructionAt(self, address: ghidra.program.model.address.Address):
        """
        Removes the instruction containing the given address from the current program.
        
        :param ghidra.program.model.address.Address address: the address to remove instruction
        :raises java.lang.Exception: if there is any exception
        """

    def removeMemoryBlock(self, block: ghidra.program.model.mem.MemoryBlock):
        """
        Remove the memory block.
        NOTE: ALL ANNOTATION (disassembly, comments, etc) defined in this
        memory block will also be removed!
        
        :param ghidra.program.model.mem.MemoryBlock block: the block to be removed
        :raises java.lang.Exception: if there is any exception
        """

    def removeReference(self, reference: ghidra.program.model.symbol.Reference):
        """
        Removes the given reference.
        
        :param ghidra.program.model.symbol.Reference reference: the reference to remove
        """

    def removeSymbol(self, address: ghidra.program.model.address.Address, name: typing.Union[java.lang.String, str]) -> bool:
        """
        Deletes the symbol with the specified name at the specified address.
        
        :param ghidra.program.model.address.Address address: the address of the symbol to delete
        :param java.lang.String or str name: the name of the symbol to delete
        :return: true if the symbol was deleted
        :rtype: bool
        """

    @typing.overload
    def saveProgram(self, program: ghidra.program.model.listing.Program):
        """
        Saves the changes to the specified program.
        If the program does not already exist in the current project
        then it will be saved into the root folder.
        If a program already exists with the specified
        name, then a time stamp will be appended to the name to make it unique.
        
        :param ghidra.program.model.listing.Program program: the program to save
        :raises java.lang.Exception: if there is any exception
        """

    @typing.overload
    def saveProgram(self, program: ghidra.program.model.listing.Program, path: java.util.List[java.lang.String]):
        """
        Saves changes to the specified program.
         
        
        If the program does not already exist in the current project
        then it will be saved into a project folder path specified by the path parameter.
         
        
        If path is NULL, the program will be saved into the root folder.  If parts of the path are
        missing, they will be created if possible.
         
        
        If a program already exists with the specified name, then a time stamp will be appended
        to the name to make it unique.
        
        :param ghidra.program.model.listing.Program program: the program to save
        :param java.util.List[java.lang.String] path: list of string path elements (starting at the root of the project) that specify
        the project folder to save the program info.  Example: { "folder1", "subfolder2",
        "final_folder" }
        :raises java.lang.Exception: if there is any exception
        """

    def setByte(self, address: ghidra.program.model.address.Address, value: typing.Union[jpype.JByte, int]):
        """
        Sets the 'byte' value at the specified address.
        
        :param ghidra.program.model.address.Address address: the address to set the 'byte'
        :param jpype.JByte or int value: the value to set
        :raises MemoryAccessException: if memory does not exist or is uninitialized
        """

    def setBytes(self, address: ghidra.program.model.address.Address, values: jpype.JArray[jpype.JByte]):
        """
        Sets the 'byte' values starting at the specified address.
        
        :param ghidra.program.model.address.Address address: the address to set the bytes
        :param jpype.JArray[jpype.JByte] values: the values to set
        :raises MemoryAccessException: if memory does not exist or is uninitialized
        """

    def setDouble(self, address: ghidra.program.model.address.Address, value: typing.Union[jpype.JDouble, float]):
        """
        Sets the 'double' value at the specified address.
        
        :param ghidra.program.model.address.Address address: the address to set the 'double'
        :param jpype.JDouble or float value: the value to set
        :raises MemoryAccessException: if memory does not exist or is uninitialized
        """

    def setEOLComment(self, address: ghidra.program.model.address.Address, comment: typing.Union[java.lang.String, str]) -> bool:
        """
        Sets an EOL comment at the specified address
        
        :param ghidra.program.model.address.Address address: the address to set the EOL comment
        :param java.lang.String or str comment: the EOL comment
        :return: true if the EOL comment was successfully set
        :rtype: bool
        """

    def setFloat(self, address: ghidra.program.model.address.Address, value: typing.Union[jpype.JFloat, float]):
        """
        Sets the 'float' value at the specified address.
        
        :param ghidra.program.model.address.Address address: the address to set the 'float'
        :param jpype.JFloat or float value: the value to set
        :raises MemoryAccessException: if memory does not exist or is uninitialized
        """

    def setInt(self, address: ghidra.program.model.address.Address, value: typing.Union[jpype.JInt, int]):
        """
        Sets the 'integer' value at the specified address.
        
        :param ghidra.program.model.address.Address address: the address to set the 'integer'
        :param jpype.JInt or int value: the value to set
        :raises MemoryAccessException: if memory does not exist or is uninitialized
        """

    def setLong(self, address: ghidra.program.model.address.Address, value: typing.Union[jpype.JLong, int]):
        """
        Sets the 'long' value at the specified address.
        
        :param ghidra.program.model.address.Address address: the address to set the 'long'
        :param jpype.JLong or int value: the value to set
        :raises MemoryAccessException: if memory does not exist or is uninitialized
        """

    def setPlateComment(self, address: ghidra.program.model.address.Address, comment: typing.Union[java.lang.String, str]) -> bool:
        """
        Sets a PLATE comment at the specified address
        
        :param ghidra.program.model.address.Address address: the address to set the PLATE comment
        :param java.lang.String or str comment: the PLATE comment
        :return: true if the PLATE comment was successfully set
        :rtype: bool
        """

    def setPostComment(self, address: ghidra.program.model.address.Address, comment: typing.Union[java.lang.String, str]) -> bool:
        """
        Sets a POST comment at the specified address
        
        :param ghidra.program.model.address.Address address: the address to set the POST comment
        :param java.lang.String or str comment: the POST comment
        :return: true if the POST comment was successfully set
        :rtype: bool
        """

    def setPreComment(self, address: ghidra.program.model.address.Address, comment: typing.Union[java.lang.String, str]) -> bool:
        """
        Sets a PRE comment at the specified address
        
        :param ghidra.program.model.address.Address address: the address to set the PRE comment
        :param java.lang.String or str comment: the PRE comment
        :return: true if the PRE comment was successfully set
        :rtype: bool
        """

    @typing.overload
    def setReferencePrimary(self, reference: ghidra.program.model.symbol.Reference):
        """
        Sets the given reference as primary.
        
        :param ghidra.program.model.symbol.Reference reference: the reference to mark as primary
        """

    @typing.overload
    def setReferencePrimary(self, reference: ghidra.program.model.symbol.Reference, primary: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the given reference as primary.
        
        :param ghidra.program.model.symbol.Reference reference: the reference
        :param jpype.JBoolean or bool primary: true if primary, false not primary
        """

    def setRepeatableComment(self, address: ghidra.program.model.address.Address, comment: typing.Union[java.lang.String, str]) -> bool:
        """
        Sets a repeatable comment at the specified address
        
        :param ghidra.program.model.address.Address address: the address to set the repeatable comment
        :param java.lang.String or str comment: the repeatable comment
        :return: true if the repeatable comment was successfully set
        :rtype: bool
        """

    def setShort(self, address: ghidra.program.model.address.Address, value: typing.Union[jpype.JShort, int]):
        """
        Sets the 'short' value at the specified address.
        
        :param ghidra.program.model.address.Address address: the address to set the 'short'
        :param jpype.JShort or int value: the value to set
        :raises MemoryAccessException: if memory does not exist or is uninitialized
        """

    def start(self):
        """
        Starts a transaction on the current program.
        """

    @typing.overload
    def toAddr(self, offset: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
        """
        Returns a new address with the specified offset in the default address space.
        
        :param jpype.JInt or int offset: the offset for the new address
        :return: a new address with the specified offset in the default address space
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def toAddr(self, offset: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        Returns a new address with the specified offset in the default address space.
        
        :param jpype.JLong or int offset: the offset for the new address
        :return: a new address with the specified offset in the default address space
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def toAddr(self, addressString: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        """
        Returns a new address inside the specified program as indicated by the string.
        
        :param java.lang.String or str addressString: string representation of the address desired
        :return: the address. Otherwise, return null if the string fails to evaluate
        to a legitimate address
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def currentProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...

    @property
    def instructionBefore(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def repeatableComment(self) -> java.lang.String:
        ...

    @property
    def symbolAfter(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def dataBefore(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def float(self) -> jpype.JFloat:
        ...

    @property
    def bookmarks(self) -> jpype.JArray[ghidra.program.model.listing.Bookmark]:
        ...

    @property
    def instructionAt(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def programFile(self) -> java.io.File:
        ...

    @property
    def postComment(self) -> java.lang.String:
        ...

    @property
    def referencesFrom(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def lastData(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def firstData(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def undefinedDataBefore(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def instructionAfter(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def firstInstruction(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def double(self) -> jpype.JDouble:
        ...

    @property
    def byte(self) -> jpype.JByte:
        ...

    @property
    def instructionContaining(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def referencesTo(self) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        ...

    @property
    def dataContaining(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def eOLComment(self) -> java.lang.String:
        ...

    @property
    def undefinedDataAt(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def symbolBefore(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def functionBefore(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def firstFunction(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def projectRootFolder(self) -> ghidra.framework.model.DomainFolder:
        ...

    @property
    def functionContaining(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def memoryBlocks(self) -> jpype.JArray[ghidra.program.model.mem.MemoryBlock]:
        ...

    @property
    def dataAt(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def lastFunction(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def long(self) -> jpype.JLong:
        ...

    @property
    def undefinedDataAfter(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def lastInstruction(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def dataTypes(self) -> jpype.JArray[ghidra.program.model.data.DataType]:
        ...

    @property
    def plateComment(self) -> java.lang.String:
        ...

    @property
    def functionAfter(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def equate(self) -> ghidra.program.model.symbol.Equate:
        ...

    @property
    def globalFunctions(self) -> java.util.List[ghidra.program.model.listing.Function]:
        ...

    @property
    def monitor(self) -> ghidra.util.task.TaskMonitor:
        ...

    @property
    def functionAt(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def preComment(self) -> java.lang.String:
        ...

    @property
    def int(self) -> jpype.JInt:
        ...

    @property
    def dataAfter(self) -> ghidra.program.model.listing.Data:
        ...

    @property
    def symbolAt(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def short(self) -> jpype.JShort:
        ...

    @property
    def memoryBlock(self) -> ghidra.program.model.mem.MemoryBlock:
        ...



__all__ = ["FlatProgramAPI"]
