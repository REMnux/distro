from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.algorithms
import generic.expressions
import generic.stl
import ghidra.app.plugin.core.analysis
import ghidra.app.plugin.processors.sleigh
import ghidra.app.services
import ghidra.app.util
import ghidra.app.util.opinion
import ghidra.features.base.codecompare.listing
import ghidra.framework.model
import ghidra.framework.options
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.lang
import ghidra.program.model.listing
import ghidra.program.model.mem
import ghidra.program.model.pcode
import ghidra.program.model.sourcemap
import ghidra.program.model.symbol
import ghidra.util
import ghidra.util.classfinder
import ghidra.util.datastruct
import ghidra.util.exception
import ghidra.util.task
import java.io # type: ignore
import java.lang # type: ignore
import java.math # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing.text # type: ignore
import utility.function


T = typing.TypeVar("T")


class FunctionUtility(java.lang.Object):
    """
    Utility methods for performing function related actions.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def applyNameAndNamespace(target: ghidra.program.model.listing.Function, source: ghidra.program.model.listing.Function):
        """
        Applies the name and namespace from source function to the target function
        
        :param ghidra.program.model.listing.Function target: the function whose name is being changed.
        :param ghidra.program.model.listing.Function source: the source function from which to get name and namespace. The source function
        can be from another program.
        :raises DuplicateNameException: if creating a namespace would create a invalid duplicate name
        :raises InvalidInputException: if the name or namespace from the source function is invalid
        :raises CircularDependencyException: if this function is an ancestor of
        the target namespace. This probably can't happen
        """

    @staticmethod
    def applySignature(destinationFunction: ghidra.program.model.listing.Function, sourceFunction: ghidra.program.model.listing.Function, applyEmptyComposites: typing.Union[jpype.JBoolean, bool], conflictHandler: ghidra.program.model.data.DataTypeConflictHandler):
        """
        Updates the destination function so its signature will match the source function's signature
        as closely as possible. This method will try to create conflict names if necessary for the
        function and its parameters.
        
        :param ghidra.program.model.listing.Function destinationFunction: the destination function to update
        :param ghidra.program.model.listing.Function sourceFunction: the source function to use as a template
        :param jpype.JBoolean or bool applyEmptyComposites: If true, applied composites will be resolved without their
                                respective components if the type does not already exist in the 
                                destination datatype manager.  If false, normal type resolution 
                                will occur.
        :param ghidra.program.model.data.DataTypeConflictHandler conflictHandler: conflict handler to be used when applying datatypes to the
                                destination program.  If this value is not null or 
                                :obj:`DataTypeConflictHandler.DEFAULT_HANDLER` the datatypes will be 
                                resolved prior to updating the destinationFunction.  This handler
                                will provide some control over how applied datatype are handled when 
                                they conflict with existing datatypes. 
                                See :obj:`DataTypeConflictHandler` which provides some predefined
                                handlers.
        :raises InvalidInputException: if the function name or a variable name is invalid or if a
                                parameter data type is not a fixed length.
        :raises DuplicateNameException: This shouldn't happen since it will try to create conflict
                                names for the function and its variables if necessary. Otherwise, 
                                this would be because the function's name or a variable name already exists.
        :raises CircularDependencyException: if namespaces have circular references
        """

    @staticmethod
    def getFunctionTitle(function: ghidra.program.model.listing.Function) -> str:
        """
        Gets a title string wrapped as HTML and indicating the function's name and the program
        containing it.
        
        :param ghidra.program.model.listing.Function function: the function to be indicated in the title.
        :return: the title string as HTML.
        :rtype: str
        """

    @staticmethod
    def isDefaultFunctionName(function: ghidra.program.model.listing.Function) -> bool:
        """
        Determines if the indicated function has a default name.
        
        :param ghidra.program.model.listing.Function function: the function
        :return: true if the function has a default name.
        :rtype: bool
        """

    @staticmethod
    def isSameLanguageAndCompilerSpec(program1: ghidra.program.model.listing.Program, program2: ghidra.program.model.listing.Program) -> bool:
        """
        Determines whether or not the two programs are considered to have the same processor
        language and compiler specification.
        
        :param ghidra.program.model.listing.Program program1: the first program
        :param ghidra.program.model.listing.Program program2: the second program
        :return: true if the two programs have the same processor language and compiler spec.
        :rtype: bool
        """

    @staticmethod
    def setUniqueParameterNames(function: ghidra.program.model.listing.Function, parameters: java.util.List[ghidra.program.model.listing.Parameter]):
        """
        Changes the names of the parameters in the array to unique names that won't conflict with
        any other names in the function's namespace when the parameters are used to replace
        the existing parameters in the function. Appends an integer number to
        the base name if necessary to create a unique name in the function's namespace.
        
        :param ghidra.program.model.listing.Function function: the function
        :param java.util.List[ghidra.program.model.listing.Parameter] parameters: the parameters that need names that won't conflict. These should be
        Impl objects and not DB objects since their names will be changed within this method.
        :raises InvalidInputException: 
        :raises DuplicateNameException:
        """

    @staticmethod
    def updateFunction(destinationFunction: ghidra.program.model.listing.Function, sourceFunction: ghidra.program.model.listing.Function):
        """
        Updates the destination function so its signature will match the source function's signature
        as closely as possible. This method will try to create conflict names if necessary for the
        function and its parameters.
         
        
        All datatypes will be resolved using the 
        :obj:`default conflict handler <DataTypeConflictHandler.DEFAULT_HANDLER>`.
        
        :param ghidra.program.model.listing.Function destinationFunction: the destination function to update
        :param ghidra.program.model.listing.Function sourceFunction: the source function to use as a template
        :raises InvalidInputException: if the function name or a variable name is invalid or if a
                                parameter data type is not a fixed length.
        :raises DuplicateNameException: This shouldn't happen since it will try to create conflict
                                names for the function and its variables if necessary. Otherwise, 
                                this would be because the function's name or a variable name already exists.
        :raises CircularDependencyException: if namespaces have circular references
        """


@typing.type_check_only
class SymbolMerge(java.lang.Object):
    """
    ``SymbolMerge`` provides functionality for replacing or merging
    symbols from one program to another.
    """

    class_: typing.ClassVar[java.lang.Class]


class ProgramMemoryComparator(java.lang.Object):
    """
    ``ProgramMemoryComparator`` is a class for comparing two programs and
    determining the address differences between them.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program1: ghidra.program.model.listing.Program, program2: ghidra.program.model.listing.Program):
        """
        ``ProgramMemoryComparator`` is used to determine the memory
        address differences between two programs.
        
        :param ghidra.program.model.listing.Program program1: the first program
        :param ghidra.program.model.listing.Program program2: the second program
        :raises ProgramConflictException: if the two programs can't be compared.
        """

    @staticmethod
    def compareAddressTypes(program1: ghidra.program.model.listing.Program, program2: ghidra.program.model.listing.Program):
        """
        Check each program to see if the memory blocks have the same address types.
        
        :param ghidra.program.model.listing.Program program1: the first program
        :param ghidra.program.model.listing.Program program2: the second program
        :raises ProgramConflictException: if the address types for the two programs
        do not match.
        """

    def getAddressRanges(self) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an iterator for the address ranges in the set containing the combined addresses
        in program1 and program2.
        Address ranges from this iterator are derived using program1.
        
        :return: the addresses for both program1 and program2.
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    def getAddressesInCommon(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns the addresses in common between program1 and program2.
        The returned address set is derived using program1.
        
        :return: the addresses in common between program1 and program2.
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getAddressesOnlyInOne(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns the addresses that are in program1, but not in program2
        The returned address set is derived using program1.
        
        :return: the addresses that are in program1, but not in program2.
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getAddressesOnlyInTwo(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns the addresses that are in program2, but not in program1
        The returned address set is derived using program2.
        
        :return: the addresses that are in program2, but not in program1.
        :rtype: ghidra.program.model.address.AddressSet
        """

    @staticmethod
    def getCombinedAddresses(program1: ghidra.program.model.listing.Program, program2: ghidra.program.model.listing.Program) -> ghidra.program.model.address.AddressSet:
        """
        Returns the addresses from combining the address sets in program1 and program2.
        Addresses in the returned address set are derived from program1.
        
        :return: the addresses for both program1 and program2.
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getCompatibleAddressesOnlyInTwo(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns the set of addresses that are in program2, but not in program1
        and that are compatible with program1.
        The returned address set is derived using program1.
        
        :return: the addresses that are in program2, but not in program1.
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getInitializedAddressesInCommon(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns the addresses of initialized memory in common between 
        program1 and program2. This includes bit memory and live memory.
        The returned address set is derived using program1.
        
        :return: the addresses in common between program1 and program2.
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getProgramOne(self) -> ghidra.program.model.listing.Program:
        """
        Gets the first program being compared by the ProgramMemoryComparator.
        
        :return: program1.
        :rtype: ghidra.program.model.listing.Program
        """

    def getProgramTwo(self) -> ghidra.program.model.listing.Program:
        """
        Gets the second program being compared by the ProgramMemoryComparator.
        
        :return: program2.
        :rtype: ghidra.program.model.listing.Program
        """

    def getSameMemTypeAddressesInCommon(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns the addresses with the same memory types in common between 
        program1 and program2.
        The returned address set is derived using program1.
        
        :return: the addresses in common between program1 and program2.
        :rtype: ghidra.program.model.address.AddressSet
        """

    def hasMemoryDifferences(self) -> bool:
        """
        Return whether or not the memory addresses for the two Programs are different.
        """

    @staticmethod
    def sameProgramContextRegisterNames(program1: ghidra.program.model.listing.Program, program2: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if the register names are the same in both programs.
        
        :param ghidra.program.model.listing.Program program1: the first program
        :param ghidra.program.model.listing.Program program2: the second program
        :return: true if the register names are the same
        :rtype: bool
        """

    @staticmethod
    def similarPrograms(p1: ghidra.program.model.listing.Program, p2: ghidra.program.model.listing.Program) -> bool:
        """
        Return whether or not the two specified programs are alike 
        (their language name or address spaces are the same).
        
        :param ghidra.program.model.listing.Program p1: the first program
        :param ghidra.program.model.listing.Program p2: the second program
        :return: true if the programs are alike (their language name or address spaces are the same).
        :rtype: bool
        """

    @property
    def programOne(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def addressesOnlyInOne(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def addressRanges(self) -> ghidra.program.model.address.AddressRangeIterator:
        ...

    @property
    def programTwo(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def addressesInCommon(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def compatibleAddressesOnlyInTwo(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def sameMemTypeAddressesInCommon(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def initializedAddressesInCommon(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def addressesOnlyInTwo(self) -> ghidra.program.model.address.AddressSet:
        ...


class DataTypeCleaner(java.io.Closeable):
    """
    :obj:`DataTypeCleaner` provides a convenient way to clean composite definitions which may be
    included within a complex datatype which was derived from an source unrelated to a target
    :obj:`DataTypeManager`.  The cleaning process entails clearing all details associated with
    all composites other than their description which may be present.  There is also an option
    to retain those composites which are already defined within the target.
     
    
    All datatypes and their referenced datatypes will be accumulated and possibly re-used across
    multiple invocations of the :meth:`clean(DataType) <.clean>` method.  It is important that this instance 
    be :meth:`closed <.close>` when instance and any resulting :obj:`DataType` is no longer in use.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, targetDtm: ghidra.program.model.data.DataTypeManager, retainExistingComposites: typing.Union[jpype.JBoolean, bool]):
        """
        Consruct a :obj:`DataTypeCleaner` instance.  The caller must ensure that this instance
        is :meth:`closed <.close>` when instance and any resulting :obj:`DataType` is no longer in
        use.
        
        :param ghidra.program.model.data.DataTypeManager targetDtm: target datatype manager
        :param jpype.JBoolean or bool retainExistingComposites: if true all composites will be checked against the 
        ``targetDtm`` and retained if it already exists, otherwise all composites will be
        cleaned.
        """

    def clean(self, dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        """
        Clean the specified datatype
        
        :param ghidra.program.model.data.DataType dt: datatype
        :return: clean datatype
        :rtype: ghidra.program.model.data.DataType
        """


class ProgramMergeManager(java.lang.Object):
    """
    ``ProgramMergeManager`` is a class for merging the differences between two
    programs as specified by a ``ProgramMergeFilter`` and the address 
    ranges to be merged.
     
    Program1 is the program being modified by the merge. Program2 is source
    for obtaining differences to apply to program1.
     
    
    ``ProgramDiff`` is being used to determine the differences between
    the two programs.
     
    If name conflicts occur while merging, the item (for example, symbol) will
    be merged with a new name that consists of the original name followed by "_conflict"
    and a one up number.
    
    
    .. seealso::
    
        | :obj:`ghidra.program.util.ProgramMergeFilter`
    
        | :obj:`ghidra.program.util.ProgramDiff`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program1: ghidra.program.model.listing.Program, program2: ghidra.program.model.listing.Program):
        """
        ``ProgramMergeManager`` allows the merging of differences from program1
        or program2 into the merged program.
        
        :param ghidra.program.model.listing.Program program1: the first program (read only) for the merge.
        :param ghidra.program.model.listing.Program program2: the second program (read only) for the merge.
        :raises ProgramConflictException: if the memory blocks, that overlap
        between the two programs, do not match. This indicates that programs
        couldn't be compared to determine the differences.
        """

    @typing.overload
    def __init__(self, program1: ghidra.program.model.listing.Program, program2: ghidra.program.model.listing.Program, p1LimitedAddressSet: ghidra.program.model.address.AddressSetView):
        """
        ``ProgramMergeManager`` allows the merging of differences from program1
        or program2 into the merged program.
        
        :param ghidra.program.model.listing.Program program1: the first program for the merge. This program will get 
        modified by merge.
        :param ghidra.program.model.listing.Program program2: the second program (read only) for the merge.
        :param ghidra.program.model.address.AddressSetView p1LimitedAddressSet: the limited address set. program differences
        can only be merged if they overlap this address set. null means find
        differences in each of the entire programs.
        The addresses in this set should be derived from program1.
        :raises ProgramConflictException: if the memory blocks, that overlap
        between the two programs, do not match. This indicates that programs
        couldn't be compared to determine the differences.
        """

    def getAddressesInCommon(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the addresses in common between program1 and program2
        
        :return: the addresses in common between program1 and program2.
        The addresses in this address set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getAddressesOnlyInOne(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the addresses that are in program1, but not in program2
        
        :return: the addresses that are in program1, but not in program2.
        The addresses in this address set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getAddressesOnlyInTwo(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the addresses that are in program2, but not in program1
        
        :return: the addresses that are in program2, but not in program1.
        The addresses in this address set are derived from program2.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getCombinedAddresses(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the addresses from combining the address sets in program1 and program2
        
        :return: the addresses for both program1 and program2.
        The addresses in this address set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getDiffFilter(self) -> ProgramDiffFilter:
        """
        Get a copy of the diff filter that the merge is using.
        """

    def getErrorMessage(self) -> str:
        """
        Get the error messages that resulted from doing the merge.
        
        :return: String empty string if there were no problems with the merge.
        :rtype: str
        """

    def getFilteredDifferences(self, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        """
        Gets the filtered program differences for this merge. Only differences are
        indicated for merge filter categories that are enabled and for address
        that have not been marked as ignored.
        
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for indicating the progress of
        determining differences. This monitor also allows the user to cancel if
        the diff takes too long. If no monitor is desired, use null.
        :return: the program differences.
        The addresses in this address set are derived from program2.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getIgnoreAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the address set indicating the addresses to be ignored (not checked) when determining
        differences between the two programs.
        
        :return: the set of addresses to ignore.
        The addresses in this address set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getInfoMessage(self) -> str:
        """
        Get the informational messages that resulted from doing the merge.
        
        :return: String empty string if there were no information messages
        generated during the merge.
        :rtype: str
        """

    def getLimitedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the address set that the process of determining differences is limited to. 
        In other words, only addresses in this set will be checked by the Diff.
        
        :return: the address set
        The addresses in this address set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getMergeFilter(self) -> ProgramMergeFilter:
        """
        Get a copy of the filter that indicates which parts of the Program 
        should be merged.
        """

    def getProgramOne(self) -> ghidra.program.model.listing.Program:
        """
        Gets the first program being compared by the ProgramDiff.
        
        :return: program1. This is the program being modified by the merge.
        The addresses in this address set are derived from program1.
        :rtype: ghidra.program.model.listing.Program
        """

    def getProgramTwo(self) -> ghidra.program.model.listing.Program:
        """
        Gets the second program being compared by the ProgramDiff.
        
        :return: program2. This is the program for obtaining the program information to merge.
        :rtype: ghidra.program.model.listing.Program
        """

    def getRestrictedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Return the address set that is currently being used to restrict the
        differences that get returned.
        
        :return: the address set being used to restrict the Diff results.
        The addresses in this set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getWarnings(self) -> str:
        """
        Gets a string indicating warnings that occurred during the initial Diff 
        of the two programs.
        
        :return: the warnings
        :rtype: str
        """

    def ignore(self, p1AddressSet: ghidra.program.model.address.AddressSetView):
        """
        Ignore the differences for the indicated address set.
        
        :param ghidra.program.model.address.AddressSetView p1AddressSet: the address set to be merged. 
        The addresses in this set should be derived from program1.
        """

    def memoryMatches(self) -> bool:
        """
        Determine whether memory between the two programs matches.
        For example, if one program has more memory than the other then it 
        doesn't match or if the address ranges for memory are different for 
        the two programs then they don't match.
        
        :return: whether the memory matches between the two programs.
        :rtype: bool
        """

    @typing.overload
    def merge(self, p2Address: ghidra.program.model.address.Address, filter: ProgramMergeFilter) -> bool:
        """
        Merge the differences from the indicated program at the specified
        address with the indicated filtering.
        
        :param ghidra.program.model.address.Address p2Address: the address to be merged. 
        This address should be derived from program2.
        :param ProgramMergeFilter filter: the filter indicating what types of differences to merge.
        :return: true if merge succeeds
        :rtype: bool
        :raises MemoryAccessException: if bytes can't be copied.
        :raises CancelledException: if user cancels via the monitor.
        """

    @typing.overload
    def merge(self, p2Address: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Merge the differences from the indicated program at the specified
        address with the current filtering.
        
        :param ghidra.program.model.address.Address p2Address: the address to be merged. 
        This address should be derived from program2.
        :param ghidra.util.task.TaskMonitor monitor: monitor for reporting merge status to the user.
        :return: true if merge succeeds
        :rtype: bool
        :raises MemoryAccessException: if bytes can't be copied.
        :raises CancelledException: if user cancels via the monitor.
        """

    @typing.overload
    def merge(self, p2Address: ghidra.program.model.address.Address, filter: ProgramMergeFilter, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Merge the differences from the indicated program at the specified
        address with the indicated filtering.
        
        :param ghidra.program.model.address.Address p2Address: the address to be merged. 
        This address should be derived from program2.
        :param ProgramMergeFilter filter: the filter indicating what types of differences to merge.
        :param ghidra.util.task.TaskMonitor monitor: monitor for reporting merge status to the user.
        :return: true if merge succeeds
        :rtype: bool
        :raises MemoryAccessException: if bytes can't be copied.
        :raises CancelledException: if user cancels via the monitor.
        """

    @typing.overload
    def merge(self, p1MergeSet: ghidra.program.model.address.AddressSetView, filter: ProgramMergeFilter) -> bool:
        """
        Merge the differences from the indicated program on the specified
        address set with the indicated filtering.
        
        :param ghidra.program.model.address.AddressSetView p1MergeSet: the address set to be merged. 
        The addresses in this set should be derived from program1.
        :param ProgramMergeFilter filter: the filter indicating what types of differences to merge.
        :return: true if merge succeeds
        :rtype: bool
        :raises MemoryAccessException: if bytes can't be copied.
        :raises CancelledException: if user cancels via the monitor.
        """

    @typing.overload
    def merge(self, p1MergeSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Merge the differences from the indicated program on the specified
        address set with the filtering that is currently set.
        
        :param ghidra.program.model.address.AddressSetView p1MergeSet: the address set to be merged
        The addresses in this set should be derived from program1.
        :param ghidra.util.task.TaskMonitor monitor: task monitor for reporting merge status to the user.
        :return: true if merge succeeds
        :rtype: bool
        :raises MemoryAccessException: if bytes can't be copied.
        :raises CancelledException: if user cancels via the monitor.
        """

    @typing.overload
    def merge(self, p1MergeSet: ghidra.program.model.address.AddressSetView, filter: ProgramMergeFilter, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Merge the differences from the indicated program on the specified
        address set with the indicated filtering.
        
        :param ghidra.program.model.address.AddressSetView p1MergeSet: the address set to be merged
        The addresses in this set should be derived from program1.
        :param ProgramMergeFilter filter: the filter indicating what types of differences to merge.
        :param ghidra.util.task.TaskMonitor monitor: task monitor for reporting merge status to the user.
        :return: true if merge succeeds
        :rtype: bool
        :raises MemoryAccessException: if bytes can't be copied.
        :raises CancelledException: if user cancels via the monitor.
        """

    def removeResultRestrictions(self):
        """
        Remove the restriction for the resulting differences to the indicated address set.
        """

    def restrictResults(self, p1AddressSet: ghidra.program.model.address.AddressSetView):
        """
        Restrict the resulting differences to the indicated address set.
        Although the Diff will check for differences based on the limited set, the resulting
        differences from calls to getDifferences() will only return addresses contained in
        this restricted address set.
        
        :param ghidra.program.model.address.AddressSetView p1AddressSet: the address set to restrict the getFilteredDifferences() to.
        The addresses in this set are derived from program1.
        """

    def setDiffFilter(self, filter: ProgramDiffFilter):
        """
        Set the filter that indicates which parts of the Program should be 
        diffed.
        
        :param ProgramDiffFilter filter: the filter indicating the types of differences to be 
        determined by this ProgramMerge.
        """

    def setMergeFilter(self, filter: ProgramMergeFilter):
        """
        Set the filter that indicates which parts of the Program should be 
        applied from the second program to the first program.
        
        :param ProgramMergeFilter filter: the filter indicating the types of differences to apply.
        """

    @property
    def limitedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def restrictedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def warnings(self) -> java.lang.String:
        ...

    @property
    def errorMessage(self) -> java.lang.String:
        ...

    @property
    def ignoreAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def combinedAddresses(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def programOne(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def addressesOnlyInOne(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def programTwo(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def addressesInCommon(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def filteredDifferences(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def mergeFilter(self) -> ProgramMergeFilter:
        ...

    @mergeFilter.setter
    def mergeFilter(self, value: ProgramMergeFilter):
        ...

    @property
    def infoMessage(self) -> java.lang.String:
        ...

    @property
    def diffFilter(self) -> ProgramDiffFilter:
        ...

    @diffFilter.setter
    def diffFilter(self, value: ProgramDiffFilter):
        ...

    @property
    def addressesOnlyInTwo(self) -> ghidra.program.model.address.AddressSetView:
        ...


class DefaultAddressTranslator(AddressTranslator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, destinationProgram: ghidra.program.model.listing.Program, sourceProgram: ghidra.program.model.listing.Program):
        ...


class ProgramDiffDetails(java.lang.Object):
    """
    ProgramDiffDetails is used to determine the detailed differences between
    two programs at a particular address. The differences are determined for
    the extent of the code units from each program at a particular address.
    """

    @typing.type_check_only
    class VariableLayout(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, p1: ghidra.program.model.listing.Program, p2: ghidra.program.model.listing.Program):
        """
        Constructor for ProgramDiffDetails.
        
        :param ghidra.program.model.listing.Program p1: the original program
        :param ghidra.program.model.listing.Program p2: the program to diff against.
        """

    def getAllDetails(self, p1DiffAddress: ghidra.program.model.address.Address, doc: javax.swing.text.StyledDocument, prefixString: typing.Union[java.lang.String, str]):
        """
        Determine the detailed differences between the two programs at the
        indicated address. The differences are determined for the extent of the
        code units in the two programs at the indicated address.
        
        :param ghidra.program.model.address.Address p1DiffAddress: the address that difference details are needed for.
        This address should be derived from program1.
        :param javax.swing.text.StyledDocument doc: the document where the details of differences between the two
        programs should be written.
        :param java.lang.String or str prefixString: Line of text to display at beginning of the difference details information.
        """

    def getDetails(self, p1DiffAddress: ghidra.program.model.address.Address, filter: ProgramDiffFilter, doc: javax.swing.text.StyledDocument, prefixString: typing.Union[java.lang.String, str]):
        """
        Determine the detailed differences between the two programs at the
        indicated address. The differences are determined for the extent of the
        code units in the two programs at the indicated address.
        
        :param ghidra.program.model.address.Address p1DiffAddress: the address that difference details are needed for.
        This address should be derived from program1.
        :param ProgramDiffFilter filter: the program diff filter that indicates the diff details to show.
        :param javax.swing.text.StyledDocument doc: the document where the details of differences between the two
        programs should be written.
        :param java.lang.String or str prefixString: Line of text to display at beginning of the difference details information.
        """

    def getDetailsAddressSet(self, p1Address: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressSetView:
        """
        Gets the address set where detailed differences will be determined for details at the
        indicated address. An address set is returned since the indicated address may be in different
        sized code units in each of the two programs.
        
        :param ghidra.program.model.address.Address p1Address: the current address where details are desired.
        This address may be from program1 or program2.
        :return: the program1 address set for code units containing that address within the programs being diffed.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @staticmethod
    @typing.overload
    def getDiffDetails(p1: ghidra.program.model.listing.Program, p2: ghidra.program.model.listing.Program, p1DiffAddress: ghidra.program.model.address.Address) -> str:
        """
        Gets a string indicating the types of differences for the code units at the indicated
        address. The string contains information from each program where there are differences.
        It containing multiple lines separated by newline characters)
        
        :param ghidra.program.model.listing.Program p1: the original program
        :param ghidra.program.model.listing.Program p2: the program to diff against.
        :param ghidra.program.model.address.Address p1DiffAddress: the address that difference details are needed for.
        This address should be derived from program1.
        :return: a string indicating the differences.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getDiffDetails(p1: ghidra.program.model.listing.Program, p2: ghidra.program.model.listing.Program, p1DiffAddress: ghidra.program.model.address.Address, filter: ProgramDiffFilter) -> str:
        """
        Gets a string indicating the types of differences for the code units at the indicated
        address. The string contains information from each program where there are differences.
        It containing multiple lines separated by newline characters)
        
        :param ghidra.program.model.listing.Program p1: the original program
        :param ghidra.program.model.listing.Program p2: the program to diff against.
        :param ghidra.program.model.address.Address p1DiffAddress: the address that difference details are needed for.
        This address should be derived from program1.
        :param ProgramDiffFilter filter: the program diff filter that indicates the diff details to show.
        :return: a string indicating the differences.
        :rtype: str
        """

    @typing.overload
    def getDiffDetails(self, p1DiffAddress: ghidra.program.model.address.Address) -> str:
        """
        Gets a string indicating the types of differences for the code units at the indicated
        address. The string contains information from each program where there are differences.
        It containing multiple lines separated by newline characters)
        
        :param ghidra.program.model.address.Address p1DiffAddress: the address that difference details are needed for.
        This address should be derived from program1.
        :return: a string indicating the differences.
        :rtype: str
        """

    @typing.overload
    def getDiffDetails(self, p1DiffAddress: ghidra.program.model.address.Address, filter: ProgramDiffFilter) -> str:
        """
        Gets a string indicating the types of differences for the code units at the indicated
        address. The string contains information from each program where there are differences.
        It containing multiple lines separated by newline characters)
        
        :param ghidra.program.model.address.Address p1DiffAddress: the address that difference details are needed for.
        This address should be derived from program1.
        :param ProgramDiffFilter filter: the program diff filter that indicates the diff details to show.
        :return: a string indicating the differences.
        :rtype: str
        """

    @property
    def detailsAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def diffDetails(self) -> java.lang.String:
        ...


class ListingDiff(java.lang.Object):
    """
    Determines where instructions couldn't be matched and where they differ between sets of 
    addresses as provided by a ListingAddressCorrelation. Initially this will be byte 
    differences and instruction operand differences for any instructions that were determined 
    to be matched.
     
    Important: This class is not intended to be used for an entire program. Instead it is 
    for comparing smaller portions such as functions. If the correlation handed to this class 
    associates two large address sets, then the address sets, such as byte differences, that are 
    created by this class could potentially consume large amounts of memory.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a ListingDiff to determine where instructions couldn't be matched and where they 
        differ between sets of addresses as provided by a ListingAddressCorrelation.
        """

    def addListingDiffChangeListener(self, listener: ghidra.features.base.codecompare.listing.ListingDiffChangeListener):
        """
        Adds the indicated listener to those that get notified when the ListingDiff's set of 
        differences and unmatched addresses changes.
        
        :param ghidra.features.base.codecompare.listing.ListingDiffChangeListener listener: the listener to be notified
        """

    def doesEntireOperandSetDiffer(self, codeUnit1: ghidra.program.model.listing.CodeUnit, codeUnit2: ghidra.program.model.listing.CodeUnit) -> bool:
        """
        Determines if the entire set of operands should indicate that it differs.
        If the code units aren't the same type then the entire set of operands is considered different.
        Also if the number of operands differs then as far as we're concerned the entire set differs.
        
        :param ghidra.program.model.listing.CodeUnit codeUnit1: the first code unit
        :param ghidra.program.model.listing.CodeUnit codeUnit2: the second code unit
        :return: true if we should indicate that all operands differ.
        :rtype: bool
        """

    def getByteDiffs(self, side: ghidra.util.datastruct.Duo.Side) -> ghidra.program.model.address.AddressSetView:
        """
        Gets the addresses in the first listing where byte differences were found based on the 
        current difference settings.
        
        :param ghidra.util.datastruct.Duo.Side side: the side (LEFT or RIGHT) to get the byte diffs for
        :return: the addresses with byte differences in the first listing.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getCodeUnitDiffs(self, side: ghidra.util.datastruct.Duo.Side) -> ghidra.program.model.address.AddressSetView:
        """
        Gets the addresses in the first listing where code unit (mnemonic and/or operand) differences 
        were found based on the current difference settings.
        
        :param ghidra.util.datastruct.Duo.Side side: the side (LEFT or RIGHT) to get the code unit diffs for
        :return: the addresses with code unit differences in the first listing.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getDiffs(self, side: ghidra.util.datastruct.Duo.Side) -> ghidra.program.model.address.AddressSetView:
        """
        Gets the addresses in the first listing where differences were found based on the current 
        difference settings.
        
        :param ghidra.util.datastruct.Duo.Side side: the side (LEFT or RIGHT) to get the listing diffs for
        :return: the addresses with differences in the first listing.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getMatchingAddress(self, address: ghidra.program.model.address.Address, isListing1: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.Address:
        """
        Gets the matching address from the other listing for the specified address from one
        of the two listings whose differences this class determines.
        
        :param ghidra.program.model.address.Address address: the address whose matching address this determines.
        :param jpype.JBoolean or bool isListing1: true indicates the address is from the first listing. false indicates
        it is from the second listing.
        :return: the matching address or null
        :rtype: ghidra.program.model.address.Address
        """

    def getMatchingCodeUnit(self, codeUnit: ghidra.program.model.listing.CodeUnit, side: ghidra.util.datastruct.Duo.Side) -> ghidra.program.model.listing.CodeUnit:
        """
        Gets the matching code unit from the other side listing given a code unit from a given side
        of the two listings whose differences this class determines.
        
        :param ghidra.program.model.listing.CodeUnit codeUnit: the code unit whose match this determines.
        :param ghidra.util.datastruct.Duo.Side side: the side the code unit came from
        :return: the matching code unit or null
        :rtype: ghidra.program.model.listing.CodeUnit
        """

    def getOperandsThatDiffer(self, codeUnit1: ghidra.program.model.listing.CodeUnit, codeUnit2: ghidra.program.model.listing.CodeUnit) -> jpype.JArray[jpype.JInt]:
        """
        Gets an array containing the operand indices where the two indicated code units differ.
        These differences are determined based on whether constants and registers are
        being ignored.
        
        :param ghidra.program.model.listing.CodeUnit codeUnit1: the first code unit
        :param ghidra.program.model.listing.CodeUnit codeUnit2: the second code unit
        :return: an array of operand indices where the operands differ between the two code units 
        based on the current settings that indicate what differences can be ignored.
        :rtype: jpype.JArray[jpype.JInt]
        """

    def getUnmatchedCode(self, side: ghidra.util.datastruct.Duo.Side) -> ghidra.program.model.address.AddressSetView:
        """
        Gets the address set for unmatched code for the given side
        second listing.
        
        :param ghidra.util.datastruct.Duo.Side side: the LEFT or RIGHT side
        :return: the addresses of the unmatched code in the first listing.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def hasCorrelation(self) -> bool:
        """
        Determines if this ListingDiff currently has an address correlation to use.
        
        :return: true if it has an address correlation currently.
        :rtype: bool
        """

    def isIgnoringByteDiffs(self) -> bool:
        """
        Gets the setting indicating if byte differences are currently being ignored.
        
        :return: true if byte differences are being ignored.
        :rtype: bool
        """

    def isIgnoringConstants(self) -> bool:
        """
        Gets the setting indicating if values of operand constants that differ are currently 
        being ignored when determining code unit differences.
        
        :return: true if code unit differences are ignoring differences in values of operand
        constants.
        :rtype: bool
        """

    def isIgnoringRegisters(self) -> bool:
        """
        Gets the setting indicating if operand registers that differ other than in size
        are currently being ignored when determining code unit differences.
        
        :return: true if code unit differences are ignoring operand register differences other 
        than in size.
        :rtype: bool
        """

    def printFunctionComparisonDiffs(self):
        """
        Outputs an information message, primarily for debugging, that indicates where code was 
        unmatched with the other listing and where various differences, such as bytes and 
        code units, were found.
        """

    def removeListingDiffChangeListener(self, listener: ghidra.features.base.codecompare.listing.ListingDiffChangeListener):
        """
        Removes the indicated listener from those that get notified when the ListingDiff's set of 
        differences and unmatched addresses changes.
        
        :param ghidra.features.base.codecompare.listing.ListingDiffChangeListener listener: the listener to be removed
        """

    def setCorrelation(self, correlation: ListingAddressCorrelation):
        """
        Sets the address correlation that is used to determine matching addresses between the two 
        listings. Differences can then be determined where a matching address is found.
         
        Important: This class is not intended to be used for an entire program. Instead it is 
        for comparing smaller portions such as functions. If the correlation handed to this class 
        associates two large address sets, then the address sets, such as byte differences, that are 
        created by this class could potentially consume large amounts of memory.
        
        :param ListingAddressCorrelation correlation: the address correlation. Otherwise, null to clear the correlation.
        :raises MemoryAccessException: if memory can't be read.
        """

    def setIgnoreByteDiffs(self, ignore: typing.Union[jpype.JBoolean, bool]):
        """
        Changes the setting indicating whether or not byte differences should be ignored.
        
        :param jpype.JBoolean or bool ignore: true indicates to ignore byte differences
        """

    def setIgnoreConstants(self, ignore: typing.Union[jpype.JBoolean, bool]):
        """
        Changes the setting indicating if values of operand constants that differ should be 
        ignored when determining code unit differences.
        
        :param jpype.JBoolean or bool ignore: true means code unit differences should ignore differences in values of 
        operand constants.
        """

    def setIgnoreRegisters(self, ignore: typing.Union[jpype.JBoolean, bool]):
        """
        Changes the setting indicating if operand registers that differ other than in size 
        should be ignored when determining code unit differences.
        
        :param jpype.JBoolean or bool ignore: true means code unit differences should ignore operand register differences
        other than in size.
        """

    @property
    def ignoringRegisters(self) -> jpype.JBoolean:
        ...

    @property
    def ignoringByteDiffs(self) -> jpype.JBoolean:
        ...

    @property
    def codeUnitDiffs(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def byteDiffs(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def ignoringConstants(self) -> jpype.JBoolean:
        ...

    @property
    def unmatchedCode(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def diffs(self) -> ghidra.program.model.address.AddressSetView:
        ...


@typing.type_check_only
class OffsetAddressFactory(ghidra.program.model.address.DefaultAddressFactory):

    class_: typing.ClassVar[java.lang.Class]

    def createNewOffsetSpace(self, name: typing.Union[java.lang.String, str], bitSize: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.AddressSpace:
        """
        Create a new address space
        
        :param java.lang.String or str name: of address space
        :return: new address space, or null if no spaces left to allocate
        :rtype: ghidra.program.model.address.AddressSpace
        """

    @staticmethod
    def isSymbolSpace(spaceID: typing.Union[jpype.JInt, int]) -> bool:
        ...


class FunctionMerge(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, originToResultTranslator: AddressTranslator):
        ...

    @typing.overload
    def replaceFunctionsNames(self, originAddressSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        ...

    @staticmethod
    @typing.overload
    def replaceFunctionsNames(pgmMerge: ProgramMerge, addressSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        ...


class ProgramConflictException(ghidra.util.exception.UsrException):
    """
    Exception for incompatible programs when comparing programs for differences
    or when merging program differences.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str msg: detailed message
        """


class AddressTranslator(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self, sourceAddress: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Converts the given source address to the returned destination address.
        This interface is intended to translate an address from the source program to an 
        address in the destination program.
        
        :param ghidra.program.model.address.Address sourceAddress: the source address to be converted.
        :return: the destination address that is equivalent in some way to the source address.
        How the address is equivalent depends upon the particular translator.
        throws AddressTranslationException if the address can't be translated to an equivalent
        address in the other program.
        :rtype: ghidra.program.model.address.Address
        """

    def getAddressRange(self, sourceAddressRange: ghidra.program.model.address.AddressRange) -> ghidra.program.model.address.AddressRange:
        """
        Converts the given source address range to the returned destination address range.
        This interface is intended to translate an address range from the source program to an 
        address range in the destination program.
         
        This method should be implemented if isOneForOneTranslator() returns true.
        
        :param ghidra.program.model.address.AddressRange sourceAddressRange: the source address range to be converted.
        :return: the destination address range that is equivalent in some way to the source address range.
        How the address range is equivalent depends upon the particular translator.
        throws AddressTranslationException if the address set can't be translated to an equivalent
        address range in the other program.
        :rtype: ghidra.program.model.address.AddressRange
        """

    def getAddressSet(self, sourceAddressSet: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSet:
        """
        Converts the given source address set to the returned destination address set.
        This interface is intended to translate an address set from the source program to an 
        address set in the destination program.
         
        This method should be implemented if isOneForOneTranslator() returns true.
        
        :param ghidra.program.model.address.AddressSetView sourceAddressSet: the source address set to be converted.
        :return: the destination address set that is equivalent in some way to the source address set.
        How the address set is equivalent depends upon the particular translator.
        throws AddressTranslationException if the address set can't be translated to an equivalent
        address set in the other program.
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getDestinationProgram(self) -> ghidra.program.model.listing.Program:
        """
        Gets the destination program for addresses that have been translated.
        
        :return: program1.
        :rtype: ghidra.program.model.listing.Program
        """

    def getSourceProgram(self) -> ghidra.program.model.listing.Program:
        """
        Gets the source program for obtaining the addresses that need to be translated.
        
        :return: program2.
        :rtype: ghidra.program.model.listing.Program
        """

    def isOneForOneTranslator(self) -> bool:
        """
        This method should return true if it can translate an address set from the source program 
        to an address set for the destination program and there is a one to one correspondence 
        between the two programs addresses. 
        In other words two addresses that make up the start and end of an address range
        would be at the same distance and relative location from each other as the equivalent two 
        individual translated addresses are from each other.
        Otherwise this should return false.
        """

    @property
    def addressSet(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def oneForOneTranslator(self) -> jpype.JBoolean:
        ...

    @property
    def addressRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def sourceProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def destinationProgram(self) -> ghidra.program.model.listing.Program:
        ...


class ExternalSymbolResolver(java.io.Closeable):
    """
    Moves dangling external function symbols found in the :obj:`EXTERNAL/UNKNOWN <Library.UNKNOWN>`
    namespace into the namespace of the external library that publishes a matching symbol.
     
    
    This uses an ordered list of external library names that was attached to the program during
    import by the Elf or Macho loader (see :obj:`.REQUIRED_LIBRARY_PROPERTY_PREFIX`).
    """

    @typing.type_check_only
    class ProgramSymbolResolver(java.lang.Object):
        """
        Represents a program that needs its external symbols to be fixed.
        """

        @typing.type_check_only
        class ExtLibInfo(java.lang.Record):

            class_: typing.ClassVar[java.lang.Class]

            def equals(self, o: java.lang.Object) -> bool:
                ...

            def hashCode(self) -> int:
                ...

            def lib(self) -> ghidra.program.model.listing.Library:
                ...

            def name(self) -> str:
                ...

            def problem(self) -> java.lang.Throwable:
                ...

            def program(self) -> ghidra.program.model.listing.Program:
                ...

            def programPath(self) -> str:
                ...

            def resolvedSymbols(self) -> java.util.List[java.lang.String]:
                ...

            def toString(self) -> str:
                ...


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, projectData: ghidra.framework.model.ProjectData, monitor: ghidra.util.task.TaskMonitor):
        ...

    @typing.overload
    def addProgramToFixup(self, program: ghidra.program.model.listing.Program):
        """
        Queues a program into this session that will be fixed when :meth:`fixUnresolvedExternalSymbols() <.fixUnresolvedExternalSymbols>`
        is called.
         
        
        The program should be fully persisted to the project if using this method, otherwise use
        :meth:`addProgramToFixup(Loaded) <.addProgramToFixup>`.
        
        :param ghidra.program.model.listing.Program program: :obj:`Program` to fix
        """

    @typing.overload
    def addProgramToFixup(self, loaded: ghidra.app.util.opinion.Loaded[ghidra.program.model.listing.Program]):
        """
        Queues a :obj:`Loaded` :obj:`Program` into this session that will be fixed when 
        :meth:`fixUnresolvedExternalSymbols() <.fixUnresolvedExternalSymbols>` is called.
        
        :param ghidra.app.util.opinion.Loaded[ghidra.program.model.listing.Program] loaded: The :obj:`Loaded` :obj:`Program` to fix
        """

    def fixUnresolvedExternalSymbols(self):
        """
        Resolves any unresolved external symbols in each program that has been queued up via
        :meth:`addProgramToFixup(Loaded) <.addProgramToFixup>` or :meth:`addProgramToFixup(Program) <.addProgramToFixup>`.
        
        :raises CancelledException: if cancelled
        """

    @staticmethod
    def getOrderedRequiredLibraryNames(program: ghidra.program.model.listing.Program) -> java.util.List[java.lang.String]:
        """
        Returns an ordered list of library names, as specified by the logic/rules of the original
        operating system's loader (eg. Elf / MachO dynamic library loading / symbol resolving
        rules)
        
        :param ghidra.program.model.listing.Program program: The :obj:`Program`
        :return: list of library names, in original order
        :rtype: java.util.List[java.lang.String]
        """

    @staticmethod
    def getRequiredLibraryProperty(libraryIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        Gets a program property name to represent the ordered required library of the given index
        
        :param jpype.JInt or int libraryIndex: The index of the required library
        :return: A program property name to represent the ordered required library of the given index
        :rtype: str
        """

    def hasProblemLibraries(self) -> bool:
        """
        Returns true if there was an error encountered when trying to open an external library.
        
        :return: boolean flag, true if there was a problem opening an external library
        :rtype: bool
        """

    def logInfo(self, logger: java.util.function.Consumer[java.lang.String], shortSummary: typing.Union[jpype.JBoolean, bool]):
        """
        Logs information about the libraries and symbols that were found during the fixup.
        
        :param java.util.function.Consumer[java.lang.String] logger: consumer that will log a string
        :param jpype.JBoolean or bool shortSummary: boolean flag, if true individual symbol names will be omitted
        """


class MarkerLocation(java.io.Serializable):
    """
    Marker location in the tool navigation bars
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, markers: ghidra.app.services.MarkerSet, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        """
        Construct a new MarkerLocation.
        
        :param ghidra.app.services.MarkerSet markers: marker manager service
        :param ghidra.program.model.listing.Program program: program containing the address
        :param ghidra.program.model.address.Address addr: address of the location
        :param jpype.JInt or int x: x position of the popup point on the screen
        :param jpype.JInt or int y: y position of the popup point on the screen
        """

    def getAddr(self) -> ghidra.program.model.address.Address:
        """
        Returns the address.
        
        :return: the address for this marker location
        :rtype: ghidra.program.model.address.Address
        """

    def getMarkerManager(self) -> ghidra.app.services.MarkerSet:
        """
        Returns the Marker Manager.
        
        :return: the marker manager
        :rtype: ghidra.app.services.MarkerSet
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the program.
        
        :return: the program for this marker location
        :rtype: ghidra.program.model.listing.Program
        """

    def getX(self) -> int:
        """
        Returns the X screen location of the popup point.
        
        :return: the X coordinate for the screen location.
        :rtype: int
        """

    def getY(self) -> int:
        """
        Returns the Y screen location of the popup point.
        
        :return: the Y coordinate for the screen location.
        :rtype: int
        """

    @property
    def x(self) -> jpype.JInt:
        ...

    @property
    def y(self) -> jpype.JInt:
        ...

    @property
    def markerManager(self) -> ghidra.app.services.MarkerSet:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def addr(self) -> ghidra.program.model.address.Address:
        ...


class ProgramDiff(java.lang.Object):
    """
    ``ProgramDiff`` is a class for comparing two programs and
    determining where there are differences between them.
     
    
    Currently, the differences can be determined if the two programs have
    equivalent address spaces. If the programs have different program context
    registers, the Diff can still occur but will not determine program context
    differences.
    
    
    .. seealso::
    
        | :obj:`ghidra.program.util.ProgramDiffFilter`
    """

    @typing.type_check_only
    class ProgramDiffComparator(java.lang.Object, typing.Generic[T]):
        """
        Interface providing a means for comparing programs to determine their differences.
        """

        class_: typing.ClassVar[java.lang.Class]

        def compare(self, obj1: T, obj2: T) -> int:
            """
            Compares two like objects to determine whether the first is effectively
            less than (comes before it in memory), equal to (at the same spot
            in memory), or greater than (comes after it in memory) the second.
            
            :param T obj1: the first object
            :param T obj2: the second object
            :return: -1 if the first comes before the second in memory.
                    0 if the objects are at the same spot in memory.
                    1 if the first comes after the second in memory.
            :rtype: int
            """

        def getAddressSet(self, obj: T, program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.AddressSet:
            """
            Returns the addresses that are to indicate the difference of this
            comparison type for this object.
            
            :param T obj: the object being examined by this comparator.
            :param ghidra.program.model.listing.Program program: the program the object is associated with.
            :return: the addresses that we want to indicate for a difference
            of this comparison type.
            The addresses in this address set are derived from the specified program.
            :rtype: ghidra.program.model.address.AddressSet
            """

        def getProgramOne(self) -> ghidra.program.model.listing.Program:
            """
            Returns the first program for this diff.
            
            :return: the first program.
            :rtype: ghidra.program.model.listing.Program
            """

        def getProgramTwo(self) -> ghidra.program.model.listing.Program:
            """
            Returns the second program for this diff.
            
            :return: the second program.
            :rtype: ghidra.program.model.listing.Program
            """

        def isSame(self, obj1: T, obj2: T) -> bool:
            """
            Returns whether the objects are the same with respect to the
            program difference type this comparator is interested in.
            
            :param T obj1: the first object
            :param T obj2: the second object
            :return: true if the objects are the same with respect to the type
            this comparator is interested in.
            :rtype: bool
            """

        @property
        def programOne(self) -> ghidra.program.model.listing.Program:
            ...

        @property
        def programTwo(self) -> ghidra.program.model.listing.Program:
            ...


    @typing.type_check_only
    class ProgramDiffComparatorImpl(ProgramDiff.ProgramDiffComparator[T], typing.Generic[T]):
        """
        Provides a means for comparing programs to determine their differences.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SymbolComparator(ProgramDiff.ProgramDiffComparatorImpl[ghidra.program.model.symbol.Symbol]):
        """
        Used to compare the symbols in two programs.
        Comparator is intended to be invoked with primary symbols only and will compare together with 
        all non-primary symbols.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionTagComparator(ProgramDiff.ProgramDiffComparatorImpl[ghidra.program.model.listing.Function]):
        """
        Compares the function tags in two programs. 
         
        Two sets of tags are considered equal if they contain the name and comment
        attributes.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class EquateComparator(ProgramDiff.ProgramDiffComparatorImpl[ghidra.program.model.address.Address]):
        """
        Used to compare the equates in two programs.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BookmarksComparator(ProgramDiff.ProgramDiffComparatorImpl[ghidra.program.model.address.Address]):
        """
        Used to compare the bookmarks in two programs.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionComparator(ProgramDiff.ProgramDiffComparatorImpl[ghidra.program.model.listing.Function]):
        """
        Used to compare the functions in two programs.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CodeUnitComparator(ProgramDiff.ProgramDiffComparatorImpl[T], typing.Generic[T]):
        """
        Abstract class for comparing two code units to determine if a particular program property
        differs. It provides a default implementation of the ``compare`` method
        which compares the code unit minimum addresses. It also implements the
        ``getAddressSet`` method, which gets the addresses for the specified
        code unit.
        Any class that extends this one must implement the ``isSame`` method.
        isSame should compare the desired property of the two code units to determine
        if it is equal in each.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CommentTypeComparator(ProgramDiff.ProgramDiffComparatorImpl[ghidra.program.model.address.Address]):
        """
        Used to compare the comments of a particular type in two programs.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ReferenceComparator(ProgramDiff.ProgramDiffComparatorImpl[ghidra.program.model.address.Address]):
        """
        Compares two addresses to determine if their memory references differ.
        References include mnemonic, operand, and value references.
        These can be memory references or external references.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UserDefinedComparator(ProgramDiff.CodeUnitComparator[ghidra.program.model.listing.CodeUnit]):
        """
        Compares two code units to determine if their user defined properties differ.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class InstructionComparator(ProgramDiff.CodeUnitComparator[ghidra.program.model.listing.Instruction]):
        """
        Provides comparisons between two instruction code units.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DefinedDataComparator(ProgramDiff.CodeUnitComparator[ghidra.program.model.listing.Data]):
        """
        Provides comparisons between two defined data code units.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program1: ghidra.program.model.listing.Program, program2: ghidra.program.model.listing.Program):
        """
        ``ProgramDiff`` is used to determine the addresses where
        there are differences between two programs.
        Possible differences are:
        the actual bytes at an address, comments, labels, mnemonics,
        references, equates, properties, functions, program context.
         
        Currently, the differences can be determined only if the address
        spaces match between the programs.
        
        :param ghidra.program.model.listing.Program program1: the first program
        :param ghidra.program.model.listing.Program program2: the second program
        :raises ProgramConflictException: indicates that programs
        couldn't be compared to determine the differences.
         
        For example,
         
        the two programs have different address spaces.
        :raises java.lang.IllegalArgumentException: if one of the programs is null.
        """

    @typing.overload
    def __init__(self, program1: ghidra.program.model.listing.Program, program2: ghidra.program.model.listing.Program, checkAddressSet: ghidra.program.model.address.AddressSetView):
        """
        ``ProgramDiff`` is used to determine the addresses where
        there are differences between two programs.
        Possible differences are:
        the actual bytes at an address, comments, labels, mnemonics,
        references, equates, properties, functions, program context.
         
        Currently, the differences can be determined only if the address
        spaces match between the programs.
        
        :param ghidra.program.model.listing.Program program1: the first program
        :param ghidra.program.model.listing.Program program2: the second program
        :param ghidra.program.model.address.AddressSetView checkAddressSet: the address set to be used to constrain where
        differences are found.
        The addresses in this address set should be derived from program1.
        :raises ProgramConflictException: indicates that programs
        couldn't be compared to determine the differences.
         
        For example,
         
        the two programs have different address spaces.
        between the two programs, do not match.
        :raises java.lang.IllegalArgumentException: if one of the programs is null.
        """

    def checkCancelled(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Checks the task associated with the indicated monitor to determine if it has
        been canceled.
        
        :param ghidra.util.task.TaskMonitor monitor: the task monitor, associated with getting differences from this Diff,
        to be checked
        :raises CancelledException: if the getDifferences() task has been canceled by the user.
        """

    def equalRefArrays(self, refs1: jpype.JArray[ghidra.program.model.symbol.Reference], refs2: jpype.JArray[ghidra.program.model.symbol.Reference]) -> bool:
        """
        Compares an array of references from program1 with an array of references from program2 to see if they are equivalent.
        
        :param jpype.JArray[ghidra.program.model.symbol.Reference] refs1: program1 array of references
        :param jpype.JArray[ghidra.program.model.symbol.Reference] refs2: program2 array of references
        :return: true if the arrays of references are equal.
        :rtype: bool
        """

    def equalRefs(self, ref1: ghidra.program.model.symbol.Reference, ref2: ghidra.program.model.symbol.Reference) -> bool:
        """
        Compares reference from program1 with reference from program2 to see if they are equivalent.
        
        :param ghidra.program.model.symbol.Reference ref1: program1 reference
        :param ghidra.program.model.symbol.Reference ref2: program2 reference
        :return: true if they are equivalent
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def equivalentFunctions(f1: ghidra.program.model.listing.Function, f2: ghidra.program.model.listing.Function) -> bool:
        ...

    @staticmethod
    @typing.overload
    def equivalentFunctions(f1: ghidra.program.model.listing.Function, f2: ghidra.program.model.listing.Function, ignoreName: typing.Union[jpype.JBoolean, bool]) -> bool:
        ...

    def getAddressesInCommon(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns the addresses in common between program1 and program2.
        
        :return: the addresses in common between program1 and program2.
        The addresses in this address set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getAddressesOnlyInOne(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns the addresses that are in program1, but not in program2.
        
        :return: the addresses that are in program1, but not in program2.
        The addresses in this address set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getAddressesOnlyInTwo(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns the addresses that are in program2, but not in program1.
        
        :return: the addresses that are in program2, but not in program1.
        The addresses in this address set are derived from program2.
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getCombinedAddresses(self) -> ghidra.program.model.address.AddressSetView:
        """
        Returns the addresses from combining the address sets in program1 and program2.
        
        :return: the addresses for both program1 and program2.
        The addresses in this address set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @staticmethod
    def getDiffRefs(refs: jpype.JArray[ghidra.program.model.symbol.Reference]) -> jpype.JArray[ghidra.program.model.symbol.Reference]:
        """
        Gets the references that need to be checked for differences from those that are handed
        to it via the refs parameter.
        
        :param jpype.JArray[ghidra.program.model.symbol.Reference] refs: the references before removing those that we don't want to diff.
        :return: only the references that should be part of the diff.
        :rtype: jpype.JArray[ghidra.program.model.symbol.Reference]
        """

    @typing.overload
    def getDifferences(self, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        """
        ``getDifferences`` is used to determine
        the addresses where there are differences between two programs using
        the current filter. This
        method only indicates that there is a difference at the address, not what
        type of difference it is. Possible differences are:
        the actual bytes at an address, comments, labels, code units,
        references, equates, properties, and program context register values.
        
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for indicating the progress of
        determining differences. This monitor also allows the user to cancel if
        the diff takes too long. If no monitor is desired, use null.
        :return: an address set of where differences were found between the two
        programs based on the current filter setting.
        The addresses in this address set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSetView
        :raises CancelledException: if the user cancelled the Diff.
        """

    @typing.overload
    def getDifferences(self, filter: ProgramDiffFilter, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        """
        ``getDifferences`` is used to determine
        the addresses where there are differences between two programs. This
        method only indicates that there is a difference at the address, not what
        type of difference it is. Possible differences are:
        the actual bytes at an address, comments, labels, code units,
        references, equates, properties, tags and program context register values.
         
        The specified filter will become the new current filter.
        
        :param ProgramDiffFilter filter: the filter to use instead of the current filter defined for
        this ProgramDiff.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for indicating the progress of
        determining differences. This monitor also allows the user to cancel if
        the diff takes too long. If no monitor is desired, use null.
        :return: an address set of where differences were found between the two
        programs based on the specified filter setting.
        The addresses in this address set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSetView
        :raises CancelledException: if the user cancelled the Diff.
        """

    def getFilter(self) -> ProgramDiffFilter:
        """
        Returns a new ProgramDiffFilter equal to the one in this program diff.
        The filter indicates which types of differences are to be determined.
        
        :return: a copy of the program diff filter currently in use.
        :rtype: ProgramDiffFilter
        """

    def getIgnoreAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the address set that contains addresses that should not be indicated as
        having any differences.
        The addresses in this address set are derived from program1.
        
        :return: ignored addresses
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getInitializedInCommon(self) -> ghidra.program.model.address.AddressSet:
        """
        Returns the initialized memory addresses in common between
        program1 and program2.
        
        :return: the initialized memory addresses in common between
        program1 and program2.
        The addresses in this set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getLimitedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the address set that the diff process is limited to when checking for differences.
        Returns null if the diff is not limited (i.e. the entire program is being diffed).
        The addresses in the returned address set are derived from program1.
        
        :return: limited address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getProgramOne(self) -> ghidra.program.model.listing.Program:
        """
        Gets the first program being compared by the ProgramDiff.
        
        :return: program1.
        :rtype: ghidra.program.model.listing.Program
        """

    def getProgramTwo(self) -> ghidra.program.model.listing.Program:
        """
        Gets the second program being compared by the ProgramDiff.
        
        :return: program2.
        :rtype: ghidra.program.model.listing.Program
        """

    def getRestrictedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        """
        Get the address set that the getDifferences method results are restricted to.
        null indicates no current restrictions.
        The addresses in the returned address set are derived from program1.
        
        :return: restricted address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getTypeDiffs(self, diffType: typing.Union[jpype.JInt, int], addrs: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        """
        Creates an address set indicating the differences between program1 and
        program2 of the specified type.
        
        :param jpype.JInt or int diffType: the type of difference to look for between the programs.
        :param ghidra.program.model.address.AddressSetView addrs: the addresses to check for differences.
        The addresses in this address set should be derived from program1.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for indicating the progress of
        determining differences. This monitor reports the progress to the user.
        :return: the address set indicating the differences.
        The addresses in this address set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSetView
        :raises ProgramConflictException: context register definition differs between programs
        :raises CancelledException: if the user cancelled the Diff.
        """

    def getUserDefinedDiffs(self, property: typing.Union[java.lang.String, str], addrs: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSetView:
        """
        Returns an address set indicating where the user defined property differs
        between the Diff's two programs within the specified address set.
        
        :param java.lang.String or str property: the user defined property
        :param ghidra.program.model.address.AddressSetView addrs: the address set for limiting checking.
        The addresses in this address set should be derived from program1.
        :param ghidra.util.task.TaskMonitor monitor: the progress monitor.
        :return: the address set indicating where the property differs.
        The addresses in this address set are derived from program1.
        :rtype: ghidra.program.model.address.AddressSetView
        :raises CancelledException: if the user cancelled the Diff.
        """

    def getWarnings(self) -> str:
        """
        Get a message indicating any warnings about this PRogramDiff. For example,
        if the program context registers don't match between the programs, the
        string is a message indicating this.
        
        :return: the warning message string. null if no warnings.
        :rtype: str
        """

    def ignore(self, addrs: ghidra.program.model.address.AddressSetView):
        """
        Set the indicated additional addresses that should not report any
        differences that are found at them.
        
        :param ghidra.program.model.address.AddressSetView addrs: the set of addresses to add to the current ignore set.
        The addresses in this address set should be derived from program1.
        """

    def isCancelled(self) -> bool:
        """
        Returns whether the last ``getDifferences`` call was cancelled.
        If a TaskMonitor displays a progress dialog to the user, then the cancel
        button could have been pressed.
        
        :return: true if the last ``getDifferences`` call was cancelled.
        :rtype: bool
        """

    @staticmethod
    def isEquivalentThunk(thunkFunction1: ghidra.program.model.listing.Function, thunkFunction2: ghidra.program.model.listing.Function) -> bool:
        """
        Compares two thunk functions from different programs to determine if they are 
        equivalent to each other (effectively the same thunk function in the other program).
        
        :param ghidra.program.model.listing.Function thunkFunction1: the first thunk function
        :param ghidra.program.model.listing.Function thunkFunction2: the second thunk function
        :return: true if the functions are equivalent thunk functions.
        :rtype: bool
        """

    def isSameOperandEquates(self, address: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Determines if the two programs have the same equates specified at
        the indicated address and operand
        
        :param ghidra.program.model.address.Address address: the address
        This address should be derived from program1.
        :param jpype.JInt or int opIndex: the operand index
        :return: true if both programs have the same operands.
        :rtype: bool
        """

    def memoryMatches(self) -> bool:
        """
        Return true if the programs to compare have matching memory maps.
        
        :return: true if program1 and program2 memory address set matches
        :rtype: bool
        """

    def printDifferences(self):
        """
        Print the differences that have been found so far by calls to
        ``getDifferences``.
        """

    def printKnownDifferences(self, type: typing.Union[jpype.JInt, int]):
        """
        Print the differences matching the types indicated that were found thus
        far by all calls to ``getDifferences``.
        
        :param jpype.JInt or int type: the type(s) of differences we want to see.
        Valid types are: BYTE_DIFFS, CODE_UNIT_DIFFS,
        COMMENT_DIFFS, REFERENCE_DIFFS, USER_DEFINED_DIFFS,
        SYMBOL_DIFFS, EQUATE_DIFFS, PROGRAM_CONTEXT_DIFFS.
        """

    def printKnownDifferencesByType(self, type: typing.Union[jpype.JInt, int]):
        """
        Print the differences matching the types indicated that were found thus
        far by all calls to getDifferences. The differences are grouped by
        each of the primary difference types.
        
        :param jpype.JInt or int type: the type(s) of differences we want to see.
        Valid types are: BYTE_DIFFS, CODE_UNIT_DIFFS,
        COMMENT_DIFFS, REFERENCE_DIFFS, USER_DEFINED_DIFFS,
        SYMBOL_DIFFS, EQUATE_DIFFS, PROGRAM_CONTEXT_DIFFS.
        """

    @staticmethod
    def sameFunctionNames(f1: ghidra.program.model.listing.Function, f2: ghidra.program.model.listing.Function) -> bool:
        ...

    def setFilter(self, filter: ProgramDiffFilter):
        """
        Sets the ProgramDiffFilter for this program diff. The filter indicates
        which types of differences are to be determined.
        
        :param ProgramDiffFilter filter: the program diff filter
        """

    @property
    def limitedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def restrictedAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def warnings(self) -> java.lang.String:
        ...

    @property
    def differences(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def ignoreAddressSet(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def combinedAddresses(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def filter(self) -> ProgramDiffFilter:
        ...

    @filter.setter
    def filter(self, value: ProgramDiffFilter):
        ...

    @property
    def programOne(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def addressesOnlyInOne(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def cancelled(self) -> jpype.JBoolean:
        ...

    @property
    def programTwo(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def addressesInCommon(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def initializedInCommon(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def addressesOnlyInTwo(self) -> ghidra.program.model.address.AddressSet:
        ...


class AddressRangeIteratorConverter(ghidra.program.model.address.AddressRangeIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, iterator: ghidra.program.model.address.AddressRangeIterator, program: ghidra.program.model.listing.Program):
        ...


class ContextEvaluator(java.lang.Object):
    """
    ContextEvaluator provides a callback mechanism for the SymbolicPropogator as code is evaluated.
    """

    class_: typing.ClassVar[java.lang.Class]

    def allowAccess(self, context: VarnodeContext, addr: ghidra.program.model.address.Address) -> bool:
        """
        Evaluate the address and check if the access to the value in the memory location to be read
        The address is read-only and is not close to this address.
        
        :param VarnodeContext context: current program context
        :param ghidra.program.model.address.Address addr: Address of memory where location is attempting to be read
        :return: true if the access should be allowed
        :rtype: bool
        """

    def evaluateConstant(self, context: VarnodeContext, instr: ghidra.program.model.listing.Instruction, pcodeop: typing.Union[jpype.JInt, int], constant: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, refType: ghidra.program.model.symbol.RefType) -> ghidra.program.model.address.Address:
        """
        Evaluate a potential constant to be used as an address or an interesting constant that
        should have a reference created for it.  Computed values that are not know to be used as an address will
        be passed to this function.  For example a value passed to a function, or a stored constant value.
        
        :param VarnodeContext context: current program context
        :param ghidra.program.model.listing.Instruction instr: instruction on which this reference was detected
        :param jpype.JInt or int pcodeop: the PcodeOp operation that is causing this potential constant
        :param ghidra.program.model.address.Address constant: constant value (in constant.getOffset() )
        :param jpype.JInt or int size: size of constant value in bytes
        :param ghidra.program.model.data.DataType dataType: dataType associated with the reference if known
        :param ghidra.program.model.symbol.RefType refType: reference type (flow, data/read/write)
        :return: the original address unchanged if it should be a reference
                null if the constant reference should not be created
                a new address if the value should be a different address or address space
                    Using something like instr.getProgram().getAddressFactory().getDefaultAddressSpace();
        :rtype: ghidra.program.model.address.Address
        """

    def evaluateContext(self, context: VarnodeContext, instr: ghidra.program.model.listing.Instruction) -> bool:
        """
        Evaluate the current instruction given the final context for the instruction
        
        :param VarnodeContext context: describes current state of registers
        :param ghidra.program.model.listing.Instruction instr: instruction whose context has been applied
        :return: true if evaluation should stop, false to continue evaluation
        :rtype: bool
        """

    def evaluateContextBefore(self, context: VarnodeContext, instr: ghidra.program.model.listing.Instruction) -> bool:
        """
        Evaluate the current instruction given the context before the instruction is evaluated
        
        :param VarnodeContext context: describes current state of registers
        :param ghidra.program.model.listing.Instruction instr: instruction whose context has not yet been applied
        :return: true if evaluation should stop
        :rtype: bool
        """

    def evaluateDestination(self, context: VarnodeContext, instruction: ghidra.program.model.listing.Instruction) -> bool:
        """
        Evaluate the instruction for an unknown destination
        
        :param VarnodeContext context: current register context
        :param ghidra.program.model.listing.Instruction instruction: instruction that has an unknown destination
        :return: true if the evaluation should stop, false to continue evaluation
        :rtype: bool
        """

    def evaluateReference(self, context: VarnodeContext, instr: ghidra.program.model.listing.Instruction, pcodeop: typing.Union[jpype.JInt, int], address: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, refType: ghidra.program.model.symbol.RefType) -> bool:
        """
        Evaluate the reference that has been found on this instruction. Computed values that are used as an
        address will be passed to this function.  For example a value passed to a function, or a stored
        constant value.
        
        :param VarnodeContext context: current program context
        :param ghidra.program.model.listing.Instruction instr: instruction on which this reference was detected
        :param jpype.JInt or int pcodeop: the PcodeOp operation that is causing this reference
        :param ghidra.program.model.address.Address address: address being referenced
        :param jpype.JInt or int size: size of the item being referenced (only non-zero if load or store of data)
        :param ghidra.program.model.data.DataType dataType: dataType associated with the reference if known
        :param ghidra.program.model.symbol.RefType refType: reference type (flow, data/read/write)
        :return: false if the reference should be ignored (or has been taken care of by this routine)
        :rtype: bool
        """

    def evaluateReturn(self, retVN: ghidra.program.model.pcode.Varnode, context: VarnodeContext, instruction: ghidra.program.model.listing.Instruction) -> bool:
        """
        Evaluate the target of a return
        
        :param ghidra.program.model.pcode.Varnode retVN: varnode that is the target of a RETURN pcodeop
        :param VarnodeContext context: current register context
        :param ghidra.program.model.listing.Instruction instruction: instruction that has an unknown destination
        :return: true if the evaluation should stop, false to continue evaluation
        :rtype: bool
        """

    def evaluateSymbolicReference(self, context: VarnodeContext, instr: ghidra.program.model.listing.Instruction, address: ghidra.program.model.address.Address) -> bool:
        """
        Evaluate the reference that has been found on this instruction that points into an unknown space that
        has been designated as tracked.
        
        :param VarnodeContext context: current program context
        :param ghidra.program.model.listing.Instruction instr: instruction on which this reference was detected
        :param ghidra.program.model.address.Address address: address being referenced
        :return: false if the reference should be ignored (or has been taken care of by this routine)
                true to allow the reference to be created
        :rtype: bool
        """

    def followFalseConditionalBranches(self) -> bool:
        """
        Follow all branches, even if the condition evaluates to false, indicating it shouldn't be followed.
        
        :return: true if false evaluated conditional branches should be followed.
        :rtype: bool
        """

    def unknownValue(self, context: VarnodeContext, instruction: ghidra.program.model.listing.Instruction, node: ghidra.program.model.pcode.Varnode) -> int:
        """
        Called when a value is needed for a register that is unknown
        
        :param VarnodeContext context: current register context
        :param ghidra.program.model.listing.Instruction instruction: instruction that has an unknown destination
        :param ghidra.program.model.pcode.Varnode node: varnode for the register being accessed to obtain a value
        :return: null if the varnode should not have an assumed value.
                a long value if the varnode such as a Global Register should have an assumed constant
        :rtype: int
        """


class MultiAddressIterator(java.lang.Object):
    """
    ``MultiAddressIterator`` is a class for iterating through multiple
    address iterators simultaneously. The next() method returns the next address
    as determined from all the iterators.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, iters: jpype.JArray[ghidra.program.model.address.AddressIterator]):
        """
        Constructor of a multi address iterator for multiple forward address iterators.
        
        :param jpype.JArray[ghidra.program.model.address.AddressIterator] iters: the address iterators.
        """

    @typing.overload
    def __init__(self, iters: jpype.JArray[ghidra.program.model.address.AddressIterator], forward: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor of a multi address iterator.
         
        Note: all iterators must iterate in the same direction (forwards or backwards).
        
        :param jpype.JArray[ghidra.program.model.address.AddressIterator] iters: the address iterators. All must iterate in the direction indicated
        by the "forward" parameter.
        :param jpype.JBoolean or bool forward: true indicates that forward iterators are in the array.
        false indicates backward iterators are in the array.
        """

    def hasNext(self) -> bool:
        """
        Determines whether or not any of the original iterators has a
        next address.
        
        :return: true if a next address can be obtained from any of
        the address iterators.
        :rtype: bool
        """

    def next(self) -> ghidra.program.model.address.Address:
        """
        Returns the next address. The next address could be from any 
        one of the iterators.
        
        :return: the next address.
        :rtype: ghidra.program.model.address.Address
        """

    def nextAddresses(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        """
        Returns the next address(es). The next address could be from any 
        one or more of the iterators.
        
        :return: an array with the next address(es). Each element in this array 
        corresponds to each iterator passed to the constructor. 
        Null is returned in an element if the next overall address is not the 
        next address from the corresponding iterator.
        :rtype: jpype.JArray[ghidra.program.model.address.Address]
        """


class MultiAddressRangeIterator(java.lang.Object):
    """
    ``MultiAddressRangeIterator`` is a class for iterating through multiple
    address range iterators simultaneously. The next() method returns the next address range
    as determined from all the iterators.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, iters: jpype.JArray[ghidra.program.model.address.AddressRangeIterator]):
        """
        Constructor of a multi address iterator for multiple forward address iterators.
        
        :param jpype.JArray[ghidra.program.model.address.AddressRangeIterator] iters: the address iterators.
        """

    @typing.overload
    def __init__(self, iters: jpype.JArray[ghidra.program.model.address.AddressRangeIterator], forward: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor of a multi address range iterator.
         
        Note: all iterators must iterate in the same direction (forwards or backwards).
        
        :param jpype.JArray[ghidra.program.model.address.AddressRangeIterator] iters: the address iterators. All must iterate in the direction indicated
        by the "forward" parameter.
        :param jpype.JBoolean or bool forward: true indicates that forward iterators are in the array.
        false indicates backward iterators are in the array.
        """

    def backwardNext(self) -> ghidra.program.model.address.AddressRange:
        """
        Returns the next address for backward iterators. The next address could be from any 
        one of the iterators.
        
        :return: the next address.
        :rtype: ghidra.program.model.address.AddressRange
        """

    def forwardNext(self) -> ghidra.program.model.address.AddressRange:
        """
        Returns the next address for forward iterators. The next address could be from any 
        one of the iterators.
        
        :return: the next address.
        :rtype: ghidra.program.model.address.AddressRange
        """

    def hasNext(self) -> bool:
        """
        Determines whether or not any of the original iterators has a
        next address.
        
        :return: true if a next address can be obtained from any of
        the address iterators.
        :rtype: bool
        """

    def next(self) -> ghidra.program.model.address.AddressRange:
        """
        Returns the next address. The next address could be from any 
        one of the iterators.
        
        :return: the next address.
        :rtype: ghidra.program.model.address.AddressRange
        """


class ProgramSelection(ghidra.program.model.address.AddressSetView):
    """
    Class to define a selection for a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct a new empty ProgramSelection.
        """

    @typing.overload
    def __init__(self, from_: ghidra.program.model.address.Address, to: ghidra.program.model.address.Address):
        """
        Constructor.
        
        :param ghidra.program.model.address.Address from: the start of the selection
        :param ghidra.program.model.address.Address to: the end of the selection
        """

    @typing.overload
    def __init__(self, setView: ghidra.program.model.address.AddressSetView):
        """
        Construct a new ProgramSelection
        
        :param ghidra.program.model.address.AddressSetView setView: address set for the selection
        """

    @typing.overload
    def __init__(self, sel: InteriorSelection):
        """
        Construct a new ProgramSelection from the indicated interior selection.
        
        :param InteriorSelection sel: the interior selection
        """

    @typing.overload
    @deprecated("use ProgramSelection()")
    def __init__(self, addressFactory: ghidra.program.model.address.AddressFactory):
        """
        Construct a new empty ProgramSelection.
        
        :param ghidra.program.model.address.AddressFactory addressFactory: NOT USED
        
        .. deprecated::
        
        use :meth:`ProgramSelection() <.ProgramSelection>`
        """

    @typing.overload
    @deprecated("use ProgramSelection(Address, Address)")
    def __init__(self, addressFactory: ghidra.program.model.address.AddressFactory, from_: ghidra.program.model.address.Address, to: ghidra.program.model.address.Address):
        """
        Constructor.
        
        :param ghidra.program.model.address.AddressFactory addressFactory: NOT USED
        :param ghidra.program.model.address.Address from: the start of the selection
        :param ghidra.program.model.address.Address to: the end of the selection
        
        .. deprecated::
        
        use :meth:`ProgramSelection(Address, Address) <.ProgramSelection>`
        """

    @typing.overload
    @deprecated("use ProgramSelection(AddressSetView)")
    def __init__(self, addressFactory: ghidra.program.model.address.AddressFactory, setView: ghidra.program.model.address.AddressSetView):
        """
        Construct a new ProgramSelection
        
        :param ghidra.program.model.address.AddressFactory addressFactory: NOT USED
        :param ghidra.program.model.address.AddressSetView setView: address set for the selection
        
        .. deprecated::
        
        use :meth:`ProgramSelection(AddressSetView) <.ProgramSelection>`
        """

    @typing.overload
    @deprecated("use ProgramSelection(InteriorSelection)s")
    def __init__(self, addressFactory: ghidra.program.model.address.AddressFactory, sel: InteriorSelection):
        """
        Construct a new ProgramSelection from the indicated interior selection.
        
        :param ghidra.program.model.address.AddressFactory addressFactory: NOT USED
        :param InteriorSelection sel: the interior selection
        
        .. deprecated::
        
        use :meth:`ProgramSelection(InteriorSelection) <.ProgramSelection>`s
        """

    def getInteriorSelection(self) -> InteriorSelection:
        """
        Get the interior selection.
        
        :return: null if there is no interior selection
        :rtype: InteriorSelection
        """

    def hasSameAddresses(self, asv: ghidra.program.model.address.AddressSetView) -> bool:
        """
        Returns true if and only if this set and the given
        address set contains exactly the same addresses.
        
        :param ghidra.program.model.address.AddressSetView asv: the address set to compare with this one.
        :return: true if the specified set has the same addresses.
        :rtype: bool
        """

    @property
    def interiorSelection(self) -> InteriorSelection:
        ...


class ProgramMerge(java.lang.Object):
    """
    ``ProgramMerge`` is a class for merging the differences between two
    programs. The differences are merged from program2 into program1.
     
    Program1 is the program being modified by the merge. Program2 is source
    for obtaining differences to apply to program1.
     
    If name conflicts occur while merging, the item (for example, symbol) will
    be merged with a new name that consists of the original name followed by "_conflict"
    and a one up number.
    """

    @typing.type_check_only
    class DupEquate(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionAddressIterator(ghidra.program.model.address.AddressIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    SYMBOL_CONFLICT_SUFFIX: typing.ClassVar[java.lang.String]
    """
    Suffix that is attached to a symbol name and then followed by a number to create a new unique symbol name.
    """


    @typing.overload
    def __init__(self, resultProgram: ghidra.program.model.listing.Program, originProgram: ghidra.program.model.listing.Program):
        """
        ``ProgramMerge`` allows the merging of differences from program2
        into program1 (the result program).
        
        :param ghidra.program.model.listing.Program resultProgram: The result program that will get modified by merge.
        :param ghidra.program.model.listing.Program originProgram: The program (used as read only) for obtaining
        differences to merge.
        """

    @typing.overload
    def __init__(self, originToResultTranslator: AddressTranslator):
        """
        ``ProgramMerge`` allows the merging of differences from program2 (the origin program)
        into program1 (the result program).
         
        If the address translator is not a "one for one translator" then certain methods within
        this class will throw an UnsupportedOperationException.
        The destination program from the address translator should be the result program into
        which changes are made.
        The source program from the translator is the origin program for obtaining the changes.
        
        :param AddressTranslator originToResultTranslator: converts addresses from the origin program into an
        equivalent address in the destination program.
        
        .. seealso::
        
            | :obj:`AddressTranslator`
        """

    def addReference(self, originRef: ghidra.program.model.symbol.Reference, toSymbolID: typing.Union[jpype.JLong, int], replaceExtLoc: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.symbol.Reference:
        """
        ``addReference`` creates a reference in program1 that is equivalent
        to the one specified as a parameter. If a symbol ID is specified, the
        reference will refer to the symbol in program1 with that ID. If the reference
        is an external reference, then the external location associated with it can be replaced
        also by setting the replace external location flag.
        
        :param ghidra.program.model.symbol.Reference originRef: the reference equivalent to the one to be created.
        :param jpype.JLong or int toSymbolID: ID of the symbol to referred to. null indicates don't
        refer directly to a symbol.
        :param jpype.JBoolean or bool replaceExtLoc: the replace external location flag. true indicates to replace the
        external location, if applicable, with the one defined for the reference passed to this method.
        :return: the reference that was created. null if none created.
        :rtype: ghidra.program.model.symbol.Reference
        """

    def applyFunctionTagChanges(self, originAddressSet: ghidra.program.model.address.AddressSetView, setting: typing.Union[jpype.JInt, int], discardTags: java.util.Set[ghidra.program.model.listing.FunctionTag], keepTags: java.util.Set[ghidra.program.model.listing.FunctionTag], monitor: ghidra.util.task.TaskMonitor):
        """
        Merges/replaces tags of program2 into program1. When merging, tags that are in
        conflict are replaced according to the user setting (ignore, replace, merge).
        
        :param ghidra.program.model.address.AddressSetView originAddressSet: the addresses to be merged.
        :param jpype.JInt or int setting: how to merge. IGNORE, REPLACE, MERGE
        :param java.util.Set[ghidra.program.model.listing.FunctionTag] discardTags: tags to keep out of the final result
        :param java.util.Set[ghidra.program.model.listing.FunctionTag] keepTags: tags to add to the final result
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        :raises CancelledException: if user cancels via the monitor.
        """

    def applySourceMapDifferences(self, originAddrs: ghidra.program.model.address.AddressSet, settings: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Merge the source map information from the origin program to the result program.
        
        :param ghidra.program.model.address.AddressSet originAddrs: address from origin program to merge
        :param jpype.JInt or int settings: merge settings
        :param ghidra.util.task.TaskMonitor monitor: monitor
        :raises LockException: if invoked without exclusive access
        """

    def clearErrorMessage(self):
        """
        This method clears the current error message.
        """

    def clearInfoMessage(self):
        """
        This method clears the current informational message.
        """

    def getErrorMessage(self) -> str:
        """
        Get the error messages that resulted from the last call to a merge or
        replace method. These are errors that prevented something from being merged.
         
        Important: Call clearErrorMessage() to clear the current error message after this returns it.
        
        :return: the error message string or an empty string if there were no problems with the merge.
        :rtype: str
        """

    def getInfoMessage(self) -> str:
        """
        Get the information messages that resulted from the last call to a merge or
        replace method. These messages are non-critical changes that were
        necessary during the merge. For example giving a symbol a name with a conflict
        extension because another symbol with that name existed elsewhere in the
        program already.
         
        Important: Call clearInfoMessage() to clear the current info message after this returns it.
        
        :return: the information message string or an empty string if there were no informational
        messages for the merge.
        :rtype: str
        """

    def getOriginProgram(self) -> ghidra.program.model.listing.Program:
        """
        Gets the origin program. This program is used for obtaining things to merge into program1.
        
        :return: the program we are obtaining the changes from which we will merge.
        :rtype: ghidra.program.model.listing.Program
        """

    def getResultProgram(self) -> ghidra.program.model.listing.Program:
        """
        Gets the result program. Merge changes are applied to this program.
        
        :return: the program being changed by the merge.
        :rtype: ghidra.program.model.listing.Program
        """

    @staticmethod
    @typing.overload
    def getUniqueName(symbolTable: ghidra.program.model.symbol.SymbolTable, name: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, namespace1: ghidra.program.model.symbol.Namespace, namespace2: ghidra.program.model.symbol.Namespace, type: ghidra.program.model.symbol.SymbolType) -> str:
        """
        Create a name that is unique in both namespaces of the given symbolTable.
        
        :param ghidra.program.model.symbol.SymbolTable symbolTable: the symbolTable where the symbol will be created.
        :param java.lang.String or str name: the desired name. This name will be given a conflict suffix if necessary
        to make it unique.
        :param ghidra.program.model.address.Address address: the address of the symbol.
        :param ghidra.program.model.symbol.Namespace namespace1: the first namespace where the new symbol should be unique. 
        This namespace must be from the same program as the symbol table.
        :param ghidra.program.model.symbol.Namespace namespace2: the second namespace where the new symbol should be unique.
        This namespace must be from the same program as the symbol table.
        :param ghidra.program.model.symbol.SymbolType type: the symbol type of the symbol.
        :return: a unique name for both namespaces.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getUniqueName(symbolTable: ghidra.program.model.symbol.SymbolTable, name: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, namespace: ghidra.program.model.symbol.Namespace, type: ghidra.program.model.symbol.SymbolType) -> str:
        """
        Create a name that is unique in the indicated namespace of the symbol table.
        
        :param ghidra.program.model.symbol.SymbolTable symbolTable: the symbolTable where the symbol will be created.
        :param java.lang.String or str name: the desired name. This name will be given a conflict suffix if necessary
        to make it unique.
        :param ghidra.program.model.address.Address address: the address of the symbol.
        :param ghidra.program.model.symbol.Namespace namespace: the namespace where the new symbol would be created.
        This namespace must be from the same program as the symbol table.
        :param ghidra.program.model.symbol.SymbolType type: the type of symbol.
        :return: a unique name within the namespace.
        :rtype: str
        """

    def hasErrorMessage(self) -> bool:
        """
        Determines if this ProgramMerge currently has an error message.
        
        :return: true if there is an error message.
        :rtype: bool
        """

    def hasInfoMessage(self) -> bool:
        """
        Determines if this ProgramMerge currently has an informational message.
        
        :return: true if there is an information message.
        :rtype: bool
        """

    def mergeBookmark(self, originAddress: ghidra.program.model.address.Address, type: typing.Union[java.lang.String, str], category: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeBookmark`` merges the indicated bookmark from the origin program into the
        result program at an address equivalent to the originAddress.
        Merging means replace any existing bookmark of the specified type for NOTEs
        or of the specified type and category for non-NOTE types.
         
        Note: This method merges a single bookmark without affecting
        other bookmarks at the indicated address.
        
        :param ghidra.program.model.address.Address originAddress: the address in the origin program where the bookmark is to be merged.
        :param java.lang.String or str type: indicates the type of bookmark to merge.
        :param java.lang.String or str category: indicates the category of the bookmark.
        :param ghidra.util.task.TaskMonitor monitor: a task monitor for providing feedback to the user.
        :raises CancelledException: if the user cancels the bookmark merge from the monitor dialog.
        """

    def mergeBytes(self, originAddressSet: ghidra.program.model.address.AddressSetView, overwriteInstructions: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeBytes`` merges byte differences within the specified
        address set.
         
        Note: Any instructions at the equivalent byte addresses in the result program will get cleared and
        re-created resulting in the existing references being dropped.
        
        :param ghidra.program.model.address.AddressSetView originAddressSet: the addresses to be merged.
        The addresses in this set are derived from the origin program.
        :param jpype.JBoolean or bool overwriteInstructions: if true affected instructions will be cleared and
        re-disassmebled after bytes are modified
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's
        progress.
        :raises MemoryAccessException: if bytes can't be merged.
        :raises CancelledException: if user cancels via the monitor.
        :raises java.lang.UnsupportedOperationException: if the ProgramMerge translator is not a
        "one for one translator".
        """

    def mergeCodeUnits(self, originAddressSet: ghidra.program.model.address.AddressSetView, byteDiffs: ghidra.program.model.address.AddressSetView, mergeDataBytes: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeCodeUnits`` merges all instructions and/or data
        (as indicated) in the specified address set from the origin program.
        It merges them into the result program. When merging
        instructions, the bytes are also replaced if they differ.
        This assumes originToResultTranslator maps address spaces and does
        not do fine-grained mapping of addresses.
        
        :param ghidra.program.model.address.AddressSetView originAddressSet: the addresses to be merged.
        The addresses in this set should be derived from the origin program.
        :param ghidra.program.model.address.AddressSetView byteDiffs: address set indicating addresses where the bytes differ
        between the result program and the origin program.
        The addresses in this set should be derived from the origin program.
        :param jpype.JBoolean or bool mergeDataBytes: true indicates bytes that differ should be copied when merging Data.
        false means don't copy any bytes for Data.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's
        progress.
        :raises MemoryAccessException: if bytes can't be copied.
        :raises CancelledException: if user cancels via the monitor.
        :raises java.lang.UnsupportedOperationException: if the ProgramMerge translator is not a
        "one for one translator".
        """

    def mergeComment(self, originAddressSet: ghidra.program.model.address.AddressSet, type: typing.Union[jpype.JInt, int], both: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeComment`` merges/replaces comments of the indicated
        type wherever they occur in the specified address set.
        
        :param ghidra.program.model.address.AddressSet originAddressSet: the addresses where comments should be merged/replaced.
        The addresses in this set should be from the origin program.
        :param jpype.JInt or int type: ProgramMergeFilter comment type.
        The comment type can be PLATE, PRE, EOL, REPEATABLE, POST.
        :param jpype.JBoolean or bool both: true means merge both program1 and program2 comments.
        false means replace the program1 comment with the program2 comment.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        :raises CancelledException: if user cancels via the monitor.
        """

    def mergeCommentType(self, originAddressSet: ghidra.program.model.address.AddressSetView, type: typing.Union[jpype.JInt, int], setting: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeCommentType`` merges/replaces comments of the indicated
        type wherever they occur in the specified address set.
        It merges them from program2 into program1.
        This merges eol, pre, post, repeatable, and plate comments.
        
        :param ghidra.program.model.address.AddressSetView originAddressSet: the addresses to be merged.
        The addresses in this set should be derived from the origin program.
        :param jpype.JInt or int type: the comment type. PLATE, PRE, EOL, REPEATABLE, POST
        :param jpype.JInt or int setting: how to merge. IGNORE, REPLACE, MERGE
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        :raises CancelledException: if user cancels via the monitor.
        """

    def mergeComments(self, commentType: ghidra.program.model.listing.CommentType, originAddress: ghidra.program.model.address.Address):
        """
        ``mergeComments`` merges the comment of the indicated
        type in program1 with the comment in program2 at the specified address.
        
        :param ghidra.program.model.listing.CommentType commentType: comment type to merge (from CodeUnit class).
         
        EOL, PRE, POST, REPEATABLE, OR PLATE.
        :param ghidra.program.model.address.Address originAddress: the address
        This address should be derived from the origin program.
        """

    def mergeEquate(self, originAddress: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], value: typing.Union[jpype.JLong, int]):
        """
        ``mergeEquate`` replaces the current equates in program1 with those in program2.
        
        :param ghidra.program.model.address.Address originAddress: the address where the equates should be merged.
        This address should be derived from the origin program.
        :param jpype.JInt or int opIndex: the operand index where the equates should be merged.
        :param jpype.JLong or int value: the scalar value where the equate is used.
        """

    def mergeEquates(self, originAddressSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeEquates`` merges the equate differences in the specified
        address set.
        
        :param ghidra.program.model.address.AddressSetView originAddressSet: the addresses to be merged.
        The addresses in this set should be derived from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's
        progress.
        :raises CancelledException: if user cancels via the monitor.
        :raises java.lang.UnsupportedOperationException: if the ProgramMerge translators are not
        "one for one translators".
        """

    def mergeFunction(self, entry: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.listing.Function:
        """
        ``mergeFunction`` completely replaces any function at the
        indicated address in program1 with the function, if any, in program2.
        
        :param ghidra.program.model.address.Address entry: the entry point address of the function to be merged.
        This address should be derived from program1.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        :raises CancelledException: if user cancels via the monitor.
        """

    def mergeFunctionLocalSize(self, entry2: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeFunctionLocalSize`` replaces the local size of the
        function in program1 with the local size of the function in program2
        at the specified entry point address.
        
        :param ghidra.program.model.address.Address entry2: the entry point address of the function.
        This address should be derived from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        """

    def mergeFunctionName(self, entry2: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeFunctionName`` replaces the name of the
        function in program1 with the name of the function in program2
        at the specified entry point address.
        
        :param ghidra.program.model.address.Address entry2: the entry point address of the function.
        This address should be derived from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        """

    def mergeFunctionReturn(self, entry2: ghidra.program.model.address.Address):
        """
        ``mergeFunctionReturn`` replaces the return type/storage of the
        function in program1 with the return type/storage of the function in program2
        at the specified entry point address.
        
        :param ghidra.program.model.address.Address entry2: the entry point address of the function.
        This address should be derived from the origin program.
        """

    def mergeFunctionReturnAddressOffset(self, entry2: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeFunctionReturnAddressOffset`` replaces the return address offset of the
        function in program1 with the return address offset of the function in program2
        at the specified entry point address.
        
        :param ghidra.program.model.address.Address entry2: the entry point address of the function.
        This address should be derived from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        """

    def mergeFunctionStackPurgeSize(self, entry2: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeFunctionStackPurgeSize`` replaces the stack purge size of the
        function in program1 with the stack purge size of the function in program2
        at the specified entry point address.
        
        :param ghidra.program.model.address.Address entry2: the entry point address of the function.
        This address should be derived from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        """

    def mergeFunctions(self, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeFunctions`` merges function differences within the specified
        address set.
        
        :param ghidra.program.model.address.AddressSetView addrSet: the addresses to be merged.
        The addresses in this set should be derived from program1.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's
        progress.
        :raises CancelledException: if user cancels via the monitor.
        """

    def mergeLabels(self, originAddressSet: ghidra.program.model.address.AddressSetView, setting: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeLabels`` merges all symbols and aliases
        in the specified address set from the second program.
        It merges them into the merge program.
        
        :param ghidra.program.model.address.AddressSetView originAddressSet: the addresses to be merged.
        The addresses in this address set should be derived from program1.
        :param jpype.JInt or int setting: the current label setting.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's
        progress.
        :raises CancelledException: if user cancels via the monitor.
        """

    def mergeProperties(self, originAddressSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeProperties`` merges user defined property differences
        within the specified address set.
        
        :param ghidra.program.model.address.AddressSetView originAddressSet: the addresses to be merged from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        :raises CancelledException: if user cancels via the monitor.
        :raises java.lang.UnsupportedOperationException: if the ProgramMerge translator is not a
        "one for one translator".
        """

    def mergeReferences(self, originAddressSet: ghidra.program.model.address.AddressSetView, onlyKeepDefaults: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        ``mergeReferences`` merges the references in
        program1 for the specified address set with the references from program2.
        If an equivalent reference already exists then it is updated to match the
        new reference if possible. A merge of references prevents the loss of any
        non-default references already in the result program.
         
        Important: Fallthrough references will not be merged by this method.
        Fallthroughs are handled by merging code units.
         
        Note: All reference types (memory, stack, external) get replaced
        where possible. i.e. If a function or variable doesn't exist for a
        variable reference then it will not be able to replace the reference.
        
        :param ghidra.program.model.address.AddressSetView originAddressSet: the addresses to be merged.
        The addresses in this set should be derived from the origin program.
        :param jpype.JBoolean or bool onlyKeepDefaults: true indicates to merge only the default references
        from the origin program into the result program. Non-default references will not be merged.
        false indicates merge all references except fallthroughs.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's
        progress.
        :raises CancelledException: if the user cancels the replace via the monitor.
        :raises java.lang.UnsupportedOperationException: if the ProgramMerge translators are not
        "one for one translators".
        """

    def mergeUserProperty(self, userPropertyName: typing.Union[java.lang.String, str], originAddress: ghidra.program.model.address.Address):
        """
        Replaces the user defined properties from the specified origin address in the origin program
        to the equivalent result address in the result program.
        Note: To merge properties, there must be a code unit AT the equivalent address
        in the result program.
        
        :param java.lang.String or str userPropertyName: original property name
        :param ghidra.program.model.address.Address originAddress: the address of the code unit to get the properties from in the origin program.
        """

    def replaceComment(self, commentType: ghidra.program.model.listing.CommentType, originAddress: ghidra.program.model.address.Address):
        """
        ``replaceComment`` replaces the comment of the indicated
        type in program1 with the comment in program2 at the specified address.
        
        :param ghidra.program.model.listing.CommentType commentType: comment type to replace (from CodeUnit class).
         
        EOL, PRE, POST, REPEATABLE, OR PLATE.
        :param ghidra.program.model.address.Address originAddress: the address
        This address should be derived from the origin program.
        """

    def replaceExternalFunction(self, toFunction: ghidra.program.model.listing.Function, fromFunction: ghidra.program.model.listing.Function, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.listing.Function:
        """
        Replaces the external result function with the origin Function.
         
        Note: This method will replace the function, but does not create
        the parent namespace or put the function in the parent namespace.
        This must be done separately.
        
        :param ghidra.program.model.listing.Function toFunction: the result function to replace.
        :param ghidra.program.model.listing.Function fromFunction: the function to use as the model when replacing the result function.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        :return: the new function that was created in the resultListing or null
        if no function was created. If null is returned you should call
        getErrorMessage() to see if an error occurred.
        :rtype: ghidra.program.model.listing.Function
        :raises CancelledException: if user cancels via the monitor.
        :raises java.lang.UnsupportedOperationException: if the ProgramMerge translators are not
        "one for one translators".
        """

    def replaceFallThroughs(self, originAddressSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFallThroughs`` replaces all fallthroughs in
        program1 for the specified address set with those in program2 where they differ.
        
        :param ghidra.program.model.address.AddressSetView originAddressSet: the addresses to be merged.
        The addresses in this set should be derived from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's
        progress.
        :raises CancelledException: if the user cancels the replace via the monitor.
        """

    def replaceFunctionCallingConvention(self, originEntryPoint: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionCallingConvention`` changes the function calling convention
        in program1 if it doesn't match the function calling convention in program2
        at the specified entry point address.
        
        :param ghidra.program.model.address.Address originEntryPoint: the entry point address of the function.
        This address should be derived from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        """

    def replaceFunctionCustomStorageFlag(self, originEntryPoint: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionCustomStorageFlag`` changes whether the flag is set indicating
        the function does not return
        in program1 if it doesn't match the "custom storage" flag in the function in program2
        at the specified entry point address.
        
        :param ghidra.program.model.address.Address originEntryPoint: the entry point address of the function.
        This address should be derived from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        """

    def replaceFunctionInlineFlag(self, originEntryPoint: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionInlineFlag`` changes whether the function is inline
        in program1 if it doesn't match whether the function is inline in program2
        at the specified entry point address.
        
        :param ghidra.program.model.address.Address originEntryPoint: the entry point address of the function.
        This address should be derived from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        """

    def replaceFunctionNames(self, originAddressSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionNames`` merges function name and namespace differences
        within the specified address set.
        
        :param ghidra.program.model.address.AddressSetView originAddressSet: the addresses to be merged.
        The addresses in this set should be derived from program1.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's
        progress.
        :raises CancelledException: if user cancels via the monitor.
        """

    def replaceFunctionNoReturnFlag(self, originEntryPoint: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionNoReturnFlag`` changes whether the flag is set indicating
        the function does not return
        in program1 if it doesn't match the "does not return" flag in the function in program2
        at the specified entry point address.
        
        :param ghidra.program.model.address.Address originEntryPoint: the entry point address of the function.
        This address should be derived from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        """

    def replaceFunctionParameterComment(self, originEntryPoint: ghidra.program.model.address.Address, ordinal: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionParameterComment`` replaces the comment of the indicated
        function parameter in program1 with the comment from the origin program.
        
        :param ghidra.program.model.address.Address originEntryPoint: the entry point address of the function to modify.
        This address should be derived from the origin program.
        :param jpype.JInt or int ordinal: the index of the parameter to change.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of progress.
        """

    def replaceFunctionParameterDataType(self, originEntryPoint: ghidra.program.model.address.Address, ordinal: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionParameterDataType`` replaces the data type of the indicated
        function parameter in program1 with the data type from the origin program.
        
        :param ghidra.program.model.address.Address originEntryPoint: the entry point address of the function to modify.
        This address should be derived from the origin program.
        :param jpype.JInt or int ordinal: the index of the parameter to change.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of progress.
        """

    def replaceFunctionParameterName(self, originEntryPoint: ghidra.program.model.address.Address, ordinal: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionParameterName`` replaces the name of the indicated
        function parameter in program1 with the name from the origin program.
        
        :param ghidra.program.model.address.Address originEntryPoint: the entry point address of the function to modify.
        This address should be derived from the origin program.
        :param jpype.JInt or int ordinal: the index of the parameter to change.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of progress.
        :raises InvalidInputException: 
        :raises DuplicateNameException:
        """

    @typing.overload
    def replaceFunctionParameters(self, originEntryPoint: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionParameters`` replaces the parameters of the
        function in program1 with the parameters of the function in program2
        at the specified entry point address.  It also replaces the return
        type/storage as well as custom storage use.
        
        :param ghidra.program.model.address.Address originEntryPoint: the entry point address of the function.
        This address should be derived from the origin program.
        """

    @typing.overload
    def replaceFunctionParameters(self, toFunc: ghidra.program.model.listing.Function, fromFunc: ghidra.program.model.listing.Function):
        """
        ``replaceFunctionParameters`` replaces the parameters of the
        function in program1 with the parameters of the function in program2
        at the specified entry point address.  It also replaces the return
        type/storage as well as custom storage use.
        
        :param ghidra.program.model.listing.Function toFunc: target function
        :param ghidra.program.model.listing.Function fromFunc: source function
        """

    def replaceFunctionSignatureSource(self, originEntryPoint: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionSignatureSource`` changes the result function's signature source
        to match the origin program's signature source.
        
        :param ghidra.program.model.address.Address originEntryPoint: the entry point address of the function.
        This address should be derived from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        """

    def replaceFunctionVarArgs(self, entry2: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionVarArgs`` changes whether the function has VarArgs
        in program1 if it doesn't match the use of VarArgs in the function in program2
        at the specified entry point address.
        
        :param ghidra.program.model.address.Address entry2: the entry point address of the function.
        This address should be derived from program1.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        """

    def replaceFunctionVariable(self, originEntryPoint: ghidra.program.model.address.Address, var: ghidra.program.model.listing.Variable, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionVariable`` replaces the name of the indicated
        function variable in program1 with that from the origin program.
        
        :param ghidra.program.model.address.Address originEntryPoint: the entry point address of the function to modify.
        This address should be derived from program1.
        :param ghidra.program.model.listing.Variable var: a variable that is equivalent to the one in program1 to be replaced.
        The variable passed here could be from another program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of progress.
        """

    def replaceFunctionVariableComment(self, originEntryPoint: ghidra.program.model.address.Address, var: ghidra.program.model.listing.Variable, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionVariableComment`` replaces the comment on the indicated
        function variable in program1 with the comment from the equivalent variable in program2.
        
        :param ghidra.program.model.address.Address originEntryPoint: entry point address of the function whose variable is getting the comment replaced.
        This address should be derived from the origin program.
        :param ghidra.program.model.listing.Variable var: a variable that is equivalent to the one in program1 to be changed.
        The variable passed here could be from another program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of progress.
        """

    def replaceFunctionVariableDataType(self, originEntryPoint: ghidra.program.model.address.Address, var: ghidra.program.model.listing.Variable, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionVariableDataType`` replaces the data type on the indicated
        function variable in program1 with the data type from the equivalent variable in program2.
        
        :param ghidra.program.model.address.Address originEntryPoint: the entry point address of the function to modify.
        This address should be derived from the origin program.
        :param ghidra.program.model.listing.Variable var: a variable that is equivalent to the one in program1 to be changed.
        The variable passed here could be from another program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of progress.
        """

    def replaceFunctionVariableName(self, originEntryPoint: ghidra.program.model.address.Address, var: ghidra.program.model.listing.Variable, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionVariableName`` replaces the name on the indicated
        function variable in program1 with the name from the equivalent variable in program2.
        
        :param ghidra.program.model.address.Address originEntryPoint: the entry point address of the function to modify.
        This address should be derived from the origin program.
        :param ghidra.program.model.listing.Variable var: a variable that is equivalent to the one in program1 to be changed.
        The variable passed here could be from another program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of progress.
        :raises InvalidInputException: 
        :raises DuplicateNameException:
        """

    def replaceLabels(self, originAddressSet: ghidra.program.model.address.AddressSet, replaceFunction: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceLabels`` replaces all symbols and aliases
        in the specified address set from the second program.
        
        :param ghidra.program.model.address.AddressSet originAddressSet: the addresses to be replaced
        The addresses in this address set should be derived from program1.
        :param jpype.JBoolean or bool replaceFunction: true indicates the function symbol should be replaced
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress
        :raises CancelledException: if user cancels via the monitor.
        """

    @typing.overload
    def replaceReference(self, resultRef: ghidra.program.model.symbol.Reference, originRef: ghidra.program.model.symbol.Reference) -> ghidra.program.model.symbol.Reference:
        """
        Replaces the reference in program1 with the reference from the origin program.
        
        :param ghidra.program.model.symbol.Reference resultRef: the program1 reference to be replaced.
        :param ghidra.program.model.symbol.Reference originRef: the program2 reference used to replace what's in program1.
        :return: the resulting reference in program1. null if reference is removed
        by the replace.
        :rtype: ghidra.program.model.symbol.Reference
        """

    @typing.overload
    def replaceReference(self, resultRef: ghidra.program.model.symbol.Reference, originRef: ghidra.program.model.symbol.Reference, toSymbolID: typing.Union[jpype.JLong, int]) -> ghidra.program.model.symbol.Reference:
        """
        Replaces the reference in program1 with the reference from the origin program.
        
        :param ghidra.program.model.symbol.Reference resultRef: the program1 reference to be replaced.
        :param ghidra.program.model.symbol.Reference originRef: the program2 reference used to replace what's in program1.
        :param jpype.JLong or int toSymbolID: ID of the symbol in program1 the resulting reference is to.
        :return: the resulting reference in program1. null if reference is removed
        by the replace.
        :rtype: ghidra.program.model.symbol.Reference
        """

    @typing.overload
    def replaceReferences(self, originAddressSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceReferences`` replaces all references in
        program1 for the specified address set with those in program2.
        If an equivalent reference already exists then it is updated to match the
        new reference.
         
        Note: All reference types (memory, stack, external) get replaced
        where possible. i.e. If a function or variable doesn't exist for a
        variable reference then it will not be able to replace the reference.
        
        :param ghidra.program.model.address.AddressSetView originAddressSet: the addresses to be merged.
        The addresses in this set should be derived from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's
        progress.
        :raises CancelledException: if the user cancels the replace via the monitor.
        :raises java.lang.UnsupportedOperationException: if the ProgramMerge translators are not
        "one for one translators".
        """

    @typing.overload
    def replaceReferences(self, originAddressSet: ghidra.program.model.address.AddressSetView, onlyKeepDefaults: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceReferences`` replaces all references in
        program1 for the specified address set with the references from program2.
        If an equivalent reference already exists then it is updated to match the
        new reference.
         
        Note: All reference types (memory, stack, external) get replaced
        where possible. i.e. If a function or variable doesn't exist for a
        variable reference then it will not be able to replace the reference.
        
        :param ghidra.program.model.address.AddressSetView originAddressSet: the addresses to be merged.
        The addresses in this set should be derived from the origin program.
        :param jpype.JBoolean or bool onlyKeepDefaults: true indicates to replace all references with only
        the default references from the origin program.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's
        progress.
        :raises CancelledException: if the user cancels the replace via the monitor.
        :raises java.lang.UnsupportedOperationException: if the ProgramMerge translators are not
        "one for one translators".
        """

    @typing.overload
    def replaceReferences(self, originAddress: ghidra.program.model.address.Address, operandIndex: typing.Union[jpype.JInt, int]):
        """
        ``replaceReferences`` replaces all references in
        program1 for the specified address and operand index with those in program2.
        If an equivalent reference already exists then it is updated to match the
        new reference.
         
        Note: All reference types (memory, stack, external) get replaced
        where possible. i.e. If a function or variable doesn't exist for a
        variable reference then it will not be able to replace the reference.
        
        :param ghidra.program.model.address.Address originAddress: the "from" address where references are to be replaced
        :param jpype.JInt or int operandIndex: the operand of the code unit at the address where
        references are to be replaced.
        """

    def replaceVariables(self, originEntryPoint: ghidra.program.model.address.Address, varList: java.util.List[ghidra.program.model.listing.Variable], monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceFunctionVariables`` replaces the
        function variables/parameters in program1 with that from the origin program.
        
        :param ghidra.program.model.address.Address originEntryPoint: the entry point address of the function to modify.
        This address should be derived from program1.
        :param java.util.List[ghidra.program.model.listing.Variable] varList: the list of variables to replace.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of progress.
        :raises CancelledException: if the user canceled the operation via the task monitor.
        """

    @property
    def originProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def errorMessage(self) -> java.lang.String:
        ...

    @property
    def resultProgram(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def infoMessage(self) -> java.lang.String:
        ...


class AddressIteratorConverter(ghidra.program.model.address.AddressIterator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, iteratorsProgram: ghidra.program.model.listing.Program, iterator: ghidra.program.model.address.AddressIterator, otherProgram: ghidra.program.model.listing.Program):
        ...


class ProgramMemoryUtil(java.lang.Object):
    """
    ``ProgramMemoryUtil`` contains some static methods for 
    checking Memory block data.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def copyBytesInRanges(toProgram: ghidra.program.model.listing.Program, fromProgram: ghidra.program.model.listing.Program, minAddr: ghidra.program.model.address.Address, maxAddr: ghidra.program.model.address.Address):
        """
        Copies the bytes to one program from another for the specified address 
        range.
        
        :param ghidra.program.model.listing.Program toProgram: program that the bytes are copied to.
        :param ghidra.program.model.listing.Program fromProgram: program the bytes are copied from.
        :param ghidra.program.model.address.Address minAddr: the minimum address of the range to be copied.
        This address should be derived from the toProgram.
        :param ghidra.program.model.address.Address maxAddr: the maximum address of the range to be copied.
        This address should be derived from the toProgram.
        :raises MemoryAccessException: if bytes can't be copied.
        """

    @staticmethod
    @typing.overload
    def copyBytesInRanges(toProgram: ghidra.program.model.listing.Program, fromProgram: ghidra.program.model.listing.Program, addrSet: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Copies the bytes to one program from another for the specified set of
        address ranges.
        
        :param ghidra.program.model.listing.Program toProgram: program that the bytes are copied to.
        :param ghidra.program.model.listing.Program fromProgram: program the bytes are copied from.
        :param ghidra.program.model.address.AddressSetView addrSet: the set of address ranges to be copied.
        The addresses in this set are derived from the "to program".
        :raises MemoryAccessException: if bytes can't be copied.
        :raises CancelledException: if user cancels copy bytes via the monitor.
        """

    @staticmethod
    @typing.overload
    def findDirectReferences(program: ghidra.program.model.listing.Program, alignment: typing.Union[jpype.JInt, int], toAddress: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> java.util.Set[ghidra.program.model.address.Address]:
        """
        Checks a programs memory for direct references to the address indicated.
        Direct references are only found at addresses that match the indicated alignment.
        
        :param ghidra.program.model.listing.Program program: the program whose memory is to be checked.
        :param jpype.JInt or int alignment: direct references are to only be found at the indicated alignment in memory.
        :param ghidra.program.model.address.Address toAddress: address that we are interested in finding references to.
        :param ghidra.util.task.TaskMonitor monitor: a task monitor for progress or to allow canceling.
        :return: list of addresses referring directly to the toAddress
        :rtype: java.util.Set[ghidra.program.model.address.Address]
        :raises CancelledException: if the user cancels via the monitor.
        """

    @staticmethod
    @typing.overload
    def findDirectReferences(program: ghidra.program.model.listing.Program, blocks: java.util.List[ghidra.program.model.mem.MemoryBlock], alignment: typing.Union[jpype.JInt, int], toAddress: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> java.util.Set[ghidra.program.model.address.Address]:
        """
        Checks a programs memory for direct references to the address indicated within the 
        listed memory blocks. If null is passed for the list of memory blocks then all of the
        program's memory blocks will be checked.
        
        Direct references are only found at addresses that match the indicated alignment.
        
        :param ghidra.program.model.listing.Program program: the program whose memory is to be checked.
        :param java.util.List[ghidra.program.model.mem.MemoryBlock] blocks: the only memory blocks to be checked. A null value indicates all memory 
        blocks should be checked.
        :param jpype.JInt or int alignment: direct references are to only be found at the indicated alignment in memory.
        :param ghidra.program.model.address.Address toAddress: address that we are interested in finding references to.
        :param ghidra.util.task.TaskMonitor monitor: a task monitor for progress or to allow canceling.
        :return: list of addresses referring directly to the toAddress
        :rtype: java.util.Set[ghidra.program.model.address.Address]
        :raises CancelledException: if the user cancels via the monitor.
        """

    @staticmethod
    def findDirectReferencesCodeUnit(program: ghidra.program.model.listing.Program, alignment: typing.Union[jpype.JInt, int], codeUnit: ghidra.program.model.listing.CodeUnit, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.program.model.address.Address]:
        """
        Checks a programs memory for direct references to the CodeUnit indicated.
        Direct references are only found at addresses that match the indicated alignment.
        
        :param ghidra.program.model.listing.Program program: the program whose memory is to be checked.
        :param jpype.JInt or int alignment: direct references are to only be found at the indicated alignment in memory.
        :param ghidra.program.model.listing.CodeUnit codeUnit: the code unit to search for references.
        :param ghidra.util.task.TaskMonitor monitor: a task monitor for progress or to allow canceling.
        :return: list of addresses referring directly to the toAddress.
        :rtype: java.util.List[ghidra.program.model.address.Address]
        """

    @staticmethod
    def findImageBaseOffsets32(program: ghidra.program.model.listing.Program, alignment: typing.Union[jpype.JInt, int], toAddress: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> java.util.Set[ghidra.program.model.address.Address]:
        """
        Checks a programs memory for 32 bit image base offset references to the address 
        indicated.  These relative references are only found at addresses that match the 
        indicated alignment.
        
        :param ghidra.program.model.listing.Program program: the program whose memory is to be checked.
        :param jpype.JInt or int alignment: 32 bit image base offset relative references are to only be found 
        at the indicated alignment in memory.
        :param ghidra.program.model.address.Address toAddress: address that we are interested in finding references to.
        :param ghidra.util.task.TaskMonitor monitor: a task monitor for progress or to allow canceling.
        :return: list of addresses with 32 bit image base offset relative references to the 
        toAddress
        :rtype: java.util.Set[ghidra.program.model.address.Address]
        :raises CancelledException: if the user cancels via the monitor.
        """

    @staticmethod
    def findString(searchString: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, blocks: java.util.List[ghidra.program.model.mem.MemoryBlock], set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.program.model.address.Address]:
        """
        Finds the string in memory indicated by the searchString limited to the indicated 
        memory blocks and address set.
        
        :param java.lang.String or str searchString: the string to find
        :param ghidra.program.model.listing.Program program: the program to search
        :param java.util.List[ghidra.program.model.mem.MemoryBlock] blocks: the only blocks to search
        :param ghidra.program.model.address.AddressSetView set: a set of the addresses to limit the results
        :param ghidra.util.task.TaskMonitor monitor: a task monitor to allow
        :return: a list of addresses where the string was found
        :rtype: java.util.List[ghidra.program.model.address.Address]
        :raises CancelledException: if the user cancels
        """

    @staticmethod
    @typing.overload
    def getAddressSet(program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.AddressSetView:
        """
        Gets the address set for the specified program.
        
        :param ghidra.program.model.listing.Program program: the program whose address set we want.
        :return: the address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @staticmethod
    @typing.overload
    def getAddressSet(program: ghidra.program.model.listing.Program, blocksWithBytes: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSet:
        """
        Gets a new address set indicating all addresses of the indicated 
        memory type in the specified program.
        
        :param ghidra.program.model.listing.Program program: the program whose address set we want.
        :param jpype.JBoolean or bool blocksWithBytes: if true, include memory blocks that have their own bytes.
        :return: the memory's address set of the indicated type.
        :rtype: ghidra.program.model.address.AddressSet
        """

    @staticmethod
    def getDirectAddressBytes(program: ghidra.program.model.listing.Program, toAddress: ghidra.program.model.address.Address) -> jpype.JArray[jpype.JByte]:
        """
        Get a representation of an address as it would appear in bytes in memory.
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address toAddress: target address
        :return: byte representation of toAddress
        :rtype: jpype.JArray[jpype.JByte]
        """

    @staticmethod
    def getImageBaseOffsets32Bytes(program: ghidra.program.model.listing.Program, alignment: typing.Union[jpype.JInt, int], toAddress: ghidra.program.model.address.Address) -> jpype.JArray[jpype.JByte]:
        ...

    @staticmethod
    def getMemBlocks(program: ghidra.program.model.listing.Program, withBytes: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[ghidra.program.model.mem.MemoryBlock]:
        """
        Gets the program memory blocks of the indicated type for the 
        specified program.
        
        :param ghidra.program.model.listing.Program program: the program whose memory blocks we want.
        :param jpype.JBoolean or bool withBytes: if true include blocks that have their own bytes. If false, include only
        blocks that don't have their own bytes (this includes bit and byte mapped blocks)
        :return: an array of program memory blocks
        :rtype: jpype.JArray[ghidra.program.model.mem.MemoryBlock]
        """

    @staticmethod
    def getMemoryBlocksStartingWithName(program: ghidra.program.model.listing.Program, set: ghidra.program.model.address.AddressSetView, name: typing.Union[java.lang.String, str], monitor: ghidra.util.task.TaskMonitor) -> java.util.List[ghidra.program.model.mem.MemoryBlock]:
        """
        Gets a list of memory blocks whose name starts with the indicated name. Only memory 
        blocks that are initialized  and part of the indicated address set will be returned.
        
        :param ghidra.program.model.listing.Program program: the program for obtaining the memory blocks
        :param ghidra.program.model.address.AddressSetView set: the address set to use to limit the blocks returned
        :param java.lang.String or str name: the text which the memory block's name must start with.
        :param ghidra.util.task.TaskMonitor monitor: a status monitor that allows the operation to be cancelled
        :return: the list of memory blocks
        :rtype: java.util.List[ghidra.program.model.mem.MemoryBlock]
        :raises CancelledException: if the user cancels
        """

    @staticmethod
    def getOverlayAddresses(program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.AddressSet:
        """
        Gets an address set with the overlay addresses that are in the specified program.
        
        :param ghidra.program.model.listing.Program program: the program
        :return: the overlay addresses within the specified program.
        :rtype: ghidra.program.model.address.AddressSet
        """

    @staticmethod
    def getShiftedDirectAddressBytes(program: ghidra.program.model.listing.Program, toAddress: ghidra.program.model.address.Address) -> jpype.JArray[jpype.JByte]:
        """
        returns shifted address bytes if they are different than un-shifted
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.Address toAddress: target address
        :return: shifted bytes, null if same as un-shifted
        :rtype: jpype.JArray[jpype.JByte]
        """

    @staticmethod
    @typing.overload
    def loadDirectReferenceList(program: ghidra.program.model.listing.Program, alignment: typing.Union[jpype.JInt, int], toAddress: ghidra.program.model.address.Address, toAddressSet: ghidra.program.model.address.AddressSetView, directReferenceList: java.util.List[ghidra.app.plugin.core.analysis.ReferenceAddressPair], monitor: ghidra.util.task.TaskMonitor):
        """
        Checks a programs memory for direct references to the addresses indicated in the toAddressSet.
        Direct references are only found at addresses that match the indicated alignment. Each
        direct reference is added to the directReferenceList as a from/to address pair.
        
        :param ghidra.program.model.listing.Program program: the program whose memory is to be checked.
        :param jpype.JInt or int alignment: direct references are to only be found at the indicated alignment in memory.
        :param ghidra.program.model.address.Address toAddress: address that we are interested in finding references to.
        :param ghidra.program.model.address.AddressSetView toAddressSet: address set indicating the addresses that we are interested in 
                finding directly referred to in memory. 
                Null if only interested in finding references to the toAddress.
        :param java.util.List[ghidra.app.plugin.core.analysis.ReferenceAddressPair] directReferenceList: the list to be populated with possible direct references
        :param ghidra.util.task.TaskMonitor monitor: a task monitor for progress or to allow cancelling.
        :raises CancelledException: if the user cancels via the monitor.
        """

    @staticmethod
    @typing.overload
    def loadDirectReferenceList(program: ghidra.program.model.listing.Program, alignment: typing.Union[jpype.JInt, int], toAddress: ghidra.program.model.address.Address, toAddressSet: ghidra.program.model.address.AddressSetView, accumulator: ghidra.util.datastruct.Accumulator[ghidra.app.plugin.core.analysis.ReferenceAddressPair], monitor: ghidra.util.task.TaskMonitor):
        """
        Checks a programs memory for direct references to the addresses indicated in the toAddressSet.
        Direct references are only found at addresses that match the indicated alignment. Each
        direct reference is added to the directReferenceList as a from/to address pair.
        
        :param ghidra.program.model.listing.Program program: the program whose memory is to be checked.
        :param jpype.JInt or int alignment: direct references are to only be found at the indicated alignment in memory.
        :param ghidra.program.model.address.Address toAddress: address that we are interested in finding references to.
        :param ghidra.program.model.address.AddressSetView toAddressSet: address set indicating the addresses that we are interested in 
                finding directly referred to in memory. 
                Null if only interested in finding references to the toAddress.
        :param ghidra.util.datastruct.Accumulator[ghidra.app.plugin.core.analysis.ReferenceAddressPair] accumulator: the datastructure to be populated with possible direct references
        :param ghidra.util.task.TaskMonitor monitor: a task monitor for progress or to allow cancelling.
        :raises CancelledException: if the user cancels via the monitor.
        """

    @staticmethod
    def locateString(searchString: typing.Union[java.lang.String, str], foundLocationConsumer: utility.function.TerminatingConsumer[ghidra.program.model.address.Address], program: ghidra.program.model.listing.Program, blocks: java.util.List[ghidra.program.model.mem.MemoryBlock], set: ghidra.program.model.address.AddressSetView, monitor: ghidra.util.task.TaskMonitor):
        """
        Finds the string in memory indicated by the searchString limited to the indicated 
        memory blocks and address set.  Each found location calls the foundLocationConsumer.consume(addr)
        method.  If the search should terminate, (ie. enough results found), then terminateRequested() should
        return true.  Requesting termination is different than a cancellation from the task monitor.
        
        :param java.lang.String or str searchString: the string to find
        :param utility.function.TerminatingConsumer[ghidra.program.model.address.Address] foundLocationConsumer: location consumer with consumer.accept(Address addr) routine defined
        :param ghidra.program.model.listing.Program program: the program to search
        :param java.util.List[ghidra.program.model.mem.MemoryBlock] blocks: the only blocks to search
        :param ghidra.program.model.address.AddressSetView set: a set of the addresses to limit the results
        :param ghidra.util.task.TaskMonitor monitor: a task monitor to allow
        :raises CancelledException: if the user cancels
        """


class MemoryRangeDiff(MemoryBlockDiff):
    """
    ``MemoryBlockDiff`` determines the types of differences between two memory blocks.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, memory1: ghidra.program.model.mem.Memory, memory2: ghidra.program.model.mem.Memory, range: ghidra.program.model.address.AddressRange):
        """
        Constructor. ``MemoryRangeDiff`` determines the types of differences 
        between two memory blocks.
        
        :param ghidra.program.model.mem.Memory memory1: the first program's memory
        :param ghidra.program.model.mem.Memory memory2: the second program's memory
        :param ghidra.program.model.address.AddressRange range: the address range where the two programs differ
        """


class InteriorSelection(java.lang.Object):
    """
    Specifies a selection that consists of components inside a structure.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, from_: ProgramLocation, to: ProgramLocation, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Construct a new interior selection.
        
        :param ProgramLocation from: start location
        :param ProgramLocation to: end location
        :param ghidra.program.model.address.Address start: start address
        :param ghidra.program.model.address.Address end: end address
        """

    def getByteLength(self) -> int:
        """
        Get the number of bytes contained in the selection.
        
        :return: int
        :rtype: int
        """

    def getEndAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the end address of this selection.
        
        :return: Address
        :rtype: ghidra.program.model.address.Address
        """

    def getFrom(self) -> ProgramLocation:
        """
        Get the start location.
        
        :return: ProgramLocation
        :rtype: ProgramLocation
        """

    def getStartAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the start address of this selection.
        
        :return: Address
        :rtype: ghidra.program.model.address.Address
        """

    def getTo(self) -> ProgramLocation:
        """
        Get the end location.
        
        :return: ProgramLocation
        :rtype: ProgramLocation
        """

    @property
    def startAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def from_(self) -> ProgramLocation:
        ...

    @property
    def byteLength(self) -> jpype.JInt:
        ...

    @property
    def to(self) -> ProgramLocation:
        ...

    @property
    def endAddress(self) -> ghidra.program.model.address.Address:
        ...


class VarnodeContext(ghidra.program.model.lang.ProcessorContext):

    @typing.type_check_only
    class TraceDepthState(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        def depth(self) -> int:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def hashCode(self) -> int:
            ...

        def state(self) -> java.util.Stack[java.util.HashMap[ghidra.program.model.address.Address, ghidra.program.model.pcode.Varnode]]:
            ...

        def toString(self) -> str:
            ...


    class_: typing.ClassVar[java.lang.Class]
    BAD_ADDRESS: typing.Final[ghidra.program.model.address.Address]
    BAD_VARNODE: typing.Final[ghidra.program.model.pcode.Varnode]
    SUSPECT_ZERO_ADDRESS: typing.Final[ghidra.program.model.address.Address]
    BAD_SPACE_ID_VALUE: typing.Final[jpype.JInt]
    debug: jpype.JBoolean

    def __init__(self, program: ghidra.program.model.listing.Program, programContext: ghidra.program.model.listing.ProgramContext, spaceProgramContext: ghidra.program.model.listing.ProgramContext, recordStartEndState: typing.Union[jpype.JBoolean, bool]):
        ...

    def add(self, val1: ghidra.program.model.pcode.Varnode, val2: ghidra.program.model.pcode.Varnode, evaluator: ContextEvaluator) -> ghidra.program.model.pcode.Varnode:
        """
        Add two varnodes together to get a new value
        This could create a new space and return a varnode pointed into that space
        
        :param ghidra.program.model.pcode.Varnode val1: first value
        :param ghidra.program.model.pcode.Varnode val2: second value
        :return: varnode that could be a constant, or an offset into a space, or null
        :rtype: ghidra.program.model.pcode.Varnode
        """

    def and_(self, val1: ghidra.program.model.pcode.Varnode, val2: ghidra.program.model.pcode.Varnode, evaluator: ContextEvaluator) -> ghidra.program.model.pcode.Varnode:
        ...

    def clearReadExecutableCode(self):
        ...

    def copy(self, out: ghidra.program.model.pcode.Varnode, in_: ghidra.program.model.pcode.Varnode, mustClearAll: typing.Union[jpype.JBoolean, bool], evaluator: ContextEvaluator):
        """
        Copy the varnode with as little manipulation as possible.
        Try to keep whatever partial state there is intact if a real value isn't required.
        
        :param ghidra.program.model.pcode.Varnode out: varnode to put it in
        :param ghidra.program.model.pcode.Varnode in: varnode to copy from.
        :param jpype.JBoolean or bool mustClearAll: true if must clear if value is not unique
        :param ContextEvaluator evaluator: user provided evaluator if needed
        """

    def createBadVarnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    def createConstantVarnode(self, value: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> ghidra.program.model.pcode.Varnode:
        ...

    @typing.overload
    def createVarnode(self, value: typing.Union[jpype.JLong, int], spaceID: typing.Union[jpype.JInt, int], size: typing.Union[jpype.JInt, int]) -> ghidra.program.model.pcode.Varnode:
        ...

    @typing.overload
    def createVarnode(self, bigVal: java.math.BigInteger, spaceVal: java.math.BigInteger, size: typing.Union[jpype.JInt, int]) -> ghidra.program.model.pcode.Varnode:
        ...

    def extendValue(self, out: ghidra.program.model.pcode.Varnode, in_: jpype.JArray[ghidra.program.model.pcode.Varnode], signExtend: typing.Union[jpype.JBoolean, bool], evaluator: ContextEvaluator) -> ghidra.program.model.pcode.Varnode:
        """
        Extend a constant value if it can be extended.
        
        :param ghidra.program.model.pcode.Varnode out: varnode to extend into (for size)
        :param jpype.JArray[ghidra.program.model.pcode.Varnode] in: varnode value to extend the size
        :return: new sign extended varnode
        :rtype: ghidra.program.model.pcode.Varnode
        """

    def flowEnd(self, address: ghidra.program.model.address.Address):
        """
        End flow and save any necessary end flow state for the current instruction at address
        """

    def flowStart(self, toAddr: ghidra.program.model.address.Address):
        """
        Start flow at an address, recording any initial state for the current instruction
        """

    def flowToAddress(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address):
        """
        Records flow from/to basic blocks, or non-fallthru flow
        """

    def getAddressSpace(self, name: typing.Union[java.lang.String, str], bitSize: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getConstant(self, vnode: ghidra.program.model.pcode.Varnode, evaluator: ContextEvaluator) -> int:
        ...

    def getCurrentInstruction(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        ...

    def getDebug(self) -> bool:
        ...

    def getEndRegisterVarnodeValue(self, reg: ghidra.program.model.lang.Register, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, signed: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.pcode.Varnode:
        """
        Get the value (value, space, size) of a register at the end of the last execution
        flow taken for the instruction at toAddr.
        
        Note: This can only be called if recordStartEndState flag is true.
        
        :param ghidra.program.model.lang.Register reg: register to retrieve the end value
        :param ghidra.program.model.address.Address fromAddr: flow from address (not used currently, future use to retrieve multiple flows)
        :param ghidra.program.model.address.Address toAddr: address of instruction to retrieve the register flow state
        :param jpype.JBoolean or bool signed: is the value signed or unsigned, will sext the top bit based on value size
        :return: instruction end state value for register, or null if no known state
        :rtype: ghidra.program.model.pcode.Varnode
        :raises UnsupportedOperationException: recordStartEndState == false at construction
        """

    def getKilledVarnodes(self, targetFunc: ghidra.program.model.listing.Function) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        """
        
        
        :param ghidra.program.model.listing.Function targetFunc: function to get killed varnodes for
         
        NOTE: this removes the return varnodes so they aren't duplicated
        :return: varnode that represents where functions place their return value
        :rtype: jpype.JArray[ghidra.program.model.pcode.Varnode]
        """

    def getKnownFlowToAddresses(self, toAddr: ghidra.program.model.address.Address) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    @typing.overload
    def getLastSetLocation(self, reg: ghidra.program.model.lang.Register, bval: java.math.BigInteger) -> ghidra.program.model.address.Address:
        """
        return the location that this register was last set
        This is a transient thing, so it should only be used as a particular flow is being processed...
        
        :param ghidra.program.model.lang.Register reg: register to find last set location
        :param java.math.BigInteger bval: value to look for to differentiate set locations, null if don't care
        :return: address that the register was set.
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def getLastSetLocation(self, rvar: ghidra.program.model.pcode.Varnode, bval: java.math.BigInteger) -> ghidra.program.model.address.Address:
        """
        return the location that this varnode was last set
        This is a transient thing, so it should only be used as a particular flow is being processed...
        
        :param ghidra.program.model.pcode.Varnode rvar: the register varnode
        :param java.math.BigInteger bval: this parameter is unused.
        :return: address that the register was set.
        :rtype: ghidra.program.model.address.Address
        """

    def getRegister(self, vnode: ghidra.program.model.pcode.Varnode) -> ghidra.program.model.lang.Register:
        """
        Return a register given a varnode
        """

    @typing.overload
    def getRegisterValue(self, reg: ghidra.program.model.lang.Register, toAddr: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the current value of the register at the address.
        Note: If recordStartEndState flag is false, then this will return the current value.
        
        :param ghidra.program.model.lang.Register reg: value of register to get
        :param ghidra.program.model.address.Address toAddr: value of register at a location
        :return: value of register or null
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @typing.overload
    def getRegisterValue(self, reg: ghidra.program.model.lang.Register, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the value of a register that was set coming from an address to an
        another address.
        Note: If recordStartEndState flag is false, then this will return the current value.
        
        :param ghidra.program.model.lang.Register reg: value of register to get
        :param ghidra.program.model.address.Address fromAddr: location the value came from
        :param ghidra.program.model.address.Address toAddr: location to get the value of the register coming from fromAddr
        :return: value of register or null
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getRegisterValueAddressRanges(self, reg: ghidra.program.model.lang.Register) -> ghidra.program.model.address.AddressRangeIterator:
        ...

    def getRegisterVarnode(self, register: ghidra.program.model.lang.Register) -> ghidra.program.model.pcode.Varnode:
        ...

    @typing.overload
    def getRegisterVarnodeValue(self, reg: ghidra.program.model.lang.Register, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, signed: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.pcode.Varnode:
        """
        Get the value (value, space, size) of a register at the start of the last execution
        flow taken for the instruction at toAddr.
        
        :param ghidra.program.model.lang.Register reg: register to retrieve the start value
        :param ghidra.program.model.address.Address fromAddr: flow from address (not used currently, future use to retrieve multiple flows)
        :param ghidra.program.model.address.Address toAddr: address of instruction to retrieve the register flow state
        :param jpype.JBoolean or bool signed: true if value is signed, will sext the top bit based on value size
        :return: instruction start state value for register, or null if no known state
        :rtype: ghidra.program.model.pcode.Varnode
        """

    @typing.overload
    def getRegisterVarnodeValue(self, register: ghidra.program.model.lang.Register) -> ghidra.program.model.pcode.Varnode:
        ...

    def getReturnVarnode(self, targetFunc: ghidra.program.model.listing.Function) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        """
        
        
        :param ghidra.program.model.listing.Function targetFunc: function to get a returning varnode for
         
        NOTE: this only gets one, unless there is custom storage on the called function
            there may be bonded ones in the default convention!
        :return: varnode that represents where functions place their return value
        :rtype: jpype.JArray[ghidra.program.model.pcode.Varnode]
        """

    def getStackRegister(self) -> ghidra.program.model.lang.Register:
        """
        
        
        :return: Register that represents the stack register
        :rtype: ghidra.program.model.lang.Register
        """

    def getStackVarnode(self) -> ghidra.program.model.pcode.Varnode:
        """
        
        
        :return: Varnode that represents the stack register
        :rtype: ghidra.program.model.pcode.Varnode
        """

    @typing.overload
    def getValue(self, varnode: ghidra.program.model.pcode.Varnode, evaluator: ContextEvaluator) -> ghidra.program.model.pcode.Varnode:
        ...

    @typing.overload
    def getValue(self, varnode: ghidra.program.model.pcode.Varnode, signed: typing.Union[jpype.JBoolean, bool], evaluator: ContextEvaluator) -> ghidra.program.model.pcode.Varnode:
        ...

    @typing.overload
    def getVarnode(self, spaceID: typing.Union[jpype.JInt, int], offset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int]) -> ghidra.program.model.pcode.Varnode:
        ...

    @typing.overload
    def getVarnode(self, space: ghidra.program.model.pcode.Varnode, offset: ghidra.program.model.pcode.Varnode, size: typing.Union[jpype.JInt, int], evaluator: ContextEvaluator) -> ghidra.program.model.pcode.Varnode:
        ...

    def hasValueOverRange(self, reg: ghidra.program.model.lang.Register, bval: java.math.BigInteger, set: ghidra.program.model.address.AddressSet) -> bool:
        ...

    def isBadAddress(self, v: ghidra.program.model.pcode.Varnode) -> bool:
        """
        Check if this is a bad address, or offset from a bad address
        
        :param ghidra.program.model.pcode.Varnode v: to check
        :return: true if should be treated as a constant for most purposes
        :rtype: bool
        """

    def isConstant(self, varnode: ghidra.program.model.pcode.Varnode) -> bool:
        """
        Check if this is a constant, or a suspect constant
        
        :param ghidra.program.model.pcode.Varnode varnode: to check
        :return: true if should be treated as a constant for most purposes
        :rtype: bool
        """

    def isExternalSpace(self, spaceID: typing.Union[jpype.JInt, int]) -> bool:
        """
        Check if the space ID is an external space.
         
        External spaces are single locations that have no size
        normally associated with a location in another program.
        
        :param jpype.JInt or int spaceID: the ID of the space
        :return: true if is a symbolic space
        :rtype: bool
        """

    def isRegister(self, varnode: ghidra.program.model.pcode.Varnode) -> bool:
        """
        Check if the varnode is associated with a register.
        
        :param ghidra.program.model.pcode.Varnode varnode: to check
        :return: true if the varnode is associated with a register
        :rtype: bool
        """

    def isStackSpaceName(self, spaceName: typing.Union[java.lang.String, str]) -> bool:
        """
        Check if spaceName is associated with the stack
        
        :param java.lang.String or str spaceName: of address space to check
        :return: true if spaceName is associated with the stack space
        :rtype: bool
        """

    def isStackSymbolicSpace(self, varnode: ghidra.program.model.pcode.Varnode) -> bool:
        """
        Check if varnode is in the stack space
        
        :param ghidra.program.model.pcode.Varnode varnode: varnode to check
        :return: true if this varnode is stored in the symbolic stack space
        :rtype: bool
        """

    def isSuspectConstant(self, varnode: ghidra.program.model.pcode.Varnode) -> bool:
        """
        Check if the constant is a suspect constant
        It shouldn't be trusted in certain cases.
        Suspect constants act like constants, but are in a Suspicious
        address space instead of the constant space.
        
        :param ghidra.program.model.pcode.Varnode varnode: varnode to check
        :return: true if varnode is a suspect constant
        :rtype: bool
        """

    def isSymbol(self, varnode: ghidra.program.model.pcode.Varnode) -> bool:
        """
        Check if the varnode is associated with a Symbolic location
        
        :param ghidra.program.model.pcode.Varnode varnode: to check
        :return: true if  the varnode is a symbolic location
        :rtype: bool
        """

    @typing.overload
    def isSymbolicSpace(self, space: ghidra.program.model.address.AddressSpace) -> bool:
        """
        Check if the space name is a symbolic space.
        A symbolic space is a space named after a register/unknown value and
        an offset into that symbolic space.
         
        Symbolic spaces come from the OffsetAddressFactory
        
        :param ghidra.program.model.address.AddressSpace space: the address space
        :return: true if is a symbolic space
        :rtype: bool
        """

    @typing.overload
    def isSymbolicSpace(self, spaceID: typing.Union[jpype.JInt, int]) -> bool:
        """
        Check if the space ID is a symbolic space.
        A symbolic space is a space named after a register/unknown value and
        an offset into that symbolic space.
         
        Symbolic spaces come from the OffsetAddressFactory
        
        :param jpype.JInt or int spaceID: the ID of the space
        :return: true if is a symbolic space
        :rtype: bool
        """

    def left(self, val1: ghidra.program.model.pcode.Varnode, val2: ghidra.program.model.pcode.Varnode, evaluator: ContextEvaluator) -> ghidra.program.model.pcode.Varnode:
        ...

    def or_(self, val1: ghidra.program.model.pcode.Varnode, val2: ghidra.program.model.pcode.Varnode, evaluator: ContextEvaluator) -> ghidra.program.model.pcode.Varnode:
        ...

    def popMemState(self):
        """
        restore a previously saved memory state
        """

    def propogateResults(self, clearContext: typing.Union[jpype.JBoolean, bool]):
        """
        Propogate any results that are in the value cache.
        
        :param jpype.JBoolean or bool clearContext: true if the cache should be cleared.
                            The propogation could be for flow purposes, and the
                            processing of the instruction is finished, so it's effects should be kept.
        """

    def propogateValue(self, reg: ghidra.program.model.lang.Register, node: ghidra.program.model.pcode.Varnode, val: ghidra.program.model.pcode.Varnode, address: ghidra.program.model.address.Address):
        ...

    def pushMemState(self):
        """
        Save the current memory state
        """

    def putValue(self, out: ghidra.program.model.pcode.Varnode, result: ghidra.program.model.pcode.Varnode, mustClear: typing.Union[jpype.JBoolean, bool]):
        ...

    def readExecutableCode(self) -> bool:
        ...

    def setCurrentInstruction(self, instr: ghidra.program.model.listing.Instruction):
        ...

    def setDebug(self, debugOn: typing.Union[jpype.JBoolean, bool]):
        ...

    def setReadExecutableCode(self):
        ...

    def splitToBytes(self, v: ghidra.program.model.pcode.Varnode, len: typing.Union[jpype.JInt, int]) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        ...

    def subtract(self, val1: ghidra.program.model.pcode.Varnode, val2: ghidra.program.model.pcode.Varnode, evaluator: ContextEvaluator) -> ghidra.program.model.pcode.Varnode:
        """
        Subtract two varnodes to get a new value
        This could create a new space and return a varnode pointed into that space
        
        :param ghidra.program.model.pcode.Varnode val1: first value
        :param ghidra.program.model.pcode.Varnode val2: second value
        :return: varnode that could be a constant, or an offset into a space
        :rtype: ghidra.program.model.pcode.Varnode
        """

    @property
    def symbol(self) -> jpype.JBoolean:
        ...

    @property
    def externalSpace(self) -> jpype.JBoolean:
        ...

    @property
    def constant(self) -> jpype.JBoolean:
        ...

    @property
    def registerValueAddressRanges(self) -> ghidra.program.model.address.AddressRangeIterator:
        ...

    @property
    def returnVarnode(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        ...

    @property
    def symbolicSpace(self) -> jpype.JBoolean:
        ...

    @property
    def registerVarnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def stackSpaceName(self) -> jpype.JBoolean:
        ...

    @property
    def stackVarnode(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def currentInstruction(self) -> ghidra.program.model.listing.Instruction:
        ...

    @currentInstruction.setter
    def currentInstruction(self, value: ghidra.program.model.listing.Instruction):
        ...

    @property
    def stackRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def registerVarnodeValue(self) -> ghidra.program.model.pcode.Varnode:
        ...

    @property
    def killedVarnodes(self) -> jpype.JArray[ghidra.program.model.pcode.Varnode]:
        ...

    @property
    def suspectConstant(self) -> jpype.JBoolean:
        ...

    @property
    def stackSymbolicSpace(self) -> jpype.JBoolean:
        ...

    @property
    def badAddress(self) -> jpype.JBoolean:
        ...

    @property
    def knownFlowToAddresses(self) -> jpype.JArray[ghidra.program.model.address.Address]:
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...


class AddressTranslationException(java.lang.RuntimeException):
    """
    Exception thrown when an attempt is made to translate an address
    from one program into an equivalent address in another program.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Construct a new AddressTranslationException with no message
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Construct a new AddressTranslationException with the given message
        
        :param java.lang.String or str msg: the exception message
        """

    @typing.overload
    def __init__(self, address: ghidra.program.model.address.Address, translator: AddressTranslator):
        """
        Construct a new AddressTranslationException with the given address and translator.
        The message will indicate there is a conflict between the two data types.
        
        :param ghidra.program.model.address.Address address: the first of the two conflicting data types. 
        (The new data type.)
        :param AddressTranslator translator: the second of the two conflicting data types. 
        (The existing data type.)
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getTranslator(self) -> AddressTranslator:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def translator(self) -> AddressTranslator:
        ...


class GhidraProgramUtilities(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getCurrentProgram(tool: ghidra.framework.plugintool.PluginTool) -> ghidra.program.model.listing.Program:
        """
        Returns the current program for the given tool or null if no program is open.
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool get the current program for
        :return: the current program for the given tool or null if no program is open
        :rtype: ghidra.program.model.listing.Program
        """

    @staticmethod
    def isAnalyzed(program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if the program has been analyzed at least once.
        
        :param ghidra.program.model.listing.Program program: the program to test to see if it has been analyzed
        :return: true if the program has been analyzed at least once.
        :rtype: bool
        """

    @staticmethod
    def markProgramAnalyzed(program: ghidra.program.model.listing.Program):
        """
        Marks the program has having been analyzed
        
        :param ghidra.program.model.listing.Program program: the program to set property
        """

    @staticmethod
    def markProgramNotToAskToAnalyze(program: ghidra.program.model.listing.Program):
        ...

    @staticmethod
    def resetAnalysisFlags(program: ghidra.program.model.listing.Program):
        """
        Resets the analysis flags to the program defaults
        With this reset, the user will be prompted to analyze the
        program the next time it is opened.
        
        :param ghidra.program.model.listing.Program program: the program whose analysis flags should be reset
        """

    @staticmethod
    def shouldAskToAnalyze(program: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if the user should be asked to analyze. They will only be asked if the program
        hasn't already been analyzed (analyzed flag property is false or null) or the
        "ask to analyze" flag property is true or null (default is true unless explicitly set to 
        false).
        
        :param ghidra.program.model.listing.Program program: the program to check for the property
        :return: true if the user should be prompted to analyze the program
        :rtype: bool
        """


class CombinedAddressRangeIterator(ghidra.program.model.address.AddressRangeIterator):

    @typing.type_check_only
    class AddressRangeManager(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def compareMax(self, mgr: CombinedAddressRangeIterator.AddressRangeManager) -> int:
            ...

        def compareMin(self, mgr: CombinedAddressRangeIterator.AddressRangeManager) -> int:
            ...

        def getNextRange(self) -> ghidra.program.model.address.AddressRange:
            ...

        def hasMoreRanges(self) -> bool:
            ...

        def severMyHeadAndAdvanceOtherManager(self, manager: CombinedAddressRangeIterator.AddressRangeManager) -> ghidra.program.model.address.AddressRange:
            """
            Makes this manager's begin range equal to that of the given manager's end range plus
            one so that this manager's next range is after the current range. The given manager's
            range is advanced to its next range. This method returns
            the current range shared by both managers before truncation.
            
            :param CombinedAddressRangeIterator.AddressRangeManager manager: The manager whose end range this manager will use for its beginning range.
            :return: The current range shared by the two managers.
            :rtype: ghidra.program.model.address.AddressRange
            """

        def severMyHeadRange(self, manager: CombinedAddressRangeIterator.AddressRangeManager) -> ghidra.program.model.address.AddressRange:
            """
            Sets this manager's begin range to be the start range of the given manager.  This method
            will return the range that exists before the begin range is adjusted.
            
            :param CombinedAddressRangeIterator.AddressRangeManager manager: The manager whose range will be used to set this manager's begin range.
            :return: The range that is the difference between this manager's original and new begin
                    range.
            :rtype: ghidra.program.model.address.AddressRange
            """

        @property
        def nextRange(self) -> ghidra.program.model.address.AddressRange:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, it1: ghidra.program.model.address.AddressRangeIterator, it2: ghidra.program.model.address.AddressRangeIterator):
        ...


class ProgramMergeFilter(java.lang.Object):
    """
    The ``ProgramMergeFilter`` is used to specify which portions of a 
    program should be merged into another program.
    It indicates the types of program differences to merge. 
    Each merge type can have its filter set to ``IGNORE`` or ``REPLACE``.
    ``IGNORE`` indicates no interest in replacing or merging that type of difference.
    ``REPLACE`` indicates to replace differences in program1 with differences of 
    that type from program2.
    Some merge types (for example, COMMENTS and SYMBOLS) allow the filter to be 
    set to ``MERGE``.
    ``MERGE`` indicates that the type should
    be taken from Program2 and merged into Program1 with whatever is alreaady there.
    """

    class_: typing.ClassVar[java.lang.Class]
    INVALID: typing.Final = -1
    """
    Indicates the merge filter difference type specified was not valid.
    """

    IGNORE: typing.Final = 0
    """
    IGNORE is a **filter value** indicating that the type of difference isn't to
    be changed in the merged program.
    """

    REPLACE: typing.Final = 1
    """
    REPLACE is a **filter value** indicating that the type of difference in program1
    should be replaced with the difference from program2.
    """

    MERGE: typing.Final = 2
    """
    MERGE is a **filter value** indicating that the type of difference should be merged 
    from program2 with what is already in program1 (the property type should be taken
    from both program1 and program2.)
    """

    PROGRAM_CONTEXT: typing.Final = 1
    """
    Indicates the **merge filter** for the program context differences.
    """

    BYTES: typing.Final = 2
    """
    Indicates the **merge filter** for the byte differences.
    """

    INSTRUCTIONS: typing.Final = 4
    """
    Indicates the **merge filter** for the instruction code unit differences.
    This includes mnemonic, operand, and value references, and equates.
    """

    DATA: typing.Final = 8
    """
    Indicates the **merge filter** for the data code unit differences.
    """

    REFERENCES: typing.Final = 16
    """
    Indicates the **merge filter** for the memory, variable, and external reference differences.
    """

    PLATE_COMMENTS: typing.Final = 32
    """
    Indicates the **merge filter** for the plate comment differences.
    """

    PRE_COMMENTS: typing.Final = 64
    """
    Indicates the **merge filter** for the pre comment differences.
    """

    EOL_COMMENTS: typing.Final = 128
    """
    Indicates the **merge filter** for the eol comment differences.
    """

    REPEATABLE_COMMENTS: typing.Final = 256
    """
    Indicates the **merge filter** for the repeatable comment differences.
    """

    POST_COMMENTS: typing.Final = 512
    """
    Indicates the **merge filter** for the post comment differences.
    """

    SYMBOLS: typing.Final = 1024
    """
    Indicates the **merge filter** for the label differences.
    """

    BOOKMARKS: typing.Final = 2048
    """
    Indicates the **merge filter** for bookmark differences.
    """

    PROPERTIES: typing.Final = 4096
    """
    Indicates the **merge filter** for the user defined property differences.
    """

    FUNCTIONS: typing.Final = 8192
    """
    Indicates the **merge filter** for the functions differences.
    """

    EQUATES: typing.Final = 16384
    """
    Indicates the **merge filter** for the equates differences.
    """

    PRIMARY_SYMBOL: typing.Final = 32768
    """
    Indicates the **merge filter** for replacing the primary symbol with the one from program 2 when merging labels.
    """

    FUNCTION_TAGS: typing.Final = 65536
    """
    Indicates the **merge filter** for function tags.
    """

    SOURCE_MAP: typing.Final = 131072
    """
    Indicates the **merge filter** for source map information.
    """

    CODE_UNITS: typing.Final = 12
    """
    Indicates to merge code unit differences. This includes instructions,
    data, and equates.
    """

    COMMENTS: typing.Final = 992
    """
    Indicates to merge all comment differences.
    """

    ALL: typing.Final = 262143
    """
    Indicates all **merge filters** for all types of differences.
    """


    @typing.overload
    def __init__(self):
        """
        Creates new ProgramMergeFilter with none of the merge types selected.
        """

    @typing.overload
    def __init__(self, filter: ProgramMergeFilter):
        """
        Creates new ProgramMergeFilter that is equal to the specified ProgramMergeFilter.
        """

    @typing.overload
    def __init__(self, type: typing.Union[jpype.JInt, int], filter: typing.Union[jpype.JInt, int]):
        """
        Creates new ProgramMergeFilter with the specified merge types selected.
        
        :param jpype.JInt or int type: the type of difference to look for between the programs.
        :param jpype.JInt or int filter: IGNORE, REPLACE, or MERGE. Indicates 
        which program difference to include of the specified type.
        If a particular type cannot be set to MERGE then it will be set to REPLACE.
        """

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Determines whether or not this filter is equal to the object that
        is passed in.
        
        :param java.lang.Object obj: the object to compare this one with.
        :return: true if the filter matches this one.
        :rtype: bool
        """

    @staticmethod
    def filterToName(type: typing.Union[jpype.JInt, int]) -> str:
        """
        ``filterToName`` returns the string associated with an
        individual (primary) merge difference setting.
        
        :param jpype.JInt or int type: the type of filter.
        Valid types are: IGNORE, REPLACE, MERGE.
        :return: the string indicating the merge difference setting.
        :rtype: str
        """

    def getFilter(self, type: typing.Union[jpype.JInt, int]) -> int:
        """
        getFilter determines whether or not the specified type of filter is set.
        Valid types are: BYTES, INSTRUCTIONS, DATA, SOURCE_MAP,
        SYMBOLS, PRIMARY_SYMBOL, COMMENTS, PROGRAM_CONTEXT, PROPERTIES, BOOKMARKS, FUNCTIONS.
        INVALID is returned if combinations of merge types (e.g. ALL) are 
        passed in.
        
        :param jpype.JInt or int type: the merge type.
        :return: IGNORE, REPLACE, or MERGE. INVALID if parameter is a combination of 
        types or not a predefined primary type.
        :rtype: int
        """

    @staticmethod
    def getPrimaryTypes() -> jpype.JArray[jpype.JInt]:
        """
        Gets all the valid individual types of differences for this filter.
        
        :return: an array containing all the currently defined primary difference 
        types.
        :rtype: jpype.JArray[jpype.JInt]
        """

    def isSet(self) -> bool:
        """
        Determines if at least one of the filter types is set to REPLACE or MERGE.
        
        :return: true if at least one type is set.
        :rtype: bool
        """

    def setFilter(self, type: typing.Union[jpype.JInt, int], filter: typing.Union[jpype.JInt, int]):
        """
        setFilter specifies whether or not the indicated type of item will
        not be included by the filter (IGNORE), replaced in the first program using the type of 
        item in the second program (REPLACE), or included from both programs (MERGE).
        Valid types are: BYTES, INSTRUCTIONS, DATA, REFERENCES,
        SYMBOLS, PRIMARY_SYMBOL, COMMENTS, PROPERTIES, BOOKMARKS, FUNCTIONS, ALL, or combinations of
        these "OR"ed together.
        if ``MERGE`` is not valid for an included primary type, then it 
        will be set to ``REPLACE`` instead for that primary type.
        
        :param jpype.JInt or int type: the type(s) of difference(s) to include.
        :param jpype.JInt or int filter: IGNORE, REPLACE, or MERGE. Indicates whether to include none, 
        one, or both programs' differences of the specified type.
        """

    def toString(self) -> str:
        """
        Returns a printable string indicating the current settings of this filter.
        
        :return: the current settings for this filter.
        :rtype: str
        """

    @staticmethod
    def typeToName(type: typing.Union[jpype.JInt, int]) -> str:
        """
        ``typeToName()`` returns the name of a predefined merge type.
        Only predefined types, as specified in ``ProgramMergeFilter``, 
        will return a name. Otherwise, an empty string is returned.
        
        :param jpype.JInt or int type: the type of merge difference whose name is wanted.
        Valid types are: BYTES, INSTRUCTIONS, DATA, REFERENCES,
        SYMBOLS, PRIMARY_SYMBOL, COMMENTS, PROGRAM_CONTEXT, PROPERTIES, BOOKMARKS, FUNCTIONS, ALL.
        :return: the name of the predefined merge difference type. 
        Otherwise, the empty string.
        :rtype: str
        """

    def validatePredefinedType(self, type: typing.Union[jpype.JInt, int]) -> bool:
        """
        validatePredefinedType determines whether or not the indicated type
        of filter item is a valid predefined type.
        Valid types are: BYTES, INSTRUCTIONS, DATA,
        SYMBOLS, PRIMARY_SYMBOL, COMMENTS, PROGRAM_CONTEXT, PROPERTIES, BOOKMARKS, FUNCTIONS, 
        SOURCE_MAP, ALL.
        
        :param jpype.JInt or int type: the type of difference to look for between the programs.
        :return: true if this is a pre-defined merge type.
        :rtype: bool
        """

    @property
    def filter(self) -> jpype.JInt:
        ...

    @property
    def set(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class OffsetAddressSpace(ghidra.program.model.address.GenericAddressSpace):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], size: typing.Union[jpype.JInt, int], type: typing.Union[jpype.JInt, int], unique: typing.Union[jpype.JInt, int]):
        ...


class ContextEvaluatorAdapter(ContextEvaluator):
    """
    Default behavior implementation of ContextEvaluator passed to SymbolicPropogator
     
    Override methods to inspect context.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class MemoryBlockDiff(java.lang.Object):
    """
    ``MemoryBlockDiff`` determines the types of differences between two memory blocks.
    """

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = 1
    START_ADDRESS: typing.Final = 2
    END_ADDRESS: typing.Final = 4
    SIZE: typing.Final = 8
    READ: typing.Final = 16
    WRITE: typing.Final = 32
    EXECUTE: typing.Final = 64
    VOLATILE: typing.Final = 128
    ARTIFICIAL: typing.Final = 256
    TYPE: typing.Final = 512
    INIT: typing.Final = 1024
    SOURCE: typing.Final = 2048
    COMMENT: typing.Final = 4096
    ALL: typing.Final = 8191

    def __init__(self, block1: ghidra.program.model.mem.MemoryBlock, block2: ghidra.program.model.mem.MemoryBlock):
        """
        Constructor. ``MemoryBlockDiff`` determines the types of differences 
        between two memory blocks.
        
        :param ghidra.program.model.mem.MemoryBlock block1: the first program's memory block
        :param ghidra.program.model.mem.MemoryBlock block2: the second program's memory block
        """

    def getDifferencesAsString(self) -> str:
        """
        Gets a string representation of the types of memory differences for this MemoryBlockDiff.
        """

    def isArtificialDifferent(self) -> bool:
        """
        Returns true if the memory blocks Artificial flags differ.
        """

    def isCommentDifferent(self) -> bool:
        """
        Returns true if the comments on the memory blocks differ.
        """

    def isEndAddressDifferent(self) -> bool:
        """
        Returns true if the end addresses of the memory blocks differ.
        """

    def isExecDifferent(self) -> bool:
        """
        Returns true if the memory blocks Execute flags differ.
        """

    def isInitDifferent(self) -> bool:
        """
        Returns true if the initialization of the memory blocks isn't the same.
        """

    def isNameDifferent(self) -> bool:
        """
        Returns true if the memory block names differ.
        """

    def isReadDifferent(self) -> bool:
        """
        Returns true if the memory blocks Read flags differ.
        """

    def isSizeDifferent(self) -> bool:
        """
        Returns true if the sizes of the memory blocks differ.
        """

    def isSourceDifferent(self) -> bool:
        """
        Returns true if the source for the memory blocks differ.
        """

    def isStartAddressDifferent(self) -> bool:
        """
        Returns true if the start addresses of the memory blocks differ.
        """

    def isTypeDifferent(self) -> bool:
        """
        Returns true if the type for the memory blocks differ.
        """

    def isVolatileDifferent(self) -> bool:
        """
        Returns true if the memory blocks Volatile flags differ.
        """

    def isWriteDifferent(self) -> bool:
        """
        Returns true if the memory blocks Write flags differ.
        """

    @property
    def nameDifferent(self) -> jpype.JBoolean:
        ...

    @property
    def sourceDifferent(self) -> jpype.JBoolean:
        ...

    @property
    def endAddressDifferent(self) -> jpype.JBoolean:
        ...

    @property
    def commentDifferent(self) -> jpype.JBoolean:
        ...

    @property
    def artificialDifferent(self) -> jpype.JBoolean:
        ...

    @property
    def execDifferent(self) -> jpype.JBoolean:
        ...

    @property
    def typeDifferent(self) -> jpype.JBoolean:
        ...

    @property
    def startAddressDifferent(self) -> jpype.JBoolean:
        ...

    @property
    def differencesAsString(self) -> java.lang.String:
        ...

    @property
    def volatileDifferent(self) -> jpype.JBoolean:
        ...

    @property
    def initDifferent(self) -> jpype.JBoolean:
        ...

    @property
    def writeDifferent(self) -> jpype.JBoolean:
        ...

    @property
    def readDifferent(self) -> jpype.JBoolean:
        ...

    @property
    def sizeDifferent(self) -> jpype.JBoolean:
        ...


class MemoryDiff(java.lang.Object):
    """
    ``MemoryDiff`` determines where the memory differs between two programs as well as the
    types of differences.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, p1: ghidra.program.model.listing.Program, p2: ghidra.program.model.listing.Program):
        """
        Constructs an object for determining memory differences between two programs.
        
        :param ghidra.program.model.listing.Program p1: the first program
        :param ghidra.program.model.listing.Program p2: the second program
        :raises ProgramConflictException: if the program memory can't be compared because the programs
        are based on different languages.
        """

    def getDifferenceInfo(self, index: typing.Union[jpype.JInt, int]) -> MemoryBlockDiff:
        """
        Gets the memory difference flags for the address range as indicated by index.
        
        :param jpype.JInt or int index: the index of the address range to get the difference flags for.
        :return: the difference flags for the indicated address range.
        :rtype: MemoryBlockDiff
        """

    def getDifferences(self, p1Address: ghidra.program.model.address.Address) -> str:
        """
        Gets a string representation of the types of memory differences that exist for the memory 
        block that contains the indicated address.
        
        :param ghidra.program.model.address.Address p1Address: address that is obtained via the first program.
        :return: a string indicating the types of memory differences.
        :rtype: str
        """

    def getDifferentAddressRanges(self) -> jpype.JArray[ghidra.program.model.address.AddressRange]:
        """
        Returns an array of address ranges where there are memory differences.
        
        :return: address ranges with differences.
        :rtype: jpype.JArray[ghidra.program.model.address.AddressRange]
        """

    def getNumRanges(self) -> int:
        """
        Gets the number of address ranges that the two programs memories are broken into for 
        comparing the programs.
        
        :return: the number of address ranges.
        :rtype: int
        """

    def getProgram1(self) -> ghidra.program.model.listing.Program:
        """
        Gets the first program that is part of this MemoryDiff.
        
        :return: the first program
        :rtype: ghidra.program.model.listing.Program
        """

    def getProgram2(self) -> ghidra.program.model.listing.Program:
        """
        Gets the second program that is part of this MemoryDiff.
        
        :return: the second program
        :rtype: ghidra.program.model.listing.Program
        """

    def getRange(self, index: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.AddressRange:
        """
        Gets the address range as indicated by index. The index is zero based. Address ranges are
        in order from the minimum address to the maximum address range.
        
        :param jpype.JInt or int index: the index of the address range to get.
        :return: the address range.
        :rtype: ghidra.program.model.address.AddressRange
        """

    def merge(self, row: typing.Union[jpype.JInt, int], mergeFields: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor) -> bool:
        ...

    @property
    def differences(self) -> java.lang.String:
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def program1(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def program2(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def differenceInfo(self) -> MemoryBlockDiff:
        ...

    @property
    def numRanges(self) -> jpype.JInt:
        ...

    @property
    def differentAddressRanges(self) -> jpype.JArray[ghidra.program.model.address.AddressRange]:
        ...


class ProgramDiffFilter(java.lang.Object):
    """
    The ``ProgramDiffFilter`` is used when determining or working with
    differences between two programs.
    It indicates the types of program differences we are interested in.
    Each difference type can be set to true, indicating interest in
    differences of that type between two programs. False indicates no interest
    in this type of program difference.
     
    Valid filter types are: 
    BOOKMARK_DIFFS, 
    BYTE_DIFFS, 
    CODE_UNIT_DIFFS, 
    EQUATE_DIFFS, 
    EOL_COMMENT_DIFFS, 
    FUNCTION_DIFFS,
    FUNCTION_TAG_DIFFS,
    PLATE_COMMENT_DIFFS, 
    POST_COMMENT_DIFFS,
    PRE_COMMENT_DIFFS,  
    PROGRAM_CONTEXT_DIFFS,
    REFERENCE_DIFFS,
    REPEATABLE_COMMENT_DIFFS, 
    SOURCE_MAP_DIFFS,
    SYMBOL_DIFFS,
    USER_DEFINED_DIFFS. 
     
    Predefined filter type combinations are:
    COMMENT_DIFFS and ALL_DIFFS.
    """

    class_: typing.ClassVar[java.lang.Class]
    PROGRAM_CONTEXT_DIFFS: typing.Final = 1
    """
    Indicates the filter for the program context (register) differences.
    """

    BYTE_DIFFS: typing.Final = 2
    """
    Indicates the filter for the byte differences.
    """

    CODE_UNIT_DIFFS: typing.Final = 4
    """
    Indicates the filter for the code unit differences.
    """

    EOL_COMMENT_DIFFS: typing.Final = 8
    """
    Indicates the filter for the end of line comment differences.
    """

    PRE_COMMENT_DIFFS: typing.Final = 16
    """
    Indicates the filter for the pre comment differences.
    """

    POST_COMMENT_DIFFS: typing.Final = 32
    """
    Indicates the filter for the post comment differences.
    """

    PLATE_COMMENT_DIFFS: typing.Final = 64
    """
    Indicates the filter for the plate comment differences.
    """

    REPEATABLE_COMMENT_DIFFS: typing.Final = 128
    """
    Indicates the filter for the repeatable comment differences.
    """

    REFERENCE_DIFFS: typing.Final = 256
    """
    Indicates the filter for memory, variable, and external reference differences.
    """

    EQUATE_DIFFS: typing.Final = 512
    """
    Indicates the filter for the equates differences.
    """

    SYMBOL_DIFFS: typing.Final = 1024
    """
    Indicates the filter for the symbol differences.
    """

    FUNCTION_DIFFS: typing.Final = 2048
    """
    Indicates the filter for the function differences.
    """

    BOOKMARK_DIFFS: typing.Final = 4096
    """
    Indicates the filter for bookmark differences.
    """

    USER_DEFINED_DIFFS: typing.Final = 8192
    """
    Indicates the filter for the user defined property differences.
    """

    FUNCTION_TAG_DIFFS: typing.Final = 16384
    """
    Indicates the filter for the function tag differences.
    """

    SOURCE_MAP_DIFFS: typing.Final = 32768
    """
    Indicates the filter for source map differences
    """

    COMMENT_DIFFS: typing.Final = 248
    """
    Indicates all comment filters.
    """

    ALL_DIFFS: typing.Final = 65535
    """
    Indicates all filters for all defined types of differences.
    """


    @typing.overload
    def __init__(self):
        """
        Creates new ProgramDiffFilter with none of the diff types selected.
        """

    @typing.overload
    def __init__(self, filter: ProgramDiffFilter):
        """
        Creates new ProgramDiffFilter equivalent to the specified ProgramDiffFilter.
        
        :param ProgramDiffFilter filter: the diff filter this one should equal.
        """

    @typing.overload
    def __init__(self, type: typing.Union[jpype.JInt, int]):
        """
        Creates new ProgramDiffFilter with the specified diff types selected.
        
        :param jpype.JInt or int type: one or more of the diff types "OR"ed together.
         
        i.e. CODE_UNIT_DIFFS | SYMBOL_DIFFS
        """

    def addToFilter(self, filter: ProgramDiffFilter):
        """
        set this filter to look for types of differences in addition to those
        types where it is already looking for differences.
        The filter that is passed as a parameter indicates the additional types
        of differences.
        
        :param ProgramDiffFilter filter: filter indicating the additional types of differences
        to look for between the programs.
        """

    def clearAll(self):
        """
        Sets all the defined types of differences to false.
        Filter indicates no interest in any difference types.
        """

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Determines whether or not this filter is equal to the object that
        is passed in.
        
        :param java.lang.Object obj: the object to compare this one with.
        :return: true if the filter matches this one.
        :rtype: bool
        """

    def getFilter(self, type: typing.Union[jpype.JInt, int]) -> bool:
        """
        getFilter determines whether or not the specified type of filter is set.
        
        :param jpype.JInt or int type: the set bits indicate the type of differences we want to 
        check as being set in the filter.
         
        For example, one or more of the diff types "OR"ed together.
         
        i.e. CODE_UNIT_DIFFS | SYMBOL_DIFFS
        :return: true if filtering for the specified type of differences.
        :rtype: bool
        """

    @staticmethod
    def getPrimaryTypes() -> jpype.JArray[jpype.JInt]:
        """
        Gets all the valid individual types of differences for this filter.
        These are also referred to as primary difference types.
        
        :return: an array containing all the currently defined difference types
        :rtype: jpype.JArray[jpype.JInt]
        """

    def selectAll(self):
        """
        Sets all the defined types of differences to true.
        Filter indicates interest in all difference types.
        """

    def setFilter(self, type: typing.Union[jpype.JInt, int], filter: typing.Union[jpype.JBoolean, bool]):
        """
        setFilter specifies whether or not the indicated type of difference will be
        included by the filter (true) or not included (false).
        
        :param jpype.JInt or int type: the set bits indicate the type of differences we want to 
        look for in the programs.
         
        For example, one or more of the diff types "OR"ed together.
         
        i.e. CODE_UNIT_DIFFS | SYMBOL_DIFFS
        :param jpype.JBoolean or bool filter: true if you want to determine differences of the specified type.
        """

    def toString(self) -> str:
        """
        Returns a string representation of the current settings for this filter.
        """

    @staticmethod
    def typeToName(type: typing.Union[jpype.JInt, int]) -> str:
        """
        ``typeToName()`` returns the name of the difference type.
        Only predefined types, as specified in ``ProgramDiffFilter``,
        will return a name. Otherwise, an empty string is returned.
        
        :param jpype.JInt or int type: the type of difference whose name is wanted.
        :return: the name of the predefined difference type. Otherwise, the empty string.
        :rtype: str
        """

    @property
    def filter(self) -> jpype.JBoolean:
        ...


class GroupView(java.io.Serializable):
    """
    Class to define a selection of GroupPath objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, paths: jpype.JArray[GroupPath]):
        """
        Constructor
        
        :param jpype.JArray[GroupPath] paths: paths in the view
        """

    @typing.overload
    def __init__(self, path: GroupPath):
        """
        Constructor for a single path in the view.
        
        :param GroupPath path: the path that is used to create this view.
        """

    def addPath(self, path: GroupPath):
        """
        Add the given group path to this view.
        
        :param GroupPath path: path to add
        """

    def equals(self, obj: java.lang.Object) -> bool:
        """
        Test if the given object is equal to this.
        """

    def getCount(self) -> int:
        """
        Get the number of paths in the view
        """

    def getPath(self, index: typing.Union[jpype.JInt, int]) -> GroupPath:
        """
        Get the path at the specified index.
        
        :param jpype.JInt or int index: the index of the desired path in the view.
        :raises ArrayIndexOutOfBoundsException: if index is invalid.
        """

    def toString(self) -> str:
        """
        Return string representation for this object.
        """

    @property
    def path(self) -> GroupPath:
        ...

    @property
    def count(self) -> jpype.JInt:
        ...


class DiffUtility(SimpleDiffUtility):
    """
    The ``DiffUtility`` class provides static methods for getting and
    creating an object in one program based on an object from another program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def compare(program1: ghidra.program.model.listing.Program, addr1: ghidra.program.model.address.Address, program2: ghidra.program.model.listing.Program, addr2: ghidra.program.model.address.Address) -> int:
        """
        Compare any two addresses from two different programs.
        
        :param ghidra.program.model.listing.Program program1: 
        :param ghidra.program.model.address.Address addr1: 
        :param ghidra.program.model.listing.Program program2: 
        :param ghidra.program.model.address.Address addr2: 
        :return: 
        :rtype: int
        """

    @staticmethod
    def createExtLocation(program: ghidra.program.model.listing.Program, extLoc: ghidra.program.model.symbol.ExternalLocation, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.ExternalLocation:
        """
        Create equivalent external location in otherProgram.
        
        :param ghidra.program.model.listing.Program program: program containing extLoc
        :param ghidra.program.model.symbol.ExternalLocation extLoc: existing external location to be copied
        :param ghidra.program.model.listing.Program otherProgram: target program
        :return: new external location
        :rtype: ghidra.program.model.symbol.ExternalLocation
        :raises InvalidInputException: if ``libraryName`` is invalid or null, or an invalid 
        ``extlabel`` is specified.  Names with spaces or the empty string are not permitted.
        Neither ``extLabel`` nor ``extAddr`` was specified properly.
        :raises DuplicateNameException: if another non-Library namespace has the same name
        """

    @staticmethod
    def createNamespace(program: ghidra.program.model.listing.Program, namespace: ghidra.program.model.symbol.Namespace, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Namespace:
        """
        Given a namespace, create the corresponding namespace in the 
        specified otherProgram. If a corresponding namespace already exists, it is returned.
        The return namespace body may be different.
        
        :param ghidra.program.model.listing.Program program: program which contains the specified namespace instance
        :param ghidra.program.model.symbol.Namespace namespace: namespace to look for
        :param ghidra.program.model.listing.Program otherProgram: other program
        :return: corresponding namespace for otherProgram or null if no such namespace exists.
        :rtype: ghidra.program.model.symbol.Namespace
        :raises InvalidInputException: if the namespace's name or path is not valid.
        :raises DuplicateNameException: if the namespace's name or path cannot be created
        due to a conflict with another namespace or symbol.
        """

    @staticmethod
    def createReference(program: ghidra.program.model.listing.Program, ref: ghidra.program.model.symbol.Reference, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Reference:
        """
        Given a reference for a specified program, create a comparable reference in the 
        specified otherProgram if possible. An open transaction on otherProgram must exist.
        
        :param ghidra.program.model.listing.Program program: program which contains the specified reference instance
        :param ghidra.program.model.symbol.Reference ref: reference to be added
        :param ghidra.program.model.listing.Program otherProgram: other program
        :return: new reference for otherProgram or null if unable to create reference.
        :rtype: ghidra.program.model.symbol.Reference
        """

    @staticmethod
    def createVariable(program: ghidra.program.model.listing.Program, var: ghidra.program.model.listing.Variable, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.listing.Variable:
        """
        Given a variable for a specified program, create a comparable variable in the 
        specified otherProgram if possible. An open transaction on otherProgram must exist.
        
        :param ghidra.program.model.listing.Program program: program which contains the specified variable instance
        :param ghidra.program.model.listing.Variable var: variable to be added from program to otherProgram.
        :param ghidra.program.model.listing.Program otherProgram: other program
        :return: new variable for otherProgram or null if unable to create variable.
        :rtype: ghidra.program.model.listing.Variable
        :raises DuplicateNameException: if another variable already exists with 
        the same name as var in the resulting function.
        :raises InvalidInputException: if data type is not a fixed length or variable name is invalid, etc.
        :raises VariableSizeException: if data type size is too large based upon storage constraints.
        """

    @staticmethod
    def getCodeUnitSet(addrSet: ghidra.program.model.address.AddressSetView, program: ghidra.program.model.listing.Program) -> ghidra.program.model.address.AddressSet:
        """
        Creates an address set that contains the entire code units within the
        program's listing that are part of the address set that is passed in.
         
        Note: This method will not remove any addresses from the address set even
        if they are not part of code units in the program's listing.
        
        :param ghidra.program.model.address.AddressSetView addrSet: The original address set that may contain portions of
        code units.
        :param ghidra.program.model.listing.Program program: the program which has the code units.
        :return: the address set that contains addresses for whole code units.
        :rtype: ghidra.program.model.address.AddressSet
        """

    @staticmethod
    @typing.overload
    def getCompatibleAddressSet(set: ghidra.program.model.address.AddressSetView, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.address.AddressSet:
        """
        Convert an address-set from one program to a compatible address-set in the 
        specified otherProgram.  Those regions which can not be mapped will be eliminated 
        from the new address-set.  Only memory addresses will be considered.
        
        :param ghidra.program.model.address.AddressSetView set: address-set corresponding to program
        :param ghidra.program.model.listing.Program otherProgram: target program which corresponds to the returned address set.
        :return: translated address-set
        :rtype: ghidra.program.model.address.AddressSet
        """

    @staticmethod
    @typing.overload
    def getCompatibleAddressSet(range: ghidra.program.model.address.AddressRange, otherProgram: ghidra.program.model.listing.Program, exactMatchOnly: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.address.AddressSet:
        """
        Convert an address range from one program to a compatible address set in the 
        specified otherProgram.  Only memory addresses will be considered.
        If none of the range can be converted then null is returned.
        
        :param ghidra.program.model.address.AddressRange range: address range to convert
        :param ghidra.program.model.listing.Program otherProgram: target program which corresponds to the returned address range.
        :param jpype.JBoolean or bool exactMatchOnly: if true and a one-to-one address mapping cannot be identified null 
        will be returned, otherwise a partial set may be returned or null if no valid translation
        was found.
        :return: compatible address set or null
        :rtype: ghidra.program.model.address.AddressSet
        """

    @staticmethod
    def getCompatibleMemoryAddress(memoryAddress: ghidra.program.model.address.Address, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address:
        """
        Determines the memory address in the other program that is compatible with the 
        specified address.
        
        :param ghidra.program.model.address.Address memoryAddress: the memory address to be converted
        :param ghidra.program.model.listing.Program otherProgram: target program which corresponds to the returned address.
        :return: the memory address derived from the other program or null if one cannot
        be determined.
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def getCompatibleProgramLocation(program: ghidra.program.model.listing.Program, location: ProgramLocation, otherProgram: ghidra.program.model.listing.Program) -> ProgramLocation:
        ...

    @staticmethod
    def getFunction(function: ghidra.program.model.listing.Function, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.listing.Function:
        """
        Given a function, get the corresponding function from the 
        specified otherProgram.  Function matchup is done based upon 
        function entry point only.  The function bodies may be different.
        
        :param ghidra.program.model.listing.Function function: function to look for
        :param ghidra.program.model.listing.Program otherProgram: other program
        :return: corresponding function for otherProgram or null if no such function exists.
        :rtype: ghidra.program.model.listing.Function
        """

    @staticmethod
    def getNamespace(namespace: ghidra.program.model.symbol.Namespace, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Namespace:
        """
        Given a namespace, get the corresponding namespace from the 
        specified otherProgram.  The return namespace body may be different.
        
        :param ghidra.program.model.symbol.Namespace namespace: namespace to look for
        :param ghidra.program.model.listing.Program otherProgram: other program
        :return: corresponding namespace for otherProgram or null if no such namespace exists.
        :rtype: ghidra.program.model.symbol.Namespace
        """

    @staticmethod
    @typing.overload
    def getReference(program: ghidra.program.model.listing.Program, ref: ghidra.program.model.symbol.Reference, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Reference:
        """
        Given a reference for a specified program, get the corresponding reference from the 
        specified otherProgram.  A Non-memory reference is considered a suitable reference
        for returning if its destination address is from the same address space (i.e., stack, 
        register, etc.)
        
        :param ghidra.program.model.listing.Program program: program which contains the specified reference instance
        :param ghidra.program.model.symbol.Reference ref: reference to look for
        :param ghidra.program.model.listing.Program otherProgram: other program
        :return: corresponding reference for otherProgram or null if no such reference exists.
        :rtype: ghidra.program.model.symbol.Reference
        """

    @staticmethod
    @typing.overload
    def getReference(p2ToP1Translator: AddressTranslator, p2Ref: ghidra.program.model.symbol.Reference) -> ghidra.program.model.symbol.Reference:
        """
        Translate reference from program p2 to target program p1
        
        :param AddressTranslator p2ToP1Translator: program address translater
        :param ghidra.program.model.symbol.Reference p2Ref: original reference to be copied
        :return: translated reference or null
        :rtype: ghidra.program.model.symbol.Reference
        """

    @staticmethod
    @typing.overload
    def getUserToAddressString(program: ghidra.program.model.listing.Program, ref: ghidra.program.model.symbol.Reference) -> str:
        """
        Returns the string representation of the specified reference's "to" address.
        
        :param ghidra.program.model.listing.Program program: the program containing the reference
        :param ghidra.program.model.symbol.Reference ref: the reference
        :return: the "to" address for the reference as a meaningful address for the user.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getUserToAddressString(program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address) -> str:
        """
        Returns a string representation of the specified address.
        
        :param ghidra.program.model.listing.Program program: the program containing the address
        :param ghidra.program.model.address.Address address: the address
        :return: the address as a meaningful string for the user.
        :rtype: str
        """

    @staticmethod
    def getUserToSymbolString(program: ghidra.program.model.listing.Program, ref: ghidra.program.model.symbol.Reference) -> str:
        """
        Returns the string representation of the specified reference's "to" symbol.
        
        :param ghidra.program.model.listing.Program program: the program containing the reference
        :param ghidra.program.model.symbol.Reference ref: the reference
        :return: the "to" symbol for the reference as a meaningful string for the user. 
        The empty string, "", is returned if the reference isn't to a symbol.
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getVariable(program: ghidra.program.model.listing.Program, var: ghidra.program.model.listing.Variable, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.listing.Variable:
        """
        Given a variable for a specified program, get the corresponding variable from the 
        specified otherProgram.
        
        :param ghidra.program.model.listing.Program program: program which contains the specified variable instance
        :param ghidra.program.model.listing.Variable var: variable to look for
        :param ghidra.program.model.listing.Program otherProgram: other program
        :return: corresponding variable for otherProgram or null if no such variable exists.
        :rtype: ghidra.program.model.listing.Variable
        """

    @staticmethod
    @typing.overload
    def getVariable(var: ghidra.program.model.listing.Variable, otherFunction: ghidra.program.model.listing.Function) -> ghidra.program.model.listing.Variable:
        """
        Given a variable, get the corresponding variable from the 
        specified otherFunction.
        
        :param ghidra.program.model.listing.Variable var: variable to look for
        :param ghidra.program.model.listing.Function otherFunction: other function
        :return: corresponding variable for otherFunction or null if no such variable exists.
        :rtype: ghidra.program.model.listing.Variable
        """

    @staticmethod
    @typing.overload
    def toSignedHexString(value: typing.Union[jpype.JInt, int]) -> str:
        """
        Returns the signed hex string representing the int value. 
        Positive values are represented beginning with 0x. (i.e. value of 12 would be 0xc)
        Negative values are represented beginning with -0x. (i.e. value of -12 would be -0xc)
        
        :param jpype.JInt or int value: the value
        :return: the signed hex string
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def toSignedHexString(value: typing.Union[jpype.JLong, int]) -> str:
        """
        Returns the signed hex string representing the long value. 
        Positive values are represented beginning with 0x. (i.e. value of 12 would be 0xc)
        Negative values are represented beginning with -0x. (i.e. value of -12 would be -0xc)
        
        :param jpype.JLong or int value: the value
        :return: the signed hex string
        :rtype: str
        """

    @staticmethod
    def variableStorageMatches(var1: ghidra.program.model.listing.Variable, var2: ghidra.program.model.listing.Variable) -> bool:
        """
        Determine if the specified variables have exactly the same storage.  This method
        should not be used with caution if both arguments are parameters which use dynamically 
        mapped storage.
        
        :param ghidra.program.model.listing.Variable var1: 
        :param ghidra.program.model.listing.Variable var2: 
        :return: true if variables have matching storage, else false
        :rtype: bool
        """

    @staticmethod
    def variableStorageOverlaps(var1: ghidra.program.model.listing.Variable, var2: ghidra.program.model.listing.Variable) -> bool:
        """
        Determine if the specified variables have overlapping storage.
        Variable storage check includes dynamically mapped storage for parameters.  This method
        should not be used with caution if both arguments are parameters which use dynamically 
        mapped storage.
        
        :param ghidra.program.model.listing.Variable var1: 
        :param ghidra.program.model.listing.Variable var2: 
        :return: true if variables overlap, else false
        :rtype: bool
        """


class SymbolicPropogator(java.lang.Object):

    class Value(java.lang.Object):
        """
        ``Value`` corresponds to a constant value or register relative value.
        
        
        .. seealso::
        
            | :obj:`SymbolicPropogator.getRegisterValue(Address, Register)`
        """

        class_: typing.ClassVar[java.lang.Class]

        def getRelativeRegister(self) -> ghidra.program.model.lang.Register:
            """
            
            
            :return: relative-register or null if this Value is a simple constant.
            :rtype: ghidra.program.model.lang.Register
            """

        def getValue(self) -> int:
            """
            
            
            :return: constant value.  This value is register-relative
            if isRegisterRelativeValue() returns true.
            :rtype: int
            """

        def isRegisterRelativeValue(self) -> bool:
            """
            
            
            :return: true if value is relative to a particular input register.
            :rtype: bool
            
            .. seealso::
            
                | :obj:`.getRelativeRegister()`
            """

        @property
        def registerRelativeValue(self) -> jpype.JBoolean:
            ...

        @property
        def relativeRegister(self) -> ghidra.program.model.lang.Register:
            ...

        @property
        def value(self) -> jpype.JLong:
            ...


    @typing.type_check_only
    class SavedFlowState(java.lang.Record):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, vContext: VarnodeContext, flowType: ghidra.program.model.symbol.FlowType, source: ghidra.program.model.address.Address, destination: ghidra.program.model.address.Address, continueAfterHittingFlow: typing.Union[jpype.JInt, int]):
            ...

        @typing.overload
        def __init__(self, vContext: VarnodeContext, flowType: ghidra.program.model.symbol.FlowType, source: ghidra.program.model.address.Address, destination: ghidra.program.model.address.Address, pcodeIndex: typing.Union[jpype.JInt, int], continueAfterHittingFlow: typing.Union[jpype.JInt, int]):
            ...

        def continueAfterHittingFlow(self) -> int:
            ...

        def destination(self) -> ghidra.program.model.address.Address:
            ...

        def equals(self, o: java.lang.Object) -> bool:
            ...

        def flowType(self) -> ghidra.program.model.symbol.FlowType:
            ...

        def hashCode(self) -> int:
            ...

        def isContinueAfterHittingFlow(self) -> bool:
            ...

        def pcodeIndex(self) -> int:
            ...

        def restoreState(self):
            ...

        def source(self) -> ghidra.program.model.address.Address:
            ...

        def toString(self) -> str:
            ...

        def vContext(self) -> VarnodeContext:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Create SymbolicPropagator for program.
         
        This will record all values at the beginning and ending of instructions.
        Recording all values can take more time and memory.  So if the SymbolicEvaluator
        callback mechanism is being used, use the alternate constructor with false for
        recordStartEndState.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, recordStartEndState: typing.Union[jpype.JBoolean, bool]):
        """
        Create SymbolicPropagator for program either recording or start/end state at each instruction.
         
        NOTE: if you are going to inspect values at instructions after :obj:`SymbolicPropogator`.flowConstants()
        has completed, then you should pass true for recordStartEndState.  If you are using a custom
        SymbolicEvaluator with the flowConstants() method, then you should pass false.
        
        :param ghidra.program.model.listing.Program program: program
        :param jpype.JBoolean or bool recordStartEndState: - true to record the value of each register at the start/end of each
                            instruction This will use more memory and be slightly slower.  If inspecting
                            values after flowContants() has completed, you must pass true.
        """

    def encounteredBranch(self) -> bool:
        """
        
        
        :return: true if any branching instructions have been encountered
        :rtype: bool
        """

    @typing.overload
    def flowConstants(self, startAddr: ghidra.program.model.address.Address, restrictSet: ghidra.program.model.address.AddressSetView, eval: ContextEvaluator, saveContext: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSet:
        """
        Process a subroutine using the processor function.
        The process function can control what flows are followed and when to stop.
        
        :param ghidra.program.model.address.Address startAddr: start address
        :param ghidra.program.model.address.AddressSetView restrictSet: the address set to restrict the constant flow to
        :param ContextEvaluator eval: the context evaluator to use
        :param jpype.JBoolean or bool saveContext: true if the context should be saved
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the address set of instructions that were followed
        :rtype: ghidra.program.model.address.AddressSet
        :raises CancelledException: if the task is cancelled
        """

    @typing.overload
    def flowConstants(self, startAddr: ghidra.program.model.address.Address, restrictSet: ghidra.program.model.address.AddressSetView, eval: ContextEvaluator, vContext: VarnodeContext, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSet:
        ...

    @typing.overload
    def flowConstants(self, fromAddr: ghidra.program.model.address.Address, startAddr: ghidra.program.model.address.Address, restrictSet: ghidra.program.model.address.AddressSetView, eval: ContextEvaluator, vContext: VarnodeContext, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.AddressSet:
        ...

    def getEndRegisterValue(self, toAddr: ghidra.program.model.address.Address, reg: ghidra.program.model.lang.Register) -> SymbolicPropogator.Value:
        """
        Get constant or register relative value assigned to the 
        specified register at the specified address after the instruction has executed.
        Note: This can only be called if recordStartEndState flag is true.
        
        :param ghidra.program.model.address.Address toAddr: address
        :param ghidra.program.model.lang.Register reg: register
        :return: register value
        :rtype: SymbolicPropogator.Value
        :raises UnsupportedOperationException: recordStartEndState == false at construction
        """

    def getFunctionAt(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Function:
        ...

    def getInstructionAt(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        ...

    def getInstructionContaining(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.listing.Instruction:
        ...

    def getInstructionPcode(self, instruction: ghidra.program.model.listing.Instruction) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        ...

    def getRegisterValue(self, toAddr: ghidra.program.model.address.Address, reg: ghidra.program.model.lang.Register) -> SymbolicPropogator.Value:
        """
        Get constant or register relative value assigned to the 
        specified register at the specified address.
         
        Note: This can only be called safely if recordStartEndState flag is true.
        Otherwise it will just return the current value, not the value at the given address.
        
        :param ghidra.program.model.address.Address toAddr: address
        :param ghidra.program.model.lang.Register reg: register
        :return: register value
        :rtype: SymbolicPropogator.Value
        """

    def getRegisterValueRepresentation(self, addr: ghidra.program.model.address.Address, reg: ghidra.program.model.lang.Register) -> str:
        """
        Do not depend on this method!  For display debugging purposes only.
        This will change.
        
        :param ghidra.program.model.address.Address addr: 
        :param ghidra.program.model.lang.Register reg: 
        :return: 
        :rtype: str
        """

    @typing.overload
    def makeReference(self, varnodeContext: VarnodeContext, instruction: ghidra.program.model.listing.Instruction, opIndex: typing.Union[jpype.JInt, int], vt: ghidra.program.model.pcode.Varnode, dataType: ghidra.program.model.data.DataType, refType: ghidra.program.model.symbol.RefType, pcodeop: typing.Union[jpype.JInt, int], knownReference: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.Address:
        """
        Make from the instruction to the reference based on the varnode passed in.
        
        :param VarnodeContext varnodeContext: - context to use for any other infomation needed
        :param ghidra.program.model.listing.Instruction instruction: - instruction to place the reference on.
        :param jpype.JInt or int pcodeop: - pcode op that caused the reference
        :param jpype.JInt or int opIndex: - operand it should be placed on, or -1 if unknown
        :param ghidra.program.model.pcode.Varnode vt: - place to reference, could be a full address, or just a constant
        :param ghidra.program.model.symbol.RefType refType: - type of reference
        :param jpype.JBoolean or bool knownReference: true if this is a know good address, speculative otherwise
        :param ghidra.util.task.TaskMonitor monitor: to cancel
        :return: address that was marked up, null otherwise
        :rtype: ghidra.program.model.address.Address
        """

    @typing.overload
    def makeReference(self, vContext: VarnodeContext, instruction: ghidra.program.model.listing.Instruction, opIndex: typing.Union[jpype.JInt, int], knownSpaceID: typing.Union[jpype.JLong, int], wordOffset: typing.Union[jpype.JLong, int], size: typing.Union[jpype.JInt, int], dataType: ghidra.program.model.data.DataType, refType: ghidra.program.model.symbol.RefType, pcodeop: typing.Union[jpype.JInt, int], knownReference: typing.Union[jpype.JBoolean, bool], preExisting: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.address.Address:
        """
        Make a reference from the instruction to the address based on the spaceID,offset passed in.
        This could make a reference into an overlay (overriding the spaceID), or into memory, if
        spaceID is a constant space.
        The target could be an external Address carried along and then finally used.
        External addresses are OK as long as nothing is done to the offset.
        
        :param VarnodeContext vContext: - context to use for any other information needed
        :param ghidra.program.model.listing.Instruction instruction: - instruction to place the reference on.
        :param jpype.JInt or int opIndex: - operand it should be placed on, or -1 if unknown
        :param jpype.JLong or int knownSpaceID: target space ID or -1 if only offset is known
        :param jpype.JLong or int wordOffset: - target offset that is word addressing based
        :param jpype.JInt or int size: - size of the access to the location
        :param ghidra.program.model.symbol.RefType refType: - type of reference
        :param jpype.JInt or int pcodeop: - op that caused the reference
        :param jpype.JBoolean or bool knownReference: - true if reference is known to be a real reference, not speculative
        :param jpype.JBoolean or bool preExisting: preExisting reference
        :param ghidra.util.task.TaskMonitor monitor: - the task monitor
        :return: address that was marked up, null otherwise
        :rtype: ghidra.program.model.address.Address
        """

    def readExecutable(self) -> bool:
        """
        
        
        :return: return true if the code ever read from an executable location
        :rtype: bool
        """

    def setDebug(self, debug: typing.Union[jpype.JBoolean, bool]):
        ...

    def setParamPointerRefCheck(self, checkParamRefsOption: typing.Union[jpype.JBoolean, bool]):
        """
        enable/disable creating param references for constants
        only if the function parameter is specified as a known pointer
        
        :param jpype.JBoolean or bool checkParamRefsOption: true to enable
        """

    def setParamRefCheck(self, checkParamRefsOption: typing.Union[jpype.JBoolean, bool]):
        """
        enable/disable checking parameters for constant references
        
        :param jpype.JBoolean or bool checkParamRefsOption: true to enable
        """

    def setRegister(self, addr: ghidra.program.model.address.Address, stackReg: ghidra.program.model.lang.Register):
        ...

    def setReturnRefCheck(self, checkReturnRefsOption: typing.Union[jpype.JBoolean, bool]):
        """
        enable/disable checking return for constant references
        
        :param jpype.JBoolean or bool checkReturnRefsOption: true if enable check return for constant references
        """

    def setStoredRefCheck(self, checkStoredRefsOption: typing.Union[jpype.JBoolean, bool]):
        """
        enable/disable checking stored values for constant references
        
        :param jpype.JBoolean or bool checkStoredRefsOption: true if enable check for stored values for constant references
        """

    @property
    def instructionAt(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def functionAt(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def instructionContaining(self) -> ghidra.program.model.listing.Instruction:
        ...

    @property
    def instructionPcode(self) -> jpype.JArray[ghidra.program.model.pcode.PcodeOp]:
        ...


class MultiCodeUnitIterator(java.lang.Object):
    """
    ``MultiCodeUnitIterator`` is a class for iterating through multiple
    code unit iterators simultaneously. The next() method returns an array 
    of code units, since a code unit can be obtained from neither, either, or
    both of the original code unit iterators.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, listings: jpype.JArray[ghidra.program.model.listing.Listing], addr: ghidra.program.model.address.Address, forward: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor of a multi-code unit iterator.
        
        :param jpype.JArray[ghidra.program.model.listing.Listing] listings: an array of the program listings whose code units are to be iterated.
        :param ghidra.program.model.address.Address addr: the address where the iterator should start.
        :param jpype.JBoolean or bool forward: true indicates a forward iterator.  false indicates a backwards iterator.
        """

    @typing.overload
    def __init__(self, listings: jpype.JArray[ghidra.program.model.listing.Listing], addrs: ghidra.program.model.address.AddressSetView, forward: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor of a multi-code unit iterator.
        
        :param jpype.JArray[ghidra.program.model.listing.Listing] listings: an array of the program listings whose code units are to be iterated.
        :param ghidra.program.model.address.AddressSetView addrs: the address set over which the code units should be iterated.
        :param jpype.JBoolean or bool forward: true indicates a forward iterator.  false indicates a backwards iterator.
        """

    def hasNext(self) -> bool:
        """
        Determines whether or not any of the iterators have a
        next code unit.
        
        :return: true if the next code unit can be obtained from any of
        the code unit iterators.
        :rtype: bool
        """

    def next(self) -> jpype.JArray[ghidra.program.model.listing.CodeUnit]:
        """
        Returns the next code unit(s). The next code unit could be from any one 
        or more of the iterators. The array returns a code unit for each listing
        that has a code unit with a minimum address at the next iterator address.
        The code units in the array match up to the listings in the array passed 
        to this classes constructor. The code unit will be null in the array if
        no code unit started at the next code unit address for that listing.
        
        :return: an array with the next code unit(s).
        :rtype: jpype.JArray[ghidra.program.model.listing.CodeUnit]
        """


class MnemonicFieldLocation(CodeUnitLocation):
    """
    The ``MnemonicFieldLocation`` class contains specific location
    information within the MNEMONIC field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], mnemonicString: typing.Union[java.lang.String, str], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new MnemonicFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of the location; should not be null
        :param jpype.JArray[jpype.JInt] componentPath: array of indexes for each nested data component; the
                    index is the data component's index within its parent; may be
                    null
        :param java.lang.String or str mnemonicString: the mnemonic string
        :param jpype.JInt or int charOffset: the character position within the mnemonic string for
                    this location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, refAddr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], mnemonicString: typing.Union[java.lang.String, str], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new MnemonicFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of the location; should not be null
        :param ghidra.program.model.address.Address refAddr: the "referred to" address if the location is over a
                    reference; may be null
        :param jpype.JArray[jpype.JInt] componentPath: array of indexes for each nested data component; the
                    index is the data component's index within its parent; may be
                    null
        :param java.lang.String or str mnemonicString: the mnemonic string
        :param jpype.JInt or int charOffset: the character position within the mnemonic string for
                    this location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, address: ghidra.program.model.address.Address):
        """
        
        
        
        .. seealso::
        
            | :obj:`ProgramLocation.ProgramLocation(Program, Address)`
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring a mnemonic field location from
        XML.
        """

    def getMnemonic(self) -> str:
        """
        Returns the mnemonic string at this location.
        """

    def toString(self) -> str:
        """
        Returns a String representation of this location.
        """

    @property
    def mnemonic(self) -> java.lang.String:
        ...


class AddressExpressionValue(generic.expressions.ExpressionValue):
    """
    Address operand values. See :obj:`ExpressionValue`. Defines supported operators and other
    operands for expression values that are addresses.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, address: ghidra.program.model.address.Address):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...


class SubDataFieldLocation(CodeUnitLocation):
    """
    The ``SubDataFieldLocation`` class contains specific location information
    within the Sub-data field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, path: GroupPath, componentPath: jpype.JArray[jpype.JInt], refAddr: ghidra.program.model.address.Address, rep: typing.Union[java.lang.String, str], charOffset: typing.Union[jpype.JInt, int], fieldName: typing.Union[java.lang.String, str]):
        """
        Construct a new SubDataFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of the location
        :param GroupPath path: path associated with the address (an address could
        appear at more than one group path); may be null
        :param jpype.JArray[jpype.JInt] componentPath: array of indexes for each nested data component;
        the index is the data component's index within its parent; may be null
        :param ghidra.program.model.address.Address refAddr: the "referred to" address if the location is
        over a reference; may be null
        :param java.lang.String or str rep: the String representation of the operand.
        :param jpype.JInt or int charOffset: the character position within the operand string.
        :param java.lang.String or str fieldName: the name of the sub-data field
        """

    @typing.overload
    def __init__(self):
        """
        Should only be used by XML restoration.
        """

    def getDataRepresentation(self) -> str:
        """
        Returns a string representation of the dataValue at this location.
        """

    def getFieldName(self) -> str:
        """
        Returns the name of the sub-data field.
        """

    def toString(self) -> str:
        """
        Returns a String representation of this location.
        """

    @property
    def fieldName(self) -> java.lang.String:
        ...

    @property
    def dataRepresentation(self) -> java.lang.String:
        ...


class CodeUnitUserDataChangeRecord(ghidra.framework.model.DomainObjectChangeRecord):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, propertyName: typing.Union[java.lang.String, str], codeUnitAddr: ghidra.program.model.address.Address, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Constructor
        
        :param java.lang.String or str propertyName: name of the property
        :param ghidra.program.model.address.Address codeUnitAddr: address of the code unit
        :param java.lang.Object oldValue: old value
        :param java.lang.Object newValue: new value
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the address of the code unit for this property change.
        
        :return: the address of the code unit for this property change
        :rtype: ghidra.program.model.address.Address
        """

    def getPropertyName(self) -> str:
        """
        Get the name of the property being changed.
        
        :return: the name of the property being changed
        :rtype: str
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def propertyName(self) -> java.lang.String:
        ...


class FunctionInlineFieldLocation(FunctionSignatureFieldLocation):
    """
    The ``FunctionInlineFieldLocation`` class provides specific information
    about the Function Inline field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str]):
        """
        Construct a new FunctionInlineFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int charOffset: the position within the function inline string for this location.
        :param java.lang.String or str signature: the function signature string at this location.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """


class CommentFieldLocation(CodeUnitLocation):
    """
    The ``CommentFieldLocation`` class contains specific location information
    within the COMMENTS field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], comment: jpype.JArray[java.lang.String], type: ghidra.program.model.listing.CommentType, row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new CommentFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of the location; should not be null
        hierarchy names; this parameter may be null
        :param jpype.JArray[jpype.JInt] componentPath: if not null, it is the array of indexes that point
        to a specific data type inside of another data type
        :param jpype.JArray[java.lang.String] comment: The array of strings that make up the comment
        :param ghidra.program.model.listing.CommentType type: The type of this comment (null for no-comment type)
        :param jpype.JInt or int row: The index of the string that contains the exact location.
        :param jpype.JInt or int charOffset: The position within the string that specifies the exact location.
        :raises IllegalArgumentException: Thrown if type is not one of the comment values given in ``CodeUnit``
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a comment field location from XML.
        """

    def getComment(self) -> jpype.JArray[java.lang.String]:
        """
        Returns the array of strings that make up the comment.
        
        :return: the comment
        :rtype: jpype.JArray[java.lang.String]
        """

    def getCommentType(self) -> ghidra.program.model.listing.CommentType:
        """
        :return: the comment type or null if no-comment.
        :rtype: ghidra.program.model.listing.CommentType
        """

    def toString(self) -> str:
        """
        Returns a String representation of this location.
        """

    @property
    def commentType(self) -> ghidra.program.model.listing.CommentType:
        ...

    @property
    def comment(self) -> jpype.JArray[java.lang.String]:
        ...


class InstructionUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getFormatedInstructionObjects(instr: ghidra.program.model.listing.Instruction, input: typing.Union[jpype.JBoolean, bool]) -> jpype.JArray[java.lang.String]:
        """
        Format instruction input or result objects
        
        :param ghidra.program.model.listing.Instruction instr: instruction
        :param jpype.JBoolean or bool input: input objects if true else result objects
        :return: formatted array of strings
        :rtype: jpype.JArray[java.lang.String]
        """

    @staticmethod
    def getFormatedOperandObjects(instr: ghidra.program.model.listing.Instruction, opIndex: typing.Union[jpype.JInt, int]) -> jpype.JArray[java.lang.String]:
        """
        Format instruction operand objects
        
        :param ghidra.program.model.listing.Instruction instr: instruction
        :param jpype.JInt or int opIndex: the operand index
        :return: formatted array of strings
        :rtype: jpype.JArray[java.lang.String]
        """

    @staticmethod
    def getFormattedContextRegisterValueBreakout(instr: ghidra.program.model.listing.Instruction, indent: typing.Union[java.lang.String, str]) -> str:
        """
        Get formatted context register as list of child register values
        
        :param ghidra.program.model.listing.Instruction instr: 
        :return: formatted context data
        :rtype: str
        """

    @staticmethod
    def getFormattedInstructionDetails(instruction: ghidra.program.model.listing.Instruction, debug: ghidra.app.plugin.processors.sleigh.SleighDebugLogger) -> str:
        """
        Get details instruction info as formatted text
        
        :param ghidra.program.model.listing.Instruction instruction: 
        :param ghidra.app.plugin.processors.sleigh.SleighDebugLogger debug: SleighDebugerLogger for specified instruction or null
        :return: instruction details
        :rtype: str
        """

    @staticmethod
    def getFormattedRegisterValueBits(value: ghidra.program.model.lang.RegisterValue, indent: typing.Union[java.lang.String, str]) -> str:
        """
        Get formatted RegisterValue as list of child register values
        
        :param ghidra.program.model.lang.RegisterValue value: 
        :return: 
        :rtype: str
        """


class OldLanguageFactory(java.lang.Object):

    @typing.type_check_only
    class LanguageTag(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    OLD_LANGUAGE_FILE_EXT: typing.Final = ".lang"

    @staticmethod
    def createOldLanguageFile(lang: ghidra.program.model.lang.Language, file: jpype.protocol.SupportsPath):
        """
        Create old-language file for the specified language.
        
        :param ghidra.program.model.lang.Language lang: language
        :param jpype.protocol.SupportsPath file: output file
        :raises IOException: if file error occurs
        :raises LanguageNotFoundException: if lang is unknown to DefaultLanguageService
        """

    def getLatestOldLanaguageDescriptions(self) -> jpype.JArray[ghidra.program.model.lang.LanguageDescription]:
        """
        Return the Language Descriptions for the latest version of all old languages.
        """

    def getLatestOldLanguage(self, languageID: ghidra.program.model.lang.LanguageID) -> ghidra.program.model.lang.LanguageDescription:
        """
        Return language description for the latest version of an old language
        
        :param ghidra.program.model.lang.LanguageID languageID: 
        :return: old language description or null if specification not found.
        :rtype: ghidra.program.model.lang.LanguageDescription
        """

    def getOldLanguage(self, languageID: ghidra.program.model.lang.LanguageID, majorVersion: typing.Union[jpype.JInt, int]) -> ghidra.program.model.lang.Language:
        """
        Return old language if an old language specification file exists for the specified language and version.
        
        :param ghidra.program.model.lang.LanguageID languageID: 
        :param jpype.JInt or int majorVersion: language major version, or -1 for latest version
        :return: old language or null if specification not found.
        :rtype: ghidra.program.model.lang.Language
        """

    @staticmethod
    def getOldLanguageFactory() -> OldLanguageFactory:
        """
        Returns the single instance of the OldLanguageFactory.
        """

    @property
    def latestOldLanguage(self) -> ghidra.program.model.lang.LanguageDescription:
        ...

    @property
    def latestOldLanaguageDescriptions(self) -> jpype.JArray[ghidra.program.model.lang.LanguageDescription]:
        ...


class FunctionStartParametersFieldLocation(FunctionSignatureFieldLocation):
    """
    The ``FunctionStartParametersFieldLocation`` class provides a field 
    for the open parenthesis of a function within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str]):
        """
        Construct a new FunctionStartParametersFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int charOffset: the position within the function name string for this location.
        :param java.lang.String or str signature: the function signature
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """


class IndentFieldLocation(CodeUnitLocation):
    """
    The ``IndentFieldLocation`` class contains specific location information
    within the indent field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt]):
        """
        Construct a new IndentFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of the location; should not be null
        fragment by its hierarchy names; this parameter may be null
        :param jpype.JArray[jpype.JInt] componentPath: array of indexes for each nested data component; the
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        an indent field location from XML
        """


class ListingAddressCorrelation(java.lang.Object):
    """
    This is the interface for a correlator that associates addresses from one program with
    addresses from another program or it can associate addresses from one part of a program 
    with addresses from another part of the same program. Given an address from one program, it
    can provide the corresponding address for the other program. The two programs are referred to
    as the LEFT program and the RIGHT program. See :obj:`ghidra.util.datastruct.Duo.Side`
    """

    class_: typing.ClassVar[java.lang.Class]

    def getAddress(self, side: ghidra.util.datastruct.Duo.Side, otherSideAddress: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Gets the address for the given side that matches the given address from the other side.
        
        :param ghidra.util.datastruct.Duo.Side side: the side to get an address for
        :param ghidra.program.model.address.Address otherSideAddress: the address from the other side to find a match for
        :return: the address for the given side that matches the given address from the other side.
        :rtype: ghidra.program.model.address.Address
        """

    def getAddresses(self, side: ghidra.util.datastruct.Duo.Side) -> ghidra.program.model.address.AddressSetView:
        """
        Gets the addresses that are part of the correlator for the given side
        
        :param ghidra.util.datastruct.Duo.Side side: LEFT or RIGHT
        :return: the addresses that are part of the correlator for the given side
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getFunction(self, side: ghidra.util.datastruct.Duo.Side) -> ghidra.program.model.listing.Function:
        """
        Gets the function for the given side. This will be null if the addresses are not function
        based.
        
        :param ghidra.util.datastruct.Duo.Side side: LEFT or RIGHT
        :return: the function for the given side or null if not function based
        :rtype: ghidra.program.model.listing.Function
        """

    def getProgram(self, side: ghidra.util.datastruct.Duo.Side) -> ghidra.program.model.listing.Program:
        """
        Gets the program for the given side.
        
        :param ghidra.util.datastruct.Duo.Side side: LEFT or RIGHT
        :return: the program for the given side
        :rtype: ghidra.program.model.listing.Program
        """

    @property
    def addresses(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class PostCommentFieldLocation(CommentFieldLocation):
    """
    The ``EolCommentFieldLocation`` class contains specific location information
    within the EOL comment field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], comment: jpype.JArray[java.lang.String], displayableCommentRow: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new PostCommentFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: the address of the codeunit.
        :param jpype.JArray[jpype.JInt] componentPath: the componentPath of the codeUnit
        :param jpype.JArray[java.lang.String] comment: comment text for the particular comment indicated by the address, subtype, and reference address.
        :param jpype.JInt or int displayableCommentRow: the line within the Post comment as displayed.
        :param jpype.JInt or int charOffset: the character position on the line within the comment line.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        an end-of-line field location from XML.
        """


class OffsetFieldType(java.lang.Enum[OffsetFieldType]):
    """
    The type of offset field
    
    
    .. seealso::
    
        | :obj:`OffsetFieldLocation`
    """

    class_: typing.ClassVar[java.lang.Class]
    FILE: typing.Final[OffsetFieldType]
    FUNCTION: typing.Final[OffsetFieldType]
    IMAGEBASE: typing.Final[OffsetFieldType]
    MEMORYBLOCK: typing.Final[OffsetFieldType]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> OffsetFieldType:
        ...

    @staticmethod
    def values() -> jpype.JArray[OffsetFieldType]:
        ...


class RepeatableCommentFieldLocation(CommentFieldLocation):
    """
    The ``RepeatableCommentFieldLocation`` class contains specific location information
    within the Repeatable comment of an EOL comment field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], comment: jpype.JArray[java.lang.String], row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int], currentCommentRow: typing.Union[jpype.JInt, int]):
        """
        Construct a new RepeatableCommentFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: the address of the codeunit.
        :param jpype.JArray[jpype.JInt] componentPath: the componentPath of the codeUnit
        :param jpype.JArray[java.lang.String] comment: comment text for the particular comment indicated by the address, subtype, and reference address.
        :param jpype.JInt or int row: the line within the Eol comment.
        :param jpype.JInt or int charOffset: the character position on the line within the comment line.
        :param jpype.JInt or int currentCommentRow: the row index relative to the beginning of the repeatable comment 
        as displayed in the Eol comment field.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        an end-of-line field location from XML.
        """

    def getCurrentCommentRow(self) -> int:
        ...

    @property
    def currentCommentRow(self) -> jpype.JInt:
        ...


class CommentChangeRecord(ProgramChangeRecord):
    """
    Change record for comment changes
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, commentType: ghidra.program.model.listing.CommentType, address: ghidra.program.model.address.Address, oldValue: typing.Union[java.lang.String, str], newValue: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param ghidra.program.model.listing.CommentType commentType: :obj:`comment type <CommentType>`
        :param ghidra.program.model.address.Address address: the address of the comment change
        :param java.lang.String or str oldValue: the old comment (may be null for a new comment)
        :param java.lang.String or str newValue: the new comment (may be null if the comment was deleted)
        """

    def getCommentType(self) -> ghidra.program.model.listing.CommentType:
        """
        Returns the comment type as defined in :obj:`CodeUnit`.
        
        :return: the comment type
        :rtype: ghidra.program.model.listing.CommentType
        """

    def getNewComment(self) -> str:
        """
        Returns the new comment or null if this is a result of deleting the comment.
        
        :return: the new comment or null if this is a result of deleting the comment
        :rtype: str
        """

    def getOldComment(self) -> str:
        """
        Returns the previous comment or null if there was no previous comment.
        
        :return: the previous comment or null if there was no previous comment.
        :rtype: str
        """

    @property
    def oldComment(self) -> java.lang.String:
        ...

    @property
    def newComment(self) -> java.lang.String:
        ...

    @property
    def commentType(self) -> ghidra.program.model.listing.CommentType:
        ...


class UserDataChangeRecord(ghidra.framework.model.DomainObjectChangeRecord):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, propertyName: typing.Union[java.lang.String, str], oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Constructor
        
        :param java.lang.String or str propertyName: name of the property
        :param java.lang.Object oldValue: old value
        :param java.lang.Object newValue: new value
        """

    @typing.overload
    def __init__(self, propertyName: typing.Union[java.lang.String, str]):
        """
        Constructor for change record for removing a range of properties.
        
        :param java.lang.String or str propertyName: name of the property
        """

    def getPropertyName(self) -> str:
        """
        Get the name of the property being changed.
        
        :return: the name of the property being changed.
        :rtype: str
        """

    @property
    def propertyName(self) -> java.lang.String:
        ...


class AbstractStoredProgramContext(AbstractProgramContext):

    @typing.type_check_only
    class RegisterAddressRangeIterator(ghidra.program.model.address.AddressRangeIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def flushProcessorContextWriteCache(self):
        """
        Flush any cached context not yet written to database
        """

    def invalidateProcessorContextWriteCache(self):
        """
        Flush any cached context not yet written to database
        """


class FunctionCallingConventionFieldLocation(FunctionSignatureFieldLocation):
    """
    The ``FunctionCallingConventionFieldLocation`` class provides specific information
    about the Function Calling Convention field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str]):
        """
        Construct a new FunctionCallingConventionFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int charOffset: the position within the function signature string for this location.
        :param java.lang.String or str signature: the function signature string at this location.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """


class SimpleDiffUtility(java.lang.Object):

    @typing.type_check_only
    class ExternalReferenceCount(java.lang.Comparable[SimpleDiffUtility.ExternalReferenceCount]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExternalMatchType(java.lang.Enum[SimpleDiffUtility.ExternalMatchType]):

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.Final[SimpleDiffUtility.ExternalMatchType]
        NAME: typing.Final[SimpleDiffUtility.ExternalMatchType]
        MANGLED_NAME: typing.Final[SimpleDiffUtility.ExternalMatchType]
        ADDRESS: typing.Final[SimpleDiffUtility.ExternalMatchType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> SimpleDiffUtility.ExternalMatchType:
            ...

        @staticmethod
        def values() -> jpype.JArray[SimpleDiffUtility.ExternalMatchType]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def expandAddressSetToIncludeFullDelaySlots(program: ghidra.program.model.listing.Program, originalSet: ghidra.program.model.address.AddressSetView) -> ghidra.program.model.address.AddressSetView:
        """
        Expand a specified address set to include complete delay slotted instructions
        which may be included at the start or end of each range within the specified
        address set.
        
        :param ghidra.program.model.listing.Program program: program
        :param ghidra.program.model.address.AddressSetView originalSet: original address set
        :return: expanded address set
        :rtype: ghidra.program.model.address.AddressSetView
        """

    @staticmethod
    def getCompatibleAddress(program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address:
        """
        Convert an address from the specified program to a comparable address in the
        specified otherProgram.  
         
        
        For external locations the match-up is very fuzzy and
        will use correlated references.  If an exact match is required for an external location
        the :meth:`getMatchingExternalLocation(Program, ExternalLocation, Program, boolean) <.getMatchingExternalLocation>` or 
        :meth:`getMatchingExternalSymbol(Program, Symbol, Program, boolean, Set) <.getMatchingExternalSymbol>` should be used 
        directly.
        
        :param ghidra.program.model.listing.Program program: program which contains the specified address instance
        :param ghidra.program.model.address.Address addr: address in program
        :param ghidra.program.model.listing.Program otherProgram: other program
        :return: address for otherProgram or null if no such address exists.
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def getCompatibleAddressSpace(addrSpace: ghidra.program.model.address.AddressSpace, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.address.AddressSpace:
        ...

    @staticmethod
    def getCompatibleVariableStorage(program: ghidra.program.model.listing.Program, storage: ghidra.program.model.listing.VariableStorage, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.listing.VariableStorage:
        """
        Convert a variable storage object from the specified program to a comparable variable storage
        object in the specified otherProgram.  Certain variable storage (UNIQUE/HASH-based) will
        always produce a null return object.
        
        :param ghidra.program.model.listing.Program program: program which contains the specified address instance
        :param ghidra.program.model.listing.VariableStorage storage: variable storage in program
        :param ghidra.program.model.listing.Program otherProgram: other program
        :return: storage for otherProgram or null if storage can not be mapped to other program
        :rtype: ghidra.program.model.listing.VariableStorage
        """

    @staticmethod
    def getCompatibleVarnode(program: ghidra.program.model.listing.Program, varnode: ghidra.program.model.pcode.Varnode, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.pcode.Varnode:
        """
        Convert a varnode from the specified program to a comparable varnode in the
        specified otherProgram.  Certain varnode addresses spaces (UNIQUE, HASH) will
        always produce a null return varnode.
        
        :param ghidra.program.model.listing.Program program: program which contains the specified address instance
        :param ghidra.program.model.pcode.Varnode varnode: varnode in program
        :param ghidra.program.model.listing.Program otherProgram: other program
        :return: varnode for otherProgram or null if varnode can not be mapped to other program
        :rtype: ghidra.program.model.pcode.Varnode
        """

    @staticmethod
    def getEndOfDelaySlots(instr: ghidra.program.model.listing.Instruction) -> ghidra.program.model.address.Address:
        """
        If the specified instruction is contained within a delay slot, or has delay slots,
        the maximum address of the last delay slot instruction will be returned.
        If a normal instruction is specified the instructions maximum address is returned.
        
        :param ghidra.program.model.listing.Instruction instr: 
        :return: maximum address of instruction or its last delay slot
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    def getMatchingExternalLocation(program: ghidra.program.model.listing.Program, externalLocation: ghidra.program.model.symbol.ExternalLocation, otherProgram: ghidra.program.model.listing.Program, allowInferredMatch: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.symbol.ExternalLocation:
        """
        Given an external location for a specified program, get the corresponding external location,
        which has the same name and path,  from the specified otherProgram.
        
        Note: The type of the returned external location may be different than the type of the
        original external location.
        
        :param ghidra.program.model.listing.Program program: program which contains the specified external location instance
        :param ghidra.program.model.symbol.ExternalLocation externalLocation: external location to look for
        :param ghidra.program.model.listing.Program otherProgram: other program
        :param jpype.JBoolean or bool allowInferredMatch: if true an inferred match may be performed using reference
        correlation.  NOTE: reference correlation is only possible if the exact same binary
        is in use.  This option is ignored if the two programs do not have the same 
        original binary hash and reference correlation will not be performed.
        :return: corresponding external location for otherProgram or null if no such external location exists.
        :rtype: ghidra.program.model.symbol.ExternalLocation
        """

    @staticmethod
    def getMatchingExternalSymbol(program: ghidra.program.model.listing.Program, symbol: ghidra.program.model.symbol.Symbol, otherProgram: ghidra.program.model.listing.Program, allowInferredMatch: typing.Union[jpype.JBoolean, bool], otherRestrictedSymbolIds: java.util.Set[java.lang.Long]) -> ghidra.program.model.symbol.Symbol:
        """
        Given an external symbol for a specified program, get the corresponding symbol,
        which has the same name and path,  from the specified otherProgram.
        
        Note: In The type of the returned symbol may be different than the type of the symbol
        (i.e., Function vs Label).
        
        :param ghidra.program.model.listing.Program program: program which contains the specified symbol instance
        :param ghidra.program.model.symbol.Symbol symbol: symbol to look for
        :param ghidra.program.model.listing.Program otherProgram: other program
        :param jpype.JBoolean or bool allowInferredMatch: if true an inferred match may be performed using reference
        correlation (NOTE: reference correlation is only possible if the exact same binary
        is in use).  This option is ignored if the two programs do not have the same 
        original binary hash.
        :param java.util.Set[java.lang.Long] otherRestrictedSymbolIds: an optional set of symbol ID's from the other program
        which will be treated as the exclusive set of candidate symbols to consider.
        :return: corresponding external symbol for otherProgram or null if no such symbol exists.
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @staticmethod
    def getStartOfDelaySlots(instr: ghidra.program.model.listing.Instruction) -> ghidra.program.model.address.Address:
        ...

    @staticmethod
    def getSymbol(symbol: ghidra.program.model.symbol.Symbol, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Symbol:
        """
        Given a symbol for a specified program, get the corresponding symbol from the
        specified otherProgram.
         
        
        In the case of external locations this performs an exact match based upon symbol name, 
        namespace and symbol type.
        
        :param ghidra.program.model.symbol.Symbol symbol: symbol to look for
        :param ghidra.program.model.listing.Program otherProgram: other program
        :return: corresponding symbol for otherProgram or null if no such symbol exists.
        :rtype: ghidra.program.model.symbol.Symbol
        """

    @staticmethod
    def getVariableSymbol(symbol: ghidra.program.model.symbol.Symbol, otherProgram: ghidra.program.model.listing.Program) -> ghidra.program.model.symbol.Symbol:
        """
        Find the variable symbol in otherProgram which corresponds to the specified varSym.
        
        :param ghidra.program.model.symbol.Symbol symbol: variable symbol
        :param ghidra.program.model.listing.Program otherProgram: other program
        :return: the variable symbol or null
        :rtype: ghidra.program.model.symbol.Symbol
        """


class FunctionReturnTypeFieldLocation(FunctionSignatureFieldLocation):
    """
    The ``FunctionReturnTypeFieldLocation`` class provides specific information
    about the Function Return Type field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str], returnType: typing.Union[java.lang.String, str]):
        """
        Construct a new FunctionReturnTypeFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int charOffset: the position within the function signature string for this location.
        :param java.lang.String or str signature: the function signature string for this location.
        :param java.lang.String or str returnType: the function return type String at this location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, functionAddr: ghidra.program.model.address.Address, col: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str], returnType: typing.Union[java.lang.String, str]):
        """
        Construct a new FunctionReturnTypeFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int col: the position within the function signature string for this location.
        :param java.lang.String or str signature: the function signature string for this location.
        :param java.lang.String or str returnType: the function return type String at this location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, functionAddr: ghidra.program.model.address.Address, returnType: typing.Union[java.lang.String, str]):
        """
        Construct a new FunctionReturnTypeFieldLocation object that is field based.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param java.lang.String or str returnType: the function return type String at this location.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """

    def getReturnType(self) -> str:
        """
        Return the function return type string at this location.
        """

    def toString(self) -> str:
        """
        Returns a String representation of this location.
        """

    @property
    def returnType(self) -> java.lang.String:
        ...


class SpaceFieldLocation(CodeUnitLocation):
    """
    The ``SpaceFieldLocation`` class contains specific location information
    within the Space field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, path: GroupPath, componentPath: jpype.JArray[jpype.JInt], row: typing.Union[jpype.JInt, int]):
        """
        Construct a new SpaceFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: the address of the codeunit.
        :param jpype.JArray[jpype.JInt] componentPath: the componentPath of the codeUnit
        :param jpype.JInt or int row: the line of the location
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a space field location from XML.
        """


class VariableLocFieldLocation(VariableLocation):
    """
    The ``VariableLocFieldLocation`` class provides specific information
    about the stack variable offset field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, var: ghidra.program.model.listing.Variable, charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new VariableLocFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.listing.Variable var: the variable which has its location (stack offset) in the field.
        :param jpype.JInt or int charOffset: the position within the variable location (stack offset) string for this location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, var: ghidra.program.model.listing.Variable, charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new VariableLocFieldLocation object.
        Variable function entry point is the assumed listing location (i.e., referent code unit).
        Care should be taken if variable corresponds to an EXTERNAL function.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.listing.Variable var: the variable which has its location (stack offset) in the field.
        :param jpype.JInt or int charOffset: the position within the variable location (stack offset) string for this location.
        """

    @typing.overload
    def __init__(self):
        """
        Should only be used by XML restoration.
        """

    def getLoc(self) -> str:
        """
        Gets the location string. (For stack variables this is the offset as a string.)
        
        :return: the location string
        :rtype: str
        """

    @property
    def loc(self) -> java.lang.String:
        ...


class FunctionLocation(ProgramLocation):
    """
    ``FunctionLocation`` provides information about the location
    in a program within a ``Function``.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFunctionAddress(self) -> ghidra.program.model.address.Address:
        """
        Return the Function symbol address which may differ from the "location address" when
        a function is indirectly inferred via a reference.  WARNING: The :meth:`getAddress() <.getAddress>` should
        not be used to obtain the function address!
        
        :return: the function address corresponding to this program location
        :rtype: ghidra.program.model.address.Address
        """

    def restoreState(self, program1: ghidra.program.model.listing.Program, obj: ghidra.framework.options.SaveState):
        """
        Restore this function location using the given program and save state object.
        
        :param ghidra.program.model.listing.Program program1: the program containing the function location
        :param ghidra.framework.options.SaveState obj: the save state object for saving the location
        """

    def saveState(self, obj: ghidra.framework.options.SaveState):
        """
        Save this function location to the given save state object.
        
        :param ghidra.framework.options.SaveState obj: the save state object for saving the location
        """

    @property
    def functionAddress(self) -> ghidra.program.model.address.Address:
        ...


class VariableXRefHeaderFieldLocation(VariableXRefFieldLocation):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Should only be used for XML restoring.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, var: ghidra.program.model.listing.Variable, charOffset: typing.Union[jpype.JInt, int], refAddr: ghidra.program.model.address.Address):
        """
        Creates a variable xref field program location
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.listing.Variable var: the variable
        :param jpype.JInt or int charOffset: the character offset
        :param ghidra.program.model.address.Address refAddr: the xref address
        """


class AddressFieldLocation(CodeUnitLocation):
    """
    The ``AddressFieldLocation`` class provides specific information
    about a program location within the ADDRESS field.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], addrRepresentation: typing.Union[java.lang.String, str], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new AddressFieldLocation object with the 
        standard string representation
        and a position within that string.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of the location
        :param jpype.JArray[jpype.JInt] componentPath: if not null, it is the array of indexes that point
        to a specific data type inside of another data type
        :param java.lang.String or str addrRepresentation: the string representation of the address
        :param jpype.JInt or int charOffset: the position into the string representation indicating the exact
        position within the Address Field.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address):
        """
        Construct a new default AddressFieldLocation for a given program address.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of the location
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        an address field location from XML.
        """

    def getAddressRepresentation(self) -> str:
        """
        Returns the standard string representation of the address in the
        address field.  If there is no address, then null should be returned.
        """

    def toString(self) -> str:
        """
        Returns a String representation of this location.
        """

    @property
    def addressRepresentation(self) -> java.lang.String:
        ...


class ProgramUtilities(java.lang.Object):
    """
    General utility class that provides convenience methods
    to deal with Program objects.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def addTrackedProgram(program: ghidra.program.model.listing.Program):
        """
        Programs will only be stored during testing and are maintained as weak references.
        
        :param ghidra.program.model.listing.Program program: The program that is being tracked (all programs during testing.
        """

    @staticmethod
    def convertFunctionWrappedExternalPointer(functionSymbol: ghidra.program.model.symbol.Symbol):
        """
        Convert old function wrapped external pointers.  Migrate function to
        external function.
        """

    @staticmethod
    def getByteCodeString(cu: ghidra.program.model.listing.CodeUnit) -> str:
        """
        Get the bytes associated with the specified code unit cu 
        formatted as a string.  Bytes will be returned as 2-digit hex
        separated with a space.  Any undefined bytes will be represented by "??".
        
        :param ghidra.program.model.listing.CodeUnit cu: code unit
        :return: formatted byte string
        :rtype: str
        """

    @staticmethod
    def getDataConverter(program: ghidra.program.model.listing.Program) -> ghidra.util.DataConverter:
        ...

    @staticmethod
    def getSystemPrograms() -> java.util.Iterator[ghidra.program.model.listing.Program]:
        """
        Returns an iterator for all of the :obj:`Program` objects in the system, which is all
        created programs in any state that have not been garbage collected.  
         
        
        **Note:**The Iterator is backed by an unmodifiable set, so any attempts to modify the
        Iterator will throw an :obj:`UnsupportedOperationException`.
        
        :return: an iterator for all of the programs in the system
        :rtype: java.util.Iterator[ghidra.program.model.listing.Program]
        """

    @staticmethod
    def isChangedWithUpgradeOnly(program: ghidra.program.model.listing.Program) -> bool:
        """
        Determine if a program has a single unsaved change which corresponds to an
        upgrade which occured during instantiation.
        
        :param ghidra.program.model.listing.Program program: the program to be checked for an unsaved upgrade condition.
        :return: true if program upgraded and has not been saved, else false
        :rtype: bool
        """

    @staticmethod
    def parseAddress(program: ghidra.program.model.listing.Program, addressString: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        ...


class EquateOperandFieldLocation(OperandFieldLocation):
    """
    A simple version of :obj:`OperandFieldLocation` that allows us to store equate information.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, refAddr: ghidra.program.model.address.Address, rep: typing.Union[java.lang.String, str], equate: ghidra.program.model.symbol.Equate, opIndex: typing.Union[jpype.JInt, int], subOpIndex: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        
        
        :param ghidra.program.model.listing.Program program: The program
        :param ghidra.program.model.address.Address addr: the address of the location
        :param ghidra.program.model.address.Address refAddr: the reference address.
        :param java.lang.String or str rep: the representation of the equate location
        :param ghidra.program.model.symbol.Equate equate: the equate object.
        :param jpype.JInt or int opIndex: the operand index
        :param jpype.JInt or int subOpIndex: the operand subOpIndex
        :param jpype.JInt or int charOffset: the character offset in to subOpPiece.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        an operand field location from XML.
        """

    def getEquate(self) -> ghidra.program.model.symbol.Equate:
        """
        Returns the equate at this operand field location.
        
        :return: equate
        :rtype: ghidra.program.model.symbol.Equate
        """

    def getEquateValue(self) -> int:
        ...

    def getReferences(self) -> jpype.JArray[ghidra.program.model.symbol.EquateReference]:
        ...

    def toString(self) -> str:
        """
        Returns a String representation of this location.
        """

    @property
    def equate(self) -> ghidra.program.model.symbol.Equate:
        ...

    @property
    def references(self) -> jpype.JArray[ghidra.program.model.symbol.EquateReference]:
        ...

    @property
    def equateValue(self) -> jpype.JLong:
        ...


class CodeUnitLocation(ProgramLocation):
    """
    ``CodeUnitLocation`` provides information about the location
    in a program within a ``CodeUnit``.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Create a new ``CodeUnitLocation`` for the given address.
        The address will be adjusted to the beginning of the code unit containing
        that address(if it exists).  The original address can be retrieved using
        the "getByteAddress()" method.
        
        :param ghidra.program.model.listing.Program program: the program for obtaining the code unit
        :param ghidra.program.model.address.Address addr: address of the location; should not be null
        :param jpype.JArray[jpype.JInt] componentPath: if this is not null it is the path to a data
        component inside of another data component
        :param jpype.JInt or int row: the row within the field.
        :param jpype.JInt or int col: - the display item index on the given row. (Note most fields only have one display item per row)
        :param jpype.JInt or int charOffset: - the character offset within the display item.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Create a new ``CodeUnitLocation`` for the given address.
        The address will be adjusted to the beginning of the code unit containing
        that address(if it exists).  The original address can be retrieved using
        the "getByteAddress()" method.
        
        :param ghidra.program.model.listing.Program program: the program for obtaining the code unit
        :param ghidra.program.model.address.Address addr: address of the location; should not be null
        :param jpype.JInt or int row: the row within the field.
        :param jpype.JInt or int col: - the display item index on the given row. (Note most fields only have one display item per row)
        :param jpype.JInt or int charOffset: - the character offset within the display item.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor for a code unit location needed for restoring from XML.
        """


class VariableCommentFieldLocation(VariableLocation):
    """
    The ``VariableCommentFieldLocation`` class provides specific information
    about the stack variable comment field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, var: ghidra.program.model.listing.Variable, charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new VariableCommentFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.listing.Variable var: the variable which has its comment in the field.
        :param jpype.JInt or int charOffset: the position within the variable comment string for this location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, var: ghidra.program.model.listing.Variable, charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new VariableCommentFieldLocation object.
        Variable function entry point is the assumed listing location (i.e., referent code unit).
        Care should be taken if variable corresponds to an EXTERNAL function.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.listing.Variable var: the variable which has its comment in the field.
        :param jpype.JInt or int charOffset: the position within the variable comment string for this location.
        """

    @typing.overload
    def __init__(self):
        """
        Should only be used by XML restoration.
        """

    def getComment(self) -> str:
        """
        Return the function variable comment string at this location.
        """

    @property
    def comment(self) -> java.lang.String:
        ...


class InstructionMaskValueFieldLocation(ProgramLocation):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        ...


class AddressCorrelator(java.lang.Object):
    """
    Interface for address correlation algorithms that can generate an address mapping from one
    set of program addresses to another.
     
    
    This interface supplies a :meth:`priority <.getPriority>` of :obj:`.DEFAULT_PRIORITY`.  
    :obj:`discoverable <DiscoverableAddressCorrelator>` correlators can change this priority to be a
    lower value to be run before the supplied system correlators.   Generally, the more specific or
    restrictive a correlator, the earlier (higher priority) it should be.
    """

    class_: typing.ClassVar[java.lang.Class]
    DEFAULT_PRIORITY: typing.Final = 500
    """
    The default priority.  This applies to client-supplied :obj:`DiscoverableAddressCorrelator`s
    """

    EARLY_PRIORITY: typing.Final = 100
    """
    A high priority (low number value) for correlators that should used before other correlators
    """

    LATE_CHANCE_PRIORITY: typing.Final = 1000
    """
    A low priority (high number value) for correlators that should used after other correlators
    """

    PRIORITY_OFFSET: typing.Final = 10
    """
    A value used to raise or lower priorities.
    """


    @typing.overload
    def correlate(self, sourceFunction: ghidra.program.model.listing.Function, destinationFunction: ghidra.program.model.listing.Function) -> AddressCorrelation:
        """
        Returns an address mapping from one function to another.
        
        :param ghidra.program.model.listing.Function sourceFunction: the source function.
        :param ghidra.program.model.listing.Function destinationFunction: the destination function.
        :return: an AddressCorrelation that represents a mapping of the addresses from the
        source function to the destination function.
        :rtype: AddressCorrelation
        """

    @typing.overload
    def correlate(self, sourceData: ghidra.program.model.listing.Data, destinationData: ghidra.program.model.listing.Data) -> AddressCorrelation:
        """
        Returns an address mapping from one piece of data to another.
        
        :param ghidra.program.model.listing.Data sourceData: the source data.
        :param ghidra.program.model.listing.Data destinationData: the destination data.
        :return: an AddressCorrelation that represents a mapping of the addresses from the
        source data to the destination data.
        :rtype: AddressCorrelation
        """

    def getDefaultOptions(self) -> ghidra.framework.options.Options:
        """
        Returns the options with the default settings for this correlator.
        
        :return: the options with the default settings for this correlator.
        :rtype: ghidra.framework.options.Options
        """

    def getOptions(self) -> ghidra.framework.options.ToolOptions:
        """
        Returns the current Option settings for this correlator.
        
        :return: the current Option settings for this correlator.
        :rtype: ghidra.framework.options.ToolOptions
        """

    def getPriority(self) -> int:
        """
        Returns a number based on an arbitrary number scheme that dictates the order that correlators 
        should be used.   If a correlator returns a null value from one of the ``correlate()``
        methods, then the next highest priority correlator will be called, and so on until a non-null
        correlation is found or all correlators have been called.
         
        
        A lower number value is a higher priority.  See :obj:`.DEFAULT_PRIORITY`.
        
        :return: the priority
        :rtype: int
        """

    def setOptions(self, options: ghidra.framework.options.ToolOptions):
        """
        Sets the options to use for this correlator.
        
        :param ghidra.framework.options.ToolOptions options: the options to use for this correlator.
        """

    @property
    def defaultOptions(self) -> ghidra.framework.options.Options:
        ...

    @property
    def options(self) -> ghidra.framework.options.ToolOptions:
        ...

    @options.setter
    def options(self, value: ghidra.framework.options.ToolOptions):
        ...

    @property
    def priority(self) -> jpype.JInt:
        ...


class OffsetFieldLocation(CodeUnitLocation):
    """
    Provides specific information about a program location within an offset field
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], charOffset: typing.Union[jpype.JInt, int], type: OffsetFieldType):
        """
        Creates a new :obj:`OffsetFieldLocation` for the given address
        
        :param ghidra.program.model.listing.Program program: the program
        :param ghidra.program.model.address.Address addr: the address of the byte for this location
        :param jpype.JArray[jpype.JInt] componentPath: the path to data, or null
        :param jpype.JInt or int charOffset: the position into the string representation indicating the exact
        position within the field
        :param OffsetFieldType type: The :obj:`type <OffsetFieldType>` of offset field
        """

    @typing.overload
    def __init__(self, type: OffsetFieldType):
        """
        Default constructor needed for restoring the field location from XML
        
        :param OffsetFieldType type: The :obj:`type <OffsetFieldType>` of offset field
        """

    def getType(self) -> OffsetFieldType:
        """
        :return: the type of offset field
        :rtype: OffsetFieldType
        """

    @property
    def type(self) -> OffsetFieldType:
        ...


class FunctionThunkFieldLocation(FunctionSignatureFieldLocation):
    """
    The ``FunctionThunkFieldLocation`` class provides specific information
    about the Function Thunk field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str]):
        """
        Construct a new FunctionThunkFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int charOffset: the position within the function thunk string for this location.
        :param java.lang.String or str signature: the function signature string at this location.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """


class PcodeFieldLocation(ProgramLocation):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, pcodeStrings: java.util.List[java.lang.String], row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        """
        Get the row within a group of pcode strings.
        """

    def getPcodeStrings(self) -> java.util.List[java.lang.String]:
        ...

    @property
    def pcodeStrings(self) -> java.util.List[java.lang.String]:
        ...


class SourceMapFieldLocation(ProgramLocation):
    """
    A :obj:`ProgramLocation` for source map information.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int], sourceMapEntry: ghidra.program.model.sourcemap.SourceMapEntry):
        ...

    @typing.overload
    def __init__(self):
        ...

    def getSourceMapEntry(self) -> ghidra.program.model.sourcemap.SourceMapEntry:
        """
        Returns the :obj:`SourceMapEntry` associated with this location.
        
        :return: source map entry
        :rtype: ghidra.program.model.sourcemap.SourceMapEntry
        """

    @property
    def sourceMapEntry(self) -> ghidra.program.model.sourcemap.SourceMapEntry:
        ...


class LinearFunctionAddressCorrelation(AddressCorrelation):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.Final = "LinearFunctionAddressCorrelation"

    def __init__(self, sourceFunction: ghidra.program.model.listing.Function, destinationFunction: ghidra.program.model.listing.Function):
        ...


class ParallelInstructionLocation(ProgramLocation):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        """
        Get the row within a group of pcode strings.
        """


class LanguageTranslatorFactoryMinion(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getLanguageTranslators(self) -> java.util.Collection[LanguageTranslator]:
        """
        
        
        :return: collection of language translators
        :rtype: java.util.Collection[LanguageTranslator]
        """

    @property
    def languageTranslators(self) -> java.util.Collection[LanguageTranslator]:
        ...


class FunctionParameterFieldLocation(FunctionSignatureFieldLocation):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str], parameter: ghidra.program.model.listing.Parameter):
        """
        Construct a new FunctionParameterFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int charOffset: the position within the function signature string for this location.
        :param java.lang.String or str signature: the function signature string at this location.
        :param ghidra.program.model.listing.Parameter parameter: the function parameter at this location.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """

    def getOrdinal(self) -> int:
        ...

    def getParameter(self) -> ghidra.program.model.listing.Parameter:
        """
        Returns the parameter associated with this location.  This value can be null if the 
        parameters are deleted from the function associated with the address of the parameter.
        
        :return: the parameter
        :rtype: ghidra.program.model.listing.Parameter
        """

    def toString(self) -> str:
        """
        Returns a String representation of this location.
        """

    @property
    def parameter(self) -> ghidra.program.model.listing.Parameter:
        ...

    @property
    def ordinal(self) -> jpype.JInt:
        ...


class OperandFieldLocation(CodeUnitLocation):
    """
    The ``OperandFieldLocation`` class contains specific location information within the
    OPERAND field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], refAddr: ghidra.program.model.address.Address, rep: typing.Union[java.lang.String, str], opIndex: typing.Union[jpype.JInt, int], characterOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new OperandFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location.
        :param ghidra.program.model.address.Address addr: address of the location; should not be null.
        :param jpype.JArray[jpype.JInt] componentPath: array of indexes for each nested data component; the index is the data
        component's index within its parent; may be null.
        :param ghidra.program.model.address.Address refAddr: the reference 'to' address.
        :param java.lang.String or str rep: the String representation of the operand.
        :param jpype.JInt or int opIndex: the index of the operand at this location.
        :param jpype.JInt or int characterOffset: the character position from the beginning of the operand.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], refAddr: ghidra.program.model.address.Address, rep: typing.Union[java.lang.String, str], opIndex: typing.Union[jpype.JInt, int], subOpIndex: typing.Union[jpype.JInt, int], characterOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new OperandFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location.
        :param ghidra.program.model.address.Address addr: address of the location; should not be null.
        :param jpype.JArray[jpype.JInt] componentPath: array of indexes for each nested data component; the index is the data
        component's index within its parent; may be null .
        :param ghidra.program.model.address.Address refAddr: the "referred to" address if the location is over a reference; may be null.
        :param java.lang.String or str rep: the String representation of the operand.
        :param jpype.JInt or int opIndex: the index indicating the operand the location is on.
        :param jpype.JInt or int subOpIndex: the index of the Object within the operand, this can be used to call an
        instructions getOpObjects() method.
        :param jpype.JInt or int characterOffset: the character position from the beginning of the operand field.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, variableOffset: ghidra.program.model.listing.VariableOffset, refAddr: ghidra.program.model.address.Address, rep: typing.Union[java.lang.String, str], opIndex: typing.Union[jpype.JInt, int], subOpIndex: typing.Union[jpype.JInt, int], characterOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new OperandFieldLocation object for an instruction operand.
        
        :param ghidra.program.model.listing.Program program: the program of the location.
        :param ghidra.program.model.address.Address addr: address of the location; should not be null.
        :param ghidra.program.model.listing.VariableOffset variableOffset: associated variable offset or null.
        :param ghidra.program.model.address.Address refAddr: the "referred to" address if the location is over a reference; may be null.
        :param java.lang.String or str rep: the String representation of the operand.
        :param jpype.JInt or int opIndex: the index indicating the operand the location is on.
        :param jpype.JInt or int subOpIndex: the index of the Object within the operand, this can be used to call an
        instructions getOpObjects() method.
        :param jpype.JInt or int characterOffset: the character position from the beginning of the operand field.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring an operand field location from XML.
        """

    def getOperandIndex(self) -> int:
        """
        Returns the index of the operand at this location.
        
        :return: the index
        :rtype: int
        """

    def getOperandRepresentation(self) -> str:
        """
        Returns a string representation of the operand at this location.
        
        :return: the representation.
        :rtype: str
        """

    def getSubOperandIndex(self) -> int:
        """
        Returns the sub operand index at this location.
         
        
        This index can be used on the instruction.getOpObjects() to find the actual object (Address,
        Register, Scalar) the cursor is over.
        
        :return: 0-n if over a valid OpObject, -1 otherwise
        :rtype: int
        """

    def getVariableOffset(self) -> ghidra.program.model.listing.VariableOffset:
        """
        Returns VariableOffset object if applicable or null.
        
        :return: the variable offset.
        :rtype: ghidra.program.model.listing.VariableOffset
        """

    @property
    def operandRepresentation(self) -> java.lang.String:
        ...

    @property
    def subOperandIndex(self) -> jpype.JInt:
        ...

    @property
    def operandIndex(self) -> jpype.JInt:
        ...

    @property
    def variableOffset(self) -> ghidra.program.model.listing.VariableOffset:
        ...


class RegisterFieldLocation(ProgramLocation):
    """
    ProgramLocation for the Register Field.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, registerNames: jpype.JArray[java.lang.String], registerStrings: jpype.JArray[java.lang.String], row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        """
        Default constructor
        """

    def getRegister(self) -> ghidra.program.model.lang.Register:
        ...

    def getRegisterStrings(self) -> jpype.JArray[java.lang.String]:
        """
        Get the register strings.
        """

    @property
    def registerStrings(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...


class DummyListingAddressCorrelation(ListingAddressCorrelation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class FunctionChangeRecord(ProgramChangeRecord):

    class FunctionChangeType(java.lang.Enum[FunctionChangeRecord.FunctionChangeType]):
        """
        Specific function changes types for when the ProgramEvent is FUNCTION_CHANGED
        """

        class_: typing.ClassVar[java.lang.Class]
        PURGE_CHANGED: typing.Final[FunctionChangeRecord.FunctionChangeType]
        INLINE_CHANGED: typing.Final[FunctionChangeRecord.FunctionChangeType]
        NO_RETURN_CHANGED: typing.Final[FunctionChangeRecord.FunctionChangeType]
        CALL_FIXUP_CHANGED: typing.Final[FunctionChangeRecord.FunctionChangeType]
        RETURN_TYPE_CHANGED: typing.Final[FunctionChangeRecord.FunctionChangeType]
        PARAMETERS_CHANGED: typing.Final[FunctionChangeRecord.FunctionChangeType]
        THUNK_CHANGED: typing.Final[FunctionChangeRecord.FunctionChangeType]
        UNSPECIFIED: typing.Final[FunctionChangeRecord.FunctionChangeType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> FunctionChangeRecord.FunctionChangeType:
            ...

        @staticmethod
        def values() -> jpype.JArray[FunctionChangeRecord.FunctionChangeType]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, function: ghidra.program.model.listing.Function, changeType: FunctionChangeRecord.FunctionChangeType):
        """
        Constructs a new Function change record.
        
        :param ghidra.program.model.listing.Function function: the function that was changed
        :param FunctionChangeRecord.FunctionChangeType changeType: the specific type of change that was applied to the function
        """

    def getFunction(self) -> ghidra.program.model.listing.Function:
        """
        Returns the function that was changed.
        
        :return: the function that was changed
        :rtype: ghidra.program.model.listing.Function
        """

    def getSpecificChangeType(self) -> FunctionChangeRecord.FunctionChangeType:
        """
        Returns the specific type of function change.
        
        :return: the specific type of function change
        :rtype: FunctionChangeRecord.FunctionChangeType
        """

    def isFunctionModifierChange(self) -> bool:
        """
        Returns true if the specific change was to one of the function's modifier properties.
        
        :return: true if the specific change was to one of the function's modifier properties
        :rtype: bool
        """

    def isFunctionSignatureChange(self) -> bool:
        """
        Returns true if the specific change was related to the function signature.
        
        :return: true if the specific change was related to the function signature
        :rtype: bool
        """

    @property
    def functionSignatureChange(self) -> jpype.JBoolean:
        ...

    @property
    def specificChangeType(self) -> FunctionChangeRecord.FunctionChangeType:
        ...

    @property
    def function(self) -> ghidra.program.model.listing.Function:
        ...

    @property
    def functionModifierChange(self) -> jpype.JBoolean:
        ...


class GroupPath(java.io.Serializable):
    """
    The ``GroupPath`` is a class to represent a unique path in a tree for a Group.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, groupName: typing.Union[java.lang.String, str]):
        """
        Construct a new GroupPath that is only a single level.
        
        :param java.lang.String or str groupName: name of group
        """

    @typing.overload
    def __init__(self, groupNames: jpype.JArray[java.lang.String]):
        """
        Construct a new GroupPath with the given names.
        
        :param jpype.JArray[java.lang.String] groupNames: group names. The first name is the oldest ancestor
        and the last name is the youngest descendant in the path.
        """

    def getGroup(self, program: ghidra.program.model.listing.Program, treeName: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Group:
        """
        Get the Group for this group path object.
        
        :return: null if there is no group with the name in this
        group path.
        :rtype: ghidra.program.model.listing.Group
        """

    def getLastPathComponent(self) -> str:
        """
        Get the last name in the path.
        
        :return: String
        :rtype: str
        """

    def getParentPath(self) -> GroupPath:
        """
        Get the parent path for this group.
        """

    def getPath(self) -> jpype.JArray[java.lang.String]:
        """
        Return the array of names that make up this group's path.
        """

    def getPathComponent(self, index: typing.Union[jpype.JInt, int]) -> str:
        """
        Get the name at the given index into this group's path.
        
        :param jpype.JInt or int index: the index in the group path
        """

    def getPathCount(self) -> int:
        """
        Get the number of names (levels) that make up this path.
        """

    def isDescendant(self, grpPath: GroupPath) -> bool:
        """
        Return true if the indicated group path is a descendant of this group path.
        
        :param GroupPath grpPath: the group path
        """

    def pathByAddingChild(self, child: typing.Union[java.lang.String, str]) -> GroupPath:
        """
        Create a new GroupPath object by adding the given
        child name to this group path.
        
        :param java.lang.String or str child: name of child to add to path
        """

    def toString(self) -> str:
        """
        Returns a string representation of this group path.
        """

    def updateGroupPath(self, oldname: typing.Union[java.lang.String, str], newname: typing.Union[java.lang.String, str]):
        """
        Update this group path with the new group name wherever the old group name is found.
        
        :param java.lang.String or str oldname: old name
        :param java.lang.String or str newname: new name
        """

    @property
    def path(self) -> jpype.JArray[java.lang.String]:
        ...

    @property
    def pathComponent(self) -> java.lang.String:
        ...

    @property
    def parentPath(self) -> GroupPath:
        ...

    @property
    def lastPathComponent(self) -> java.lang.String:
        ...

    @property
    def descendant(self) -> jpype.JBoolean:
        ...

    @property
    def pathCount(self) -> jpype.JInt:
        ...


class FunctionNameFieldLocation(FunctionSignatureFieldLocation):
    """
    The ``FunctionNameFieldLocation`` class provides specific information
    about the Function Name field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str], functionName: typing.Union[java.lang.String, str]):
        """
        Construct a new FunctionNameFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int charOffset: the position within the function signature string for this location.
        :param java.lang.String or str signature: the function signature string for this location.
        :param java.lang.String or str functionName: the function name String at this location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, functionAddr: ghidra.program.model.address.Address, col: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str], functionName: typing.Union[java.lang.String, str]):
        """
        Construct a new FunctionNameFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int col: the position within the function signature string for this location.
        :param java.lang.String or str signature: the function signature string for this location.
        :param java.lang.String or str functionName: the function name String at this location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, functionName: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """

    def getFunctionName(self) -> str:
        ...

    def toString(self) -> str:
        """
        Returns a String representation of this location.
        """

    @property
    def functionName(self) -> java.lang.String:
        ...


class FunctionParameterNameFieldLocation(FunctionParameterFieldLocation):
    """
    A :obj:`FunctionSignatureFieldLocation` that indicates the user clicked on a function
    parameter name.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str], parameter: ghidra.program.model.listing.Parameter):
        """
        Construct a new FunctionParameterNameFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int charOffset: the position within the function signature string for this location.
        :param java.lang.String or str signature: the function signature string at this location.
        :param ghidra.program.model.listing.Parameter parameter: the function parameter at this location.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """

    def getParameterName(self) -> str:
        ...

    @property
    def parameterName(self) -> java.lang.String:
        ...


class ProgramEvent(java.lang.Enum[ProgramEvent], ghidra.framework.model.EventType):
    """
    Event types for :obj:`Program` changes.
    """

    class_: typing.ClassVar[java.lang.Class]
    MEMORY_BLOCK_ADDED: typing.Final[ProgramEvent]
    MEMORY_BLOCK_REMOVED: typing.Final[ProgramEvent]
    MEMORY_BLOCK_CHANGED: typing.Final[ProgramEvent]
    MEMORY_BLOCK_MOVED: typing.Final[ProgramEvent]
    MEMORY_BLOCK_SPLIT: typing.Final[ProgramEvent]
    MEMORY_BLOCKS_JOINED: typing.Final[ProgramEvent]
    MEMORY_BYTES_CHANGED: typing.Final[ProgramEvent]
    IMAGE_BASE_CHANGED: typing.Final[ProgramEvent]
    CODE_ADDED: typing.Final[ProgramEvent]
    CODE_REMOVED: typing.Final[ProgramEvent]
    CODE_REPLACED: typing.Final[ProgramEvent]
    CODE_UNIT_PROPERTY_CHANGED: typing.Final[ProgramEvent]
    CODE_UNIT_PROPERTY_ALL_REMOVED: typing.Final[ProgramEvent]
    CODE_UNIT_PROPERTY_RANGE_REMOVED: typing.Final[ProgramEvent]
    SYMBOL_ADDED: typing.Final[ProgramEvent]
    SYMBOL_REMOVED: typing.Final[ProgramEvent]
    SYMBOL_SOURCE_CHANGED: typing.Final[ProgramEvent]
    SYMBOL_ANCHOR_FLAG_CHANGED: typing.Final[ProgramEvent]
    SYMBOL_PRIMARY_STATE_CHANGED: typing.Final[ProgramEvent]
    SYMBOL_RENAMED: typing.Final[ProgramEvent]
    SYMBOL_SCOPE_CHANGED: typing.Final[ProgramEvent]
    SYMBOL_ASSOCIATION_ADDED: typing.Final[ProgramEvent]
    SYMBOL_ASSOCIATION_REMOVED: typing.Final[ProgramEvent]
    SYMBOL_DATA_CHANGED: typing.Final[ProgramEvent]
    SYMBOL_ADDRESS_CHANGED: typing.Final[ProgramEvent]
    EXTERNAL_ENTRY_ADDED: typing.Final[ProgramEvent]
    EXTERNAL_ENTRY_REMOVED: typing.Final[ProgramEvent]
    EXTERNAL_PATH_CHANGED: typing.Final[ProgramEvent]
    EXTERNAL_NAME_ADDED: typing.Final[ProgramEvent]
    EXTERNAL_NAME_REMOVED: typing.Final[ProgramEvent]
    EXTERNAL_NAME_CHANGED: typing.Final[ProgramEvent]
    EXTERNAL_REFERENCE_ADDED: typing.Final[ProgramEvent]
    EXTERNAL_REFERENCE_REMOVED: typing.Final[ProgramEvent]
    REFERENCE_ADDED: typing.Final[ProgramEvent]
    REFERENCE_REMOVED: typing.Final[ProgramEvent]
    REFERENCE_TYPE_CHANGED: typing.Final[ProgramEvent]
    REFERNCE_PRIMARY_SET: typing.Final[ProgramEvent]
    REFERENCE_PRIMARY_REMOVED: typing.Final[ProgramEvent]
    EQUATE_ADDED: typing.Final[ProgramEvent]
    EQUATE_REMOVED: typing.Final[ProgramEvent]
    EQUATE_REFERENCE_ADDED: typing.Final[ProgramEvent]
    EQUATE_REFERENCE_REMOVED: typing.Final[ProgramEvent]
    EQUATE_RENAMED: typing.Final[ProgramEvent]
    PROGRAM_TREE_CREATED: typing.Final[ProgramEvent]
    PROGRAM_TREE_REMOVED: typing.Final[ProgramEvent]
    PROGRAM_TREE_RENAMED: typing.Final[ProgramEvent]
    GROUP_ADDED: typing.Final[ProgramEvent]
    GROUP_REMOVED: typing.Final[ProgramEvent]
    GROUP_RENAMED: typing.Final[ProgramEvent]
    GROUP_COMMENT_CHANGED: typing.Final[ProgramEvent]
    GROUP_ALIAS_CHANGED: typing.Final[ProgramEvent]
    GROUP_REPARENTED: typing.Final[ProgramEvent]
    MODULE_REORDERED: typing.Final[ProgramEvent]
    FRAGMENT_MOVED: typing.Final[ProgramEvent]
    FRAGMENT_CHANGED: typing.Final[ProgramEvent]
    COMMENT_CHANGED: typing.Final[ProgramEvent]
    DATA_TYPE_CATEGORY_ADDED: typing.Final[ProgramEvent]
    DATA_TYPE_CATEGORY_REMOVED: typing.Final[ProgramEvent]
    DATA_TYPE_CATEGORY_RENAMED: typing.Final[ProgramEvent]
    DATA_TYPE_CATEGORY_MOVED: typing.Final[ProgramEvent]
    DATA_TYPE_ADDED: typing.Final[ProgramEvent]
    DATA_TYPE_REMOVED: typing.Final[ProgramEvent]
    DATA_TYPE_RENAMED: typing.Final[ProgramEvent]
    DATA_TYPE_MOVED: typing.Final[ProgramEvent]
    DATA_TYPE_CHANGED: typing.Final[ProgramEvent]
    DATA_TYPE_SETTING_CHANGED: typing.Final[ProgramEvent]
    DATA_TYPE_REPLACED: typing.Final[ProgramEvent]
    SOURCE_ARCHIVE_ADDED: typing.Final[ProgramEvent]
    SOURCE_ARCHIVE_CHANGED: typing.Final[ProgramEvent]
    BOOKMARK_TYPE_ADDED: typing.Final[ProgramEvent]
    BOOKMARK_TYPE_REMOVED: typing.Final[ProgramEvent]
    BOOKMARK_ADDED: typing.Final[ProgramEvent]
    BOOKMARK_REMOVED: typing.Final[ProgramEvent]
    BOOKMARK_CHANGED: typing.Final[ProgramEvent]
    LANGUAGE_CHANGED: typing.Final[ProgramEvent]
    REGISTER_VALUES_CHANGED: typing.Final[ProgramEvent]
    OVERLAY_SPACE_ADDED: typing.Final[ProgramEvent]
    OVERLAY_SPACE_REMOVED: typing.Final[ProgramEvent]
    OVERLAY_SPACE_RENAMED: typing.Final[ProgramEvent]
    FUNCTION_TAG_CREATED: typing.Final[ProgramEvent]
    FUNCTION_TAG_CHANGED: typing.Final[ProgramEvent]
    FUNCTION_TAG_DELETED: typing.Final[ProgramEvent]
    FUNCTION_TAG_APPLIED: typing.Final[ProgramEvent]
    FUNCTION_TAG_UNAPPLIED: typing.Final[ProgramEvent]
    FUNCTION_ADDED: typing.Final[ProgramEvent]
    FUNCTION_REMOVED: typing.Final[ProgramEvent]
    FUNCTION_BODY_CHANGED: typing.Final[ProgramEvent]
    FUNCTION_CHANGED: typing.Final[ProgramEvent]
    VARIABLE_REFERENCE_ADDED: typing.Final[ProgramEvent]
    VARIABLE_REFERENCE_REMOVED: typing.Final[ProgramEvent]
    FALLTHROUGH_CHANGED: typing.Final[ProgramEvent]
    FLOW_OVERRIDE_CHANGED: typing.Final[ProgramEvent]
    LENGTH_OVERRIDE_CHANGED: typing.Final[ProgramEvent]
    ADDRESS_PROPERTY_MAP_ADDED: typing.Final[ProgramEvent]
    ADDRESS_PROPERTY_MAP_REMOVED: typing.Final[ProgramEvent]
    ADDRESS_PROPERTY_MAP_CHANGED: typing.Final[ProgramEvent]
    INT_PROPERTY_MAP_ADDED: typing.Final[ProgramEvent]
    INT_PROPERTY_MAP_REMOVED: typing.Final[ProgramEvent]
    INT_PROPERTY_MAP_CHANGED: typing.Final[ProgramEvent]
    CODE_UNIT_USER_DATA_CHANGED: typing.Final[ProgramEvent]
    USER_DATA_CHANGED: typing.Final[ProgramEvent]
    RELOCATION_ADDED: typing.Final[ProgramEvent]
    SOURCE_FILE_ADDED: typing.Final[ProgramEvent]
    SOURCE_FILE_REMOVED: typing.Final[ProgramEvent]
    SOURCE_MAP_CHANGED: typing.Final[ProgramEvent]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ProgramEvent:
        ...

    @staticmethod
    def values() -> jpype.JArray[ProgramEvent]:
        ...


class ChangeManager(java.lang.Object):
    """
    ProgramEventerface to define event types and the method to generate an
    event within Program.
     
    
    Note: Previously (before 11.1), program change event types were defined in this file as
    integer constants. Event ids have since been converted to enum types. The defines in this file  
    have been converted to point to the new enum values to make it easier to convert to this new way  
    and to clearly see how the old values map to the new enums. In future releases, these defines 
    will be removed.
    """

    class_: typing.ClassVar[java.lang.Class]
    DOCR_MEMORY_BLOCK_ADDED: typing.Final[ProgramEvent]
    """
    A memory block was created.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_MEMORY_BLOCK_REMOVED: typing.Final[ProgramEvent]
    """
    A memory block was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_MEMORY_BLOCK_CHANGED: typing.Final[ProgramEvent]
    """
    A memory block was changed. 
    (for example: its name, comment, or read, write, or execute flags were changed.)
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_MEMORY_BLOCK_MOVED: typing.Final[ProgramEvent]
    """
    A block of memory was moved to a new start address.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_MEMORY_BLOCK_SPLIT: typing.Final[ProgramEvent]
    """
    A memory block was split ProgramEvento two memory blocks.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_MEMORY_BLOCKS_JOINED: typing.Final[ProgramEvent]
    """
    Two memory blocks were joined ProgramEvento a single memory block.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_MEMORY_BYTES_CHANGED: typing.Final[ProgramEvent]
    """
    The bytes changed in memory.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_IMAGE_BASE_CHANGED: typing.Final[ProgramEvent]
    """
    The memory image base has changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CODE_ADDED: typing.Final[ProgramEvent]
    """
    A CodeUnit was added.  The "New Value" may be null when a block
    of Instructions are added
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CODE_REMOVED: typing.Final[ProgramEvent]
    """
    A CodeUnit was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CODE_MOVED: typing.Final[ProgramEvent]
    """
    CodeUnits were moved from one Fragment to another.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CODE_REPLACED: typing.Final[ProgramEvent]
    """
    Data was replaced.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CODE_UNIT_PROPERTY_CHANGED: typing.Final[ProgramEvent]
    """
    A property on a code unit was changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CODE_UNIT_PROPERTY_ALL_REMOVED: typing.Final[ProgramEvent]
    """
    Generated whenever an entire user property manager is deleted.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED: typing.Final[ProgramEvent]
    """
    Property over a range of addresses was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_SYMBOL_ADDED: typing.Final[ProgramEvent]
    """
    A symbol was created.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_SYMBOL_REMOVED: typing.Final[ProgramEvent]
    """
    A symbol was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_SYMBOL_SOURCE_CHANGED: typing.Final[ProgramEvent]
    """
    The source of a symbol name was changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_SYMBOL_ANCHORED_FLAG_CHANGED: typing.Final[ProgramEvent]
    """
    The anchor flag for the symbol was changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_SYMBOL_SET_AS_PRIMARY: typing.Final[ProgramEvent]
    """
    A symbol was set as primary.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_SYMBOL_RENAMED: typing.Final[ProgramEvent]
    """
    A symbol was renamed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EXTERNAL_ENTRY_POINT_ADDED: typing.Final[ProgramEvent]
    """
    An external entry poProgramEvent was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EXTERNAL_ENTRY_POINT_REMOVED: typing.Final[ProgramEvent]
    """
    An external entry poProgramEvent was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_SYMBOL_SCOPE_CHANGED: typing.Final[ProgramEvent]
    """
    The scope on a symbol changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_SYMBOL_ASSOCIATION_ADDED: typing.Final[ProgramEvent]
    """
    An association to a symbol for a reference was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_SYMBOL_ASSOCIATION_REMOVED: typing.Final[ProgramEvent]
    """
    An association to a symbol for a reference was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_SYMBOL_DATA_CHANGED: typing.Final[ProgramEvent]
    """
    Symbol data changed.  This corresponds to various
    changes within the symbol (e.g., primary status, datatype, external path or VariableStorage).
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_SYMBOL_ADDRESS_CHANGED: typing.Final[ProgramEvent]
    """
    Symbol address changed.  
    NOTE: This is only permitted for variable/parameter symbols
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_MEM_REFERENCE_ADDED: typing.Final[ProgramEvent]
    """
    A reference was added to a symbol.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_MEM_REFERENCE_REMOVED: typing.Final[ProgramEvent]
    """
    A reference was removed from a symbol.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_MEM_REF_TYPE_CHANGED: typing.Final[ProgramEvent]
    """
    The ref type on a memory reference changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_MEM_REF_PRIMARY_SET: typing.Final[ProgramEvent]
    """
    The reference was identified as the primary.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_MEM_REF_PRIMARY_REMOVED: typing.Final[ProgramEvent]
    """
    The primary reference was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EXTERNAL_PATH_CHANGED: typing.Final[ProgramEvent]
    """
    The external path name changed for an external program name.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EXTERNAL_NAME_ADDED: typing.Final[ProgramEvent]
    """
    An external program name was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EXTERNAL_NAME_REMOVED: typing.Final[ProgramEvent]
    """
    An external program name was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EXTERNAL_NAME_CHANGED: typing.Final[ProgramEvent]
    """
    The name for an external program changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EQUATE_ADDED: typing.Final[ProgramEvent]
    """
    An Equate was created.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EQUATE_REMOVED: typing.Final[ProgramEvent]
    """
    An Equate was deleted.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EQUATE_REFERENCE_ADDED: typing.Final[ProgramEvent]
    """
    A reference at an operand was added to an Equate.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EQUATE_REFERENCE_REMOVED: typing.Final[ProgramEvent]
    """
    A reference at an operand was removed from an Equate.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EQUATE_RENAMED: typing.Final[ProgramEvent]
    """
    An Equate was renamed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_GROUP_ADDED: typing.Final[ProgramEvent]
    """
    A Module or Fragment was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_GROUP_REMOVED: typing.Final[ProgramEvent]
    """
    A Module or Fragment was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_GROUP_RENAMED: typing.Final[ProgramEvent]
    """
    A Module or Fragment was renamed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_GROUP_COMMENT_CHANGED: typing.Final[ProgramEvent]
    """
    The comment for a Module or Fragment changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_GROUP_ALIAS_CHANGED: typing.Final[ProgramEvent]
    """
    The alias for a Module or Fragment changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_MODULE_REORDERED: typing.Final[ProgramEvent]
    """
    The children of a Module have been reordered.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_FRAGMENT_MOVED: typing.Final[ProgramEvent]
    """
    Fragment or set of fragments have been moved.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_GROUP_REPARENTED: typing.Final[ProgramEvent]
    """
    Group was reparented.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EOL_COMMENT_CHANGED: typing.Final[ProgramEvent]
    """
    The end-of-line comment changed for a CodeUnit.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_PRE_COMMENT_CHANGED: typing.Final[ProgramEvent]
    """
    The pre comment changed for a CodeUnit.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_POST_COMMENT_CHANGED: typing.Final[ProgramEvent]
    """
    The post comment changed for a CodeUnit.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_PLATE_COMMENT_CHANGED: typing.Final[ProgramEvent]
    """
    A Plate comment was added, deleted, or changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_REPEATABLE_COMMENT_CHANGED: typing.Final[ProgramEvent]
    """
    A Repeatable Comment changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CATEGORY_ADDED: typing.Final[ProgramEvent]
    """
    Category was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CATEGORY_REMOVED: typing.Final[ProgramEvent]
    """
    Category was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CATEGORY_RENAMED: typing.Final[ProgramEvent]
    """
    Category was renamed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CATEGORY_MOVED: typing.Final[ProgramEvent]
    """
    Category was moved.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_ADDED: typing.Final[ProgramEvent]
    """
    Data type was added to a category.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_REMOVED: typing.Final[ProgramEvent]
    """
    Data type was removed from a category.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_RENAMED: typing.Final[ProgramEvent]
    """
    Data Type was renamed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_MOVED: typing.Final[ProgramEvent]
    """
    Data type was moved to another category.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_CHANGED: typing.Final[ProgramEvent]
    """
    Data type was updated.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_SETTING_CHANGED: typing.Final[ProgramEvent]
    """
    The settings on a data type were updated.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_REPLACED: typing.Final[ProgramEvent]
    """
    Data type was replaced in a category.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_SOURCE_ARCHIVE_ADDED: typing.Final[ProgramEvent]
    """
    Data type was added to a category.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_SOURCE_ARCHIVE_CHANGED: typing.Final[ProgramEvent]
    """
    Data type was updated.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_BOOKMARK_TYPE_ADDED: typing.Final[ProgramEvent]
    """
    Bookmark type was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_BOOKMARK_TYPE_REMOVED: typing.Final[ProgramEvent]
    """
    Bookmark type was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_BOOKMARK_ADDED: typing.Final[ProgramEvent]
    """
    Bookmark was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_BOOKMARK_REMOVED: typing.Final[ProgramEvent]
    """
    Bookmark was deleted.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_BOOKMARK_CHANGED: typing.Final[ProgramEvent]
    """
    Bookmark category or comment was changed (old value not provided).
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_LANGUAGE_CHANGED: typing.Final[ProgramEvent]
    """
    The language for the Program changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_REGISTER_VALUES_CHANGED: typing.Final[ProgramEvent]
    """
    Register values changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_OVERLAY_SPACE_ADDED: typing.Final[ProgramEvent]
    """
    An overlay address space was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_OVERLAY_SPACE_REMOVED: typing.Final[ProgramEvent]
    """
    An overlay address space was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_OVERLAY_SPACE_RENAMED: typing.Final[ProgramEvent]
    """
    An overlay address space was renamed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_TREE_CREATED: typing.Final[ProgramEvent]
    """
    Tree was created.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_TREE_REMOVED: typing.Final[ProgramEvent]
    """
    Tree was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_TREE_RENAMED: typing.Final[ProgramEvent]
    """
    Tree was renamed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_FUNCTION_TAG_CHANGED: typing.Final[ProgramEvent]
    """
    A function tag was edited
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_FUNCTION_TAG_CREATED: typing.Final[ProgramEvent]
    """
    A function tag was created
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_FUNCTION_TAG_DELETED: typing.Final[ProgramEvent]
    """
    A function tag was created
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_FUNCTION_ADDED: typing.Final[ProgramEvent]
    """
    Function was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_FUNCTION_REMOVED: typing.Final[ProgramEvent]
    """
    Function was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_FUNCTION_CHANGED: typing.Final[ProgramEvent]
    """
    Function was changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_VARIABLE_REFERENCE_ADDED: typing.Final[ProgramEvent]
    """
    A function variable reference was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_VARIABLE_REFERENCE_REMOVED: typing.Final[ProgramEvent]
    """
    A function variable reference was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_FUNCTION_BODY_CHANGED: typing.Final[ProgramEvent]
    """
    A function's body changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    FUNCTION_CHANGED_PURGE: typing.Final[FunctionChangeRecord.FunctionChangeType]
    """
    A function's purge size was changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    FUNCTION_CHANGED_INLINE: typing.Final[FunctionChangeRecord.FunctionChangeType]
    """
    A function's inline state was changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    FUNCTION_CHANGED_NORETURN: typing.Final[FunctionChangeRecord.FunctionChangeType]
    """
    A function's no-return state was changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    FUNCTION_CHANGED_CALL_FIXUP: typing.Final[FunctionChangeRecord.FunctionChangeType]
    """
    A function's call-fixup state was changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    FUNCTION_CHANGED_RETURN: typing.Final[FunctionChangeRecord.FunctionChangeType]
    """
    A functions return type/storage was modified
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    FUNCTION_CHANGED_PARAMETERS: typing.Final[FunctionChangeRecord.FunctionChangeType]
    """
    A functions parameter list was modified
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    FUNCTION_CHANGED_THUNK: typing.Final[FunctionChangeRecord.FunctionChangeType]
    """
    A functions thunk status has changed
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EXTERNAL_REFERENCE_ADDED: typing.Final[ProgramEvent]
    """
    An external reference was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_EXTERNAL_REFERENCE_REMOVED: typing.Final[ProgramEvent]
    """
    An external reference was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_FALLTHROUGH_CHANGED: typing.Final[ProgramEvent]
    """
    A Fallthrough address was changed for an instruction.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_FLOWOVERRIDE_CHANGED: typing.Final[ProgramEvent]
    """
    The flow override for an instruction has changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_LENGTH_OVERRIDE_CHANGED: typing.Final[ProgramEvent]
    """
    An instruction length override was changed for an instruction.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_ADDRESS_SET_PROPERTY_MAP_ADDED: typing.Final[ProgramEvent]
    """
    An AddressSetPropertyMap was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_ADDRESS_SET_PROPERTY_MAP_REMOVED: typing.Final[ProgramEvent]
    """
    An AddressSetPropertyMap was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_ADDRESS_SET_PROPERTY_MAP_CHANGED: typing.Final[ProgramEvent]
    """
    An AddressSetPropertyMap was changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_INT_ADDRESS_SET_PROPERTY_MAP_ADDED: typing.Final[ProgramEvent]
    """
    An ProgramEventAddressSetPropertyMap was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_INT_ADDRESS_SET_PROPERTY_MAP_REMOVED: typing.Final[ProgramEvent]
    """
    An ProgramEventAddressSetPropertyMap was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_INT_ADDRESS_SET_PROPERTY_MAP_CHANGED: typing.Final[ProgramEvent]
    """
    An ProgramEventAddressSetPropertyMap was changed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CODE_UNIT_USER_DATA_CHANGED: typing.Final[ProgramEvent]
    """
    User Data for a code unit changed
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_USER_DATA_CHANGED: typing.Final[ProgramEvent]
    """
    User Data changed
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """


    @typing.overload
    def setChanged(self, eventType: ProgramEvent, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Mark the state of a Program as having changed and generate
        the event of the specified type.  Any or all parameters may be null.
        
        :param ProgramEvent eventType: the event type
        :param java.lang.Object oldValue: original value or an Object that is related to
        the event
        :param java.lang.Object newValue: new value or an Object that is related to the
        the event
        """

    @typing.overload
    def setChanged(self, eventType: ProgramEvent, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Mark the state of a Program as having changed and generate
        the event of the specified type.  Any or all parameters may be null.
        
        :param ProgramEvent eventType: the event type
        :param ghidra.program.model.address.Address start: starting address that is affected by the event
        :param ghidra.program.model.address.Address end: ending address that is affected by the event
        :param java.lang.Object oldValue: original value or an Object that is related to
        the event
        :param java.lang.Object newValue: new value or an Object that is related to the
        the event
        """

    @typing.overload
    def setObjChanged(self, eventType: ProgramEvent, affected: java.lang.Object, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Mark the state of a Program as having changed and generate
        the event of the specified type.  Any or all parameters may be null.
        
        :param ProgramEvent eventType: the event type
        :param java.lang.Object affected: object that is the subject of the event
        :param java.lang.Object oldValue: original value or an Object that is related to
        the event
        :param java.lang.Object newValue: new value or an Object that is related to the
        the event
        """

    @typing.overload
    def setObjChanged(self, eventType: ProgramEvent, addr: ghidra.program.model.address.Address, affected: java.lang.Object, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Mark the state of a Program as having changed and generate
        the event of the specified type.  Any or all parameters may be null.
        
        :param ProgramEvent eventType: the event type
        :param ghidra.program.model.address.Address addr: program address affected
        :param java.lang.Object affected: object that is the subject of the event
        :param java.lang.Object oldValue: original value or an Object that is related to
        the event
        :param java.lang.Object newValue: new value or an Object that is related to the
        the event
        """

    def setPropertyChanged(self, propertyName: typing.Union[java.lang.String, str], codeUnitAddr: ghidra.program.model.address.Address, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Mark the state of a Program as having changed and generate
        the DOCR_CODE_UNIT_PROPERTY_CHANGED event.
        
        :param java.lang.String or str propertyName: name of property for the range that changed
        :param ghidra.program.model.address.Address codeUnitAddr: address of the code unit with the property change
        :param java.lang.Object oldValue: old value for the property
        :param java.lang.Object newValue: new value for the property
        """

    def setPropertyRangeRemoved(self, propertyName: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Mark the state of the Program as having changed and generate
        the DOCR_CODE_UNIT_PROPERTY_RANGE_REMOVED event.
        
        :param java.lang.String or str propertyName: name of property for the range being removed
        :param ghidra.program.model.address.Address start: start address of the range
        :param ghidra.program.model.address.Address end: end address of the range
        """

    def setRegisterValuesChanged(self, register: ghidra.program.model.lang.Register, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Notifies that register values have changed over the indicated address range.
        
        :param ghidra.program.model.lang.Register register: register value which was modified (a value of null indicates all
        registers affected or unknown)
        :param ghidra.program.model.address.Address start: the start address for the range where values changed
        :param ghidra.program.model.address.Address end: the end address (inclusive) for the range where values changed
        """


class VariableStorageConflicts(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, variablesList1: java.util.List[ghidra.program.model.listing.Variable], variablesList2: java.util.List[ghidra.program.model.listing.Variable], ignoreParamToParamConflicts: typing.Union[jpype.JBoolean, bool], monitor: ghidra.util.task.TaskMonitor):
        """
        Construct a VariableStorageConflicts object for the variables contained within two
        functions.
        
        :param java.util.List[ghidra.program.model.listing.Variable] variablesList1: 
        :param java.util.List[ghidra.program.model.listing.Variable] variablesList2: 
        :param jpype.JBoolean or bool ignoreParamToParamConflicts: if true param-to-param overlaps will be ignored unless
        a param-to-local overlap occurs in which case all params will be pulled in to the
        overlap.  If true, it is assumed that the current overlap iteration was initiated by
        a parameter overlap check.
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises CancelledException:
        """

    def getOverlappingVariables(self) -> java.util.List[generic.stl.Pair[java.util.List[ghidra.program.model.listing.Variable], java.util.List[ghidra.program.model.listing.Variable]]]:
        ...

    def hasOverlapConflict(self) -> bool:
        ...

    def hasParameterConflict(self) -> bool:
        ...

    def isConflicted(self, var1: ghidra.program.model.listing.Variable, var2: ghidra.program.model.listing.Variable) -> bool:
        """
        Check to see if either var1 or var2 is contained within the conflicted/overlapping
        set of variables.  In general, one of the specified variables should be null.
        
        :param ghidra.program.model.listing.Variable var1: a variable which corresponds to function1 at time of construction or null
        :param ghidra.program.model.listing.Variable var2: a variable which corresponds to function2 at time of construction or null
        :return: true if either variable is contained within the conflicted/overlapping
        set of variables.
        :rtype: bool
        """

    @property
    def overlappingVariables(self) -> java.util.List[generic.stl.Pair[java.util.List[ghidra.program.model.listing.Variable], java.util.List[ghidra.program.model.listing.Variable]]]:
        ...


class RegisterTransitionFieldLocation(ProgramLocation):
    """
    ProgramLocation for the Register Field.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, registerNames: jpype.JArray[java.lang.String], row: typing.Union[jpype.JInt, int], column: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        """
        Default constructor
        """

    def getRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def register(self) -> ghidra.program.model.lang.Register:
        ...


class XRefHeaderFieldLocation(XRefFieldLocation):
    """
    The ``XRefHeaderFieldLocation`` class contains specific location information
    within the XREF field header that precedes the XREF field locations.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], charOffset: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        """
        Should only be used for XML restoring.
        """


class AbstractProgramContext(ghidra.program.model.listing.ProgramContext, ghidra.program.model.listing.DefaultProgramContext):

    class_: typing.ClassVar[java.lang.Class]

    def getFlowValue(self, value: ghidra.program.model.lang.RegisterValue) -> ghidra.program.model.lang.RegisterValue:
        """
        Modify register value to eliminate non-flowing bits
        
        :param ghidra.program.model.lang.RegisterValue value: context register value to be modified
        :return: value suitable for flowing
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Get underlying language associated with this context and its registers
        
        :return: language
        :rtype: ghidra.program.model.lang.Language
        """

    def getNonFlowValue(self, value: ghidra.program.model.lang.RegisterValue) -> ghidra.program.model.lang.RegisterValue:
        """
        Modify register value to only include non-flowing bits
        
        :param ghidra.program.model.lang.RegisterValue value: context register value to be modified
        :return: new value or null if value does not correspond to a context register or
        non-flowing context fields have not been defined
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    @property
    def flowValue(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @property
    def nonFlowValue(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @property
    def language(self) -> ghidra.program.model.lang.Language:
        ...


class FieldNameFieldLocation(CodeUnitLocation):
    """
    The ``FieldNameFieldLocation`` class provides specific information about the Function
    Name field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], fieldName: typing.Union[java.lang.String, str], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new FieldNameFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: the address of the code unit
        :param jpype.JArray[jpype.JInt] componentPath: if not null, it is the array of indexes that point to a specific data
                    type inside of another data type
        :param java.lang.String or str fieldName: the field name
        :param jpype.JInt or int charOffset: the character position within the field name for this location.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring a field name location from XML
        """

    def getDataComponent(self) -> ghidra.program.model.listing.Data:
        """
        Get the data component representing the named field
        
        :return: the data unit
        :rtype: ghidra.program.model.listing.Data
        """

    def getFieldName(self) -> str:
        """
        Returns the field name of this location.
        
        :return: the name.
        :rtype: str
        """

    @property
    def fieldName(self) -> java.lang.String:
        ...

    @property
    def dataComponent(self) -> ghidra.program.model.listing.Data:
        ...


class VariableTypeFieldLocation(VariableLocation):
    """
    The ``VariableTypeFieldLocation`` class provides specific information
    about the variable type field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, var: ghidra.program.model.listing.Variable, charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new VariableTypeFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.listing.Variable var: the variable associated with this type field location.
        :param jpype.JInt or int charOffset: the position within the function name string for this location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, var: ghidra.program.model.listing.Variable, charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new VariableTypeFieldLocation object.
        Variable function entry point is the assumed listing location (i.e., referent code unit).
        Care should be taken if variable corresponds to an EXTERNAL function.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.listing.Variable var: the variable associated with this type field location.
        :param jpype.JInt or int charOffset: the position within the function name string for this location.
        """

    @typing.overload
    def __init__(self):
        """
        Should only be used by XML restoration.
        """

    def getType(self) -> str:
        """
        Return the function stack variable type string at this location.
        """

    def toString(self) -> str:
        """
        Returns a String representation of this location.
        """

    @property
    def type(self) -> java.lang.String:
        ...


class FunctionEndParametersFieldLocation(FunctionSignatureFieldLocation):
    """
    The ``FunctionEndParametersFieldLocation`` class provides a field 
    for the close parenthesis of a function within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str]):
        """
        Construct a new FunctionEndParametersFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int charOffset: the position within the function signature string for this location.
        :param java.lang.String or str signature: the function signature string at this location.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """


class LabelFieldLocation(CodeUnitLocation):
    """
    This class contains specific location information within the label field of a 
    :obj:`CodeUnitLocation`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring a label field location from XML
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], label: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace, row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new LabelFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of the location; should not be null
        :param jpype.JArray[jpype.JInt] componentPath: array of indexes for each nested data component; the
        index is the data component's index within its parent; may be null.
        :param java.lang.String or str label: the label String at this location.
        :param ghidra.program.model.symbol.Namespace namespace: the namespace; may be null.
        :param jpype.JInt or int row: the row in list of labels as displayed by the label field.  Only used for
        program location comparison purposes.
        :param jpype.JInt or int charOffset: the column position within the label string for this location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, label: typing.Union[java.lang.String, str]):
        """
        Construct a new LabelFieldLocation where the namespace is global, primary is false, and
        the cursor location is at row 0, column 0;
        
        :param ghidra.program.model.listing.Program program: the program of the location.
        :param ghidra.program.model.address.Address addr: the address of the location.
        :param java.lang.String or str label: the name of the symbol for this label location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, label: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace, row: typing.Union[jpype.JInt, int]):
        """
        Construct a new LabelFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location.
        :param ghidra.program.model.address.Address addr: address of the location; should not be null
        :param java.lang.String or str label: the label String at this location.
        :param ghidra.program.model.symbol.Namespace namespace: the namespace for the label. Null will default to the global namespace.
        :param jpype.JInt or int row: the row in list of labels as displayed by the label field.  Only used for
        program location comparison purposes.
        """

    @typing.overload
    def __init__(self, s: ghidra.program.model.symbol.Symbol):
        """
        Creates a label field location using the specified symbol
        and an index of 0.
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to use when creating the location
        """

    @typing.overload
    def __init__(self, s: ghidra.program.model.symbol.Symbol, row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Creates a label field location using the specified symbol
        and the specified field index.
        
        :param ghidra.program.model.symbol.Symbol s: the symbol to use when creating the location
        :param jpype.JInt or int row: the row of the symbol.
        :param jpype.JInt or int charOffset: the position within the label string for this location
        """

    def getName(self) -> str:
        ...

    def getSymbol(self) -> ghidra.program.model.symbol.Symbol:
        """
        Returns the symbol at this LabelFieldLocation
        NOTE: currently a null symbol will be returned for default thunk functions
        
        :return: the symbol at this LabelFieldLocation or null if symbol lookup fails
        :rtype: ghidra.program.model.symbol.Symbol
        """

    def getSymbolPath(self) -> ghidra.app.util.SymbolPath:
        """
        Returns the symbol path which corresponds to the label location
        
        :return: symbol path
        :rtype: ghidra.app.util.SymbolPath
        """

    @property
    def symbol(self) -> ghidra.program.model.symbol.Symbol:
        ...

    @property
    def symbolPath(self) -> ghidra.app.util.SymbolPath:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class XRefFieldLocation(CodeUnitLocation):
    """
    The ``XRefFieldLocation`` class contains specific location information
    within the XREF field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], refAddr: ghidra.program.model.address.Address, index: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new XRefFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of the location
        appear at more than one group path); may be null
        :param jpype.JArray[jpype.JInt] componentPath: array of indexes for each nested data component;
        the index is the data component's index within its parent; may be null
        :param ghidra.program.model.address.Address refAddr: the reference address at this location.
        :param jpype.JInt or int index: the index of the XREF in the list of all XREFs at this address.
        :param jpype.JInt or int charOffset: the character position within the XREF.
        """

    @typing.overload
    def __init__(self):
        """
        Creates a cross reference field location. Should only be used for XML restoring.
        """

    def getIndex(self) -> int:
        """
        :return: the index of the XREF in the list.
        :rtype: int
        """

    @property
    def index(self) -> jpype.JInt:
        ...


class ProgramLocation(java.lang.Cloneable, java.lang.Comparable[ProgramLocation]):
    """
    ``ProgramLocation`` provides information about a location in a program in the most
    generic way.
    
     
    
    ProgramLocations refer to a specific location in a program and can be specified down to an
    address, a field at that address, and within that field, a row, col, and character offset. The
    field is not recorded directly, but by the subclass of the ProgramLocation. The "cursor position"
    within a field is specified by three variables: row, col, and character offset. The row is
    literally the row (line #) the cursor is on within the field, the column represents the display
    item on that row (For example, in the bytes field the column will represent which "byte" the
    cursor is on. Most fields only have one column item per row.) And finally, the character offset
    is the character position within the display item specified by the row and column. Simple fields
    like the address field and Mnemonic field will always have a row and column of 0.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, byteAddr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], refAddr: ghidra.program.model.address.Address, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new ProgramLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of the location; cannot be null; This could be a code unit minimum
                    address where the byteAddr is within the code unit.
        :param ghidra.program.model.address.Address byteAddr: address of the location; cannot be null
        :param jpype.JArray[jpype.JInt] componentPath: array of indexes for each nested data component; the data index is the
                    data component's index within its parent; may be null
        :param ghidra.program.model.address.Address refAddr: the "referred to" address if the location is over a reference; may be null
        :param jpype.JInt or int row: the row within the field.
        :param jpype.JInt or int col: the display item index on the given row. (Note most fields only have one display
                    item per row)
        :param jpype.JInt or int charOffset: the character offset within the display item.
        :raises NullPointerException: if ``addr`` or ``program`` is null
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], refAddr: ghidra.program.model.address.Address, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new ProgramLocation for the given address. The address will be adjusted to the
        beginning of the :obj:`code unit <CodeUnit>` containing that address (if it exists). The
        original address can be retrieved using the :meth:`getByteAddress() <.getByteAddress>`" method.
        
        :param ghidra.program.model.listing.Program program: the program associated with this program location (also used to obtain a
                    code-unit-aligned address)
        :param ghidra.program.model.address.Address addr: address of the location; cannot be null
        :param jpype.JArray[jpype.JInt] componentPath: array of indexes for each nested data component; the index is the data
                    component's index within its parent; may be null
        :param ghidra.program.model.address.Address refAddr: the "referred to" address if the location is over a reference; may be null
        :param jpype.JInt or int row: the row within the field.
        :param jpype.JInt or int col: the display item index on the given row. (Note most fields only have one display
                    item per row)
        :param jpype.JInt or int charOffset: the character offset within the display item.
        :raises NullPointerException: if ``addr`` or ``program`` is null
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address):
        """
        Construct a new ProgramLocation for the given address. The address will be adjusted to the
        beginning of the :obj:`code unit <CodeUnit>` containing that address (if it exists). The
        original address can be retrieved using the :meth:`getByteAddress() <.getByteAddress>` method.
        
        :param ghidra.program.model.listing.Program program: the program associated with this program location (also used to obtain a
                    code-unit-aligned address)
        :param ghidra.program.model.address.Address addr: address for the location
        :raises NullPointerException: if ``addr`` or ``program`` is null
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new ProgramLocation for the given address. The address will be adjusted to the
        beginning of the :obj:`code unit <CodeUnit>` containing that address (if it exists). The
        original address can be retrieved using the :meth:`getByteAddress() <.getByteAddress>` method.
        
        :param ghidra.program.model.listing.Program program: the program associated with this program location (also used to obtain a
                    code-unit-aligned address)
        :param ghidra.program.model.address.Address addr: address for the location
        :param jpype.JInt or int row: the row within the field.
        :param jpype.JInt or int col: the display item index on the given row. (Note most fields only have one display
                    item per row)
        :param jpype.JInt or int charOffset: the character offset within the display item.
        :raises NullPointerException: if ``addr`` or ``program`` is null
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, refAddr: ghidra.program.model.address.Address):
        """
        Construct a new ProgramLocation for the given address. The address will be adjusted to the
        beginning of the :obj:`code unit <CodeUnit>` containing that address (if it exists). The
        original address can be retrieved using the :meth:`getByteAddress() <.getByteAddress>` method.
        
        :param ghidra.program.model.listing.Program program: the program associated with this program location (also used to obtain a
                    code-unit-aligned address)
        :param ghidra.program.model.address.Address addr: address for the location
        :param ghidra.program.model.address.Address refAddr: the "referred to" address if the location is over a reference
        :raises NullPointerException: if ``addr`` or ``program`` is null
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor required for restoring a program location from XML.
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address associated with this location.
        
         
        
        Note: this may not be the same as the byte address. For example, in a :obj:`code
        unit <CodeUnit>` location this may be the minimum address of the code unit that contains the byte
        address.
        
        :return: the address.
        :rtype: ghidra.program.model.address.Address
        """

    def getByteAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the byte level address associated with this location.
        
        :return: the byte address.
        :rtype: ghidra.program.model.address.Address
        """

    def getCharOffset(self) -> int:
        """
        Returns the character offset in the display item at the (row,col).
        
        :return: the character offset in the display item at the (row,col).
        :rtype: int
        """

    def getColumn(self) -> int:
        """
        Returns the column index of the display piece represented by this location. For most
        locations, there is only one display item per row, in which case this value will be 0.
        
        :return: the column.
        :rtype: int
        """

    def getComponentPath(self) -> jpype.JArray[jpype.JInt]:
        """
        Returns the componentPath for the :obj:`code unit <CodeUnit>`. Null will be returned if the
        object is an :obj:`Instruction` or a top-level :obj:`Data` object.
        
        :return: the path.
        :rtype: jpype.JArray[jpype.JInt]
        """

    @staticmethod
    def getLocation(program: ghidra.program.model.listing.Program, saveState: ghidra.framework.options.SaveState) -> ProgramLocation:
        """
        Get the program location for the given program and save state object.
        
        :param ghidra.program.model.listing.Program program: the program for the location
        :param ghidra.framework.options.SaveState saveState: the state to restore
        :return: the restored program location
        :rtype: ProgramLocation
        """

    def getProgram(self) -> ghidra.program.model.listing.Program:
        """
        Returns the program associated with this location.
        
        :return: the program.
        :rtype: ghidra.program.model.listing.Program
        """

    def getRefAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the "referred to" address if the location is over an address in some field.
        
        :return: the address.
        :rtype: ghidra.program.model.address.Address
        """

    def getRow(self) -> int:
        """
        Returns the row within the program location.
        
        :return: the row within the program location.
        :rtype: int
        """

    @staticmethod
    def getTranslatedCopy(loc: ProgramLocation, program: ghidra.program.model.listing.Program, translatedAddress: ghidra.program.model.address.Address) -> ProgramLocation:
        """
        Create a new translated copy of the specified :obj:`ProgramLocation` using the specified
        :obj:`program <Program>`
        
        :param ProgramLocation loc: original program location
        :param ghidra.program.model.listing.Program program: updated program
        :param ghidra.program.model.address.Address translatedAddress: original loc address translated for using within specified program
        :return: translated program location
        :rtype: ProgramLocation
        """

    def isValid(self, testProgram: ghidra.program.model.listing.Program) -> bool:
        """
        Returns true if this location represents a valid location in the given program.
        
        :param ghidra.program.model.listing.Program testProgram: the program to test if this location is valid.
        :return: true if this location represents a valid location in the given program.
        :rtype: bool
        """

    def restoreState(self, newProgram: ghidra.program.model.listing.Program, obj: ghidra.framework.options.SaveState):
        """
        Restore this program location using the given program and save state object.
        
        :param ghidra.program.model.listing.Program newProgram: program to restore from
        :param ghidra.framework.options.SaveState obj: the save state to restore from
        """

    def saveState(self, obj: ghidra.framework.options.SaveState):
        """
        Save this program location to the given save state object.
        
        :param ghidra.framework.options.SaveState obj: the save state object for saving the location
        """

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def byteAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def charOffset(self) -> jpype.JInt:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def componentPath(self) -> jpype.JArray[jpype.JInt]:
        ...

    @property
    def column(self) -> jpype.JInt:
        ...

    @property
    def row(self) -> jpype.JInt:
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...

    @property
    def refAddress(self) -> ghidra.program.model.address.Address:
        ...


class FunctionTagFieldLocation(FunctionLocation):
    """
    Provides information about the location of an object that 
    represents the tag names assigned to a function.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, tags: typing.Union[java.lang.String, str], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new FunctionTagFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param java.lang.String or str tags: the function tag field text.
        :param jpype.JInt or int charOffset: the character position within the field
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """


class VariableXRefFieldLocation(VariableLocation):
    """
    The ``VariableXRefFieldLocation`` class provides specific information
    about the variable's cross reference field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, var: ghidra.program.model.listing.Variable, refAddr: ghidra.program.model.address.Address, index: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new VariableXRefFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.listing.Variable var: the variable
        :param ghidra.program.model.address.Address refAddr: the reference address.
        :param jpype.JInt or int index: the index of the XREF (tells which XREF).
        :param jpype.JInt or int charOffset: the character position within the XREF.
        """

    @typing.overload
    def __init__(self):
        """
        Should only be used by XML restoration.
        """

    def getIndex(self) -> int:
        """
        Returns the index of the XREF in the list.
        """

    def getReferenceAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the reference address at this location.
        """

    def toString(self) -> str:
        """
        Returns a String representation of this location.
        """

    @property
    def referenceAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def index(self) -> jpype.JInt:
        ...


class VariableNameFieldLocation(VariableLocation):
    """
    The ``VariableNameFieldLocation`` class provides specific information
    about the variable name field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, var: ghidra.program.model.listing.Variable, charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new VariableNameFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.listing.Variable var: the variable the name is for.
        :param jpype.JInt or int charOffset: the position within the function name string for this location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, var: ghidra.program.model.listing.Variable, charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new VariableNameFieldLocation object.
        Variable function entry point is the assumed listing location (i.e., referent code unit).
        Care should be taken if variable corresponds to an EXTERNAL function.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.listing.Variable var: the variable the name is for.
        :param jpype.JInt or int charOffset: the position within the function name string for this location.
        """

    @typing.overload
    def __init__(self):
        """
        Should only be used by XML restoration.
        """

    def getName(self) -> str:
        """
        Returns the name of the variable for this location.
        """

    @property
    def name(self) -> java.lang.String:
        ...


class DiscoverableAddressCorrelator(AddressCorrelator, ghidra.util.classfinder.ExtensionPoint):
    """
    AddressCorrelators that want to be discovered by version tracking should implement this interface.
    """

    class_: typing.ClassVar[java.lang.Class]


class ProgramContextImpl(AbstractStoredProgramContext):
    """
    Implementation for a processor context over the address space
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, language: ghidra.program.model.lang.Language):
        """
        Construct a new program context
        
        :param ghidra.program.model.lang.Language language: program language
        """


class DataTypeArchiveChangeManager(java.lang.Object):
    """
    Interface to define event types and the method to generate an
    event within Program.
    """

    class_: typing.ClassVar[java.lang.Class]
    DOCR_CATEGORY_ADDED: typing.Final[ProgramEvent]
    """
    Category was added.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CATEGORY_REMOVED: typing.Final[ProgramEvent]
    """
    Category was removed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CATEGORY_RENAMED: typing.Final[ProgramEvent]
    """
    Category was renamed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_CATEGORY_MOVED: typing.Final[ProgramEvent]
    """
    Category was moved.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_ADDED: typing.Final[ProgramEvent]
    """
    Data type was added to a category.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_REMOVED: typing.Final[ProgramEvent]
    """
    Data type was removed from a category.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_RENAMED: typing.Final[ProgramEvent]
    """
    Data Type was renamed.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_MOVED: typing.Final[ProgramEvent]
    """
    Data type was moved to another category.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_CHANGED: typing.Final[ProgramEvent]
    """
    Data type was updated.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_SETTING_CHANGED: typing.Final[ProgramEvent]
    """
    The settings on a data type were updated.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """

    DOCR_DATA_TYPE_REPLACED: typing.Final[ProgramEvent]
    """
    Data type was replaced in a category.
    
    
    .. deprecated::
    
    Event type numeric constants have been changed to enums. Use the enum directly.
    """



class VariableLocation(FunctionLocation):
    """
    ``VariableLocation`` provides information about the location
    on a variable within a ``Function``.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a variable location from XML.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, var: ghidra.program.model.listing.Variable, index: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Create a new VariableLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.listing.Variable var: the variable associated with this location.
        :param jpype.JInt or int index: the index of the sub-piece on that variable (only the xrefs have subpieces
        :param jpype.JInt or int charOffset: the character position on the piece.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, var: ghidra.program.model.listing.Variable, index: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Create a new VariableLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.listing.Variable var: the variable associated with this location.
        :param jpype.JInt or int index: the index of the sub-piece on that variable (only the xrefs have subpieces
        :param jpype.JInt or int charOffset: the character position on the piece.
        """

    def getVariable(self) -> ghidra.program.model.listing.Variable:
        """
        Get the variable associated with this variable location
        
        :return: associated function variable
        :rtype: ghidra.program.model.listing.Variable
        """

    def isLocationFor(self, var: ghidra.program.model.listing.Variable) -> bool:
        """
        Checks to see if this location is for the indicated variable.
        
        :param ghidra.program.model.listing.Variable var: the variable
        :return: true if this location is for the specified variable.
        :rtype: bool
        """

    def isParameter(self) -> bool:
        ...

    def isReturn(self) -> bool:
        ...

    @property
    def return_(self) -> jpype.JBoolean:
        ...

    @property
    def parameter(self) -> jpype.JBoolean:
        ...

    @property
    def variable(self) -> ghidra.program.model.listing.Variable:
        ...

    @property
    def locationFor(self) -> jpype.JBoolean:
        ...


class SpacerFieldLocation(CodeUnitLocation):
    """
    The ``SpacerFieldLocation`` class contains specific location information
    within a spacer field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], charOffset: typing.Union[jpype.JInt, int], text: typing.Union[java.lang.String, str]):
        """
        Construct a new SpacerFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: the address of the codeunit.
        :param jpype.JArray[jpype.JInt] componentPath: the componentPath of the codeUnit
        :param jpype.JInt or int charOffset: the character position on the row of the location.
        :param java.lang.String or str text: the constant text in this spacer.
        """

    @typing.overload
    def __init__(self):
        """
        Should only be used by XML restoration.
        """

    def getText(self) -> str:
        """
        Returns the text of the Spacer field containing this location.
        """

    def toString(self) -> str:
        """
        returns a String representation of this location.
        """

    @property
    def text(self) -> java.lang.String:
        ...


class CodeUnitContainer(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, codeUnit: ghidra.program.model.listing.CodeUnit):
        ...

    def getArity(self) -> int:
        ...

    def getCodeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        ...

    def getMnemonic(self) -> str:
        ...

    @property
    def arity(self) -> jpype.JInt:
        ...

    @property
    def codeUnit(self) -> ghidra.program.model.listing.CodeUnit:
        ...

    @property
    def mnemonic(self) -> java.lang.String:
        ...


class FunctionSignatureSourceFieldLocation(FunctionLocation):
    """
    The ``FunctionSignatureFieldLocation`` class provides specific information
    about the Function Signature field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, source: typing.Union[java.lang.String, str], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new FunctionSignatureFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of this location.
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param java.lang.String or str source: the function signature SourceType at this location.
        :param jpype.JInt or int charOffset: field character position
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """

    def getSignatureSource(self) -> str:
        """
        Return the function signature source at this location.
        
        
        .. seealso::
        
            | :obj:`SourceType`
        """

    def toString(self) -> str:
        """
        Returns a String representation of this location.
        """

    @property
    def signatureSource(self) -> java.lang.String:
        ...


class RangeMapAdapter(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def checkWritableState(self):
        """
        Verify that adapter is in a writable state (i.e., valid transaction has been started).
        
        :raises IllegalStateException: if not in a writable state
        """

    def clearAll(self):
        """
        Clears all values.
        """

    def clearRange(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Clears all associated values in the given range.
        
        :param ghidra.program.model.address.Address start: the first address in the range to clear.
        :param ghidra.program.model.address.Address end: the end address in the range to clear.
        """

    @typing.overload
    def getAddressRangeIterator(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an :obj:`IndexRangeIterator` over all stored values in the given range.  If the
        given range intersects an actual stored range either at the beginning or end, the iterator
        will return those ranges truncated to fit within the given range.
        
        :param ghidra.program.model.address.Address start: the first Address in the range.
        :param ghidra.program.model.address.Address end: the last Address (inclusive) index in the range.
        :return: an :obj:`IndexRangeIterator` over all stored values.
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    @typing.overload
    def getAddressRangeIterator(self) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an :obj:`IndexRangeIterator` over all stored values.
        
        :return: an :obj:`IndexRangeIterator` over all stored values.
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    def getValue(self, address: ghidra.program.model.address.Address) -> jpype.JArray[jpype.JByte]:
        """
        Returns the byte array that has been associated with the given index.
        
        :param ghidra.program.model.address.Address address: the address at which to retrieve a byte array.
        :return: the byte array that has been associated with the given index or null if no such
        association exists.
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getValueRangeContaining(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRange:
        """
        Returns the bounding address-range containing addr and the same value throughout.
        This range will be limited by any value change associated with the base register.
        
        :param ghidra.program.model.address.Address addr: the containing address
        :return: single value address-range containing addr
        :rtype: ghidra.program.model.address.AddressRange
        """

    def invalidate(self):
        """
        Notification that something has changed that may affect internal caching
        """

    def isEmpty(self) -> bool:
        """
        Returns true if this storage has no associated values for any address
        
        :return: true if this storage has no associated values for any address
        :rtype: bool
        """

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Move all values within an address range to a new range.
        
        :param ghidra.program.model.address.Address fromAddr: the first address of the range to be moved.
        :param ghidra.program.model.address.Address toAddr: the address where to the range is to be moved.
        :param jpype.JLong or int length: the number of addresses to move.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor.
        :raises CancelledException: if the user canceled the operation via the task monitor.
        """

    def set(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, bytes: jpype.JArray[jpype.JByte]):
        """
        Associates the given byte array with all indexes in the given range.  Any existing values
        will be over written.
        
        :param ghidra.program.model.address.Address start: the first address in the range.
        :param ghidra.program.model.address.Address end: the last Address(inclusive) in the range.
        :param jpype.JArray[jpype.JByte] bytes: the bytes to associate with the range.
        """

    def setLanguage(self, translator: LanguageTranslator, mapReg: ghidra.program.model.lang.Register, monitor: ghidra.util.task.TaskMonitor):
        """
        Update table name and values to reflect new base register
        
        :param LanguageTranslator translator: 
        :param ghidra.program.model.lang.Register mapReg: 
        :param ghidra.util.task.TaskMonitor monitor: 
        :raises CancelledException:
        """

    @property
    def valueRangeContaining(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def addressRangeIterator(self) -> ghidra.program.model.address.AddressRangeIterator:
        ...

    @property
    def value(self) -> jpype.JArray[jpype.JByte]:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


class VariablesOpenCloseLocation(CodeUnitLocation):
    """
    ProgramLocation that represents the cursor being on the variables open/close widget
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of the location
        """

    @typing.overload
    def __init__(self):
        ...


class BlockStartLocation(CommentFieldLocation):
    """
    ``BlockStartLocation`` provides information about the location 
    (within a program) of an object that represents the start of a memory block.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int], comment: jpype.JArray[java.lang.String], commentRow: typing.Union[jpype.JInt, int]):
        """
        Create a new BlockStartLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of block
        :param jpype.JArray[jpype.JInt] componentPath: object that uniquely identifies a module or fragment
        by its hierarchy names; this parameter may be null
        :param jpype.JInt or int row: the component row
        :param jpype.JInt or int charOffset: character position of the location
        :param jpype.JArray[java.lang.String] comment: the block comments
        :param jpype.JInt or int commentRow: the comment row
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """


class ChangeManagerAdapter(ChangeManager):
    """
    Empty implementation for a ChangeManager.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class EolCommentFieldLocation(CommentFieldLocation):
    """
    The ``EolCommentFieldLocation`` class contains specific location information
    within the EOL comment field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], comment: jpype.JArray[java.lang.String], displayableCommentRow: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int], currentCommentRow: typing.Union[jpype.JInt, int]):
        """
        Construct a new EolCommentFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: the address of the codeunit.
        :param jpype.JArray[jpype.JInt] componentPath: the componentPath of the codeUnit
        :param jpype.JArray[java.lang.String] comment: comment text for the particular comment indicated by the address, subtype, and reference address.
        :param jpype.JInt or int displayableCommentRow: the line within the Eol comment as displayed.
        :param jpype.JInt or int charOffset: the character position on the line within the comment line.
        :param jpype.JInt or int currentCommentRow: the row index relative to the beginning of the End of Line comment 
        as displayed in the Eol comment field.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        an end-of-line field location from XML.
        """

    def getCurrentCommentRow(self) -> int:
        ...

    @property
    def currentCommentRow(self) -> jpype.JInt:
        ...


class AutomaticCommentFieldLocation(CommentFieldLocation):
    """
    The ``AutomaticCommentFieldLocation`` class contains specific location information
    within the automatic comment of an EOL comment field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], comment: jpype.JArray[java.lang.String], row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int], currentCommentRow: typing.Union[jpype.JInt, int]):
        """
        Construct a new AutomaticCommentFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: the address of the codeunit.
        :param jpype.JArray[jpype.JInt] componentPath: the componentPath of the codeUnit
        :param jpype.JArray[java.lang.String] comment: comment text for the particular comment indicated by the address, subtype, and reference address.
        :param jpype.JInt or int row: the line within the Eol comment.
        :param jpype.JInt or int charOffset: the character position on the line within the comment line.
        :param jpype.JInt or int currentCommentRow: the row index relative to the beginning of the automatic comment 
        as displayed in the Eol comment field.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        an end-of-line field location from XML.
        """

    def getCurrentCommentRow(self) -> int:
        ...

    @property
    def currentCommentRow(self) -> jpype.JInt:
        ...


class CodeUnitLCS(generic.algorithms.Lcs[CodeUnitContainer]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, xList: java.util.List[CodeUnitContainer], yList: java.util.List[CodeUnitContainer]):
        ...


class ProgramTask(ghidra.util.task.Task):
    """
    Task for operating on programs. Will open and close a transaction around the
    work.
    """

    class_: typing.ClassVar[java.lang.Class]


class FunctionNoReturnFieldLocation(FunctionSignatureFieldLocation):
    """
    The ``FunctionNoReturnFieldLocation`` class provides specific information
    about the Function noreturn field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str], noreturn: typing.Union[java.lang.String, str]):
        """
        Construct a new FunctionNoReturnFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int charOffset: the position within the function noreturn string for this location.
        :param java.lang.String or str signature: the function signature string at this location.
        :param java.lang.String or str noreturn: the function noreturn String at this location.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """


class ThunkedFunctionFieldLocation(FunctionLocation):
    """
    The ``ThunkedFunctionFieldLocation`` class provides specific information
    about a thunked function within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, thunkedFunctionAddr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new ThunkedFunctionFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program containing the thinked function
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param ghidra.program.model.address.Address thunkedFunctionAddr: the thunked function address
        :param jpype.JInt or int charOffset: field character offset
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """


class FunctionSignatureFieldLocation(FunctionLocation):
    """
    The ``FunctionSignatureFieldLocation`` class provides specific information
    about the Function Signature field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str]):
        """
        Construct a new FunctionSignatureFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int charOffset: the character position within the function signature string for this location.
        :param java.lang.String or str signature: the function signature String at this location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, functionAddr: ghidra.program.model.address.Address, col: typing.Union[jpype.JInt, int], signature: typing.Union[java.lang.String, str]):
        """
        Construct a new FunctionSignatureFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JInt or int col: the character position within the function signature string for this location.
        :param java.lang.String or str signature: the function signature String at this location.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, functionAddr: ghidra.program.model.address.Address):
        """
        Construct a new FunctionSignatureFieldLocation object with field-based positioning.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address functionAddr: the function address
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """

    def getSignature(self) -> str:
        """
        Return the function signature string at this location.
        """

    def isFieldBasedPositioning(self) -> bool:
        ...

    def toString(self) -> str:
        """
        Returns a String representation of this location.
        """

    @property
    def fieldBasedPositioning(self) -> jpype.JBoolean:
        ...

    @property
    def signature(self) -> java.lang.String:
        ...


@typing.type_check_only
class SimpleLanguageTranslator(LanguageTranslatorAdapter):
    """
    ``SimpleLanguageTranslator`` provides a simple translator which
    derives its mappings from an XML translation specification file.
    """

    class_: typing.ClassVar[java.lang.Class]


class CommentTypeUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getCommentType(cu: ghidra.program.model.listing.CodeUnit, loc: ProgramLocation, defaultCommentType: ghidra.program.model.listing.CommentType) -> ghidra.program.model.listing.CommentType:
        """
        Get the comment type from the current location. If the cursor
        is not over a comment, then just return EOL as the default.
        
        :param ghidra.program.model.listing.CodeUnit cu: 
        :param ProgramLocation loc: 
        :param ghidra.program.model.listing.CommentType defaultCommentType: 
        :return: comment type or defaultCommentType if location does not correspond 
        to a comment
        :rtype: ghidra.program.model.listing.CommentType
        """

    @staticmethod
    def isCommentAllowed(cu: ghidra.program.model.listing.CodeUnit, loc: ProgramLocation) -> bool:
        ...


class LanguageTranslator(ghidra.util.classfinder.ExtensionPoint):
    """
    NOTE:  ALL LanguageTranslator CLASSES MUST END IN "LanguageTranslator".  If not,
    the ClassSearcher will not find them.
     
    ``LanguageTranslator`` provides translation capabilities used by Program.setLanguage
    when converting a program from one language to another or from one version to another.
     
    
    Explicit translator implementations must implement the default constructor and should not
    instantiate Language, AddressSpace, AddressFactory or Register objects until isValid() is invoked.
    """

    class_: typing.ClassVar[java.lang.Class]

    def fixupInstructions(self, program: ghidra.program.model.listing.Program, oldLanguage: ghidra.program.model.lang.Language, monitor: ghidra.util.task.TaskMonitor):
        """
        Invoked after Program language upgrade has completed.  
        Implementation of this method permits the final re-disassembled program to be
        examined/modified to address more complex language upgrades.  This method will only be 
        invoked on the latest translator, which means all complex multi-version post-upgrade
        concerns must factor in the complete language transition.  The program's language 
        information will still reflect the original pre-upgrade state, and if the program is
        undergoing a schema version upgrade as well, certain complex upgrades may not
        have been completed (e.g., Function and Variable changes).  Program modifications should
        be restricted to instruction and instruction context changes only.
        
        :param ghidra.program.model.listing.Program program: 
        :param ghidra.program.model.lang.Language oldLanguage: the oldest language involved in the current upgrade translation
        (this is passed since this is the only fixup invocation which must handle the any
        relevant fixup complexities when transitioning from the specified oldLanguage).
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises java.lang.Exception: if a bad exception occurs with the post upgrade fixup
        :raises CancelledException: if upgrade cancelled
        """

    def getNewAddressSpace(self, oldSpaceName: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.AddressSpace:
        """
        Translate BASE address spaces (Overlay spaces are not handled)
        
        :param java.lang.String or str oldSpaceName: old space name
        :return: corresponding address space in new language
        :rtype: ghidra.program.model.address.AddressSpace
        """

    def getNewCompilerSpecID(self, oldCompilerSpecID: ghidra.program.model.lang.CompilerSpecID) -> ghidra.program.model.lang.CompilerSpecID:
        """
        Obtain the new compiler specification ID given the old compiler spec ID.
        
        :param ghidra.program.model.lang.CompilerSpecID oldCompilerSpecID: old compiler spec ID.
        :return: new compiler spec ID.
        :rtype: ghidra.program.model.lang.CompilerSpecID
        """

    def getNewContextRegister(self) -> ghidra.program.model.lang.Register:
        """
        Returns the new processor context register or null if not defined
        """

    def getNewLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Returns new language
        """

    def getNewLanguageID(self) -> ghidra.program.model.lang.LanguageID:
        """
        Returns new language name
        """

    def getNewRegister(self, oldReg: ghidra.program.model.lang.Register) -> ghidra.program.model.lang.Register:
        """
        Find new register which corresponds to the specified old register.
        
        :param ghidra.program.model.lang.Register oldReg: old register
        :return: new register or null if corresponding register not found.
        :rtype: ghidra.program.model.lang.Register
        """

    def getNewRegisterValue(self, oldValue: ghidra.program.model.lang.RegisterValue) -> ghidra.program.model.lang.RegisterValue:
        """
        Get the translated register value
        
        :param ghidra.program.model.lang.RegisterValue oldValue: old register value (may not be null)
        :return: new register value or null if register not mapped
        :rtype: ghidra.program.model.lang.RegisterValue
        
        .. seealso::
        
            | :obj:`.isValueTranslationRequired(Register)`
        """

    def getNewVersion(self) -> int:
        """
        Returns new language version
        """

    def getOldCompilerSpec(self, oldCompilerSpecID: ghidra.program.model.lang.CompilerSpecID) -> ghidra.program.model.lang.CompilerSpec:
        """
        Get a compiler spec suitable for use with the old language.  The compiler 
        spec returned is intended for upgrade use only prior to the setLanguage
        and may be based upon compiler conventions specified in the new compiler 
        spec returned by getNewCompilerSpec given the same compilerSpecID.
        
        :param ghidra.program.model.lang.CompilerSpecID oldCompilerSpecID: old compiler spec ID.
        :return: compiler spec for use with old language
        :rtype: ghidra.program.model.lang.CompilerSpec
        :raises CompilerSpecNotFoundException: if new compiler spec not found based upon 
        translator mappings.
        """

    def getOldContextRegister(self) -> ghidra.program.model.lang.Register:
        """
        Returns the old processor context register or null if not defined
        """

    def getOldLanguage(self) -> ghidra.program.model.lang.Language:
        """
        Returns old language
        
        :raises IllegalStateException: if instance has not been validated
        
        .. seealso::
        
            | :obj:`.isValid()`
        """

    def getOldLanguageID(self) -> ghidra.program.model.lang.LanguageID:
        """
        Returns old language name
        """

    def getOldRegister(self, oldAddr: ghidra.program.model.address.Address, size: typing.Union[jpype.JInt, int]) -> ghidra.program.model.lang.Register:
        """
        Get the old register at the specified oldAddr.  This will null if the specified
        address is offcut within the register.
        The smallest register will be returned which is greater than or equal to the specified size.
        
        :param ghidra.program.model.address.Address oldAddr: old register address.
        :param jpype.JInt or int size: minimum register size
        :return: old register or null if suitable register can not be found.
        :rtype: ghidra.program.model.lang.Register
        
        .. seealso::
        
            | :obj:`.getOldRegisterContaining(Address)`
        """

    def getOldRegisterContaining(self, oldAddr: ghidra.program.model.address.Address) -> ghidra.program.model.lang.Register:
        """
        Get the largest old register which contains the specified oldAddr
        
        :param ghidra.program.model.address.Address oldAddr: old register address which may be offcut
        :return: old register or null if suitable register can not be found.
        :rtype: ghidra.program.model.lang.Register
        """

    def getOldVersion(self) -> int:
        """
        Returns old language version
        """

    def isValid(self) -> bool:
        """
        Validate translator to complete initialization and ensure language compatibility.
        This method will be invoked by the LanguageTranslatorFactory before handing out this
        translator.
        
        :return: true if translator successfully validated
        :rtype: bool
        """

    def isValueTranslationRequired(self, oldReg: ghidra.program.model.lang.Register) -> bool:
        """
        Returns true if register value translation required for 
        program context.
        
        :param ghidra.program.model.lang.Register oldReg: 
        
        .. seealso::
        
            | :obj:`.getNewRegisterValue(RegisterValue)`
        """

    @property
    def oldCompilerSpec(self) -> ghidra.program.model.lang.CompilerSpec:
        ...

    @property
    def oldContextRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def newLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def newAddressSpace(self) -> ghidra.program.model.address.AddressSpace:
        ...

    @property
    def oldRegisterContaining(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def newRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def valueTranslationRequired(self) -> jpype.JBoolean:
        ...

    @property
    def oldVersion(self) -> jpype.JInt:
        ...

    @property
    def newLanguageID(self) -> ghidra.program.model.lang.LanguageID:
        ...

    @property
    def valid(self) -> jpype.JBoolean:
        ...

    @property
    def oldLanguage(self) -> ghidra.program.model.lang.Language:
        ...

    @property
    def newContextRegister(self) -> ghidra.program.model.lang.Register:
        ...

    @property
    def newRegisterValue(self) -> ghidra.program.model.lang.RegisterValue:
        ...

    @property
    def newCompilerSpecID(self) -> ghidra.program.model.lang.CompilerSpecID:
        ...

    @property
    def oldLanguageID(self) -> ghidra.program.model.lang.LanguageID:
        ...

    @property
    def newVersion(self) -> jpype.JInt:
        ...


class DefaultLanguageService(ghidra.program.model.lang.LanguageService):
    """
    Default Language service used gather up all the languages that were found
    during the class search (search was for language providers)
    """

    @typing.type_check_only
    class LanguageInfo(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getDefinedExternalToolNames(languageId: typing.Union[java.lang.String, str], tool: typing.Union[java.lang.String, str], includeDeprecated: typing.Union[jpype.JBoolean, bool]) -> java.util.List[java.lang.String]:
        """
        Returns external names for specified language associated with other
        tools. For example, x86 languages are usually referred to as "metapc" by
        IDA-PRO.
        
        :param java.lang.String or str languageId: language to search against
        :param java.lang.String or str tool: name of external tool to search against
        :param jpype.JBoolean or bool includeDeprecated: include deprecated LanguageDescriptions
        :return: external names for this language associated with tool
        :rtype: java.util.List[java.lang.String]
        """

    def getExternalLanguageDescriptions(self, externalProcessorName: typing.Union[java.lang.String, str], externalTool: typing.Union[java.lang.String, str], endianness: ghidra.program.model.lang.Endian, size: typing.Union[java.lang.Integer, int]) -> java.util.List[ghidra.program.model.lang.LanguageDescription]:
        ...

    @staticmethod
    def getLanguageService() -> ghidra.program.model.lang.LanguageService:
        """
        Returns the single instance of the DefaultLanguageService.
        
        :return: the language service
        :rtype: ghidra.program.model.lang.LanguageService
        """


class StackDepthFieldLocation(ProgramLocation):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        ...


class RefRepeatCommentFieldLocation(CommentFieldLocation):
    """
    The ``RefRepeatCommentFieldLocation`` class contains specific location information
    within the Referenced Repeatable comments of an EOL comment field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], comment: jpype.JArray[java.lang.String], row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int], currentCommentRow: typing.Union[jpype.JInt, int], refRepeatAddress: ghidra.program.model.address.Address):
        """
        Construct a new RefRepeatCommentFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: the address of the codeunit.
        :param jpype.JArray[jpype.JInt] componentPath: the componentPath of the codeUnit
        :param jpype.JArray[java.lang.String] comment: comment text for the particular comment indicated by the address, subtype, and reference address.
        :param jpype.JInt or int row: the line within the Eol comment.
        :param jpype.JInt or int charOffset: the character position on the line within the comment line.
        :param jpype.JInt or int currentCommentRow: the row index relative to the beginning of the particular 
        referenced repeatable comment that is displayed at this location in the Eol comment field.
        :param ghidra.program.model.address.Address refRepeatAddress: the referred to address for the referenced repeatable comment that
        is being displayed at this location.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        an end-of-line field location from XML.
        """

    def getCurrentCommentRow(self) -> int:
        ...

    def getReferencedRepeatableAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def currentCommentRow(self) -> jpype.JInt:
        ...

    @property
    def referencedRepeatableAddress(self) -> ghidra.program.model.address.Address:
        ...


class CodeUnitPropertyChangeRecord(ProgramChangeRecord):
    """
    Change record generated when a property on a code unit changes.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, type: ProgramEvent, propertyName: typing.Union[java.lang.String, str], address: ghidra.program.model.address.Address, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Constructor for a property change at an address
        
        :param ProgramEvent type: the program event type
        :param java.lang.String or str propertyName: the name of the code unit property
        :param ghidra.program.model.address.Address address: the address of the of the property that was changed.
        :param java.lang.Object oldValue: the old property value
        :param java.lang.Object newValue: the new property value
        """

    @typing.overload
    def __init__(self, type: ProgramEvent, propertyName: typing.Union[java.lang.String, str], start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address):
        """
        Constructor for events that affect a range of values
        
        :param ProgramEvent type: the program event type
        :param java.lang.String or str propertyName: the name of the code unit property
        :param ghidra.program.model.address.Address start: the start address of the range affected
        :param ghidra.program.model.address.Address end: the end address of the range affected
        """

    def getPropertyName(self) -> str:
        """
        Get the name of the property being changed.
        
        :return: the name of the property being changed
        :rtype: str
        """

    @property
    def propertyName(self) -> java.lang.String:
        ...


class LinearDataAddressCorrelation(AddressCorrelation):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, sourceData: ghidra.program.model.listing.Data, destinationData: ghidra.program.model.listing.Data):
        ...


@typing.type_check_only
class FactoryLanguageTranslator(LanguageTranslator):
    ...
    class_: typing.ClassVar[java.lang.Class]


class FunctionRepeatableCommentFieldLocation(FunctionLocation):
    """
    The ``FunctionRepeatableCommentFieldLocation`` class provides specific information
    about the Function Repeatable Comment field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, comment: jpype.JArray[java.lang.String], row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new FunctionRepeatableCommentFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param jpype.JArray[java.lang.String] comment: the function comment array String at this location.
        :param jpype.JInt or int row: row number (index into the comment array)
        :param jpype.JInt or int charOffset: character position within the comment, indexed by row
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, functionAddr: ghidra.program.model.address.Address, comment: jpype.JArray[java.lang.String], row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]):
        """
        Construct a new FunctionRepeatableCommentFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address functionAddr: the function address (must not be an EXTERNAL function)
        :param jpype.JArray[java.lang.String] comment: the function comment array String at this location.
        :param jpype.JInt or int row: row number (index into the comment array)
        :param jpype.JInt or int col: character position within the comment, indexed by row
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """

    def getComment(self) -> jpype.JArray[java.lang.String]:
        """
        Return the function comment string at this location.
        """

    @property
    def comment(self) -> jpype.JArray[java.lang.String]:
        ...


class AddressCorrelation(java.lang.Object):
    """
    Interface representing the address mapping for any means of correlating addresses
    between a source program and a destination program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCorrelatedDestinationRange(self, sourceAddress: ghidra.program.model.address.Address, monitor: ghidra.util.task.TaskMonitor) -> AddressCorrelationRange:
        """
        Returns the AddressRange of a set of addresses in the destination
        program that correlates to corresponding range in the source program.
        
        :param ghidra.program.model.address.Address sourceAddress: the source program address
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :return: the destination program address range, or null if there is not address range mapped
        :rtype: AddressCorrelationRange
        :raises CancelledException: if cancelled
        """

    def getName(self) -> str:
        """
        This method is no longer part of the API.  Leaving a default implementation to reduce 
        breaking clients.
        
        :return: the simple class name of the implementing class
        :rtype: str
        """

    @property
    def name(self) -> java.lang.String:
        ...


class DefinedDataIterator(ghidra.program.model.listing.DataIterator):
    """
    Iterator that visits each defined data instance in the initialized memory of a Program or in the footprint of
    a specified data element.
     
    
    Data elements that are nested inside of composites or arrays are visited, not just the
    parent/containing data element.
     
    
    Not thread safe.
    """

    @typing.type_check_only
    class DataComponentIterator(ghidra.program.model.listing.DataIterator):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, data: ghidra.program.model.listing.Data):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def byDataInstance(program: ghidra.program.model.listing.Program, dataInstancePredicate: java.util.function.Predicate[ghidra.program.model.listing.Data]) -> DefinedDataIterator:
        """
        Creates a new iterator that traverses the entire Program's address space, returning
        data instances that successfully match the predicate.
        
        :param ghidra.program.model.listing.Program program: Program to search
        :param java.util.function.Predicate[ghidra.program.model.listing.Data] dataInstancePredicate: :obj:`Predicate` that tests each data instance's properties
        :return: new iterator
        :rtype: DefinedDataIterator
        """

    @staticmethod
    @typing.overload
    def byDataType(program: ghidra.program.model.listing.Program, dataTypePredicate: java.util.function.Predicate[ghidra.program.model.data.DataType]) -> DefinedDataIterator:
        """
        Creates a new iterator that traverses the entire Program's address space, returning
        data instances that successfully match the predicate.
        
        :param ghidra.program.model.listing.Program program: Program to search
        :param java.util.function.Predicate[ghidra.program.model.data.DataType] dataTypePredicate: :obj:`Predicate` that tests each data instance's :obj:`DataType`
        :return: new iterator
        :rtype: DefinedDataIterator
        """

    @staticmethod
    @typing.overload
    def byDataType(program: ghidra.program.model.listing.Program, addresses: ghidra.program.model.address.AddressSetView, dataTypePredicate: java.util.function.Predicate[ghidra.program.model.data.DataType]) -> DefinedDataIterator:
        """
        Creates a new iterator that traverses a portion of the Program's address space, returning
        data instances that successfully match the predicate.
        
        :param ghidra.program.model.listing.Program program: Program to search
        :param ghidra.program.model.address.AddressSetView addresses: addresses to limit the iteration to
        :param java.util.function.Predicate[ghidra.program.model.data.DataType] dataTypePredicate: :obj:`Predicate` that tests each data instance's :obj:`DataType`
        :return: new iterator
        :rtype: DefinedDataIterator
        """


class MemoryBlockStartFieldLocation(CommentFieldLocation):
    """
    ``BlockStartLocation`` provides information about the location 
    (within a program) of an object that represents the start of a memory block.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int], comment: jpype.JArray[java.lang.String], commentRow: typing.Union[jpype.JInt, int]):
        """
        Create a new BlockStartLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of block
        :param jpype.JArray[jpype.JInt] componentPath: the component path
        :param jpype.JInt or int row: component row
        :param jpype.JInt or int charOffset: character position of the location
        :param jpype.JArray[java.lang.String] comment: the location comment
        :param jpype.JInt or int commentRow: the comment row
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """


@typing.type_check_only
class TemporaryCompilerSpec(ghidra.program.model.lang.CompilerSpec):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, translator: LanguageTranslator, oldCompilerSpecID: ghidra.program.model.lang.CompilerSpecID):
        ...

    def getDefaultStackAlignment(self) -> int:
        ...

    def reloadCompilerSpec(self):
        ...

    @property
    def defaultStackAlignment(self) -> jpype.JInt:
        ...


class LanguageTranslatorFactory(java.lang.Object):
    """
    ``LanguageTranslatorFactory`` manages all language translators within Ghidra.  
    Language translators support either a version translation for a single language, or a 
    language transition from one language to another.  The following types of translators 
    are supported:
     
    * Simple translators are established based upon a translator XML specification file (*.trans).
    * Explicit translators are class implementations of the LanguageTranslator interface.
    The abstract LanguageTranslatorAdapter has been supplied for this purpose so that
    default mappings can be used if needed.  Such custom translator classes should not be
    created within the 'ghidra.program.util' package since they will be ignored by the factory.
    * Default translators can be instantiated for languages whose address spaces map to one-another.
    Such default translations may be lossy with register mappings and could result in lost register
    variables and references.
    """

    class_: typing.ClassVar[java.lang.Class]
    LANGUAGE_TRANSLATOR_FILE_EXT: typing.Final = ".trans"

    @typing.overload
    def getLanguageTranslator(self, fromLanguage: ghidra.program.model.lang.Language, toLanguage: ghidra.program.model.lang.Language) -> LanguageTranslator:
        """
        Returns a language translator for the transition from an oldLanguage to a newLanguage.
        The toLanguage may be a different language or a newer version of fromLanguage.
        
        :param ghidra.program.model.lang.Language fromLanguage: old language
        :param ghidra.program.model.lang.Language toLanguage: new language
        :return: language translator if transition is supported, otherwise null is returned.
        :rtype: LanguageTranslator
        """

    @typing.overload
    def getLanguageTranslator(self, languageName: ghidra.program.model.lang.LanguageID, majorVersion: typing.Union[jpype.JInt, int]) -> LanguageTranslator:
        """
        Returns a language translation for a language version which is no longer supported.
        
        :param ghidra.program.model.lang.LanguageID languageName: old unsupported language name
        :param jpype.JInt or int majorVersion: language major version within program
        :return: language translator if one can be determined, otherwise null is returned.
        :rtype: LanguageTranslator
        """

    @staticmethod
    def getLanguageTranslatorFactory() -> LanguageTranslatorFactory:
        """
        Returns the single instance of the OldLanguageFactory.
        """

    @staticmethod
    def registerLanguageTranslatorFactoryMinion(minion: LanguageTranslatorFactoryMinion):
        ...


class PlateFieldLocation(CommentFieldLocation):
    """
    The ``PlateFieldLocation`` class contains specific location information
    within the Plate field of a CodeUnitLocation object.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int], comment: jpype.JArray[java.lang.String], commentRow: typing.Union[jpype.JInt, int]):
        """
        Construct a new PlateFieldLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: the address of the code unit.
        :param jpype.JArray[jpype.JInt] componentPath: the componentPath of the codeUnit
        :param jpype.JInt or int row: the line of the location
        :param jpype.JInt or int charOffset: the character position on the row of the location.
        :param jpype.JArray[java.lang.String] comment: plate comment text
        :param jpype.JInt or int commentRow: The row index into the comments of this location.  This is different 
                than the ``row`` due to the fact that the PlateField has fictitious borders
                that don't exist in the actual comment.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a plate field location from XML.
        """

    def getCommentRow(self) -> int:
        """
        Returns the index into the String[] returned by :meth:`getComment() <.getComment>` that represents
        the comment row that was clicked.  ``-1`` will be returned if the border of the 
        plate field was clicked. 
         
        
        **Note: ** This value is different than that returned by :meth:`getRow() <.getRow>`, as that
                value represents the screen row clicked.  Further, the PlateField adds screen
                decoration to the comments, which causes the screen row to differ from the comment
                row.
        
        :return: the index into the String[] returned by :meth:`getComment() <.getComment>` that represents
        the comment row that was clicked.  ``-1`` will be returned if the border of the 
        plate field was clicked.
        :rtype: int
        """

    @property
    def commentRow(self) -> jpype.JInt:
        ...


class DefinedStringIterator(ghidra.program.model.listing.DataIterator):
    """
    Iterator that visits each defined string instance in the initialized memory of a Program 
    or in the footprint of a specified data element.
     
    
    Strings that are nested inside of composites or arrays are visited, not just the
    parent/containing data element.
     
    
    Not thread safe.
    """

    @typing.type_check_only
    class StructDtcIterator(ghidra.program.model.listing.DataIterator):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, data: ghidra.program.model.listing.Data, compDT: ghidra.program.model.data.Composite):
            ...


    @typing.type_check_only
    class DataComponentIterator(ghidra.program.model.listing.DataIterator):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, data: ghidra.program.model.listing.Data):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def forDataInstance(singleDataInstance: ghidra.program.model.listing.Data) -> DefinedStringIterator:
        """
        Creates a new iterator that traverses the address space of a single data item (ie. a
        composite or array data instance that needs to be recursed into).
        
        :param ghidra.program.model.listing.Data singleDataInstance: Data instance
        :return: new iterator
        :rtype: DefinedStringIterator
        """

    @staticmethod
    @typing.overload
    def forProgram(program: ghidra.program.model.listing.Program) -> DefinedStringIterator:
        """
        Creates a new iterator that traverses the entire Program's address space returning
        data instances that are strings.
        
        :param ghidra.program.model.listing.Program program: Ghidra :obj:`Program` to search
        :return: new iterator
        :rtype: DefinedStringIterator
        """

    @staticmethod
    @typing.overload
    def forProgram(program: ghidra.program.model.listing.Program, addrs: ghidra.program.model.address.AddressSetView) -> DefinedStringIterator:
        """
        Creates a new iterator that traverses a portion of the Program's address space returning
        data instances that are strings.
        
        :param ghidra.program.model.listing.Program program: Ghidra :obj:`Program` to search
        :param ghidra.program.model.address.AddressSetView addrs: addresses to limit the iteration to
        :return: new iterator
        :rtype: DefinedStringIterator
        """

    def getDataCandidateCount(self) -> int:
        ...

    @property
    def dataCandidateCount(self) -> jpype.JInt:
        ...


class AssignedVariableLocation(ProgramLocation):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, row: typing.Union[jpype.JInt, int], charOffset: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        """
        Get the row within a group of pcode strings.
        """


class CyclomaticComplexity(java.lang.Object):
    """
    Class with a utility function to calculate the cyclomatic complexity of a function.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def calculateCyclomaticComplexity(self, function: ghidra.program.model.listing.Function, monitor: ghidra.util.task.TaskMonitor) -> int:
        """
        Calculates the cyclomatic complexity of a function by decomposing it into a flow
        graph using a BasicBlockModel.
        
        :param ghidra.program.model.listing.Function function: the function
        :param ghidra.util.task.TaskMonitor monitor: a monitor
        :return: the cyclomatic complexity
        :rtype: int
        :raises CancelledException:
        """


class LanguageTranslatorAdapter(LanguageTranslator):
    """
    ``LanguageTranslatorAdapter`` provides a default language translator 
    behavior which may be extended to provide customized language translations.
    """

    @typing.type_check_only
    class DefaultLanguageTranslator(LanguageTranslatorAdapter):
        """
        Default language translator.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def getDefaultLanguageTranslator(oldLanguage: ghidra.program.model.lang.Language, newLanguage: ghidra.program.model.lang.Language) -> LanguageTranslator:
        """
        Return a validated default translator if one can be determined.
        
        :param ghidra.program.model.lang.Language oldLanguage: 
        :param ghidra.program.model.lang.Language newLanguage: 
        :return: default translator or null if reasonable mappings can not be determined.
        :rtype: LanguageTranslator
        """


class LanguagePostUpgradeInstructionHandler(java.lang.Object):
    """
    ``LanguagePostUpgradeInstructionHandler`` provides an abstract implementation 
    of a post language-upgrade instruction modification handler.  The Simple Language Translator
    facilitates the specification of such a handler implementation within a language 
    translator specification file using the *post_upgrade_handler* element.
    Following a major-version language upgrade, the last translator invoked is given an
    opportunity to perform additional instruction modifications on the entire program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program):
        """
        Constructor
        
        :param ghidra.program.model.listing.Program program:
        """

    def fixupInstructions(self, oldLanguage: ghidra.program.model.lang.Language, monitor: ghidra.util.task.TaskMonitor):
        """
        Invoked after Program language upgrade has completed.  
        Implementation of this method permits the final re-disassembled program to be
        examined/modified to address more complex language upgrades.  This method will only be 
        invoked on the latest translator, which means all complex multi-version post-upgrade
        concerns must factor in the complete language transition.  The program's language 
        information will still reflect the original pre-upgrade state, and if the program is
        undergoing a schema version upgrade as well, certain complex upgrades may not
        have been completed (e.g., Function and Variable changes).  Program modifications should
        be restricted to instruction and instruction context changes only.
        
        :param ghidra.program.model.lang.Language oldLanguage: the oldest language involved in the current upgrade translation
        (this is passed since this is the only fixup invocation which must handle the any
        relevant fixup complexities when transitioning from the specified oldLanguage).
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        :raises CancelledException: if upgrade cancelled
        """


class EquateInfo(java.lang.Object):
    """
    Class to hold information about an Equate; it is used
    in a ProgramChangeRecord when an equate is created and
    when references to the Equate are updated.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], value: typing.Union[jpype.JLong, int], refAddr: ghidra.program.model.address.Address, opIndex: typing.Union[jpype.JInt, int], dynamicHash: typing.Union[jpype.JLong, int]):
        """
        Constructor.
        
        :param java.lang.String or str name: Equate name
        :param jpype.JLong or int value: Equate value
        :param ghidra.program.model.address.Address refAddr: Reference address (may be null for some event types)
        :param jpype.JInt or int opIndex: operand index for the reference; useful only if 
        refAddr is not null. May be -1 if only dynamicHash applies.
        :param jpype.JLong or int dynamicHash: dynamic hash. May be 0 if only opIndex applies.
        """

    def getDynamicHash(self) -> int:
        """
        Get the varnode dynamic hash of where the equate was placed;
        This value is meaningful only if the reference address is not null, and
        may be 0 if only the operand index applies.
        """

    def getName(self) -> str:
        """
        Get the equate name.
        """

    def getOperandIndex(self) -> int:
        """
        Get the operand index of where the equate was placed;
        This value is meaningful only if the reference address is not null, and
        may be -1 if only the dynamicHash applies.
        """

    def getReferenceAddress(self) -> ghidra.program.model.address.Address:
        """
        Get the reference address.
        """

    def getValue(self) -> int:
        """
        Get the equate value.
        """

    def toString(self) -> str:
        """
        Return a meaningful string for debugging purposes.
        """

    @property
    def referenceAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def dynamicHash(self) -> jpype.JLong:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def value(self) -> jpype.JLong:
        ...

    @property
    def operandIndex(self) -> jpype.JInt:
        ...


class ProgramChangeRecord(ghidra.framework.model.DomainObjectChangeRecord):
    """
    Event data for a DomainObjectChangeEvent generated by a Program.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, eventType: ProgramEvent, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, affected: java.lang.Object, oldValue: java.lang.Object, newValue: java.lang.Object):
        """
        Construct a new ProgramChangeRecord; any of the Address or
        Object params may be null, depending on what the type param is.
        
        :param ProgramEvent eventType: event type
        :param ghidra.program.model.address.Address start: starting address that is affected by the event
        :param ghidra.program.model.address.Address end: ending address that is affected by the event
        :param java.lang.Object affected: the object that was affected by this change, if applicable
        :param java.lang.Object oldValue: original value
        :param java.lang.Object newValue: new value
        """

    @typing.overload
    def __init__(self, eventType: ProgramEvent, oldValue: java.lang.Object, newValue: java.lang.Object):
        ...

    def getEnd(self) -> ghidra.program.model.address.Address:
        """
        Get the end address of the affected addresses of this change or null if not applicable.
        
        :return: the end address of the effected address of this change
        :rtype: ghidra.program.model.address.Address
        """

    def getObject(self) -> java.lang.Object:
        """
        Return the object that is the subject of this change record.
        
        :return: the object affected or null if not applicable
        :rtype: java.lang.Object
        """

    def getStart(self) -> ghidra.program.model.address.Address:
        """
        Get the start address of the affected addresses of this change or null if not applicable.
        
        :return: the start address of the effected address of this change
        :rtype: ghidra.program.model.address.Address
        """

    @property
    def start(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def end(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def object(self) -> java.lang.Object:
        ...


class BytesFieldLocation(CodeUnitLocation):
    """
    Provides specific information about the bytes field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, byteAddress: ghidra.program.model.address.Address, componentPath: jpype.JArray[jpype.JInt], columnInByte: typing.Union[jpype.JInt, int]):
        """
        Create a new BytesFieldLocation which represents a specific byte address.
        
        :param ghidra.program.model.listing.Program program: the program for this location.
        :param ghidra.program.model.address.Address addr: the address of the code unit containing this location.
        :param ghidra.program.model.address.Address byteAddress: the address of this location which can be the address of a specific
        byte within a code unit.
        :param jpype.JArray[jpype.JInt] componentPath: the data component path which is specified as an array of indexes
        where each index indicates the index into nested structures. For instructions or
        simple data, this should be null.
        :param jpype.JInt or int columnInByte: the character position in the bytes
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address):
        """
        Creates a new BytesFieldLocation for the given address. The address will be adjusted to the 
        beginning of the code unit containing that address(if it exists).  The original address can 
        be retrieved using the "getByteAddress()" method.
        
        :param ghidra.program.model.listing.Program program: the program that this location is related.
        :param ghidra.program.model.address.Address addr: the address of the byte for this location.
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a byte field location from XML.
        """

    def getAddressForByte(self) -> ghidra.program.model.address.Address:
        ...

    def getByteIndex(self) -> int:
        """
        Returns the index of byte that represents the current program location. Sources that do not 
        get this specific should simply return 0.
        
        :return: the index
        :rtype: int
        """

    def getColumn(self) -> int:
        """
        This is overridden here because previous versions used to store the byte index in the
        column field.  So if anyone was incorrectly using getColumn() to get the byte index,
        then this override will allow that to keep working.
        """

    def getColumnInByte(self) -> int:
        """
        Returns the character position within the byte specified by getByteIndex().  Normally,
        this is 1, 2, or 3 corresponding to before the byte, between the nibbles of the byte or
        past the byte.  Sometimes, extra delimiters may exist allowing the position to be
        greater than 3.
        
        :return: the column
        :rtype: int
        """

    @property
    def column(self) -> jpype.JInt:
        ...

    @property
    def addressForByte(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def columnInByte(self) -> jpype.JInt:
        ...

    @property
    def byteIndex(self) -> jpype.JInt:
        ...


class DividerLocation(ProgramLocation):
    """
    ``DividerLocation`` provides information about the location 
    (within a program) of an object that represents some kind of a separation.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, groupPath: GroupPath, charOffset: typing.Union[jpype.JInt, int]):
        """
        Create a new DividerLocation.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address addr: address of bookmark
        :param GroupPath groupPath: object that uniquely identifies a module or fragment
        by its hierarchy names; this parameter may be null
        :param jpype.JInt or int charOffset: character position of the location
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """


class AddressEvaluator(generic.expressions.ExpressionEvaluator):
    """
    Class for evaluating expressions as an Address. See 
    :obj:`ExpressionOperator` for the full list of supported operators. All values are interpreted
    as longs or symbols that resolve to an address.
     
    
    ExpressionEvaluators can operate in either decimal or hex mode. If in hex mode, all numbers are
    assumed to be hexadecimal values. In decimal mode, numbers are assumed to be decimal values, but
    hexadecimal values can still be specified by prefixing them with "0x".
     
    
    There are also two convenience static methods that can be called to evaluate address expressions.
    These methods will either return an Address as the result or null if there was an error
    evaluating the expression. To get error messages related to parsing the expression, instantiate 
    an AddressEvaluator and call :meth:`parseAsAddress(String) <.parseAsAddress>` which will throw a 
    :obj:`ExpressionException` when the expression can't be evaluated.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, assumeHex: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs an AddressEvalutor for the given program and in the specified hex/decimal mode.
        
        :param ghidra.program.model.listing.Program program: the program to use to evaluate expressions into valid addresses.
        :param jpype.JBoolean or bool assumeHex: if true, all numeric values are assumed to be hexadecimal numbers.
        """

    @typing.overload
    def __init__(self, factory: ghidra.program.model.address.AddressFactory, assumeHex: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs an AdddressEvaluator without a full program. This version will not be able to
        evaluate symbol or memory block names. This is mostly for backwards compatibility.
        
        :param ghidra.program.model.address.AddressFactory factory: the address factory for creating addresses
        :param jpype.JBoolean or bool assumeHex: if true, all numeric values are assumed to be hexadecimal numbers.
        """

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, defaultSpace: ghidra.program.model.address.AddressSpace, assumeHex: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs an AddressEvalutor for the given program and in the specified hex/decimal mode.
        
        :param ghidra.program.model.listing.Program program: the program to use to evaluate expressions into valid addresses.
        :param ghidra.program.model.address.AddressSpace defaultSpace: The address space to use when converting long values into addresses. If
        this value is null, then the default address space will be used.
        :param jpype.JBoolean or bool assumeHex: if true, all numeric values are assumed to be hexadecimal numbers.
        """

    @staticmethod
    @typing.overload
    def evaluate(p: ghidra.program.model.listing.Program, inputExpression: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        """
        Gets a valid address for the specified program as indicated by the input expression.
        
        :param ghidra.program.model.listing.Program p: the program to use for determining the address.
        :param java.lang.String or str inputExpression: string representation of the address desired.
        :return: the address. Otherwise, return null if the string fails to evaluate
        to a unique legitimate address.
        :rtype: ghidra.program.model.address.Address
        """

    @staticmethod
    @typing.overload
    def evaluate(p: ghidra.program.model.listing.Program, baseAddr: ghidra.program.model.address.Address, inputExpression: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        """
        Gets a valid address for the specified program as indicated by the input expression.
        
        :param ghidra.program.model.listing.Program p: the program to use for determining the address.
        :param ghidra.program.model.address.Address baseAddr: the base address to use for relative addressing.
        :param java.lang.String or str inputExpression: string representation of the address desired.
        :return: the address. Otherwise, return null if the string fails to evaluate
        to a unique legitimate address.
        :rtype: ghidra.program.model.address.Address
        """

    def getAddressFactory(self) -> ghidra.program.model.address.AddressFactory:
        """
        Returns the :obj:`AddressFactory` being used by this address evaluator
        
        :return: the :obj:`AddressFactory` being used by this address evaluator
        :rtype: ghidra.program.model.address.AddressFactory
        """

    def parseAsAddress(self, input: typing.Union[java.lang.String, str]) -> ghidra.program.model.address.Address:
        """
        Evaluates the given input expression as an address.
        
        :param java.lang.String or str input: the expression to evaluate
        :return: the Address the expression evaluates to
        :rtype: ghidra.program.model.address.Address
        :raises ExpressionException: if the input expression can't be evaluated to a valid, unique
        address.
        """

    def parseAsRelativeAddress(self, input: typing.Union[java.lang.String, str], baseAddress: ghidra.program.model.address.Address) -> ghidra.program.model.address.Address:
        """
        Evaluates the given input expression as a relative offset that will be added to the given
        base address.
        
        :param java.lang.String or str input: the expression to evaluate as an offset
        :param ghidra.program.model.address.Address baseAddress: the base address the evaluted expression will be added to to get the 
        resulting address.
        :return: the Address after the evaluated offset is added to the given base address.
        :rtype: ghidra.program.model.address.Address
        :raises ExpressionException: if the input expression can't be evaluated to a valid, unique
        address.
        """

    def setPreferredAddressSpace(self, space: ghidra.program.model.address.AddressSpace):
        """
        Sets the :obj:`AddressSpace` to be used to convert long values into addresses.
        
        :param ghidra.program.model.address.AddressSpace space: the address space to convert long values into addresses
        """

    @property
    def addressFactory(self) -> ghidra.program.model.address.AddressFactory:
        ...


class FunctionPurgeFieldLocation(ProgramLocation):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, charOffset: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self):
        ...


class RegisterValueStore(java.lang.Object):
    """
    This is a generalized class for storing register values over ranges.  The values include mask bits
    to indicate which bits within the register are being set.  The mask is stored along with the
    value so the getValue method can indicate back which bits in the value are valid.  If existing
    values already exist at an address, the values are combined according to the masks.  Any new value
    bits that have their associated mask bits on will overwrite any existing bits and the new mask will
    be anded to the existing mask.  Other bits will not be affected.
     
    This class takes a RangeMapAdapter that will adapt to some lower level storage.  There are current
    two implementations - one that uses an ObjectRangeMap for storing register values in memory and
    the other that uses RangeMapDB for storing register values in the database.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, register: ghidra.program.model.lang.Register, rangeMap: RangeMapAdapter, enableRangeWriteCache: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new RegisterValueStore.
        
        :param RangeMapAdapter rangeMap: the rangeMapAdapter that handles the low level storage of byte arrays
        """

    def clearAll(self):
        """
        Delete all stored values and free/delete underlying storage.
        """

    def clearValue(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, register: ghidra.program.model.lang.Register):
        """
        Clears the address range of any set bits using the mask from the given register value.
        existing values in the range that have values that are not part of the input mask are 
        not changed. If register is null, just clear all the values in range
        
        :param ghidra.program.model.address.Address start: the start of the range to clear the register value bits.
        :param ghidra.program.model.address.Address end: the end of the range(inclusive) to clear the register value bits.
        :param ghidra.program.model.lang.Register register: the register whos mask to use.  If null, clear all values in the given range.
        """

    @typing.overload
    def getAddressRangeIterator(self, startAddress: ghidra.program.model.address.Address, endAddress: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an AddressRangeIterator that will return address ranges everywhere that register values
        have been set within the given range.
        
        :param ghidra.program.model.address.Address startAddress: the start address to get stored register values.
        :param ghidra.program.model.address.Address endAddress: the end address to get stored register values.
        :return: an AddressRangeIterator that will return address ranges everywhere that register
        values have been set within the given range.
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    @typing.overload
    def getAddressRangeIterator(self) -> ghidra.program.model.address.AddressRangeIterator:
        """
        Returns an AddressRangeIterator that will return address ranges everywhere that register
        values have been set.
        
        :return: an AddressRangeIterator that will return address ranges everywhere that register
        values have been set.
        :rtype: ghidra.program.model.address.AddressRangeIterator
        """

    def getValue(self, register: ghidra.program.model.lang.Register, address: ghidra.program.model.address.Address) -> ghidra.program.model.lang.RegisterValue:
        """
        Returns the RegisterValue (value and mask) associated with the given address.
        
        :param ghidra.program.model.lang.Register register: register (base or child) for which context value should be returned
        :param ghidra.program.model.address.Address address: the address at which to get the RegisterValue.
        :return: the RegisterValue
        :rtype: ghidra.program.model.lang.RegisterValue
        """

    def getValueRangeContaining(self, addr: ghidra.program.model.address.Address) -> ghidra.program.model.address.AddressRange:
        """
        Returns the bounding address-range containing addr and the same value throughout.
        This range will be limited by any value change associated with the base register.
        
        :param ghidra.program.model.address.Address addr: the contained address
        :return: single value address-range containing addr
        :rtype: ghidra.program.model.address.AddressRange
        """

    def invalidate(self):
        """
        Notifies that something changed, may need to invalidate any caches
        """

    def isEmpty(self) -> bool:
        """
        Returns true if this store has no associated values for any address.
        
        :return: true if this store has no associated values for any address.
        :rtype: bool
        """

    def moveAddressRange(self, fromAddr: ghidra.program.model.address.Address, toAddr: ghidra.program.model.address.Address, length: typing.Union[jpype.JLong, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Move all register values within an address range to a new range.
        
        :param ghidra.program.model.address.Address fromAddr: the first address of the range to be moved.
        :param ghidra.program.model.address.Address toAddr: the address where to the range is to be moved.
        :param jpype.JLong or int length: the number of addresses to move.
        :param ghidra.util.task.TaskMonitor monitor: the task monitor.
        :raises CancelledException: if the user canceled the operation via the task monitor.
        """

    def setLanguage(self, translator: LanguageTranslator, monitor: ghidra.util.task.TaskMonitor) -> bool:
        """
        Preserve register values and handle register name/size change.
        
        :param LanguageTranslator translator: 
        :param ghidra.util.task.TaskMonitor monitor: 
        :return: true if translated successfully, false if register not mapped 
        value storage should be discarded.
        :rtype: bool
        :raises CancelledException:
        """

    def setValue(self, start: ghidra.program.model.address.Address, end: ghidra.program.model.address.Address, newValue: ghidra.program.model.lang.RegisterValue):
        """
        Sets the given register value (contains value and mask) across the given address range.  Any
        existing values in the range that have values that are not part of the input mask are 
        not changed.
        
        :param ghidra.program.model.address.Address start: the start of the range to set the register value.
        :param ghidra.program.model.address.Address end: the end of the range(inclusive) to set the register value.
        :param ghidra.program.model.lang.RegisterValue newValue: the new register value to set.
        """

    @property
    def valueRangeContaining(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def addressRangeIterator(self) -> ghidra.program.model.address.AddressRangeIterator:
        ...

    @property
    def empty(self) -> jpype.JBoolean:
        ...


@typing.type_check_only
class OldLanguage(ghidra.program.model.lang.Language):

    class_: typing.ClassVar[java.lang.Class]

    def getAddressShiftAmount(self) -> int:
        ...

    def getOldCompilerSpecID(self) -> ghidra.program.model.lang.CompilerSpecID:
        """
        If this old language corresponds to a legacy language which was tied to a
        specific compiler specification, a suitable ID will be returned.
        
        :return: associated compiler specification ID or null if unknown
        :rtype: ghidra.program.model.lang.CompilerSpecID
        """

    @property
    def addressShiftAmount(self) -> jpype.JInt:
        ...

    @property
    def oldCompilerSpecID(self) -> ghidra.program.model.lang.CompilerSpecID:
        ...


class ProgramLocationComparator(java.util.Comparator[ProgramLocation]):
    """
    A comparator for the common fields of :obj:`ProgramLocation`
     
     
    
    This comparator only compares the program, address, and class of the program location. To compare
    at greater granularity, invoke the :meth:`ProgramLocation.compareTo(ProgramLocation) <ProgramLocation.compareTo>` method, or
    use the natural ordering. Each particular type of location uses this comparator, and then
    compares the more detailed fields, if necessary. If this comparator indicates equality, then the
    two locations are definitely of the same class.
    """

    class_: typing.ClassVar[java.lang.Class]
    INSTANCE: typing.Final[ProgramLocationComparator]
    """
    The singleton instance
    """



class AddressCorrelationRange(java.lang.Object):
    """
    A simple object that holds an :obj:`AddressCorrelation` address range and then name of the 
    correlation.s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, range: ghidra.program.model.address.AddressRange, correlatorName: typing.Union[java.lang.String, str]):
        ...

    def getCorrelatorName(self) -> str:
        ...

    def getMinAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getRange(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def range(self) -> ghidra.program.model.address.AddressRange:
        ...

    @property
    def minAddress(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def correlatorName(self) -> java.lang.String:
        ...


class FunctionCallFixupFieldLocation(FunctionLocation):
    """
    The ``FunctionCallFixupFieldLocation`` class provides specific information
    about the Function call-fixup field within a program location.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, program: ghidra.program.model.listing.Program, locationAddr: ghidra.program.model.address.Address, functionAddr: ghidra.program.model.address.Address, callFixupName: typing.Union[java.lang.String, str], charOffset: typing.Union[jpype.JInt, int]):
        """
        Construct a new FunctionCallFixupFieldLocation object.
        
        :param ghidra.program.model.listing.Program program: the program of the location
        :param ghidra.program.model.address.Address locationAddr: the address of the listing location (i.e., referent code unit)
        :param ghidra.program.model.address.Address functionAddr: the function address
        :param java.lang.String or str callFixupName: the function call-fixup field text String at this location.
        :param jpype.JInt or int charOffset: the character position within the field
        """

    @typing.overload
    def __init__(self):
        """
        Default constructor needed for restoring
        a program location from XML
        """

    def getCallFixupName(self) -> str:
        """
        Get function call fixup name
        
        :return: function call fixup name
        :rtype: str
        """

    @property
    def callFixupName(self) -> java.lang.String:
        ...



__all__ = ["FunctionUtility", "SymbolMerge", "ProgramMemoryComparator", "DataTypeCleaner", "ProgramMergeManager", "DefaultAddressTranslator", "ProgramDiffDetails", "ListingDiff", "OffsetAddressFactory", "FunctionMerge", "ProgramConflictException", "AddressTranslator", "ExternalSymbolResolver", "MarkerLocation", "ProgramDiff", "AddressRangeIteratorConverter", "ContextEvaluator", "MultiAddressIterator", "MultiAddressRangeIterator", "ProgramSelection", "ProgramMerge", "AddressIteratorConverter", "ProgramMemoryUtil", "MemoryRangeDiff", "InteriorSelection", "VarnodeContext", "AddressTranslationException", "GhidraProgramUtilities", "CombinedAddressRangeIterator", "ProgramMergeFilter", "OffsetAddressSpace", "ContextEvaluatorAdapter", "MemoryBlockDiff", "MemoryDiff", "ProgramDiffFilter", "GroupView", "DiffUtility", "SymbolicPropogator", "MultiCodeUnitIterator", "MnemonicFieldLocation", "AddressExpressionValue", "SubDataFieldLocation", "CodeUnitUserDataChangeRecord", "FunctionInlineFieldLocation", "CommentFieldLocation", "InstructionUtils", "OldLanguageFactory", "FunctionStartParametersFieldLocation", "IndentFieldLocation", "ListingAddressCorrelation", "PostCommentFieldLocation", "OffsetFieldType", "RepeatableCommentFieldLocation", "CommentChangeRecord", "UserDataChangeRecord", "AbstractStoredProgramContext", "FunctionCallingConventionFieldLocation", "SimpleDiffUtility", "FunctionReturnTypeFieldLocation", "SpaceFieldLocation", "VariableLocFieldLocation", "FunctionLocation", "VariableXRefHeaderFieldLocation", "AddressFieldLocation", "ProgramUtilities", "EquateOperandFieldLocation", "CodeUnitLocation", "VariableCommentFieldLocation", "InstructionMaskValueFieldLocation", "AddressCorrelator", "OffsetFieldLocation", "FunctionThunkFieldLocation", "PcodeFieldLocation", "SourceMapFieldLocation", "LinearFunctionAddressCorrelation", "ParallelInstructionLocation", "LanguageTranslatorFactoryMinion", "FunctionParameterFieldLocation", "OperandFieldLocation", "RegisterFieldLocation", "DummyListingAddressCorrelation", "FunctionChangeRecord", "GroupPath", "FunctionNameFieldLocation", "FunctionParameterNameFieldLocation", "ProgramEvent", "ChangeManager", "VariableStorageConflicts", "RegisterTransitionFieldLocation", "XRefHeaderFieldLocation", "AbstractProgramContext", "FieldNameFieldLocation", "VariableTypeFieldLocation", "FunctionEndParametersFieldLocation", "LabelFieldLocation", "XRefFieldLocation", "ProgramLocation", "FunctionTagFieldLocation", "VariableXRefFieldLocation", "VariableNameFieldLocation", "DiscoverableAddressCorrelator", "ProgramContextImpl", "DataTypeArchiveChangeManager", "VariableLocation", "SpacerFieldLocation", "CodeUnitContainer", "FunctionSignatureSourceFieldLocation", "RangeMapAdapter", "VariablesOpenCloseLocation", "BlockStartLocation", "ChangeManagerAdapter", "EolCommentFieldLocation", "AutomaticCommentFieldLocation", "CodeUnitLCS", "ProgramTask", "FunctionNoReturnFieldLocation", "ThunkedFunctionFieldLocation", "FunctionSignatureFieldLocation", "SimpleLanguageTranslator", "CommentTypeUtils", "LanguageTranslator", "DefaultLanguageService", "StackDepthFieldLocation", "RefRepeatCommentFieldLocation", "CodeUnitPropertyChangeRecord", "LinearDataAddressCorrelation", "FactoryLanguageTranslator", "FunctionRepeatableCommentFieldLocation", "AddressCorrelation", "DefinedDataIterator", "MemoryBlockStartFieldLocation", "TemporaryCompilerSpec", "LanguageTranslatorFactory", "PlateFieldLocation", "DefinedStringIterator", "AssignedVariableLocation", "CyclomaticComplexity", "LanguageTranslatorAdapter", "LanguagePostUpgradeInstructionHandler", "EquateInfo", "ProgramChangeRecord", "BytesFieldLocation", "DividerLocation", "AddressEvaluator", "FunctionPurgeFieldLocation", "RegisterValueStore", "OldLanguage", "ProgramLocationComparator", "AddressCorrelationRange", "FunctionCallFixupFieldLocation"]
