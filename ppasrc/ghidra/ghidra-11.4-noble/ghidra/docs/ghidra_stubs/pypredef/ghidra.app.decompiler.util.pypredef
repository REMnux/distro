from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.app.decompiler
import ghidra.framework.cmd
import ghidra.program.model.address
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.program.model.pcode
import ghidra.program.util
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class FillOutStructureHelper(java.lang.Object):
    """
    Automatically create a Structure data-type based on references found by the decompiler to a
    root parameter or other variable.
    
    If the parameter is already a Structure pointer, any new references found can optionally be added
    to the existing Structure data-type.
    :meth:`processStructure(HighVariable, Function, boolean, boolean, DecompInterface) <.processStructure>` is the primary
    entry point to the helper, which computes the new or updated Structure based on an existing
    decompiled function. Decompilation, if not provided externally, can be performed by calling
    :meth:`computeHighVariable(Address, Function, DecompInterface) <.computeHighVariable>`.  A decompiler process,
    if not provided externally, can be started by calling :meth:`setUpDecompiler(DecompileOptions) <.setUpDecompiler>`.
    """

    @typing.type_check_only
    class PointerRef(java.lang.Object):
        """
        Varnode with data-flow traceable to original pointer
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, ref: ghidra.program.model.pcode.Varnode, off: typing.Union[jpype.JLong, int]):
            ...


    class OffsetPcodeOpPair(java.lang.Object):
        """
        Class to create pair between an offset and its related PcodeOp
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, offset: typing.Union[java.lang.Long, int], pcodeOp: ghidra.program.model.pcode.PcodeOp):
            ...

        def getOffset(self) -> int:
            ...

        def getPcodeOp(self) -> ghidra.program.model.pcode.PcodeOp:
            ...

        @property
        def offset(self) -> jpype.JLong:
            ...

        @property
        def pcodeOp(self) -> ghidra.program.model.pcode.PcodeOp:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor):
        """
        Constructor.
        
        :param ghidra.program.model.listing.Program program: the current program
        :param ghidra.util.task.TaskMonitor monitor: task monitor
        """

    def computeHighVariable(self, storageAddress: ghidra.program.model.address.Address, function: ghidra.program.model.listing.Function, decomplib: ghidra.app.decompiler.DecompInterface) -> ghidra.program.model.pcode.HighVariable:
        """
        Decompile a function and return the resulting HighVariable associated with a storage address
        
        :param ghidra.program.model.address.Address storageAddress: the storage address of the variable
        :param ghidra.program.model.listing.Function function: is the function
        :param ghidra.app.decompiler.DecompInterface decomplib: is the active interface to use for decompiling
        :return: the corresponding HighVariable or null
        :rtype: ghidra.program.model.pcode.HighVariable
        """

    def getComponentMap(self) -> ghidra.program.model.data.NoisyStructureBuilder:
        """
        Retrieve the component map that was generated when structure was created using decompiler 
        info. Results are not valid until 
        :meth:`processStructure(HighVariable, Function, boolean, boolean, DecompInterface) <.processStructure>` is invoked.
        
        :return: componentMap
        :rtype: ghidra.program.model.data.NoisyStructureBuilder
        """

    def getLoadPcodeOps(self) -> java.util.List[FillOutStructureHelper.OffsetPcodeOpPair]:
        """
        Retrieve the offset/pcodeOp pairs that are used to load data from the variable
        used to fill-out structure.
        Results are not valid until 
        :meth:`processStructure(HighVariable, Function, boolean, boolean, DecompInterface) <.processStructure>` is invoked.
        
        :return: the pcodeOps doing the loading from the associated variable
        :rtype: java.util.List[FillOutStructureHelper.OffsetPcodeOpPair]
        """

    def getStorePcodeOps(self) -> java.util.List[FillOutStructureHelper.OffsetPcodeOpPair]:
        """
        Retrieve the offset/pcodeOp pairs that are used to store data into the variable
        used to fill-out structure.
        Results are not valid until 
        :meth:`processStructure(HighVariable, Function, boolean, boolean, DecompInterface) <.processStructure>` is invoked.
        
        :return: the pcodeOps doing the storing to the associated variable
        :rtype: java.util.List[FillOutStructureHelper.OffsetPcodeOpPair]
        """

    @staticmethod
    def getStructureForExtending(dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.Structure:
        """
        Check if a variable has a data-type that is suitable for being extended.
        If so return the structure data-type, otherwise return null.
        Modulo typedefs, the data-type of the variable must be exactly a
        "pointer to a structure".  Not a "structure" itself, or a
        "pointer to a pointer to ... a structure".
        
        :param ghidra.program.model.data.DataType dt: is the data-type of the variable to test
        :return: the extendable structure data-type or null
        :rtype: ghidra.program.model.data.Structure
        """

    def processStructure(self, var: ghidra.program.model.pcode.HighVariable, function: ghidra.program.model.listing.Function, createNewStructure: typing.Union[jpype.JBoolean, bool], createClassIfNeeded: typing.Union[jpype.JBoolean, bool], decomplib: ghidra.app.decompiler.DecompInterface) -> ghidra.program.model.data.Structure:
        """
        Create or update a Structure data-type given a function and a root pointer variable.
        The function must already be decompiled, but if a decompiler interface is provided, this
        method will recursively follow variable references into CALLs, possibly triggering additional
        decompilation.
        
        :param ghidra.program.model.pcode.HighVariable var: is the pointer variable
        :param ghidra.program.model.listing.Function function: is the function to process
        :param jpype.JBoolean or bool createNewStructure: if true a new Structure with a unique name will always be generated,
        if false and the variable corresponds to a Structure pointer, the existing Structure will be 
        updated instead.
        :param jpype.JBoolean or bool createClassIfNeeded: if true and variable corresponds to a **this** pointer without 
        an assigned Ghidra Class (i.e., ``void * this``), the function will be assigned to a 
        new unique Ghidra Class namespace with a new identically named Structure returned.  If false,
        a new unique Structure will be created.
        :param ghidra.app.decompiler.DecompInterface decomplib: is the (optional) decompiler interface, which can be used to recursively
        decompile into CALLs.
        :return: a filled-in Structure or null if one could not be created
        :rtype: ghidra.program.model.data.Structure
        """

    def setUpDecompiler(self, options: ghidra.app.decompiler.DecompileOptions) -> ghidra.app.decompiler.DecompInterface:
        """
        Set up a decompiler interface and prepare for decompiling on the currentProgram. 
        The interface can be used to pass to computeHighVariable or to processStructure.
        
        :param ghidra.app.decompiler.DecompileOptions options: are the options to pass to the decompiler
        :return: the decompiler interface
        :rtype: ghidra.app.decompiler.DecompInterface
        """

    @property
    def loadPcodeOps(self) -> java.util.List[FillOutStructureHelper.OffsetPcodeOpPair]:
        ...

    @property
    def componentMap(self) -> ghidra.program.model.data.NoisyStructureBuilder:
        ...

    @property
    def storePcodeOps(self) -> java.util.List[FillOutStructureHelper.OffsetPcodeOpPair]:
        ...


class FillOutStructureCmd(ghidra.framework.cmd.BackgroundCommand[ghidra.program.model.listing.Program]):
    """
    Automatically creates a structure definition based on the references found by the decompiler.
    
    If the parameter is already a structure pointer, any new references found will be added
    to the structure, even if the structure must grow.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, location: ghidra.program.util.ProgramLocation, decompileOptions: ghidra.app.decompiler.DecompileOptions):
        """
        Constructor.
        
        :param ghidra.program.util.ProgramLocation location: the current program location.  Supported location types include:
        :obj:`DecompilerLocation`, :obj:`VariableLocation` or 
        :obj:`FunctionParameterFieldLocation`.
        :param ghidra.app.decompiler.DecompileOptions decompileOptions: decompiler options.  
        (see :meth:`DecompilerUtils.getDecompileOptions(ServiceProvider, Program) <DecompilerUtils.getDecompileOptions>`)
        """



__all__ = ["FillOutStructureHelper", "FillOutStructureCmd"]
