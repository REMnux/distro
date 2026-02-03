from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import generic.lsh.vector
import ghidra.docking.settings
import ghidra.features.bsim.gui
import ghidra.features.bsim.gui.search.dialog
import ghidra.features.bsim.query
import ghidra.features.bsim.query.description
import ghidra.features.bsim.query.facade
import ghidra.features.bsim.query.protocol
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.util.exception
import ghidra.util.table
import ghidra.util.table.column
import ghidra.util.table.field
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore


class FunctionComparisonException(ghidra.util.exception.UsrException):
    """
    An exception that can be thrown if an error is encountered while trying to compare two functions
    or apply information between them.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str msg: a message indicating details of the error.
        """

    @typing.overload
    def __init__(self, msg: typing.Union[java.lang.String, str], cause: java.lang.Throwable):
        """
        Constructor
        
        :param java.lang.String or str msg: a message indicating details of the error.
        :param java.lang.Throwable cause: another exception indicating the cause that led to this error exception.
        """


class BSimMatchResult(java.lang.Object):
    """
    A possible BSim function match.  The similarity 
    of this function is scored and denoted by :meth:`similarity <.getSimilarity>`.  The 
    significance of the match is denoted by :meth:`getSignificance() <.getSignificance>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, queriedFunction: ghidra.features.bsim.query.description.FunctionDescription, addr: ghidra.program.model.address.Address, similarityNote: ghidra.features.bsim.query.protocol.SimilarityNote):
        ...

    @staticmethod
    def filterMatchRows(filter: ghidra.features.bsim.query.protocol.BSimFilter, rows: java.util.List[BSimMatchResult]) -> java.util.List[BSimMatchResult]:
        ...

    @staticmethod
    def generate(results: java.util.List[ghidra.features.bsim.query.protocol.SimilarityResult], prog: ghidra.program.model.listing.Program) -> java.util.List[BSimMatchResult]:
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        ...

    def getArchitecture(self) -> str:
        ...

    def getCompilerName(self) -> str:
        ...

    def getDate(self) -> java.util.Date:
        ...

    def getExeCategoryAlphabetic(self, type: typing.Union[java.lang.String, str]) -> str:
        ...

    def getExecutableName(self) -> str:
        """
        The name of the executable containing this function.
        
        :return: the name of the executable containing this function.
        :rtype: str
        """

    def getExecutableURLString(self) -> str:
        ...

    def getMatchFunctionDescription(self) -> ghidra.features.bsim.query.description.FunctionDescription:
        ...

    def getMd5(self) -> str:
        ...

    def getOriginalFunctionAddress(self) -> int:
        ...

    def getOriginalFunctionDescription(self) -> ghidra.features.bsim.query.description.FunctionDescription:
        ...

    def getOriginalFunctionName(self) -> str:
        """
        The name of the input function to which this function is similar.
        
        :return: name of the input function to which this function is similar.
        :rtype: str
        """

    def getSignificance(self) -> float:
        """
        The significance of the similarity of this function to the input function.  This is a value
        that starts at 0.0, with no upper bound.  Functions small in size will have a low 
        significance score, as there is a chance that many small functions will have a 
        similar makeup.
        
        :return: the significance of the similarity of this function to the input function.
        :rtype: float
        """

    def getSimilarFunctionAddress(self) -> int:
        ...

    def getSimilarFunctionName(self) -> str:
        """
        The name of this function.
        
        :return: the name of this function.
        :rtype: str
        """

    def getSimilarity(self) -> float:
        """
        The similarity of this function to the input function.   This is a value from 0.0 to 1.0.
        
        :return: the similarity of this function to the input function.
        :rtype: float
        """

    def getStatus(self) -> BSimResultStatus:
        ...

    def isFlagSet(self, mask: typing.Union[jpype.JInt, int]) -> bool:
        ...

    def setStatus(self, status: BSimResultStatus):
        ...

    @property
    def similarFunctionAddress(self) -> jpype.JLong:
        ...

    @property
    def date(self) -> java.util.Date:
        ...

    @property
    def executableURLString(self) -> java.lang.String:
        ...

    @property
    def similarFunctionName(self) -> java.lang.String:
        ...

    @property
    def originalFunctionName(self) -> java.lang.String:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def originalFunctionDescription(self) -> ghidra.features.bsim.query.description.FunctionDescription:
        ...

    @property
    def executableName(self) -> java.lang.String:
        ...

    @property
    def significance(self) -> jpype.JDouble:
        ...

    @property
    def exeCategoryAlphabetic(self) -> java.lang.String:
        ...

    @property
    def originalFunctionAddress(self) -> jpype.JLong:
        ...

    @property
    def similarity(self) -> jpype.JDouble:
        ...

    @property
    def compilerName(self) -> java.lang.String:
        ...

    @property
    def flagSet(self) -> jpype.JBoolean:
        ...

    @property
    def matchFunctionDescription(self) -> ghidra.features.bsim.query.description.FunctionDescription:
        ...

    @property
    def status(self) -> BSimResultStatus:
        ...

    @status.setter
    def status(self, value: BSimResultStatus):
        ...

    @property
    def md5(self) -> java.lang.String:
        ...

    @property
    def architecture(self) -> java.lang.String:
        ...


class BSimSearchResultsFilterDialog(docking.DialogComponentProvider):
    """
    Dialog for configuring post BSim search filters
    """

    class_: typing.ClassVar[java.lang.Class]

    def getFilters(self) -> ghidra.features.bsim.gui.search.dialog.BSimFilterSet:
        ...

    @property
    def filters(self) -> ghidra.features.bsim.gui.search.dialog.BSimFilterSet:
        ...


class BSimResultRowObjectToAddressTableRowMapper(ghidra.util.table.ProgramLocationTableRowMapper[BSimMatchResult, ghidra.program.model.address.Address]):
    """
    Maps BSimMatchResult objects to Address to get addition table columns
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BSimMatchResultsModel(ghidra.util.table.AddressBasedTableModel[BSimMatchResult]):
    """
    Table model for BSim Similar function search results
    """

    @typing.type_check_only
    class StatusColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, BSimResultStatus]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class QueryFunctionColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FuncNameMatchColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExecNameMatchColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MatchCountTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.Integer]):
        """
        Column for showing the number of matches each base function has.
        
        Note the use of the :obj:`BSimMatchResultsModel.functionMatchMap`; this is
        for performance reasons. We don't want this class looping over the entire
        result set calculating match counts every time the table is refreshed.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MatchingFunctionAddressTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.Long]):
        """
        Column for showing the address of the matching function.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AddressOffsetHexRenderer(ghidra.util.table.column.AbstractGColumnRenderer[java.lang.Long]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionSizeTableColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.Long]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExecDateColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.util.Date]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExecCategoryColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ArchitectureMatchColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CompilerMatchColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExecMd5Column(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SimilarityColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.Double]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SignificanceColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.Double]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SelfSignificanceColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.Double]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, vectorFactory: generic.lsh.vector.LSHVectorFactory):
            ...


    @typing.type_check_only
    class FunctionTagColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimMatchResult, java.lang.Boolean]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DoubleRenderer(ghidra.util.table.column.AbstractGColumnRenderer[java.lang.Double]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, info: ghidra.features.bsim.query.description.DatabaseInformation, lshVectorFactory: generic.lsh.vector.LSHVectorFactory):
        ...

    @staticmethod
    def recoverAddress(desc: ghidra.features.bsim.query.description.FunctionDescription, prog: ghidra.program.model.listing.Program) -> ghidra.program.model.address.Address:
        """
        Associate a given FunctionDescription with the entry point of the matching function in a program
        
        :param ghidra.features.bsim.query.description.FunctionDescription desc: is the FunctionDescription to recover
        :param ghidra.program.model.listing.Program prog: is the Program (possibly) containing the Function object
        :return: the entry point address of the function (if it exists), or just the address within the default space
        :rtype: ghidra.program.model.address.Address
        """


class ExecutableResult(java.lang.Comparable[ExecutableResult]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, rec: ghidra.features.bsim.query.description.ExecutableRecord):
        ...

    def addFunction(self, signif: typing.Union[jpype.JDouble, float]):
        ...

    @staticmethod
    def generateFromMatchRows(filteredrows: java.util.List[BSimMatchResult]) -> java.util.TreeSet[ExecutableResult]:
        ...

    def getExecutableRecord(self) -> ghidra.features.bsim.query.description.ExecutableRecord:
        ...

    def getFunctionCount(self) -> int:
        """
        
        
        :return: number of functions with matches into this executable
        :rtype: int
        """

    def getSignificanceSum(self) -> float:
        """
        
        
        :return: sum of significance scores for all matching functions
        :rtype: float
        """

    @property
    def executableRecord(self) -> ghidra.features.bsim.query.description.ExecutableRecord:
        ...

    @property
    def significanceSum(self) -> jpype.JDouble:
        ...

    @property
    def functionCount(self) -> jpype.JInt:
        ...


class BSimStatusRenderer(ghidra.util.table.column.AbstractGColumnRenderer[BSimResultStatus]):
    """
    Renderer for display BSim apply results from attempting to apply function names and signatures
    from BSim Search results.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class BSimApplyResultsTableModel(ghidra.util.table.AddressBasedTableModel[BSimApplyResult]):
    """
    This is the model that backs the table in the :obj:`BSimApplyResultsDisplayDialog`. It defines
    four columns for the following:
            function address being changed
            original function name
            new function name
            error/warning information.
    
    Also note that this table is address-based and will emit a GoTo service event when a row is double-clicked.
    
    
    .. seealso::
    
        | :obj:`BSimApplyResultsDisplayDialog`
    
        | :obj:`AbstractBSimApplyTask`
    """

    @typing.type_check_only
    class StatusColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[BSimApplyResult, BSimResultStatus]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AddressColumn(ghidra.util.table.field.AbstractProgramLocationTableColumn[BSimApplyResult, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OriginalNameColumn(docking.widgets.table.AbstractDynamicTableColumn[BSimApplyResult, java.lang.String, java.lang.Object]):
        """
        Defines the column in the table for displaying the original function name (the name
        to be changed).
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DestinationNameColumn(docking.widgets.table.AbstractDynamicTableColumn[BSimApplyResult, java.lang.String, java.lang.Object]):
        """
        Defines the column in the table for displaying the destination function name (the
        name to use as the replacement).
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MessageColumn(docking.widgets.table.AbstractDynamicTableColumn[BSimApplyResult, java.lang.String, java.lang.Object]):
        """
        Defines the column for displaying any status information related to the rename. This
        is where error information will be displayed for rename operations that fail.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, title: typing.Union[java.lang.String, str], serviceProvider: ghidra.framework.plugintool.ServiceProvider, program: ghidra.program.model.listing.Program, monitor: ghidra.util.task.TaskMonitor, results: java.util.List[BSimApplyResult]):
        ...

    def getAddress(self, row: typing.Union[jpype.JInt, int]) -> ghidra.program.model.address.Address:
        """
        Returns the address for the given row.
        """

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...


class BSimApplyResult(java.lang.Object):
    """
    Contains information regarding the result of a BSim 'apply function name' operation. It 
    indicates the function name being changed, the new name to use, the address, and any 
    pertinent error/informational text.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, result: BSimMatchResult, status: BSimResultStatus, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, target: ghidra.program.model.listing.Function, source: ghidra.program.model.listing.Function, status: BSimResultStatus, message: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, target: typing.Union[java.lang.String, str], source: typing.Union[java.lang.String, str], status: BSimResultStatus, address: ghidra.program.model.address.Address, message: typing.Union[java.lang.String, str]):
        ...

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        
        
        :return: the address
        :rtype: ghidra.program.model.address.Address
        """

    def getMessage(self) -> str:
        """
        
        
        :return: the message
        :rtype: str
        """

    def getSourceFunctionName(self) -> str:
        """
        
        
        :return: the similar function name
        :rtype: str
        """

    def getStatus(self) -> BSimResultStatus:
        """
        
        
        :return: the status
        :rtype: BSimResultStatus
        """

    def getTargetFunctionName(self) -> str:
        """
        
        
        :return: the target function name
        :rtype: str
        """

    def isError(self) -> bool:
        ...

    def isIgnored(self) -> bool:
        ...

    @property
    def ignored(self) -> jpype.JBoolean:
        ...

    @property
    def targetFunctionName(self) -> java.lang.String:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def sourceFunctionName(self) -> java.lang.String:
        ...

    @property
    def error(self) -> jpype.JBoolean:
        ...

    @property
    def message(self) -> java.lang.String:
        ...

    @property
    def status(self) -> BSimResultStatus:
        ...


class BSimResultStatus(java.lang.Enum[BSimResultStatus]):
    """
    Enum of BSim results apply statuses for when users attempt to apply function names or signatures
    """

    class_: typing.ClassVar[java.lang.Class]
    NOT_APPLIED: typing.Final[BSimResultStatus]
    NAME_APPLIED: typing.Final[BSimResultStatus]
    SIGNATURE_APPLIED: typing.Final[BSimResultStatus]
    MATCHES: typing.Final[BSimResultStatus]
    APPLIED_NO_LONGER_MATCHES: typing.Final[BSimResultStatus]
    ERROR: typing.Final[BSimResultStatus]
    NO_FUNCTION: typing.Final[BSimResultStatus]
    IGNORED: typing.Final[BSimResultStatus]

    def getDescription(self) -> str:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> BSimResultStatus:
        ...

    @staticmethod
    def values() -> jpype.JArray[BSimResultStatus]:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


class BSimSearchResultsProvider(ghidra.framework.plugintool.ComponentProviderAdapter):
    """
    ComponentProvider for displaying BSim Similar Functions Search results.
    """

    @typing.type_check_only
    class BSimMatchesTableActionContext(docking.DefaultActionContext):

        class_: typing.ClassVar[java.lang.Class]

        def getSelectedRowCount(self) -> int:
            ...

        @property
        def selectedRowCount(self) -> jpype.JInt:
            ...


    @typing.type_check_only
    class ExecutableTableActionContext(docking.DefaultActionContext):

        class_: typing.ClassVar[java.lang.Class]

        def getSelectedExecutableResult(self) -> ExecutableResult:
            ...

        def getSelectedRowCount(self) -> int:
            ...

        @property
        def selectedExecutableResult(self) -> ExecutableResult:
            ...

        @property
        def selectedRowCount(self) -> jpype.JInt:
            ...


    @typing.type_check_only
    class MyDomainObjectListener(ghidra.framework.model.DomainObjectListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.features.bsim.gui.BSimSearchPlugin, tool: ghidra.framework.plugintool.PluginTool, serverInfo: ghidra.features.bsim.query.BSimServerInfo, dbInfo: ghidra.features.bsim.query.description.DatabaseInformation, lshVectorFactory: generic.lsh.vector.LSHVectorFactory, queryInfo: ghidra.features.bsim.query.facade.SFQueryInfo, settings: ghidra.features.bsim.gui.search.dialog.BSimSearchSettings):
        ...

    def getProgram(self) -> ghidra.program.model.listing.Program:
        ...

    def setFinalQueryResults(self, result: ghidra.features.bsim.query.facade.SFQueryResult):
        ...

    @property
    def program(self) -> ghidra.program.model.listing.Program:
        ...


class BSimApplyResultsDisplayDialog(docking.DialogComponentProvider):
    """
    Panel that displays the results of executing an "apply-rename" operation on a set of BSim 
    query results. The results are presented in a :obj:`GhidraTable`; see the 
    :obj:`BSimApplyResultsTableModel` for details on its structure.
     
    
    Filtering is provided on the results using a standard :obj:`GTableFilterPanel`.
    
    
    .. seealso::
    
        | :obj:`BSimApplyResultsTableModel`
    
        | :obj:`AbstractBSimApplyTask`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, serviceProvider: ghidra.framework.plugintool.ServiceProvider, results: java.util.List[BSimApplyResult], program: ghidra.program.model.listing.Program):
        ...


class BSimSearchInfoDisplayDialog(docking.DialogComponentProvider):
    """
    Dialog for displaying the search criteria used to generate a BSim Similar Functions Search.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, server: ghidra.features.bsim.query.BSimServerInfo, searchSettings: ghidra.features.bsim.gui.search.dialog.BSimSearchSettings, isOverview: typing.Union[jpype.JBoolean, bool]):
        ...


class ShowNamespaceSettingsDefinition(ghidra.docking.settings.BooleanSettingsDefinition):
    """
    Settings definition for showing function namespaces in the BSim Results table
    """

    class_: typing.ClassVar[java.lang.Class]
    DEF: typing.Final[ShowNamespaceSettingsDefinition]

    def __init__(self):
        ...


class BSimExecutablesSummaryModel(ghidra.util.table.GhidraProgramTableModel[ExecutableResult]):
    """
    Table model built by aggregating or "summing" the columns of rows from the QueryResultModel.
    QueryResultModel rows represent functions contained in specific executables.
    This model groups function rows from the same executable and produces a single
    row for that executable.  Columns are populated roughly:
        CountColumn is the number of functions in the group
        SignificanceColumn is the sum of the individual function significances in the group
    All the other columns are inherited from properties of the single executable used
    to define the group of functions.
        ExecutableNameMatch        name of the executable
        ExecutableCategoryMatch    a category associated with the executable    
        ExecutableDateMatch        date associated with the executable
        ArchitectureMatch          architecture
        CompilerMatch              compiler
        RepoColumn                 repository containing the executable
    """

    @typing.type_check_only
    class ExecutableNameMatchColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ExecutableResult, java.lang.String]):
        """
        Column holding the name of an executable containing 1 or more functions in the result set
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExecutableCategoryMatchColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ExecutableResult, java.lang.String]):
        """
        Column holding the value of an executable category for an
        executable containing 1 or more functions in the result set
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class ExecutableDateMatchColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ExecutableResult, java.util.Date]):
        """
        Column holding the date for an executable containing 1 or more functions in the result set
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, name: typing.Union[java.lang.String, str]):
            ...


    @typing.type_check_only
    class ArchitectureMatchColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ExecutableResult, java.lang.String]):
        """
        Column holding the architecture for an executable containing 1 or more functions in the result set
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CompilerMatchColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ExecutableResult, java.lang.String]):
        """
        Column holding the compiler for an executable containing 1 or more functions in the result set
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CountColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ExecutableResult, java.lang.Integer]):
        """
        Column holding the number of functions in the result set from a single executable
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SignificanceColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ExecutableResult, java.lang.Double]):
        """
        Column holding the sum of significance scores for functions in the result set from a single executable
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class RepoColumn(ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn[ExecutableResult, java.lang.String]):
        """
        Column holding the repository URL for an executable containing 1 or more functions in the result set
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]



__all__ = ["FunctionComparisonException", "BSimMatchResult", "BSimSearchResultsFilterDialog", "BSimResultRowObjectToAddressTableRowMapper", "BSimMatchResultsModel", "ExecutableResult", "BSimStatusRenderer", "BSimApplyResultsTableModel", "BSimApplyResult", "BSimResultStatus", "BSimSearchResultsProvider", "BSimApplyResultsDisplayDialog", "BSimSearchInfoDisplayDialog", "ShowNamespaceSettingsDefinition", "BSimExecutablesSummaryModel"]
