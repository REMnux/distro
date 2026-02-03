from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets
import docking.widgets.button
import docking.widgets.checkbox
import docking.widgets.label
import docking.widgets.table
import ghidra.app.merge
import ghidra.app.merge.tool
import ghidra.app.services
import ghidra.app.util.viewer.multilisting
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.program.util
import ghidra.util.datastruct
import ghidra.util.task
import java.awt # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.table # type: ignore


@typing.type_check_only
class RegisterMergeManager(ListingMergeConstants):
    """
    ``RegisterMergeManager`` handles the merge for a single named register.
    """

    @typing.type_check_only
    class RegisterConflicts(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def merge(self, monitor: ghidra.util.task.TaskMonitor):
        """
        Merges all the register values for the named register being managed by this merge manager.
        
        :param ghidra.util.task.TaskMonitor monitor: the monitor that provides feedback to the user.
        :raises CancelledException: if the user cancels
        """


class VerticalChoicesPanel(ConflictPanel):
    """
    ``VerticalChoicesPanel`` is a conflict panel for the Listing Merge.
    It lays out rows of information vertically in a table format. 
    Each row can be a header row, an information row, a single choice row, 
    or a multiple choice row.
     
    Single choice rows provide a radio button and are used when a single 
    choice must be made from multiple rows of choices.
     
    Multiple choice rows provide a check box and are used when more than one 
    choice can be made from multiple rows of choices.
     
    Note: Single choice and multiple choice rows are not intended to be 
    intermixed on the same panel.
     
    A header label can be set. This appears above the row table. The text
    for the header label should be HTML.
    """

    @typing.type_check_only
    class MyLabel(docking.widgets.label.GDHtmlLabel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str]):
            """
            
            
            :param java.lang.String or str text: the text of this label.
            """


    @typing.type_check_only
    class MyRadioButton(docking.widgets.button.GRadioButton):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], option: typing.Union[jpype.JInt, int]):
            """
            
            
            :param java.lang.String or str text: the text for this radio button
            :param jpype.JInt or int option: the option value associated with this radio button.
            """


    @typing.type_check_only
    class MyCheckBox(docking.widgets.checkbox.GCheckBox):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str], option: typing.Union[jpype.JInt, int]):
            """
            
            
            :param java.lang.String or str text: the text for this check box
            :param jpype.JInt or int option: the option value associated with this check box.
            """


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, isDoubleBuffered: typing.Union[jpype.JBoolean, bool]):
        ...

    def allChoicesAreResolved(self) -> bool:
        """
        Returns true if the user made a selection for every conflict in the table.
        """

    def allChoicesAreSame(self) -> bool:
        """
        Returns true if the user made a selection for every conflict in the table and 
        made the same choice for every row.
        """

    def clear(self):
        """
        Removes header text for this panel and all table/row information.
        It also sets the columnCount back to 1.
        """


@typing.type_check_only
class ResolveConflictChangeEvent(javax.swing.event.ChangeEvent):
    """
    Event that gets passed to a listener to indicate that a user changed 
    one of the choices in the row of a table that is part of the 
    VerticalChoicesPanel or VariousChoicesPanel.
    """

    class_: typing.ClassVar[java.lang.Class]


class FunctionTagMerger(ghidra.app.merge.MergeResolver, ListingMergeConstants):
    """
    Class for merging function tag changes. Most tag differences can be easily auto-merged, 
    which is to say the result will be the set of all of tags from both program 1 and 
    program 2. Conflicts arise when both parties have edited/deleted the same tag.
     
    The specific cases handled by the class are described below, where:
     
    - X and Y are tags
    - X(A) means to take A's version of tag X
    - ** indicates a conflict
    - NP means the situation is not possible
      
            User A    |    Add X    Add Y    Delete X    Delete Y    Edit X        Edit Y
                    |
    User B        |
    ---------------------------------------------------------------------------
    Add X        |    X        X,Y            NP            X        NP            X,Y(A)
                    |
    Add Y        |    X,Y        Y            Y            NP        X(A),Y        NP
                    |
    Delete X        |    NP        Y            -            -        **            Y(A)        
                    |
    Delete Y        |    X        NP            -            -        X(A)        **
                    |
    Edit X        |    NP        X(B),Y        **            X(B)    **            X(B),Y(A)    
                    |
    Edit Y        |    X,Y(B)    NP            Y(B)        **        X(A),Y(B)    **
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mergeManager: ghidra.app.merge.ProgramMultiUserMergeManager, resultPgm: ghidra.program.model.listing.Program, originalPgm: ghidra.program.model.listing.Program, latestPgm: ghidra.program.model.listing.Program, myPgm: ghidra.program.model.listing.Program, latestChanges: ghidra.program.model.listing.ProgramChangeSet, myChanges: ghidra.program.model.listing.ProgramChangeSet):
        """
        Constructor.
        
        :param ghidra.app.merge.ProgramMultiUserMergeManager mergeManager: the merge manager
        :param ghidra.program.model.listing.Program resultPgm: the program storing the result of the merge
        :param ghidra.program.model.listing.Program originalPgm: the state of the program before any changes
        :param ghidra.program.model.listing.Program latestPgm: the checked in program version
        :param ghidra.program.model.listing.Program myPgm: the checked out program version
        :param ghidra.program.model.listing.ProgramChangeSet latestChanges: tag changes in Latest
        :param ghidra.program.model.listing.ProgramChangeSet myChanges: tag changes in My
        """

    def getName(self) -> str:
        """
        PUBLIC METHODS
        """

    def setConflictResolution(self, option: typing.Union[jpype.JInt, int]):
        """
        For JUnit testing only, set the option for resolving a conflict.
        
        :param jpype.JInt or int option:
        """

    @property
    def name(self) -> java.lang.String:
        ...


class ConflictInfoPanel(javax.swing.JPanel):
    """
    ``ConflictInfoPanel`` appears above the 4 listings in the ListingMergeWindow.
    It indicates the current sub-phase of the ListingMerge (Code Units, Functions, Symbols, etc.).
    It also indicates how many groups of conflicts to resolve (typically address ranges),
    how many individual conflict need resolving for that address range,
    and how far you are along in the process.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new ``ConflictInfoPanel`` to use above the listings.
        """


class ScrollingListChoicesPanel(ConflictPanel):
    """
    ``ScrollingListChoicesPanel`` provides a table type of format for resolving
    Each row that has choices represents the choices for a single conflict. Each conflict
    choice has a corresponding radio button and scrolling table/list of text.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor for a various choices panel.
        """

    @typing.overload
    def __init__(self, isDoubleBuffered: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for a various choices panel.
        
        :param jpype.JBoolean or bool isDoubleBuffered:
        """

    def allChoicesAreResolved(self) -> bool:
        """
        Returns true if the user made a selection for every conflict in the table.
        """

    def allChoicesAreSame(self) -> bool:
        """
        Returns true if the user made a selection for every conflict in the table and
        made the same choice for every row.
        """

    def clear(self):
        """
        Removes header text for this panel and all table/row information.
        """


class ConflictPanel(ChoiceComponent):
    """
    Abstract class that should be implemented by the conflict panel that appears 
    below the 4 listings in the merge window.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, isDoubleBuffered: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, layout: java.awt.LayoutManager, isDoubleBuffered: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, layout: java.awt.LayoutManager):
        ...

    def clear(self):
        """
        Called to reset the panel back to an empty state so it can be reused.
        """

    def getUseForAllChoice(self) -> int:
        """
        Returns an int value that indicates the choices currently selected for 
        the Use For All choice in the conflict resolution table. If there are
        multiple rows of choices, then all selected choices must be the same for each
        row or 0 is returned.
        Each button or check box has an associated value that can be bitwise 'OR'ed together
        to get the entire choice for the row.
        
        :return: the choice(s) currently selected.
        :rtype: int
        """

    def hasChoice(self) -> bool:
        """
        Returns true if the conflict panel currently provides at least one choice
        to the user.
        
        :return: true if the panel has a choice the user can select.
        :rtype: bool
        """

    def removeAllListeners(self):
        """
        Removes all listeners that were set on this panel for indicating user
        choices were being made or changed.
        """

    @property
    def useForAllChoice(self) -> jpype.JInt:
        ...


@typing.type_check_only
class UserDefinedPropertyMerger(AbstractListingMerger):
    """
    Class for merging user defined property changes. This class can merge non-conflicting
    user defined property changes that were made to the checked out version. It can determine
    where there are conflicts between the latest checked in version and my
    checked out version. It can then manually merge the conflicting user defined properties.
    Wherever a user defined property conflict is detected, the user will be allowed to choose
    the property at the address in conflict from the latest, my or original program.
     
    Important: This class is intended to be used only for a single program 
    version merge. It should be constructed, followed by an autoMerge(), and lastly
    each address with a conflict should have mergeConflicts() called on it.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class CodeUnitMerger(AbstractListingMerger):
    """
    Manages byte and code unit changes and conflicts between the latest versioned
    program and the modified program being checked into version control.
     
    Indirect conflicts include:
     
    * bytes and code units
    * bytes and equates
    * code units and equates
    
     
    Important: This class is intended to be used only for a single program
    version merge. It should be constructed, followed by an autoMerge(), and lastly
    should call mergeConflicts() passing it ASK_USER for the conflictOption.
    """

    class_: typing.ClassVar[java.lang.Class]

    def mergeConflicts(self, listingPanel: ghidra.app.merge.tool.ListingMergePanel, chosenConflictOption: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Merges all the current conflicts according to the conflictOption.
        
        :param ghidra.app.merge.tool.ListingMergePanel listingPanel: the listing merge panel
        :param jpype.JInt or int chosenConflictOption: the conflict option to use when merging (should be ASK_USER for interactive).
        :param ghidra.util.task.TaskMonitor monitor: the status monitor
        :raises CancelledException: if the user cancels
        :raises MemoryAccessException: if bytes can't be merged.
        """


class ExternalProgramMerger(ghidra.app.merge.MergeResolver, ListingMergeConstants):
    """
    Manages external program name changes and conflicts between the latest versioned
    program and the modified program being checked into version control.
    """

    @typing.type_check_only
    class IDGroup(java.lang.Object):
        """
        IDGroup is used to associate the symbol IDs from each of the four programs
        (Result, Original, Latest, My) for a single symbol. If the symbol doesn't
        exist for any particular program a -1 is entered for its ID.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mergeManager: ghidra.app.merge.ProgramMultiUserMergeManager, resultPgm: ghidra.program.model.listing.Program, originalPgm: ghidra.program.model.listing.Program, latestPgm: ghidra.program.model.listing.Program, myPgm: ghidra.program.model.listing.Program, latestChanges: ghidra.program.model.listing.ProgramChangeSet, myChanges: ghidra.program.model.listing.ProgramChangeSet):
        """
        Manages code unit changes and conflicts between the latest versioned
        program and the modified program being checked into version control.
        
        :param ghidra.app.merge.ProgramMultiUserMergeManager mergeManager: the top level merge manager for merging a program version.
        :param ghidra.program.model.listing.Program resultPgm: the program to be updated with the result of the merge.
        This is the program that will actually get checked in.
        :param ghidra.program.model.listing.Program originalPgm: the program that was checked out.
        :param ghidra.program.model.listing.Program latestPgm: the latest checked-in version of the program.
        :param ghidra.program.model.listing.Program myPgm: the program requesting to be checked in.
        :param ghidra.program.model.listing.ProgramChangeSet latestChanges: the address set of changes between original and latest versioned program.
        :param ghidra.program.model.listing.ProgramChangeSet myChanges: the address set of changes between original and my modified program.
        """

    def autoMerge(self, monitor: ghidra.util.task.TaskMonitor):
        ...

    def getConflictCount(self) -> int:
        ...

    def getConflictInfo(self, idGroup: ExternalProgramMerger.IDGroup, conflictIndex: typing.Union[jpype.JInt, int], totalConflicts: typing.Union[jpype.JInt, int]) -> str:
        """
        Gets the information to display at the top of the conflict window indicating
        which conflict this is of the total external program name conflicts.
        
        :param ExternalProgramMerger.IDGroup idGroup: the symbol ID group for the external program (Library) in conflict.
        :param jpype.JInt or int conflictIndex: the index of the current conflict.
        :param jpype.JInt or int totalConflicts: the total number of conflicts.
        """

    def getConflicts(self) -> jpype.JArray[ExternalProgramMerger.IDGroup]:
        """
        Returns an array of symbol ID groups for all the external programs that are in conflict.
        """

    def hasConflict(self) -> bool:
        ...

    def init(self):
        ...

    def mergeConflicts(self, chosenConflictOption: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Performs a manual merge of external program conflicts.
        
        :param jpype.JInt or int chosenConflictOption: ASK_USER means interactively resolve conflicts.
        JUnit testing also allows setting this to LATEST, MY, or ORIGINAL to force
        selection of a particular version change.
        :param ghidra.util.task.TaskMonitor monitor: task monitor for informing the user of progress.
        :raises CancelledException: if the user cancels the merge.
        """

    def mergeExternalProgramName(self, program1: ghidra.program.model.listing.Program, program2: ghidra.program.model.listing.Program, idGroup: ExternalProgramMerger.IDGroup, monitor: ghidra.util.task.TaskMonitor):
        """
        Actually merges (sets or removes) the indicated external program name in
        program1 based on the same external program name in program2
        
        :param ghidra.program.model.listing.Program program1: the program to merge into.
        :param ghidra.program.model.listing.Program program2: the program to get the merge information from.
        :param ExternalProgramMerger.IDGroup idGroup: the symbol ID group for the external program (Library) to merge.
        :param ghidra.util.task.TaskMonitor monitor: task monitor for feedback or canceling the merge.s
        """

    @property
    def conflicts(self) -> jpype.JArray[ExternalProgramMerger.IDGroup]:
        ...

    @property
    def conflictCount(self) -> jpype.JInt:
        ...


@typing.type_check_only
class FunctionVariableStorageConflicts(ghidra.program.util.VariableStorageConflicts):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FunctionMerger(AbstractFunctionMerger, ListingMerger):
    """
    Class for merging function changes. This class can merge function changes
    that were made to the checked out version. It can determine
    where there are conflicts between the latest checked in version and my
    checked out version. It can then manually merge the conflicting functions.
    The FunctionMerger merges entire functions wherever the function bodies are
    potentially in conflict between Latest and My. It then merges individual
    parts that make up functions with matching bodies.
     
    Note: Function name differences are not resolved by this merger. Instead,
    they are resolved by the SymbolMerger.
     
    Important: This class is intended to be used only for a single program
    version merge. It should be constructed, followed by an autoMerge(), and lastly
    each address with a conflict should have mergeConflicts() called on it.
    """

    @typing.type_check_only
    class FunctionConflictType(java.lang.Enum[FunctionMerger.FunctionConflictType]):

        class_: typing.ClassVar[java.lang.Class]
        FUNCTION_OVERLAP_CONFLICT: typing.Final[FunctionMerger.FunctionConflictType]
        FUNCTION_BODY_CONFLICT: typing.Final[FunctionMerger.FunctionConflictType]
        FUNCTION_REMOVE_CONFLICT: typing.Final[FunctionMerger.FunctionConflictType]
        FUNCTION_RETURN_CONFLICT: typing.Final[FunctionMerger.FunctionConflictType]
        FUNCTION_DETAILS_CONFLICT: typing.Final[FunctionMerger.FunctionConflictType]
        VARIABLE_STORAGE_CONFLICT: typing.Final[FunctionMerger.FunctionConflictType]
        PARAMETER_SIGNATURE_CONFLICT: typing.Final[FunctionMerger.FunctionConflictType]
        PARAMETER_INFO_CONFLICT: typing.Final[FunctionMerger.FunctionConflictType]
        REMOVED_LOCAL_VARIABLE_CONFLICT: typing.Final[FunctionMerger.FunctionConflictType]
        LOCAL_VARIABLE_DETAIL_CONFLICT: typing.Final[FunctionMerger.FunctionConflictType]
        THUNK_CONFLICT: typing.Final[FunctionMerger.FunctionConflictType]
        TAG_CONFLICT: typing.Final[FunctionMerger.FunctionConflictType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> FunctionMerger.FunctionConflictType:
            ...

        @staticmethod
        def values() -> jpype.JArray[FunctionMerger.FunctionConflictType]:
            ...


    @typing.type_check_only
    class FunctionOverlapConflictChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ParameterChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def init(self):
        ...

    def mergeThunks(self, listingPanel: ghidra.app.merge.tool.ListingMergePanel, currentConflictOption: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        ...


@typing.type_check_only
class BookmarkMerger(AbstractListingMerger):
    """
    Class for merging bookmark changes. This class can merge non-conflicting
    bookmark changes that were made to the checked out version. It can determine
    where there are conflicts between the latest checked in version and my
    checked out version. It can then manually merge the conflicting bookmarks.
     
    Important: This class is intended to be used only for a single program 
    version merge. It should be constructed, followed by an autoMerge(), and lastly
    each address with a conflict should have mergeConflicts() called on it.
    """

    @typing.type_check_only
    class BookmarkMergeChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BookmarkUid(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class ChoiceComponent(javax.swing.JPanel):
    """
    Abstract class for a GUI panel that allows the user to select choices for 
    resolving conflicts.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, isDoubleBuffered: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, layout: java.awt.LayoutManager, isDoubleBuffered: typing.Union[jpype.JBoolean, bool]):
        ...

    @typing.overload
    def __init__(self, layout: java.awt.LayoutManager):
        ...

    def allChoicesAreResolved(self) -> bool:
        """
        Returns whether or not all of the choices (conflicts) have been resolved
        by the user making selections.
        
        :return: true if all conflicts are resolved.
        :rtype: bool
        """

    def allChoicesAreSame(self) -> bool:
        """
        Returns whether or not all of the choices (conflicts) have been resolved
        by the user making selections and the user made the same choice for all the conflicts.
        
        :return: true if all conflicts are resolved the same.
        :rtype: bool
        """

    def getNumConflictsResolved(self) -> int:
        """
        Returns the number of conflicts that have currently been resolved in this GUI component.
        
        :return: the number resolved.
        :rtype: int
        """

    @property
    def numConflictsResolved(self) -> jpype.JInt:
        ...


class ExternalFunctionMerger(AbstractFunctionMerger, ListingMerger):
    """
    Class for merging external function and label changes. This class can merge external function
    and label changes that were made to the checked out version. It can determine
    where there are conflicts between the latest checked in version and my
    checked out version. It can then allow the user to manually merge the conflicting
    functions and labels. External functions do not have bodies.
    However their signatures, stacks and variables do get merged.
    This class extends the AbstractFunctionMerger to handle merging of function changes when both
    My and Latest have changed functions.
     
    Note: Externals are uniquely identified by symbol ID and the name (including namespace is
    also used to match externals when the external is transitioned from a label to a function
    and vice versa.
     
    Important: This class is intended to be used only for a single program
    version merge. It should be constructed, followed by an autoMerge(), and lastly
    each external with a conflict should have mergeConflicts() called on it.
    """

    @typing.type_check_only
    class ExternalConflictType(java.lang.Enum[ExternalFunctionMerger.ExternalConflictType]):

        class_: typing.ClassVar[java.lang.Class]
        EXTERNAL_FUNCTION_REMOVE_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        EXTERNAL_FUNCTION_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        EXTERNAL_DETAILS_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        EXTERNAL_DATA_TYPE_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        EXTERNAL_FUNCTION_VS_DATA_TYPE_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        EXTERNAL_ADD_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        EXTERNAL_REMOVE_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        FUNCTION_OVERLAP_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        FUNCTION_BODY_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        FUNCTION_REMOVE_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        FUNCTION_RETURN_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        FUNCTION_DETAILS_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        VARIABLE_STORAGE_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        PARAMETER_SIGNATURE_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        PARAMETER_INFO_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        REMOVED_LOCAL_VARIABLE_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        LOCAL_VARIABLE_DETAIL_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]
        THUNK_CONFLICT: typing.Final[ExternalFunctionMerger.ExternalConflictType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> ExternalFunctionMerger.ExternalConflictType:
            ...

        @staticmethod
        def values() -> jpype.JArray[ExternalFunctionMerger.ExternalConflictType]:
            ...


    @typing.type_check_only
    class ExternalParameterChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExternalAddConflictChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExternalDataTypeConflictChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExternalFunctionVsDataTypeConflictChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExternalRemoveFunctionConflictChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExternalRemoveConflictChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ExternalDetailChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ConflictListener(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def resolveConflict(self):
            ...


    class_: typing.ClassVar[java.lang.Class]
    KEEP_LATEST_ADD: typing.Final = 1
    """
    Keep the external location added in LATEST to resolve a conflict.
    """

    KEEP_MY_ADD: typing.Final = 2
    """
    Keep the external location added in MY to resolve a conflict.
    """

    KEEP_BOTH_ADDS: typing.Final = 4
    """
    Keep both of the external locations added in the LATEST and in MY when in conflict.
    """

    MERGE_BOTH_ADDS: typing.Final = 8
    """
    Merge both of the external locations added in the LATEST and in MY when in conflict.
    """

    KEEP_BOTH_BUTTON_NAME: typing.Final = "KeepBothVersionsRB"
    MERGE_BOTH_BUTTON_NAME: typing.Final = "MergeBothVersionsRB"

    def __init__(self, listingMergeManager: ListingMergeManager, showListingPanel: typing.Union[jpype.JBoolean, bool]):
        """
        Manages changes and conflicts for externals between the latest versioned
        program and the modified program being checked into version control.
        
        :param ListingMergeManager listingMergeManager: the top level merge manager for merging a program version.
        :param jpype.JBoolean or bool showListingPanel: true to show the listing panel.
        """

    def allChoicesAreResolved(self) -> bool:
        ...

    def getDescription(self) -> str:
        ...

    def getName(self) -> str:
        ...

    def init(self):
        ...

    def mergeConflicts(self, chosenConflictOption: typing.Union[jpype.JInt, int], listingConflictInfoPanel: ConflictInfoPanel, monitor: ghidra.util.task.TaskMonitor):
        """
        Performs a manual merge of external program conflicts.
        
        :param jpype.JInt or int chosenConflictOption: ASK_USER means interactively resolve conflicts.
        JUnit testing also allows setting this to LATEST, MY, or ORIGINAL to force
        selection of a particular version change.
        :param ghidra.util.task.TaskMonitor monitor: task monitor for informing the user of progress.
        :raises CancelledException: if the user cancels the merge.
        """

    def mergeConflictsForAdd(self, externalLocations: jpype.JArray[ghidra.program.model.symbol.ExternalLocation], chosenConflictOption: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        ...

    def mergeFunction(self, externalLocations: jpype.JArray[ghidra.program.model.symbol.ExternalLocation], currentChosenOption: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        ...

    def refreshResultPanel(self, externalLocations: jpype.JArray[ghidra.program.model.symbol.ExternalLocation]):
        ...

    def replaceExternalDataType(self, resultExternalLocation: ghidra.program.model.symbol.ExternalLocation, fromExternalLocation: ghidra.program.model.symbol.ExternalLocation, monitor: ghidra.util.task.TaskMonitor):
        """
        ``replaceExternalDataType`` replaces the data type of the
        external label in program1 with the data type of the external label in program2
        at the specified external space address.
        
        :param ghidra.program.model.symbol.ExternalLocation resultExternalLocation: 
        :param ghidra.program.model.symbol.ExternalLocation fromExternalLocation: 
        :param ghidra.util.task.TaskMonitor monitor: the task monitor for notifying the user of this merge's progress.
        :raises CancelledException:
        """

    def replaceExternalLocation(self, toExternalLocation: ghidra.program.model.symbol.ExternalLocation, fromExternalLocation: ghidra.program.model.symbol.ExternalLocation, programMerge: ghidra.program.util.ProgramMerge, monitor: ghidra.util.task.TaskMonitor) -> ghidra.program.model.symbol.ExternalLocation:
        ...

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...


@typing.type_check_only
class EquateMerger(AbstractListingMerger):
    """
    Class for merging equate changes. This class can merge equate changes 
    that were made to the checked out version. It can determine
    where there are conflicts between the latest checked in version and my
    checked out version. It can then manually merge the conflicting equates.
     
    The EquateMerger takes into account anywhere that code units have been merged.
    If code units were merged, then this will not try to merge at those addresses.
    The code unit merger should have already merged the equates where it 
    merged code units.
     
    Important: This class is intended to be used only for a single program 
    version merge. It should be constructed, followed by an autoMerge(), and lastly
    each address with a conflict should have mergeConflicts() called on it.
    """

    @typing.type_check_only
    class EquateConflict(java.lang.Object):
        """
        ``EquateConflict`` provides the information needed to retain 
        and display an equate conflict to the user. It contains the address,
        operand index, and scalar value.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class VariousChoicesPanel(ConflictPanel):
    """
    ``VariousChoicesPanel`` provides a table type of format for resolving
    multiple conflicts in one panel. Each row that has choices represents the
    choices for a single conflict. 
    So each row can have multiple radio buttons or multiple check boxes.
    At least one choice must be made in each row that provides choices before 
    this panel will indicate that all choices are resolved.
    """

    @typing.type_check_only
    class ChoiceRow(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyLabel(docking.widgets.label.GLabel):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str]):
            """
            
            
            :param java.lang.String or str text: the text of this label.
            """


    @typing.type_check_only
    class MyRadioButton(docking.widgets.button.GRadioButton):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str]):
            """
            
            
            :param java.lang.String or str text: the text for this radio button
            """


    @typing.type_check_only
    class MyCheckBox(docking.widgets.checkbox.GCheckBox):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, text: typing.Union[java.lang.String, str]):
            """
            
            
            :param java.lang.String or str text: the text for this check box
            """


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Constructor for a various choices panel.
        """

    @typing.overload
    def __init__(self, isDoubleBuffered: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor for a various choices panel.
        
        :param jpype.JBoolean or bool isDoubleBuffered: true if double buffered
        """

    def adjustUseForAllEnablement(self):
        """
        Adjusts the enablement of the Use For All checkbox based on whether choices have been made 
        for all the conflicts currently on the screen and whether the same choice was made for all 
        conflicts on the screen.
        """

    def allChoicesAreResolved(self) -> bool:
        """
        Returns true if the user made a selection for every conflict in the table.
        """

    def allChoicesAreSame(self) -> bool:
        """
        Returns true if the user made a selection for every conflict in the table and 
        made the same choice for every row.
        """

    def clear(self):
        """
        Removes header text for this panel and all table/row information.
        """


@typing.type_check_only
class CommentMerger(AbstractListingMerger):
    """
    Class for merging comment changes. This class can merge non-conflicting
    comment changes that were made to the checked out version. It can determine
    where there are conflicts between the latest checked in version and my
    checked out version. It can then manually merge the conflicting comments.
     
    Important: This class is intended to be used only for a single program 
    version merge. It should be constructed, followed by an autoMerge(), and lastly
    each address with a conflict should have mergeConflicts() called on it.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class AbstractListingMerger(ListingMerger, ListingMergeConstants):
    """
    ``AbstractListingMerger`` is an abstract class that each type of
    listing merge manager can extend to gain access to commonly needed information
    such as the programs, the listing merge panel,
    Diffs for Latest-Original and My-Original and Latest-My, etc.
    """

    class_: typing.ClassVar[java.lang.Class]


class ExternalConflictInfoPanel(javax.swing.JPanel):
    """
    ``ExternalConflictInfoPanel`` appears above the 4 listings in the ListingMergeWindow.
    It indicates the Externals phase.
    It also indicates how many groups of conflicts to resolve,
    how many individual conflict need resolving for that named external, 
    and how far you are along in the process.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        """
        Creates a new ``ExternalConflictInfoPanel`` to use above the listings.
        """


class ExternalsAddressTranslator(ghidra.program.util.AddressTranslator):
    """
    ExternalsAddressTranslator is a translator that can be used for merging external functions and
    labels. 
    
    Important: Before using this with ProgramMerge you must add all the address pairs that
    will translate the external address space address from the source program to the address
    in the destination program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, destinationProgram: ghidra.program.model.listing.Program, sourceProgram: ghidra.program.model.listing.Program):
        ...

    def setPair(self, destinationAddress: ghidra.program.model.address.Address, sourceAddress: ghidra.program.model.address.Address):
        ...


class ListingMergeManager(ghidra.app.merge.MergeResolver, ListingMergeConstants):
    """
    Manages program listing changes and conflicts between the latest versioned
    program (LATEST) and the modified program (MY) being checked into version control.
     
    Listing changes include:
     
    * bytes
    * code units [instructions and data]
    * equates
    * functions
    * symbols
    * references [memory, stack, and external]
    * comments [plate, pre, end-of-line, repeatable, and post]
    * properties
    * bookmarks
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mergeManager: ghidra.app.merge.ProgramMultiUserMergeManager, resultPgm: ghidra.program.model.listing.Program, originalPgm: ghidra.program.model.listing.Program, latestPgm: ghidra.program.model.listing.Program, myPgm: ghidra.program.model.listing.Program, latestChanges: ghidra.program.model.listing.ProgramChangeSet, myChanges: ghidra.program.model.listing.ProgramChangeSet):
        """
        Manages listing changes and conflicts between the latest versioned
        program and the modified program being checked into version control.
        
        :param ghidra.app.merge.ProgramMultiUserMergeManager mergeManager: the top level merge manager for merging a program version.
        :param ghidra.program.model.listing.Program resultPgm: the program to be updated with the result of the merge.
        This is the program that will actually get checked in.
        :param ghidra.program.model.listing.Program originalPgm: the program that was checked out.
        :param ghidra.program.model.listing.Program latestPgm: the latest checked-in version of the program.
        :param ghidra.program.model.listing.Program myPgm: the program requesting to be checked in.
        :param ghidra.program.model.listing.ProgramChangeSet latestChanges: the address set of changes between original and latest versioned program.
        :param ghidra.program.model.listing.ProgramChangeSet myChanges: the address set of changes between original and my modified program.
        """

    def getFunctionTagListingMerger(self) -> FunctionTagListingMerger:
        ...

    def getMergedCodeUnits(self) -> ghidra.program.model.address.AddressSet:
        """
        Gets the address set for the code units that were changed in the result
        by the merge.
        
        :return: the address set indicating the code units that changed in the
        result program due to the merge
        :rtype: ghidra.program.model.address.AddressSet
        """

    def getPhases(self) -> jpype.JArray[jpype.JArray[java.lang.String]]:
        """
        This method returns all of the phases of the Listing Merge Manager that will be
        displayed in the Program Merge Manager.
        The first item is a phase indicator for the Listing Phase as a whole and
        the others are for each sub-phase of the Listing.
        """

    def initMergeInfo(self):
        """
        Sets up the change address sets, Diffs between the various program versions,
        and Merges from various versions to the resulting program.
        """

    @property
    def functionTagListingMerger(self) -> FunctionTagListingMerger:
        ...

    @property
    def mergedCodeUnits(self) -> ghidra.program.model.address.AddressSet:
        ...

    @property
    def phases(self) -> jpype.JArray[jpype.JArray[java.lang.String]]:
        ...


@typing.type_check_only
class UserDefinedPropertyPanel(VerticalChoicesPanel):
    """
    ``UserDefinedPropertyPanel`` adds a checkbox as the southern component
    of the ``VerticalChoicesPanel``. The check box allows the user to 
    indicate that they want to select the same option for all conflicts of a 
    particular property type.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class SymbolMerger(AbstractListingMerger):
    """
    Class for merging symbol changes. This class can merge non-conflicting
    symbol changes that were made to the checked out version. It can determine
    where there are conflicts between the latest checked in version and my
    checked out version. It can then manually merge the conflicting symbols.
     
    Important: This class is intended to be used only for a single program
    version merge. It should be constructed and then merge() should be called on it.
    The merge() will perform an autoMerge() followed by mergeConflicts().
    If symbols were automatically renamed due to conflicts, then a dialog will appear
    that shows this information to the user.
    """

    @typing.type_check_only
    class SymbolConflictType(java.lang.Enum[SymbolMerger.SymbolConflictType]):

        class_: typing.ClassVar[java.lang.Class]
        ADDRESS_SYMBOL_CONFLICT: typing.Final[SymbolMerger.SymbolConflictType]
        PRIMARY_SYMBOL_CONFLICT: typing.Final[SymbolMerger.SymbolConflictType]
        REMOVE_SYMBOL_CONFLICT: typing.Final[SymbolMerger.SymbolConflictType]
        RENAME_SYMBOL_CONFLICT: typing.Final[SymbolMerger.SymbolConflictType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> SymbolMerger.SymbolConflictType:
            ...

        @staticmethod
        def values() -> jpype.JArray[SymbolMerger.SymbolConflictType]:
            ...


    @typing.type_check_only
    class LongHashSet(java.util.HashSet[java.lang.Long]):
        """
        A convenience class that is simply a hash set containing long values.
        """

        class_: typing.ClassVar[java.lang.Class]

        def add(self, l: typing.Union[jpype.JLong, int]) -> bool:
            ...

        def contains(self, l: typing.Union[jpype.JLong, int]) -> bool:
            ...

        def remove(self, l: typing.Union[jpype.JLong, int]) -> bool:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def getPath(self, name: typing.Union[java.lang.String, str], namespace: ghidra.program.model.symbol.Namespace) -> jpype.JArray[java.lang.String]:
        """
        Gets an array of strings indicating what the full path  would be if a symbol with
        the indicated name were in the specified namespace.
        
        :param java.lang.String or str name: the symbol name
        :param ghidra.program.model.symbol.Namespace namespace: the namespace
        :return: the path as an array
        :rtype: jpype.JArray[java.lang.String]
        """

    def merge(self, progressMinimum: typing.Union[jpype.JInt, int], progressMaximum: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        ...


class FunctionTagListingMerger(AbstractListingMerger):
    """
    Handles merging of function tags when they are added/removed from 
    functions. 
     
    Most merging can be done automatically; the exception being when a
    tag has been added to a function by one user, but deleted from the
    program by another.
     
    Note that there are other tag related conflict cases, but they are 
    handled by the :obj:`FunctionTagMerger`, which handles all aspects of
    creation/deletion/editing of tags independent of functions. 
     
    THIS CLASS ONLY DEALS WITH FUNCTION-RELATED ADDS/REMOVES.
     
    The specific cases handled by the class are described below:
     
    - X and Y are tags
    - ** indicates a conflict
      
            User A    |    Add X    Add Y    Delete X    Delete Y    
                    |
    User B        |
    -------------------------------------------------------
    Add X        |    X        X,Y            **            X        
                    |
    Add Y        |    X,Y        Y            Y            **        
                    |
    Delete X        |    **        Y            -            -                
                    |
    Delete Y        |    X        **            -            -
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, listingMergeMgr: ListingMergeManager):
        """
        Constructor.
        
        :param ListingMergeManager listingMergeMgr: the listing merge manager that owns this merger.
        """

    def init(self):
        """
        PUBLIC METHODS
        """

    def setConflictResolution(self, option: typing.Union[jpype.JInt, int]):
        """
        Stores the users' selection for how to handle a conflict.
        
        :param jpype.JInt or int option: user option, from :obj:`ListingMergeConstants`
        """


@typing.type_check_only
class ExternalAddConflictPanel(javax.swing.JPanel, ghidra.app.services.CodeFormatService):
    """
    Panel to select a data type in order to resolve an add conflict in the multi-user
    external location merger.
    """

    @typing.type_check_only
    class ShowHeaderButton(docking.widgets.EmptyBorderButton):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    KEEP_LATEST_BUTTON_NAME: typing.Final = "LatestVersionRB"
    KEEP_MY_BUTTON_NAME: typing.Final = "CheckedOutVersionRB"
    KEEP_BOTH_BUTTON_NAME: typing.Final = "KeepBothVersionsRB"
    MERGE_BOTH_BUTTON_NAME: typing.Final = "MergeBothVersionsRB"

    def addDomainObjectListener(self):
        """
        Add the latest program's listing model as a listener to the latest program
        for domain object events.
        """

    def removeDomainObjectListener(self):
        """
        Remove the latest program's listing model as a listener to the latest program
        for domain object events.
        """

    def setAddressTranslator(self, translator: ghidra.app.util.viewer.multilisting.AddressTranslator):
        ...

    def setBottomComponent(self, comp: javax.swing.JComponent):
        ...


@typing.type_check_only
class ListChoice(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def isSelected(self) -> bool:
        ...

    @property
    def selected(self) -> jpype.JBoolean:
        ...


class CodeUnitDetails(java.lang.Object):
    """
    This is a class with static methods for obtaining information about a code unit and its 
    references. The information is provided as a String.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getCodeUnitDetails(cu: ghidra.program.model.listing.CodeUnit) -> str:
        """
        Gets a string that indicates the code unit along with its overrides.
        This can contain new line characters.
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit
        :return: info about the code unit.
        :rtype: str
        """

    @staticmethod
    def getInstructionDetails(cu: ghidra.program.model.listing.CodeUnit) -> str:
        """
        Gets a string that indicates the code unit along with its overrides and its "from" references.
        This can contain new line characters.
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit
        :return: info about the code unit and its references.
        :rtype: str
        """

    @staticmethod
    def getReferenceDetails(cu: ghidra.program.model.listing.CodeUnit) -> str:
        """
        Gets a string that indicates the references from a code unit.
        This can contain new line characters.
         
        Note: Data currently only indicates references on the minimum address.
        
        :param ghidra.program.model.listing.CodeUnit cu: the code unit
        :return: info about the code unit's references.
        :rtype: str
        """


@typing.type_check_only
class OffsetRanges(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def addRangeList(self, firstUse: typing.Union[jpype.JInt, int], commonSrl: ghidra.util.datastruct.SortedRangeList):
        """
        
        
        :param jpype.JInt or int firstUse: 
        :param ghidra.util.datastruct.SortedRangeList commonSrl:
        """


class ListingMergeConstants(java.lang.Object):
    """
    ``ListingMergeConstants`` is an interface that provides constants 
    that are used throughout all of the Listing merge managers for multi-user.
    """

    class_: typing.ClassVar[java.lang.Class]
    CANCELED: typing.Final = -1
    """
    Conflict Option indicating the user canceled the merge.
    """

    ASK_USER: typing.Final = 0
    """
    Conflict Option indicating to prompt the user for a response.
    """

    INFO_ROW: typing.Final = 0
    """
    Indicates a row on the conflicts panel is strictly information and doesn't contain a choice.
    """

    KEEP_ORIGINAL: typing.Final = 1
    """
    Keep the Original program's information to resolve a conflict.
    """

    KEEP_LATEST: typing.Final = 2
    """
    Keep the Latest program's information to resolve a conflict.
    """

    KEEP_MY: typing.Final = 4
    """
    Keep My program's information to resolve a conflict.
    """

    KEEP_RESULT: typing.Final = 8
    """
    Keep Result program's existing information to resolve a conflict.
    """

    KEEP_BOTH: typing.Final = 6
    """
    Keep both the Latest program's and My program's information to resolve a conflict.
    """

    KEEP_ALL: typing.Final = 7
    """
    Keep the Original program's, the Latest program's, and My program's information to resolve a conflict.
    """

    REMOVE_LATEST: typing.Final = 8
    """
    Remove the Latest program's conflict item to resolve a conflict.
    """

    RENAME_LATEST: typing.Final = 16
    """
    Rename the conflict item as in the Latest program to resolve a conflict.
    """

    REMOVE_MY: typing.Final = 32
    """
    Remove the My program's conflict item to resolve a conflict.
    """

    RENAME_MY: typing.Final = 64
    """
    Rename the conflict item as in My program to resolve a conflict.
    """

    TRUNCATE_LENGTH: typing.Final = 160
    """
    Maximum length to display before truncating occurs in conflict panel.
    This is needed for comments, etc. which could be very large.
    """

    RESULT_TITLE: typing.Final = "Result"
    ORIGINAL_TITLE: typing.Final = "Original"
    LATEST_TITLE: typing.Final = "Latest"
    MY_TITLE: typing.Final = "Checked Out"
    LATEST_LIST_BUTTON_NAME: typing.Final = "LatestListRB"
    CHECKED_OUT_LIST_BUTTON_NAME: typing.Final = "CheckedOutListRB"
    LATEST_BUTTON_NAME: typing.Final = "LatestVersionRB"
    CHECKED_OUT_BUTTON_NAME: typing.Final = "CheckedOutVersionRB"
    ORIGINAL_BUTTON_NAME: typing.Final = "OriginalVersionRB"
    RESULT_BUTTON_NAME: typing.Final = "ResultVersionRB"
    LATEST_CHECK_BOX_NAME: typing.Final = "LatestVersionCheckBox"
    CHECKED_OUT_CHECK_BOX_NAME: typing.Final = "CheckedOutVersionCheckBox"
    ORIGINAL_CHECK_BOX_NAME: typing.Final = "OriginalVersionCheckBox"
    LATEST_LABEL_NAME: typing.Final = "LatestVersionLabel"
    CHECKED_OUT_LABEL_NAME: typing.Final = "CheckedOutVersionLabel"
    ORIGINAL_LABEL_NAME: typing.Final = "OriginalVersionLabel"
    REMOVE_LATEST_BUTTON_NAME: typing.Final = "RemoveLatestRB"
    RENAME_LATEST_BUTTON_NAME: typing.Final = "RenameLatestRB"
    REMOVE_CHECKED_OUT_BUTTON_NAME: typing.Final = "RemoveCheckedOutRB"
    RENAME_CHECKED_OUT_BUTTON_NAME: typing.Final = "RenameCheckedOutRB"


@typing.type_check_only
class ListChoiceTable(docking.widgets.table.GTable):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: javax.swing.table.TableModel):
        ...


@typing.type_check_only
class AbstractFunctionMerger(ListingMergeConstants):
    """
    Abstract class that other function mergers can extend to get basic constants and methods 
    for merging function changes. 
     
    Important: This class is intended to be used only for a single program 
    version merge.
    """

    @typing.type_check_only
    class ParamInfoConflict(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LocalVariableConflict(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionAddressIterator(ghidra.program.model.address.AddressIterator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionDetailChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LocalVarChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FunctionConflictChangeListener(javax.swing.event.ChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mergeManager: ghidra.app.merge.ProgramMultiUserMergeManager, programs: jpype.JArray[ghidra.program.model.listing.Program]):
        ...

    def dispose(self):
        ...


@typing.type_check_only
class ListingMerger(java.lang.Object):
    """
    ``ListingMerger`` is an interface implemented by an individual 
    listing merge manager. It defines methods that the overall ListingMergeManager
    can call on the individual listing merge managers.
    """

    class_: typing.ClassVar[java.lang.Class]

    def apply(self) -> bool:
        """
        Method called when the Apply button is pressed on the GUI conflict resolution window.
        
        :return: true if apply succeeded.
        :rtype: bool
        """

    def autoMerge(self, progressMin: typing.Union[jpype.JInt, int], progressMax: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Performs the automatic merge for all changes in my Checked Out program version.
        It also determines the conflicts requiring manual resolution.
        
        :param ghidra.util.task.TaskMonitor monitor: task monitor for informing the user of progress.
        :param jpype.JInt or int progressMin: minimum progress value, between 0 and 100, for this auto merge. 
        The merge manager's progress should be updated from progressMin to progressMax 
        as the autoMerge occurs.
        :param jpype.JInt or int progressMax: maximum progress value, between 0 and 100, for this auto merge.
        :raises ProgramConflictException: if the programs for different versions are not compatible.
        :raises MemoryAccessException: if memory can't be accessed to get/set byte values.
        :raises CancelledException: if the user cancels the merge.
        """

    def cancel(self):
        """
        Method called when the Cancel button is pressed on the GUI conflict resolution window.
        """

    def getConflictCount(self, addr: ghidra.program.model.address.Address) -> int:
        """
        Determines the number of conflicts at the indicated address.
        
        :param ghidra.program.model.address.Address addr: the address
        :return: the number of conflicts at the indicated address.
        :rtype: int
        """

    def getConflictType(self) -> str:
        """
        Returns a string indicating the type of listing conflict this merger handles.
         
        For example, Function, Symbol, etc.
        """

    def getConflicts(self) -> ghidra.program.model.address.AddressSetView:
        """
        
        
        :return: an address set indicating where there are conflicts to resolve.
        :rtype: ghidra.program.model.address.AddressSetView
        """

    def getNumConflictsResolved(self) -> int:
        """
        Determines the number of conflicts that have currently been resolved on 
        the conflict resolution window.
        
        :return: the number of conflicts resolved by the user selecting buttons or checkboxes.
        :rtype: int
        """

    def hasConflict(self, addr: ghidra.program.model.address.Address) -> bool:
        """
        Determines if there is a conflict at the specified address.
        
        :param ghidra.program.model.address.Address addr: 
        :return: true if there is one or more conflicts at the address.
        :rtype: bool
        """

    def mergeConflicts(self, listingPanel: ghidra.app.merge.tool.ListingMergePanel, addr: ghidra.program.model.address.Address, conflictOption: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Performs a manual merge of all conflicts at the indicated address for 
        the type of conflicts that this merge manager handles.
        
        :param ghidra.app.merge.tool.ListingMergePanel listingPanel: the listing merge panel with the 4 version listings.
        :param ghidra.program.model.address.Address addr: 
        :param jpype.JInt or int conflictOption: ASK_USER means interactively resolve conflicts. 
        JUnit testing also allows setting this to LATEST, MY, or ORIGINAL to force
        selection of a particular version change.
        :param ghidra.util.task.TaskMonitor monitor: task monitor for informing the user of progress.
        :raises CancelledException: if the user cancels the merge.
        :raises MemoryAccessException: if memory can't be accessed to get/set byte values.
        """

    @property
    def conflicts(self) -> ghidra.program.model.address.AddressSetView:
        ...

    @property
    def conflictType(self) -> java.lang.String:
        ...

    @property
    def conflictCount(self) -> jpype.JInt:
        ...

    @property
    def numConflictsResolved(self) -> jpype.JInt:
        ...


class ProgramContextMergeManager(ghidra.app.merge.MergeResolver, ListingMergeConstants):
    """
    ``ProgramContextMergeManager`` merges register value changes 
    for multi-user program versions. It merges changes for each named register
    in the program.
     
    Note: If a register gets changed that is part of another register that has been set, 
    then each named register will get merged independently. This means that 
    when in conflict with another version the conflict would arise for each 
    instead of just the larger register.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, mergeManager: ghidra.app.merge.ProgramMultiUserMergeManager, resultPgm: ghidra.program.model.listing.Program, originalPgm: ghidra.program.model.listing.Program, latestPgm: ghidra.program.model.listing.Program, myPgm: ghidra.program.model.listing.Program, latestChanges: ghidra.program.model.listing.ProgramChangeSet, myChanges: ghidra.program.model.listing.ProgramChangeSet):
        """
        Creates a new ``ProgramContextMergeManager``.
        
        :param ghidra.program.model.listing.Program resultPgm: the program to be updated with the result of the merge.
        This is the program that will actually get checked in.
        :param ghidra.program.model.listing.Program originalPgm: the program that was checked out.
        :param ghidra.program.model.listing.Program latestPgm: the latest checked-in version of the program.
        :param ghidra.program.model.listing.Program myPgm: the program requesting to be checked in.
        :param ghidra.program.model.listing.ProgramChangeSet latestChanges: the address set of changes between original and latest versioned program.
        :param ghidra.program.model.listing.ProgramChangeSet myChanges: the address set of changes between original and my modified program.
        """


@typing.type_check_only
class ReferenceMerger(AbstractListingMerger):
    """
    Class for merging reference changes. This class can determine
    where there are conflicts between the latest checked in version and my
    checked out version. It can then automatically merge non-conflicting changes
    and manually merge the conflicting references.
     
    The ReferenceMerger takes into account anywhere that code units have been merged.
    If code units were merged, then this will not try to merge at those addresses.
    The code unit merger should have already merged the references where it 
    merged code units.
     
    Important: This class is intended to be used only for a single program 
    version merge. It should be constructed, followed by an autoMerge(), and lastly
    each address with a conflict should have mergeConflicts() called on it.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["RegisterMergeManager", "VerticalChoicesPanel", "ResolveConflictChangeEvent", "FunctionTagMerger", "ConflictInfoPanel", "ScrollingListChoicesPanel", "ConflictPanel", "UserDefinedPropertyMerger", "CodeUnitMerger", "ExternalProgramMerger", "FunctionVariableStorageConflicts", "FunctionMerger", "BookmarkMerger", "ChoiceComponent", "ExternalFunctionMerger", "EquateMerger", "VariousChoicesPanel", "CommentMerger", "AbstractListingMerger", "ExternalConflictInfoPanel", "ExternalsAddressTranslator", "ListingMergeManager", "UserDefinedPropertyPanel", "SymbolMerger", "FunctionTagListingMerger", "ExternalAddConflictPanel", "ListChoice", "CodeUnitDetails", "OffsetRanges", "ListingMergeConstants", "ListChoiceTable", "AbstractFunctionMerger", "ListingMerger", "ProgramContextMergeManager", "ReferenceMerger"]
