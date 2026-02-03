from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import db.util
import docking
import docking.action
import docking.dnd
import docking.widgets.fieldpanel.support
import docking.widgets.table
import ghidra.app.context
import ghidra.app.services
import ghidra.framework.plugintool
import ghidra.program.model.data
import ghidra.program.model.listing
import ghidra.util.task
import java.awt # type: ignore
import java.awt.dnd # type: ignore
import java.awt.event # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore
import javax.swing.border # type: ignore
import javax.swing.table # type: ignore
import utility.function


M = typing.TypeVar("M")
T = typing.TypeVar("T")


class ComponentStandAloneActionContext(docking.DefaultActionContext, ComponentContext):
    """
    ``ComponentStandAloneActionContext`` provides an action context when editing a 
    composite with a single selected component, and the composite is associated with a
    stand-alone archive.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, compositeEditorProvider: CompositeEditorProvider[typing.Any, typing.Any], component: ghidra.program.model.data.DataTypeComponent):
        ...


class RedoChangeAction(CompositeEditorTableAction):
    """
    :obj:`RedoChangeAction` facilitates an redo of recently undone/reverted composite editor changes.
    """

    class_: typing.ClassVar[java.lang.Class]
    DESCRIPTION: typing.ClassVar[java.lang.String]
    ACTION_NAME: typing.Final = "Redo Editor Change"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


@typing.type_check_only
class IDMapDB(java.lang.Object):
    """
    :obj:`IDMapDB` provides a bidirectional map for tracking view to/from original datatype ID
    correspondence and faciliate recovery across undo/redo of the view's datatype manager.
    """

    class_: typing.ClassVar[java.lang.Class]


class DuplicateAction(CompositeEditorTableAction):
    """
    Action to duplicate the selected row
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Duplicate Component"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


@typing.type_check_only
class ComponentCellEditorListener(java.lang.Object):
    """
    The composite data type editor uses this listener so that the cell editor can indicate
    to the panel that it should try to stop editing the current cell and move to the indicated cell.
    """

    class_: typing.ClassVar[java.lang.Class]
    NEXT: typing.Final = 1
    PREVIOUS: typing.Final = 2
    UP: typing.Final = 3
    DOWN: typing.Final = 4

    def moveCellEditor(self, direction: typing.Union[jpype.JInt, int], value: typing.Union[java.lang.String, str]):
        ...


class CycleGroupAction(CompositeEditorTableAction):
    """
    Action to apply a data type cycle group. For use in the composite data type editor.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any], cycleGroup: ghidra.program.model.data.CycleGroup):
        ...

    def getCycleGroup(self) -> ghidra.program.model.data.CycleGroup:
        ...

    @property
    def cycleGroup(self) -> ghidra.program.model.data.CycleGroup:
        ...


class CompositeChangeListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def componentChanged(self, ordinal: typing.Union[jpype.JInt, int]):
        """
        Indicates the ordinal of the component which has been added, updated or cleared.
        
        :param jpype.JInt or int ordinal: component ordinal
        """


class EditFieldAction(CompositeEditorTableAction):
    """
    Action for use in the composite data type editor.
    This action has help associated with it.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Edit Component Field"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class CompositeViewerDataTypeManager(ghidra.program.model.data.StandAloneDataTypeManager, db.util.ErrorHandler, typing.Generic[T]):
    """
    :obj:`CompositeViewerDataTypeManager` provides a data type manager that the structure editor 
    will use internally for updating the structure being edited and tracks all directly and 
    indirectly referenced datatypes.  This manager also facilitates undo/redo support within
    the editor.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, rootName: typing.Union[java.lang.String, str], originalDTM: ghidra.program.model.data.DataTypeManager):
        """
        Creates a data type manager that the composite editor will use internally for managing 
        dependencies without resolving the actual composite being edited.  A single transaction 
        will be started with this instantiation and held open until this instance is closed.  
        Undo/redo and datatype pruning is not be supported.
        
        :param java.lang.String or str rootName: the root name for this data type manager (usually the program name).
        :param ghidra.program.model.data.DataTypeManager originalDTM: the original data type manager.
        """

    @typing.overload
    def __init__(self, rootName: typing.Union[java.lang.String, str], originalComposite: T, changeCallback: utility.function.Callback, restoredCallback: utility.function.Callback):
        """
        Creates a data type manager that the structure editor will use internally for managing a 
        structure being edited and its dependencies.
        
        :param java.lang.String or str rootName: the root name for this data type manager (usually the program name).
        :param T originalComposite: the original composite data type that is being edited.
        :param utility.function.Callback changeCallback: Callback will be invoked when any change is made to the view composite.
        :param utility.function.Callback restoredCallback: Callback will be invoked following any undo/redo.
        """

    def clearUndoOnChange(self):
        """
        Flag the next transaction end to check for subsequent database modifications 
        and clear undo/redo stack if changes are detected.  This call is ignored if 
        there is already a pending check.
        """

    def findMyDataTypeFromOriginalID(self, originalId: typing.Union[jpype.JLong, int]) -> ghidra.program.model.data.DataType:
        """
        Find a resolved DB-datatype within this manager based upon its source datatype's ID 
        within the original datatype manager associated with this manager.  This method is 
        useful when attempting to matchup a datatype within this manager to one which has changed
        within the original datatype manager.
        
        :param jpype.JLong or int originalId: datatype ID within original datatype manager
        :return: matching DB-datatype or null if not found
        :rtype: ghidra.program.model.data.DataType
        """

    def findOriginalDataTypeFromMyID(self, myId: typing.Union[jpype.JLong, int]) -> ghidra.program.model.data.DataType:
        """
        Find a resolved DB-datatype within the original datatype manager based upon a resolved 
        datatype's ID within this manager. This method is useful when attempting to matchup a 
        datatype within this manager to one which has possibly changed within the original 
        datatype manager.
        
        :param jpype.JLong or int myId: resolved datatype ID within this datatype manager
        :return: matching DB-datatype or null if not found
        :rtype: ghidra.program.model.data.DataType
        """

    def getModCount(self) -> int:
        """
        Provides a means of detecting changes to the underlying database during a transaction.
        
        :return: current modification count
        :rtype: int
        """

    def getOriginalDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        """
        Get the :obj:`DataTypeManager` associated with the original composite datatype being edited.
        
        :return: original datatype manager
        :rtype: ghidra.program.model.data.DataTypeManager
        """

    def getResolvedViewComposite(self) -> T:
        """
        Return the view composite
        
        :return: view composite or null if not resolved during instantiation.
        :rtype: T
        """

    def isUndoRedoAllowed(self) -> bool:
        """
        Determine if undo/redo is allowed.
        
        :return: true if undo/redo is allowed with use of individual transactions, else false
        :rtype: bool
        """

    def isViewDataTypeFromOriginalDTM(self, existingViewDt: ghidra.program.model.data.DataType) -> bool:
        """
        Determine if the specified datatype which has previsouly been resolved to this datatype
        manager originated from original composite's source (e.g., program).  
         
        
        NOTE: Non-DB datatypes will always return false.
        
        :param ghidra.program.model.data.DataType existingViewDt: existing datatype which has previously been resolved to this
        datatype manager.
        :return: true if specified datatype originated from this manager's associated original 
        datatype manager.
        :rtype: bool
        """

    def refreshDBTypesFromOriginal(self) -> bool:
        """
        Refresh all datatypes which originate from the originalDTM.
        This methods is intended for use following an undo/redo of the originalDTM only
        and will purge the ID mappings for any datatypes which no longer exist or become
        orphaned.
        
        :return: true if a dependency change is detected, else false
        :rtype: bool
        """

    @property
    def modCount(self) -> jpype.JLong:
        ...

    @property
    def originalDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        ...

    @property
    def resolvedViewComposite(self) -> T:
        ...

    @property
    def viewDataTypeFromOriginalDTM(self) -> jpype.JBoolean:
        ...

    @property
    def undoRedoAllowed(self) -> jpype.JBoolean:
        ...


class CreateInternalStructureAction(CompositeEditorTableAction):
    """
    Action for use in the structure data type editor.
    This action has help associated with it.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Create Structure From Selection"

    def __init__(self, provider: StructureEditorProvider):
        ...


class ShowComponentPathAction(CompositeEditorTableAction):
    """
    Action for use in the composite data type editor.
    This action has help associated with it.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Show Component Path"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class PointerAction(CompositeEditorTableAction):
    """
    Action for use in the composite data type editor.
    This action has help associated with it.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Create Pointer"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class ShowDataTypeInTreeAction(CompositeEditorTableAction):
    """
    Shows the editor's data type in the UI using the :obj:`DataTypeManagerService`.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Show In Data Type Manager"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class EditBitFieldAction(CompositeEditorTableAction):

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Edit Bitfield"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class CompositeEditorLockListener(java.lang.Object):
    """
    Composite Editor Lock change listener interface.
    This has a notification method for the lock/unlock mode of the 
    composite data editor. The lock/unlock mode controls whether or 
    not the size of the composite data type being edited can change.
    """

    class_: typing.ClassVar[java.lang.Class]
    EDITOR_LOCKED: typing.Final = 1
    EDITOR_UNLOCKED: typing.Final = 2

    def lockStateChanged(self, type: typing.Union[jpype.JInt, int]):
        """
        Called whenever the composite data type editor lock/unlock state changes.
        Whether the editor is in locked or unlocked mode.
        
        :param jpype.JInt or int type: the type of state change: EDITOR_LOCKED, EDITOR_UNLOCKED.
        """


class FavoritesAction(CompositeEditorTableAction):
    """
    Action to apply a favorite data type.
    Used in a composite data type editor.
    This action has help associated with it.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any], dt: ghidra.program.model.data.DataType):
        """
        Creates an action for applying a favorite data type.
        
        :param CompositeEditorProvider[typing.Any, typing.Any] provider: the provider that owns this action
        :param ghidra.program.model.data.DataType dt: the favorite data type
        """

    def getDataType(self) -> ghidra.program.model.data.DataType:
        ...

    @property
    def dataType(self) -> ghidra.program.model.data.DataType:
        ...


class BitFieldPlacementComponent(javax.swing.JPanel, javax.swing.Scrollable):

    class BitFieldLegend(javax.swing.JPanel):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class MyMouseWheelListener(java.awt.event.MouseWheelListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BitFieldPlacement(java.lang.Object):
        """
        ``BitFieldPlacement`` provides the ability to translate a
        composite component to a bit-level placement within the allocation
        range including the notion of clipped edges when one or both sides
        extend beyond the allocation range.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BitFieldAllocation(java.lang.Object):
        """
        ``BitFieldAllocation`` provides the bit-level details within the
        allocation range including the optional overlay of an edit component
        with confict detection.  The bit-level details are defined via
        :obj:`BitAttributes`.
        """

        class_: typing.ClassVar[java.lang.Class]

        def getBitOffset(self) -> int:
            ...

        def getBitSize(self) -> int:
            ...

        @property
        def bitSize(self) -> jpype.JInt:
            ...

        @property
        def bitOffset(self) -> jpype.JInt:
            ...


    @typing.type_check_only
    class EditMode(java.lang.Enum[BitFieldPlacementComponent.EditMode]):

        class_: typing.ClassVar[java.lang.Class]
        NONE: typing.Final[BitFieldPlacementComponent.EditMode]
        ADD: typing.Final[BitFieldPlacementComponent.EditMode]
        EDIT: typing.Final[BitFieldPlacementComponent.EditMode]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> BitFieldPlacementComponent.EditMode:
            ...

        @staticmethod
        def values() -> jpype.JArray[BitFieldPlacementComponent.EditMode]:
            ...


    @typing.type_check_only
    class EndBitType(java.lang.Enum[BitFieldPlacementComponent.EndBitType]):

        class_: typing.ClassVar[java.lang.Class]
        NOT_END: typing.Final[BitFieldPlacementComponent.EndBitType]
        END: typing.Final[BitFieldPlacementComponent.EndBitType]
        TRUNCATED_END: typing.Final[BitFieldPlacementComponent.EndBitType]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> BitFieldPlacementComponent.EndBitType:
            ...

        @staticmethod
        def values() -> jpype.JArray[BitFieldPlacementComponent.EndBitType]:
            ...


    @typing.type_check_only
    class BitAttributes(java.lang.Object):
        """
        ``BitAttributes`` provide bit attributes which identify the
        associated component, a conflict component and left/right line
        types to be displayed.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getComposite(self) -> ghidra.program.model.data.Composite:
        """
        Get the composite associated with this component.
        
        :return: composite or null
        :rtype: ghidra.program.model.data.Composite
        """

    def getPreferredHeight(self) -> int:
        """
        
        
        :return: fixed height of component
        :rtype: int
        """

    def isShowOffsetsInHex(self) -> bool:
        ...

    def isWithinBitCell(self, p: java.awt.Point) -> bool:
        """
        Determine if specified point is within bit cell region
        
        :param java.awt.Point p: point within this component's bounds
        :return: true if p is within bit cell region
        :rtype: bool
        """

    def setComposite(self, composite: ghidra.program.model.data.Composite):
        """
        Set the current composite.  State will reset to a non-edit mode.
        The edit use enablement will remain unchanged.
        
        :param ghidra.program.model.data.Composite composite: composite or null
        """

    def setShowOffsetsInHex(self, useHex: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def composite(self) -> ghidra.program.model.data.Composite:
        ...

    @composite.setter
    def composite(self, value: ghidra.program.model.data.Composite):
        ...

    @property
    def withinBitCell(self) -> jpype.JBoolean:
        ...

    @property
    def showOffsetsInHex(self) -> jpype.JBoolean:
        ...

    @showOffsetsInHex.setter
    def showOffsetsInHex(self, value: jpype.JBoolean):
        ...

    @property
    def preferredHeight(self) -> jpype.JInt:
        ...


class CompEditorPanel(CompositeEditorPanel[T, M], typing.Generic[T, M]):
    """
    Panel for editing a composite with a blank line at the bottom of the table
    when in unlocked mode.
    """

    @typing.type_check_only
    class UpAndDownKeyListener(java.awt.event.KeyAdapter):
        """
        A simple class that allows clients to focus other components when the up or down arrows keys
        are pressed
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: M, provider: CompositeEditorProvider[T, M]):
        """
        Constructor for a panel that has a blank line in unlocked mode and
        composite name and description that are editable.
        
        :param M model: the model for editing the composite data type
        :param CompositeEditorProvider[T, M] provider: the editor provider furnishing this panel for editing.
        """

    def getCategoryName(self) -> str:
        """
        Returns the currently displayed structure category name.
        
        :return: the name
        :rtype: str
        """

    def getCompositeSize(self) -> int:
        """
        Returns the currently displayed composite's size.
        
        :return: the size
        :rtype: int
        """

    def refreshGUIActualAlignmentValue(self):
        """
        Updates the GUI display of the actual alignment value.
        """

    def refreshGUIMinimumAlignmentValue(self):
        ...

    def refreshGUIPackingValue(self):
        """
        Sets the currently displayed structure packing value (maximum component alignment)
        """

    def setCategoryName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the currently displayed structure category name.
        
        :param java.lang.String or str name: the new category name
        """

    def undoDragUnderFeedback(self):
        """
        Called from the DropTgtAdapter to revert any feedback changes back to
        normal.
        """

    @property
    def compositeSize(self) -> jpype.JInt:
        ...

    @property
    def categoryName(self) -> java.lang.String:
        ...

    @categoryName.setter
    def categoryName(self, value: java.lang.String):
        ...


class StructureEditorProvider(CompositeEditorProvider[ghidra.program.model.data.Structure, StructureEditorModel]):
    """
    Editor for a Structure Data Type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin, structureDataType: ghidra.program.model.data.Structure, showHexNumbers: typing.Union[jpype.JBoolean, bool]):
        ...


class DataTypeCellRenderer(docking.widgets.table.GTableCellRenderer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, originalDataTypeManager: ghidra.program.model.data.DataTypeManager):
        ...


class CompositeEditorProvider(ghidra.framework.plugintool.ComponentProviderAdapter, EditorProvider, EditorActionListener, typing.Generic[T, M]):
    """
    Editor provider for a Composite Data Type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getDtmService(self) -> ghidra.app.services.DataTypeManagerService:
        ...

    def getFirstEditableColumn(self, row: typing.Union[jpype.JInt, int]) -> int:
        ...

    def getHelpName(self) -> str:
        ...

    def getHelpTopic(self) -> str:
        ...

    def getTable(self) -> javax.swing.JTable:
        ...

    def selectField(self, fieldName: typing.Union[java.lang.String, str]):
        ...

    @property
    def helpName(self) -> java.lang.String:
        ...

    @property
    def dtmService(self) -> ghidra.app.services.DataTypeManagerService:
        ...

    @property
    def firstEditableColumn(self) -> jpype.JInt:
        ...

    @property
    def helpTopic(self) -> java.lang.String:
        ...

    @property
    def table(self) -> javax.swing.JTable:
        ...


class UnionEditorPanel(CompEditorPanel[ghidra.program.model.data.Union, UnionEditorModel]):
    """
    Editor panel for Union datatype
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: UnionEditorModel, provider: CompositeEditorProvider[ghidra.program.model.data.Union, UnionEditorModel]):
        ...


@typing.type_check_only
class UnionEditorModel(CompEditorModel[ghidra.program.model.data.Union]):

    class_: typing.ClassVar[java.lang.Class]

    def clearSelectedComponents(self):
        """
        Clear the selected components
        
        :raises UsrException: if clearing isn't allowed
        """

    def getMaxAddLength(self, index: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the maximum number of bytes available for a data type that is added at the indicated
        index.
        
        :param jpype.JInt or int index: index of the component in the union data type.
        :return: no limit on union elements.
        :rtype: int
        """

    def getMaxReplaceLength(self, currentIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the maximum number of bytes available for a new data type that 
        will replace the current data type at the indicated index.
        If there isn't a component with the indicated index, the max length 
        will be determined by the lock mode.
        Note: This method doesn't care whether there is a selection or not.
        
        :param jpype.JInt or int currentIndex: index of the component in the union.
        :return: the maximum number of bytes that can be replaced
        :rtype: int
        """

    def insert(self, rowIndex: typing.Union[jpype.JInt, int], dt: ghidra.program.model.data.DataType, dtLength: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.DataTypeComponent:
        """
        Insert the named data type before the specified index.
        
        :param jpype.JInt or int rowIndex: index of the row (component).
        :raises InvalidDataTypeException: if the union being edited is part
                of the data type being inserted or if inserting isn't allowed.
        """

    def isAddAllowed(self, rowIndex: typing.Union[jpype.JInt, int], datatype: ghidra.program.model.data.DataType) -> bool:
        """
        Returns whether or not addition of the specified component is allowed
        at the specified index. the addition could be an insert or replace as
        determined by the state of the edit model.
        
        :param jpype.JInt or int rowIndex: index of the row in the union table.
        :param ghidra.program.model.data.DataType datatype: the data type to be inserted.
        """

    def isArrayAllowed(self) -> bool:
        """
        Returns whether or not the selection
        is allowed to be changed into an array.
        """

    def isCellEditable(self, rowIndex: typing.Union[jpype.JInt, int], columnIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        returns whether or not a particular component row and field in this
        structure is editable.
          
        Warning: There shouldn't be a selection when this is called.
        
        :param jpype.JInt or int rowIndex: the row index in the component table.
        :param jpype.JInt or int columnIndex: the index for the field of the component.
        """

    def isClearAllowed(self) -> bool:
        """
        Returns whether or not clearing the component at the specified index is allowed
        """

    def isDeleteAllowed(self) -> bool:
        """
        Returns whether or not delete of the component at the selected index is allowed
        """

    def isDuplicateAllowed(self) -> bool:
        """
        Returns whether or not the component at the selected index is allowed to be duplicated
        """

    def isInsertAllowed(self, rowIndex: typing.Union[jpype.JInt, int], datatype: ghidra.program.model.data.DataType) -> bool:
        """
        Returns whether or not insertion of the specified component is allowed
        at the specified index.
        
        :param jpype.JInt or int rowIndex: index of the row in the union table.
        :param ghidra.program.model.data.DataType datatype: the data type to be inserted.
        """

    def isLockable(self) -> bool:
        ...

    @property
    def arrayAllowed(self) -> jpype.JBoolean:
        ...

    @property
    def maxAddLength(self) -> jpype.JInt:
        ...

    @property
    def deleteAllowed(self) -> jpype.JBoolean:
        ...

    @property
    def lockable(self) -> jpype.JBoolean:
        ...

    @property
    def clearAllowed(self) -> jpype.JBoolean:
        ...

    @property
    def maxReplaceLength(self) -> jpype.JInt:
        ...

    @property
    def duplicateAllowed(self) -> jpype.JBoolean:
        ...


class CompEditorModel(CompositeEditorModel[T], typing.Generic[T]):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def add(self, rowIndex: typing.Union[jpype.JInt, int], dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataTypeComponent:
        """
        Adds the specified data type at the specified component index. Whether
        an insert or replace occurs depends on whether the indicated index is
        in a selection and whether in locked or unlocked mode.
        
        :param jpype.JInt or int rowIndex: the index of the row where the data type should be added.
        :param ghidra.program.model.data.DataType dt: the data type to add
        :return: true if the component is added, false if it doesn't.
        :rtype: ghidra.program.model.data.DataTypeComponent
        :raises UsrException: if add fails
        """

    @typing.overload
    def add(self, rowIndex: typing.Union[jpype.JInt, int], dt: ghidra.program.model.data.DataType, dtLength: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.DataTypeComponent:
        """
        Adds the specified data type at the specified component index. Whether
        an insert or replace occurs depends on whether the indicated index is
        in a selection and whether in locked or unlocked mode.
        
        :param jpype.JInt or int rowIndex: the index of the row where the data type should be added.
        :param ghidra.program.model.data.DataType dt: the data type to add
        :param jpype.JInt or int dtLength: datatype instance length
        :return: the component is added, null if it doesn't.
        :rtype: ghidra.program.model.data.DataTypeComponent
        :raises UsrException: if add fails
        """

    def apply(self) -> bool:
        """
        Apply the changes for the current edited composite back to the
        original composite.
        
        :return: true if apply succeeds
        :rtype: bool
        :raises InvalidDataTypeException: if this structure has a component that it is part of.
        """

    def getActualAlignment(self) -> int:
        ...

    def getAlignmentType(self) -> ghidra.program.model.data.AlignmentType:
        """
        Return the (minimum) alignment type for the structure or union being viewed
        
        :return: the alignment type
        :rtype: ghidra.program.model.data.AlignmentType
        """

    def getExplicitMinimumAlignment(self) -> int:
        ...

    def getExplicitPackingValue(self) -> int:
        ...

    def getLastNumDuplicates(self) -> int:
        """
        Return the last number of duplicates the user entered when prompted for
        creating duplicates of a component.
        """

    def getMaxDuplicates(self, rowIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Determine the maximum number of duplicates that can be created for
        the component at the indicated index. The duplicates would follow
        the component. The number allowed depends on how many fit based on
        the current lock/unlock state of the editor.
         
        Note: This method doesn't care whether there is a selection or not.
        
        :param jpype.JInt or int rowIndex: the index of the row for the component to be duplicated.
        :return: the maximum number of duplicates. -1 indicates unlimited.
        :rtype: int
        """

    def getMaxElements(self) -> int:
        """
        Determine the maximum number of array elements that can be created for
        the current selection. The array data type is assumed to become the
        data type of the first component in the selection. The current selection
        must be contiguous or 0 is returned.
        
        :return: the number of array elements that fit in the current selection.
        :rtype: int
        """

    def getPackingType(self) -> ghidra.program.model.data.PackingType:
        ...

    @typing.overload
    def insert(self, rowIndex: typing.Union[jpype.JInt, int], dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataTypeComponent:
        """
        Inserts the specified data type at the specified component index.
        
        :param jpype.JInt or int rowIndex: the component index of where to add the data type.
        :param ghidra.program.model.data.DataType dt: the data type to add
        :return: true if the component is inserted, false if it doesn't.
        :rtype: ghidra.program.model.data.DataTypeComponent
        :raises UsrException: if insert fails
        """

    @typing.overload
    def insert(self, rowIndex: typing.Union[jpype.JInt, int], datatype: ghidra.program.model.data.DataType, length: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.DataTypeComponent:
        """
        Insert the named data type before the specified index.
        Returns null, if the inserted component is an Undefined byte
        and it gets consumed by the component before it.
        
        :param jpype.JInt or int rowIndex: index of the row (component).
        :raises InvalidDataTypeException: if the structure being edited is part
                of the data type being inserted or if inserting isn't allowed.
        """

    @typing.overload
    def isInsertAllowed(self, dataType: ghidra.program.model.data.DataType) -> bool:
        ...

    @typing.overload
    def isInsertAllowed(self, rowIndex: typing.Union[jpype.JInt, int], datatype: ghidra.program.model.data.DataType) -> bool:
        """
        Returns whether or not a component with the specified data type is allowed
        to be inserted before the component at the specified row index.
        
        :param jpype.JInt or int rowIndex: row index of the component in the structure.
        :param ghidra.program.model.data.DataType datatype: the data type to be inserted.
        """

    def isMoveDownAllowed(self) -> bool:
        """
        Returns whether the selected component(s) can be moved down (to the next higher index).
        """

    def isMoveUpAllowed(self) -> bool:
        """
        Returns whether the selected component(s) can be moved up (to the next lower index).
        """

    def isPackingEnabled(self) -> bool:
        ...

    def isReplaceAllowed(self, dataType: ghidra.program.model.data.DataType) -> bool:
        ...

    def load(self, dataType: T):
        """
        Sets the data type that is being edited and the category where it will get saved.
        
        :param T dataType: the composite data type being edited.
        """

    @typing.overload
    def replace(self, dataType: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataTypeComponent:
        ...

    @typing.overload
    def replace(self, rowIndex: typing.Union[jpype.JInt, int], dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataTypeComponent:
        """
        Adds the specified data type at the specified component index. Whether
        an insert or replace occurs depends on whether the indicated index is
        in a selection and whether in locked or unlocked mode.
        
        :param jpype.JInt or int rowIndex: the index of row where the data type should be replaced.
        :param ghidra.program.model.data.DataType dt: the new data type
        :return: component added, null or exception if it does not
        :rtype: ghidra.program.model.data.DataTypeComponent
        :raises UsrException: if add error occurs
        """

    def setAlignmentType(self, alignmentType: ghidra.program.model.data.AlignmentType, explicitValue: typing.Union[jpype.JInt, int]):
        ...

    def setPackingType(self, packingType: ghidra.program.model.data.PackingType, explicitValue: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def setSelection(self, rows: jpype.JArray[jpype.JInt]):
        """
        Saves the current selection in the components viewing area.
        
        :param jpype.JArray[jpype.JInt] rows: the indexes for the selected rows.
        """

    @typing.overload
    def setSelection(self, selection: docking.widgets.fieldpanel.support.FieldSelection):
        """
        Sets the model's current selection to the indicated selection.
        If the selection is empty, it gets adjusted to the empty last line.
        
        :param docking.widgets.fieldpanel.support.FieldSelection selection: the new selection
        """

    @property
    def maxDuplicates(self) -> jpype.JInt:
        ...

    @property
    def replaceAllowed(self) -> jpype.JBoolean:
        ...

    @property
    def explicitPackingValue(self) -> jpype.JInt:
        ...

    @property
    def packingEnabled(self) -> jpype.JBoolean:
        ...

    @property
    def moveUpAllowed(self) -> jpype.JBoolean:
        ...

    @property
    def explicitMinimumAlignment(self) -> jpype.JInt:
        ...

    @property
    def packingType(self) -> ghidra.program.model.data.PackingType:
        ...

    @property
    def lastNumDuplicates(self) -> jpype.JInt:
        ...

    @property
    def alignmentType(self) -> ghidra.program.model.data.AlignmentType:
        ...

    @property
    def moveDownAllowed(self) -> jpype.JBoolean:
        ...

    @property
    def maxElements(self) -> jpype.JInt:
        ...

    @property
    def actualAlignment(self) -> jpype.JInt:
        ...

    @property
    def insertAllowed(self) -> jpype.JBoolean:
        ...


class ApplyAction(CompositeEditorTableAction):
    """
    ApplyAction is an action for applying editor changes.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Apply Editor Changes"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class EditorListener(java.lang.Object):
    """
    Interface used for notification when an edit session is ending.
    """

    class_: typing.ClassVar[java.lang.Class]

    def closed(self, editor: EditorProvider):
        """
        Notification that the editor is closed.
        
        :param EditorProvider editor: the editor
        """


class BitFieldEditorPanel(javax.swing.JPanel):
    """
    ``BitFieldEditorPanel`` provides the ability to add or modify bitfields
    within non-packed structures.
    """

    @typing.type_check_only
    class BitSelectionHandler(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BitFieldEditorContext(docking.DefaultActionContext):

        class_: typing.ClassVar[java.lang.Class]

        def getAllocationOffset(self) -> int:
            ...

        def getSelectedBitOffset(self) -> int:
            ...

        @property
        def selectedBitOffset(self) -> jpype.JInt:
            ...

        @property
        def allocationOffset(self) -> jpype.JInt:
            ...


    @typing.type_check_only
    class JSpinnerWithMouseWheel(javax.swing.JSpinner, java.awt.event.MouseWheelListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class MoveUpAction(CompositeEditorTableAction):
    """
    Action for use in the composite data type editor.
    This action has help associated with it.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Move Components Up"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class InsertUndefinedAction(CompositeEditorTableAction):
    """
    Action for use in the structure data type editor.
    This action has help associated with it.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Insert Undefined Byte"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class BitFieldEditorDialog(docking.DialogComponentProvider):

    @typing.type_check_only
    class EditBitFieldAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AddBitFieldAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class DeleteComponentAction(docking.action.DockingAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ToggleHexUseAction(docking.action.DockingAction, docking.action.ToggleDockingActionIf):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class ComponentCellEditor(docking.widgets.table.GTableTextCellEditor):
    """
    ComponentCellEditor provides the editor for each editable field in a 
    component of a composite data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, field: javax.swing.JTextField):
        ...


class FindReferencesToStructureFieldAction(CompositeEditorTableAction):
    """
    An action to show references to the field in the currently selected editor row.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class MoveDownAction(CompositeEditorTableAction):
    """
    Action for use in the composite data type editor.
    This action has help associated with it.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Move Components Down"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class CompositeEditorModel(CompositeViewerModel[T], typing.Generic[T]):
    """
    Model for editing a composite data type. Specific composite data type editors
    should extend this class.
    """

    class_: typing.ClassVar[java.lang.Class]

    def add(self, dataType: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataTypeComponent:
        ...

    def addCompositeEditorModelListener(self, listener: CompositeEditorModelListener):
        """
        Adds a CompositeEditorModelListener to be notified when changes occur.
        
        :param CompositeEditorModelListener listener: the listener to add.
        """

    def apply(self) -> bool:
        """
        Apply the changes for the current edited composite back to the
        original composite.
        
        :return: true if apply succeeds
        :rtype: bool
        :raises EmptyCompositeException: if the structure doesn't have any components.
        :raises InvalidDataTypeException: if this structure has a component that it is part of.
        """

    def clearSelectedComponents(self):
        """
        Clear the selected components.
        
        :raises UsrException: if the data type isn't allowed to be cleared.
        """

    def cycleDataType(self, cycleGroup: ghidra.program.model.data.CycleGroup):
        ...

    def getCompositeName(self) -> str:
        """
        Return the currently specified data type name of the composite being viewed.
        """

    def getViewDataTypeManager(self) -> CompositeViewerDataTypeManager[T]:
        """
        Get the composite edtor's datatype manager
        
        :return: composite edtor's datatype manager
        :rtype: CompositeViewerDataTypeManager[T]
        """

    def hasChanges(self) -> bool:
        """
        Returns whether or not the editor has changes that haven't been applied.
        Changes can also mean a new data type that hasn't yet been saved.
        
        :return: if there are changes
        :rtype: bool
        """

    def isEditingField(self) -> bool:
        """
        Returns whether the user is currently editing a field's value.
        
        :return: whether the user is currently editing a field's value.
        :rtype: bool
        """

    def isValidName(self) -> bool:
        ...

    def removeCompositeEditorModelListener(self, listener: CompositeEditorModelListener):
        """
        Removes a CompositeEditorModelListener that was being notified when changes occur.
        
        :param CompositeEditorModelListener listener: the listener to remove.
        """

    def setComponentComment(self, rowIndex: typing.Union[jpype.JInt, int], comment: typing.Union[java.lang.String, str]) -> bool:
        """
        Sets the data type for the component at the indicated index.
        
        :param jpype.JInt or int rowIndex: the row index of the component
        :param java.lang.String or str comment: the comment
        :return: true if a change was made
        :rtype: bool
        """

    def setComponentName(self, rowIndex: typing.Union[jpype.JInt, int], name: typing.Union[java.lang.String, str]) -> bool:
        """
        Sets the data type for the component at the indicated index.
        
        :param jpype.JInt or int rowIndex: the row index of the component
        :param java.lang.String or str name: the name
        :return: true if a change was made
        :rtype: bool
        :raises InvalidNameException: if the name is invalid
        """

    def setName(self, name: typing.Union[java.lang.String, str]):
        """
        Sets the name for the composite data type being edited.
        
        :param java.lang.String or str name: the new name.
        :raises DuplicateNameException: if the name already exists.
        :raises InvalidNameException: if the name is invalid
        """

    def setSelection(self, rows: jpype.JArray[jpype.JInt]):
        """
        Saves the current selection in the structure components viewing area.
        
        :param jpype.JArray[jpype.JInt] rows: the indices for the selected rows.
        """

    def setValueAt(self, aValue: java.lang.Object, rowIndex: typing.Union[jpype.JInt, int], modelColumnIndex: typing.Union[jpype.JInt, int]):
        """
        This updates one of the values for a component that is a field of
        this data structure.
        
        :param java.lang.Object aValue: the new value for the field
        :param jpype.JInt or int rowIndex: the index of the row in the component table.
        :param jpype.JInt or int modelColumnIndex: the model field index within the component
        """

    def updateAndCheckChangeState(self) -> bool:
        ...

    @property
    def validName(self) -> jpype.JBoolean:
        ...

    @property
    def editingField(self) -> jpype.JBoolean:
        ...

    @property
    def compositeName(self) -> java.lang.String:
        ...

    @property
    def viewDataTypeManager(self) -> CompositeViewerDataTypeManager[T]:
        ...


class DeleteAction(CompositeEditorTableAction):

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Delete Components"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class StructureEditorPanel(CompEditorPanel[ghidra.program.model.data.Structure, StructureEditorModel]):
    """
    Editor panel for Union datatype
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: StructureEditorModel, provider: StructureEditorProvider):
        ...


class EditorActionListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def actionsAdded(self, actions: jpype.JArray[CompositeEditorTableAction]):
        """
        Notification that the indicated actions were added.
        
        :param jpype.JArray[CompositeEditorTableAction] actions: the composite editor actions.
        """

    def actionsRemoved(self, actions: jpype.JArray[CompositeEditorTableAction]):
        """
        Notification that the indicated actions were removed.
        
        :param jpype.JArray[CompositeEditorTableAction] actions: the composite editor actions.
        """


class UnionEditorProvider(CompositeEditorProvider[ghidra.program.model.data.Union, UnionEditorModel]):
    """
    Editor for a Union Data Type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: ghidra.framework.plugintool.Plugin, unionDataType: ghidra.program.model.data.Union, showInHex: typing.Union[jpype.JBoolean, bool]):
        ...


class ArrayAction(CompositeEditorTableAction):
    """
    Action for use in the composite data type editor.
    This action has help associated with it.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Create Array"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class CompositeEditorTableAction(docking.action.DockingAction):
    """
    CompositeEditorAction is an abstract class that should be extended for any action that is to be 
    associated with a composite editor.
     
    
    Note: Any new actions must be registered in the editor manager via the actions's name.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any], name: typing.Union[java.lang.String, str], group: typing.Union[java.lang.String, str], popupPath: jpype.JArray[java.lang.String], menuPath: jpype.JArray[java.lang.String], icon: javax.swing.Icon):
        ...

    def getHelpName(self) -> str:
        ...

    @property
    def helpName(self) -> java.lang.String:
        ...


class CompositeModelDataListener(java.lang.Object):
    """
    Composite Viewer Model component selection change listener interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def componentDataChanged(self):
        """
        Called whenever the composite's component data is changed.
        """

    def compositeInfoChanged(self):
        """
        Called whenever the composite's non-component data is changed.
        For example, the composite's name, description, size, ...
        """


class AddBitFieldAction(CompositeEditorTableAction):

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Add Bitfield"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class CompositeEditorModelListener(CompositeViewerModelListener):
    """
    Composite Editor Model change listener interface.
    This extends the CompositeViewerModelListener, which has a method for
    notifying when a composite's data changes in the model.
    This adds notification methods for selection changes due to an edit
    of the editor model.
    """

    class_: typing.ClassVar[java.lang.Class]
    COMPOSITE_MODIFIED: typing.Final = 1
    COMPOSITE_UNMODIFIED: typing.Final = 2
    COMPOSITE_LOADED: typing.Final = 3
    NO_COMPOSITE_LOADED: typing.Final = 4
    EDIT_STARTED: typing.Final = 5
    EDIT_ENDED: typing.Final = 6

    def compositeEditStateChanged(self, type: typing.Union[jpype.JInt, int]):
        """
        Called whenever the data composite edit state changes.
        Examples:
        
        Whether or not the composite being edited has been
        modified from the original.
        
        Whether or not a composite is loaded in the model.
        
        :param jpype.JInt or int type: the type of state change: COMPOSITE_MODIFIED, COMPOSITE_UNMODIFIED,
        COMPOSITE_LOADED, NO_COMPOSITE_LOADED, EDIT_STARTED, EDIT_ENDED.
        """

    def endFieldEditing(self):
        """
        Called when the model wants to end cell editing that is in progress.
        This is due to an attempt to modify the composite data type in the
        editor while the model's field edit state indicates a field is being
        edited. It is up to the application to determine whether to cancel or 
        apply the field edits.
        """

    def showUndefinedStateChanged(self, showUndefinedBytes: typing.Union[jpype.JBoolean, bool]):
        """
        Called whenever the composite data type editor state changes for whether or not
        to show undefined bytes in the editor.
        
        :param jpype.JBoolean or bool showUndefinedBytes: true if undefined bytes should be displayed in the editor
        """


class CompositeEditorActionManager(java.lang.Object):
    """
    A CompositeEditorActionManager manages the actions for a single composite editor.
    By default it provides actions for favorites and cycle groups.
    Other CompositeEditorActions can be added for it to manage.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        """
        Constructor
         
        NOTE: After constructing a manager, you must call setEditorModel() 
        and setParentComponent() for the actions to work.
        
        :param CompositeEditorProvider[typing.Any, typing.Any] provider: the provider that owns this composite editor action manager
        favorites and cycle groups.
        """

    def addEditorActionListener(self, listener: EditorActionListener):
        """
        Adds a listener that wants notification of actions being added or removed.
        
        :param EditorActionListener listener: the editor action listener to be notified
        """

    def getAllActions(self) -> jpype.JArray[CompositeEditorTableAction]:
        """
        Gets all composite editor actions that are currently added to this 
        action manager. This includes the favorites and cycle groups actions.
        
        :return: all composite editor actions
        :rtype: jpype.JArray[CompositeEditorTableAction]
        """

    def getCycleGroupActions(self) -> jpype.JArray[CompositeEditorTableAction]:
        """
        Gets the favorites actions that the manager created by default.
        
        :return: the favorites actions
        :rtype: jpype.JArray[CompositeEditorTableAction]
        """

    def getEditorActions(self) -> jpype.JArray[CompositeEditorTableAction]:
        """
        Gets the composite editor actions that are currently added to this 
        action manager. The favorites and cycle groups actions that the 
        manager created by default are not part of the actions returned.
        
        :return: the composite editor actions
        :rtype: jpype.JArray[CompositeEditorTableAction]
        """

    def getFavoritesActions(self) -> jpype.JArray[CompositeEditorTableAction]:
        """
        Gets the cycle group actions that the manager created by default.
        
        :return: the cycle group actions
        :rtype: jpype.JArray[CompositeEditorTableAction]
        """

    def getNamedAction(self, actionName: typing.Union[java.lang.String, str]) -> CompositeEditorTableAction:
        """
        Gets the named composite editor action if it exists.
        
        :param java.lang.String or str actionName: the name of the action to find.
        :return: the action or null
        :rtype: CompositeEditorTableAction
        """

    def removeEditorActionListener(self, listener: EditorActionListener):
        """
        Removes a listener that wanted notification of actions being added or removed.
        
        :param EditorActionListener listener: the editor action listener that was being notified
        """

    def setEditorActions(self, actions: jpype.JArray[CompositeEditorTableAction]):
        """
        Sets the composite editor actions to those in the array.
        The manager will still also manage the favorites and cycle group actions.
        Any previously set composite editor actions are removed before 
        setting the new actions.
        
        :param jpype.JArray[CompositeEditorTableAction] actions: the composite editor actions.
        """

    @property
    def cycleGroupActions(self) -> jpype.JArray[CompositeEditorTableAction]:
        ...

    @property
    def editorActions(self) -> jpype.JArray[CompositeEditorTableAction]:
        ...

    @editorActions.setter
    def editorActions(self, value: jpype.JArray[CompositeEditorTableAction]):
        ...

    @property
    def allActions(self) -> jpype.JArray[CompositeEditorTableAction]:
        ...

    @property
    def namedAction(self) -> CompositeEditorTableAction:
        ...

    @property
    def favoritesActions(self) -> jpype.JArray[CompositeEditorTableAction]:
        ...


class CompositeViewerModelListener(java.lang.Object):
    """
    Composite Viewer Model change listener interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def componentDataChanged(self):
        """
        Called whenever the composite's component data is changed.
        """

    def compositeInfoChanged(self):
        """
        Called whenever the composite's non-component data is changed.
        For example, the composite's name, description, size, ...
        """

    def selectionChanged(self):
        """
        Called to indicate the model's component selection has changed.
        """

    def statusChanged(self, message: typing.Union[java.lang.String, str], beep: typing.Union[jpype.JBoolean, bool]):
        """
        Notification that the CompositeViewerModel's status information has changed.
        
        :param java.lang.String or str message: the information to provide to the user.
        :param jpype.JBoolean or bool beep: true indicates an audible beep is suggested.
        """


class SearchControlPanel(javax.swing.JPanel):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, editorPanel: CompositeEditorPanel[typing.Any, typing.Any]):
        ...

    def getTextField(self) -> javax.swing.JTextField:
        ...

    @property
    def textField(self) -> javax.swing.JTextField:
        ...


class CompositeEditorModelAdapter(CompositeEditorModelListener):
    """
    Adapter for a composite editor model listener.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class CompositeViewerModel(javax.swing.table.AbstractTableModel, ghidra.program.model.data.DataTypeManagerChangeListener, typing.Generic[T]):
    """
    :obj:`CompositeViewerModel` provides the base composite viewer/editor implementation
    """

    class_: typing.ClassVar[java.lang.Class]

    def addCompositeViewerModelListener(self, listener: CompositeViewerModelListener):
        """
        Adds a CompositeViewerModelListener to be notified when model changes occur
        
        :param CompositeViewerModelListener listener: the listener
        """

    def clearStatus(self):
        """
        Clears the current status string.
        """

    def displayNumbersInHex(self, showHex: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether or not the editor displays numeric values in hexadecimal.
        
        :param jpype.JBoolean or bool showHex: true means show in hexadecimal. false means show in decimal
        """

    def getColumn(self) -> int:
        """
        Gets the current column
        
        :return: the current column
        :rtype: int
        """

    def getColumnClass(self, columnIndex: typing.Union[jpype.JInt, int]) -> java.lang.Class[typing.Any]:
        """
        Returns ``String.class`` regardless of ``columnIndex``.
        
        :param jpype.JInt or int columnIndex: the column being queried
        :return: the String.class
        :rtype: java.lang.Class[typing.Any]
        """

    def getColumnCount(self) -> int:
        """
        Returns the number of columns (display fields) for each component in this structure or
        union.
        
        :return: the number of display fields for each component
        :rtype: int
        """

    def getColumnName(self, columnIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        Return a header name for the indicated column.
        
        :param jpype.JInt or int columnIndex: the index number indicating the component field (column) to get the
        header for.
        """

    def getCommentColumn(self) -> int:
        ...

    def getComponent(self, rowIndex: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.DataTypeComponent:
        """
        Return the nth component for the structure being viewed. Since the number of rows can exceed
        the number of components defined within the composite (:meth:`Composite.getNumComponents() <Composite.getNumComponents>`)
        this method will return null for a blank row.
        
        :param jpype.JInt or int rowIndex: the index of the component to return. First component is index of 0
        :return: the component
        :rtype: ghidra.program.model.data.DataTypeComponent
        """

    def getDataTypeColumn(self) -> int:
        ...

    def getDescription(self) -> str:
        """
        Return the description for the structure being viewed
        
        :return: the description
        :rtype: str
        """

    def getFieldName(self, columnIndex: typing.Union[jpype.JInt, int]) -> str:
        """
        Return a header name for the indicated field (column)
        
        :param jpype.JInt or int columnIndex: the index number indicating the component field (column) to get the
        header for
        :return: the name
        :rtype: str
        """

    def getFieldWidth(self, columnIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the display width of the component field at the specified column index.
        
        :param jpype.JInt or int columnIndex: the field index within the component
        :return: the width of the component field
        :rtype: int
        """

    @staticmethod
    def getHexString(offset: typing.Union[jpype.JInt, int], showPrefix: typing.Union[jpype.JBoolean, bool]) -> str:
        ...

    def getLeftMargin(self) -> int:
        """
        Return the size of the left margin for the component viewing area
        
        :return: the margin
        :rtype: int
        """

    def getLength(self) -> int:
        """
        Return the size of the structure being viewed in bytes
        
        :return: this size
        :rtype: int
        """

    def getLengthAsString(self) -> str:
        """
        Return the size of the structure being viewed in bytes as a hex or decimal string depending
        on the model's current display setting for numbers
        
        :return: the length
        :rtype: str
        """

    def getLengthColumn(self) -> int:
        ...

    def getMinIndexSelected(self) -> int:
        """
        Gets the minimum row index that is selected or -1 if no index is selected.
        
        :return: the index
        :rtype: int
        """

    def getMnemonicColumn(self) -> int:
        ...

    def getNameColumn(self) -> int:
        ...

    def getNumComponents(self) -> int:
        """
        Returns the number of components in this structure or union.
        
        :return: the number of components in the model
        :rtype: int
        """

    def getNumFields(self) -> int:
        """
        Returns the number of display fields for this structure or union.
        
        :return: the number of display fields for each component
        :rtype: int
        """

    def getNumSelectedComponentRows(self) -> int:
        """
        Returns the number of component rows currently selected.
         
         
        Note: This only includes rows that are actually components.
        
        :return: the selected row count
        :rtype: int
        """

    def getNumSelectedRows(self) -> int:
        """
        Returns the number of rows currently selected.
         
         
        Note: In unlocked mode this can include the additional blank line.
        
        :return: the selected row count
        :rtype: int
        """

    def getOffsetColumn(self) -> int:
        ...

    def getOriginalCategory(self) -> ghidra.program.model.data.Category:
        """
        Return the original category for the composite data type being viewed
        
        :return: the category
        :rtype: ghidra.program.model.data.Category
        """

    def getOriginalCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        """
        Return the path of the data category for the structure being viewed
        
        :return: the path
        :rtype: ghidra.program.model.data.CategoryPath
        """

    def getOriginalDataTypeName(self) -> str:
        """
        Returns the original name of the CompositeDataType being viewed
        
        :return: the name
        :rtype: str
        """

    def getOriginalDataTypePath(self) -> ghidra.program.model.data.DataTypePath:
        """
        Determines the full path name for the composite data type based on the original composite
        and original category.
        
        :return: the full path name
        :rtype: ghidra.program.model.data.DataTypePath
        """

    def getRow(self) -> int:
        """
        Gets the current row
        
        :return: the current row
        :rtype: int
        """

    def getRowCount(self) -> int:
        """
        Returns the number of component rows in the viewer. There may be a blank row at the end for
        selecting. Therefore this number can be different than the actual number of components
        currently in the structure being viewed.
        
        :return: the number of rows in the model
        :rtype: int
        """

    def getSelection(self) -> docking.widgets.fieldpanel.support.FieldSelection:
        """
        Returns a copy of the model's current field selection
        
        :return: the selection
        :rtype: docking.widgets.fieldpanel.support.FieldSelection
        """

    def getStatus(self) -> str:
        """
        Returns the current status string.
        
        :return: the status
        :rtype: str
        """

    def getTypeName(self) -> str:
        """
        Returns the current dataType name (Structure, Union, etc.) as a string.
        
        :return: the type of composite being edited
        :rtype: str
        """

    def getWidth(self) -> int:
        """
        Gets the component display field area's total width
        
        :return: the total width of the component field area
        :rtype: int
        """

    def hasComponentSelection(self) -> bool:
        """
        Returns true if the GUI has a component row selected
        
        :return: true if there is a selection
        :rtype: bool
        """

    def hasSelection(self) -> bool:
        """
        Returns true if the GUI has a table row selected
        
        :return: true if there is a selection
        :rtype: bool
        """

    def isCellEditable(self, rowIndex: typing.Union[jpype.JInt, int], columnIndex: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns whether or not a particular component row and field in this structure is editable
        
        :param jpype.JInt or int rowIndex: index for the row (component within this structure).
        :param jpype.JInt or int columnIndex: index for the column (field of the component within this structure).
        """

    def isContiguousSelection(self) -> bool:
        """
        Returns true if the component list selection is contiguous.
        
        :return: true if contiguous
        :rtype: bool
        """

    def isLoaded(self) -> bool:
        """
        Returns whether or not the editor has a structure loaded.  If no structure is loaded then
        only unload() or dispose() methods should be called.
        
        :return: true if an editable structure is currently loaded in the model.
        :rtype: bool
        """

    def isShowingNumbersInHex(self) -> bool:
        """
        Returns whether or not the editor is displaying numbers in hex
        
        :return: true if hex
        :rtype: bool
        """

    def isSingleComponentRowSelection(self) -> bool:
        """
        Returns true if the component list selection is a single component.
        
        :return: true if the component list selection is a single component
        :rtype: bool
        """

    def removeCompositeViewerModelListener(self, listener: CompositeViewerModelListener):
        """
        Removes a CompositeViewerModelListener that was being notified when model changes occur
        
        :param CompositeViewerModelListener listener: the listener
        """

    def setColumn(self, column: typing.Union[jpype.JInt, int]):
        """
        Sets the current column to the indicated column
        
        :param jpype.JInt or int column: the new column
        """

    def setRow(self, row: typing.Union[jpype.JInt, int]):
        """
        Sets the current row to the indicated row
        
        :param jpype.JInt or int row: the new row
        """

    @typing.overload
    def setStatus(self, status: typing.Union[java.lang.String, str]):
        """
        Sets the current status string.
        
        :param java.lang.String or str status: the status message
        """

    @typing.overload
    def setStatus(self, status: typing.Union[java.lang.String, str], beep: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the current status string and performs notification to all listeners.
        
        :param java.lang.String or str status: the status message
        :param jpype.JBoolean or bool beep: true indicates an audible beep should sound when the message is displayed
        """

    @property
    def originalDataTypePath(self) -> ghidra.program.model.data.DataTypePath:
        ...

    @property
    def fieldWidth(self) -> jpype.JInt:
        ...

    @property
    def mnemonicColumn(self) -> jpype.JInt:
        ...

    @property
    def fieldName(self) -> java.lang.String:
        ...

    @property
    def showingNumbersInHex(self) -> jpype.JBoolean:
        ...

    @property
    def minIndexSelected(self) -> jpype.JInt:
        ...

    @property
    def typeName(self) -> java.lang.String:
        ...

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def numSelectedComponentRows(self) -> jpype.JInt:
        ...

    @property
    def loaded(self) -> jpype.JBoolean:
        ...

    @property
    def nameColumn(self) -> jpype.JInt:
        ...

    @property
    def originalDataTypeName(self) -> java.lang.String:
        ...

    @property
    def commentColumn(self) -> jpype.JInt:
        ...

    @property
    def rowCount(self) -> jpype.JInt:
        ...

    @property
    def row(self) -> jpype.JInt:
        ...

    @row.setter
    def row(self, value: jpype.JInt):
        ...

    @property
    def numSelectedRows(self) -> jpype.JInt:
        ...

    @property
    def numFields(self) -> jpype.JInt:
        ...

    @property
    def originalCategoryPath(self) -> ghidra.program.model.data.CategoryPath:
        ...

    @property
    def leftMargin(self) -> jpype.JInt:
        ...

    @property
    def singleComponentRowSelection(self) -> jpype.JBoolean:
        ...

    @property
    def dataTypeColumn(self) -> jpype.JInt:
        ...

    @property
    def contiguousSelection(self) -> jpype.JBoolean:
        ...

    @property
    def length(self) -> jpype.JInt:
        ...

    @property
    def column(self) -> jpype.JInt:
        ...

    @column.setter
    def column(self, value: jpype.JInt):
        ...

    @property
    def lengthAsString(self) -> java.lang.String:
        ...

    @property
    def lengthColumn(self) -> jpype.JInt:
        ...

    @property
    def columnCount(self) -> jpype.JInt:
        ...

    @property
    def component(self) -> ghidra.program.model.data.DataTypeComponent:
        ...

    @property
    def columnClass(self) -> java.lang.Class[typing.Any]:
        ...

    @property
    def selection(self) -> docking.widgets.fieldpanel.support.FieldSelection:
        ...

    @property
    def width(self) -> jpype.JInt:
        ...

    @property
    def originalCategory(self) -> ghidra.program.model.data.Category:
        ...

    @property
    def offsetColumn(self) -> jpype.JInt:
        ...

    @property
    def status(self) -> java.lang.String:
        ...

    @status.setter
    def status(self, value: java.lang.String):
        ...

    @property
    def numComponents(self) -> jpype.JInt:
        ...

    @property
    def columnName(self) -> java.lang.String:
        ...


class CompositeModelStatusListener(java.lang.Object):
    """
    Composite Viewer Model status information change listener interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def statusChanged(self, message: typing.Union[java.lang.String, str], beep: typing.Union[jpype.JBoolean, bool]):
        """
        Notification that the CompositeViewerModel's status information has changed.
        
        :param java.lang.String or str message: the information to provide to the user.
        :param jpype.JBoolean or bool beep: true indicates an audible beep is suggested.
        """


class DndTableCellRenderer(javax.swing.table.TableCellRenderer):

    class DndBorder(javax.swing.border.AbstractBorder):

        class_: typing.ClassVar[java.lang.Class]
        TOP: typing.Final = 1
        RIGHT: typing.Final = 2
        BOTTOM: typing.Final = 4
        LEFT: typing.Final = 8
        ALL: typing.Final = 15

        def __init__(self, borders: typing.Union[jpype.JInt, int], thickness: typing.Union[jpype.JInt, int], color: java.awt.Color, under: javax.swing.border.Border):
            ...

        def addBorders(self, border: typing.Union[jpype.JInt, int]):
            ...

        def clrBorders(self):
            ...

        def delBorders(self, border: typing.Union[jpype.JInt, int]):
            ...

        def getColor(self) -> java.awt.Color:
            ...

        def getUnderBorder(self) -> javax.swing.border.Border:
            ...

        def setColor(self, color: java.awt.Color):
            ...

        def setUnderBorder(self, under: javax.swing.border.Border):
            ...

        @property
        def color(self) -> java.awt.Color:
            ...

        @color.setter
        def color(self, value: java.awt.Color):
            ...

        @property
        def underBorder(self) -> javax.swing.border.Border:
            ...

        @underBorder.setter
        def underBorder(self, value: javax.swing.border.Border):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, orig: javax.swing.table.TableCellRenderer, table: javax.swing.JTable):
        ...

    def getBorderColor(self) -> java.awt.Color:
        ...

    def selectRange(self, isInsert: typing.Union[jpype.JBoolean, bool]):
        """
        
        
        :param jpype.JBoolean or bool isInsert: true indicates that only the top of the row is highlighted for feedback.
        false indicates that the entire selection should be bordered on all sides.
        """

    def setBorderColor(self, color: java.awt.Color):
        ...

    def setRowForFeedback(self, row: typing.Union[jpype.JInt, int]) -> bool:
        ...

    @property
    def borderColor(self) -> java.awt.Color:
        ...

    @borderColor.setter
    def borderColor(self, value: java.awt.Color):
        ...


class DuplicateMultipleAction(CompositeEditorTableAction):
    """
    Action that allows the user to make multiple duplicates of the selected item
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Duplicate Multiple of Component"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class ClearAction(CompositeEditorTableAction):

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Clear Components"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class CompositeModelSelectionListener(java.lang.Object):
    """
    Composite Viewer Model component selection change listener interface.
    """

    class_: typing.ClassVar[java.lang.Class]

    def selectionChanged(self):
        """
        Called to indicate the model's component selection has changed.
        """


class EditComponentAction(CompositeEditorTableAction):
    """
    Action for use in the composite data type editor.
    This action has help associated with it.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Edit Component"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class ComponentContext(java.lang.Object):
    """
    ``ComponentContext`` provides a selected component context when editing a structure/union
    """

    class_: typing.ClassVar[java.lang.Class]

    def getCompositeDataType(self) -> ghidra.program.model.data.Composite:
        """
        Get the editor's selected component's parent composite (structure or union)
        
        :return: editor's selected component's parent composite
        :rtype: ghidra.program.model.data.Composite
        """

    def getDataTypeComponent(self) -> ghidra.program.model.data.DataTypeComponent:
        """
        Get the editor's selected component
        
        :return: editor's selected component
        :rtype: ghidra.program.model.data.DataTypeComponent
        """

    def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        """
        Get editor's data type manager
        
        :return: editor's datatype manager
        :rtype: ghidra.program.model.data.DataTypeManager
        """

    @property
    def compositeDataType(self) -> ghidra.program.model.data.Composite:
        ...

    @property
    def dataTypeComponent(self) -> ghidra.program.model.data.DataTypeComponent:
        ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        ...


class UndoChangeAction(CompositeEditorTableAction):
    """
    :obj:`UndoChangeAction` facilitates an undo of recent composite editor changes.
    """

    class_: typing.ClassVar[java.lang.Class]
    DESCRIPTION: typing.ClassVar[java.lang.String]
    ACTION_NAME: typing.Final = "Undo Editor Change"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class DataTypeHelper(java.lang.Object):
    """
    DataTypeHelper is a helper class for dealing with data types in the Composite
    Data Type Editor (Structure or Union Editor). It provides static methods for 
    use with the data type text field in the editor.
    It also has a static method to prompt the user for the size of a data type.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getBaseType(dt: ghidra.program.model.data.DataType) -> ghidra.program.model.data.DataType:
        ...

    @staticmethod
    def getFixedLength(model: CompositeEditorModel[typing.Any], index: typing.Union[jpype.JInt, int], dt: ghidra.program.model.data.DataType, useAlignedLength: typing.Union[jpype.JBoolean, bool]) -> ghidra.program.model.data.DataTypeInstance:
        """
        Creates a fixed length data type from the one that is passed in.
        The user is prompted for a size, if the data type doesn't have a size.
        The valid size depends upon the current editor state and the component
        index where it will be located. If the data type is a valid size, it
        will be returned unchanged. If the user cancels from the size dialog,
        then a null is returned.
        
        :param CompositeEditorModel[typing.Any] model: The composite editor model
        :param jpype.JInt or int index: the component index of where to add the data type.
        :param ghidra.program.model.data.DataType dt: the data type to add
        :param jpype.JBoolean or bool useAlignedLength: if true a fixed-length primitive data type will use its 
        :meth:`aligned-length <DataType.getAlignedLength>`, otherwise it will use its
        :meth:`raw length <DataType.getLength>`.
        :return: the data type and its size or null if the user canceled when 
        prompted for a size.
        :rtype: ghidra.program.model.data.DataTypeInstance
        """

    @staticmethod
    def parseDataType(index: typing.Union[jpype.JInt, int], dtValue: typing.Union[java.lang.String, str], editModel: CompositeEditorModel[typing.Any], dtManager: ghidra.program.model.data.DataTypeManager, dtmService: ghidra.app.services.DataTypeManagerService) -> ghidra.program.model.data.DataType:
        """
        Parses a data type that was typed in the composite data type editor.
        It creates a DataTypeInstance that consists of the data type and its size.
        If there are multiple of the named data type, this method will ask the
        user to select the desired data type.
        If the data type size can't be determined, then the user is prompted for
        the appropriate size.
        
        :param jpype.JInt or int index: the component index being edited.
        :param java.lang.String or str dtValue: the new data type to parse.
        :param CompositeEditorModel[typing.Any] editModel: the model indicating the composite editor's state.
        :param ghidra.program.model.data.DataTypeManager dtManager: the data type manager of the composite data type being edited.
        :param ghidra.app.services.DataTypeManagerService dtmService: the data type manager service to use to determine the
        data type the user specified.
        :return: the data type instance or null if the user canceled when prompted 
        for more information.
        :rtype: ghidra.program.model.data.DataType
        :raises InvalidDataTypeException: if the specified data type isn't valid.
        :raises UsrException: if the specified data type can't be used at the 
        specified index in the composite.
        """

    @staticmethod
    def requestBytes(model: CompositeEditorModel[typing.Any], dt: ghidra.program.model.data.DataType, maxBytes: typing.Union[jpype.JInt, int]) -> ghidra.program.model.data.DataTypeInstance:
        ...

    @staticmethod
    def requestDtSize(provider: CompositeEditorProvider[typing.Any, typing.Any], dtName: typing.Union[java.lang.String, str], defaultSize: typing.Union[jpype.JInt, int], maxBytes: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    def stripWhiteSpace(original: typing.Union[java.lang.String, str]) -> str:
        """
        Method stripWhiteSpace removes all blanks and control characters from
        the original string.
        
        :param java.lang.String or str original: the original string
        :return: String the string with blanks and control characters removed.
        :rtype: str
        """


@typing.type_check_only
class OriginalCompositeListener(java.lang.Object):
    """
    Original Composite change listener interface.
    This has a notification method for notification that the composite data 
    editor has closed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def originalCategoryChanged(self, newPath: ghidra.program.model.data.CategoryPath):
        """
        
        
        :param ghidra.program.model.data.CategoryPath newPath: the new name for the original category where the 
        edited data type is to be applied.
        """

    def originalComponentsChanged(self):
        ...

    def originalNameChanged(self, newName: typing.Union[java.lang.String, str]):
        """
        
        
        :param java.lang.String or str newName: the new name for the original data type being edited.
        """


class HexNumbersAction(CompositeEditorTableAction, docking.action.ToggleDockingActionIf):
    """
    Action for use in the composite data type editor.
    This action has help associated with it.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Show Numbers In Hex"

    def __init__(self, provider: CompositeEditorProvider[typing.Any, typing.Any]):
        ...


class ComponentProgramActionContext(ghidra.app.context.ProgramActionContext, ComponentContext):
    """
    ``ComponentProgramActionContext`` provides an action context when editing a 
    composite with a single selected component, and the composite is associated with a program.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, compositeEditorProvider: CompositeEditorProvider[typing.Any, typing.Any], program: ghidra.program.model.listing.Program, component: ghidra.program.model.data.DataTypeComponent):
        ...


@typing.type_check_only
class StructureEditorModel(CompEditorModel[ghidra.program.model.data.Structure]):

    class_: typing.ClassVar[java.lang.Class]

    def getMaxAddLength(self, rowIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the maximum number of bytes available for a data type that is added at the indicated
        index. This can vary based on whether or not it is in a selection.
         
        In unlocked mode, the size is unrestricted when no selection or single row selection.
        Multi-row selection always limits the size.
         
        In locked mode, single row selection is limited to selected row plus undefined bytes
        following it that can be absorbed.
        
        :param jpype.JInt or int rowIndex: index of the row in the editor's composite data type table.
        :return: the max length or -1 for no limit.
        :rtype: int
        """

    def getMaxReplaceLength(self, currentIndex: typing.Union[jpype.JInt, int]) -> int:
        """
        Gets the maximum number of bytes available for a new data type that
        will replace the current data type at the indicated index.
        If there isn't a component with the indicated index, the max length
        will be determined by the lock mode.
        
        :param jpype.JInt or int currentIndex: index of the component in the structure.
        :return: the maximum number of bytes that can be replaced.
        :rtype: int
        """

    def getRowCount(self) -> int:
        """
        Returns the number of component rows in the viewer. There may be a
        blank row at the end for selecting. Therefore this number can be
        different than the actual number of components currently in the
        structure being viewed.
        
        :return: the number of rows in the model
        :rtype: int
        """

    def getValueAt(self, rowIndex: typing.Union[jpype.JInt, int], columnIndex: typing.Union[jpype.JInt, int]) -> java.lang.Object:
        """
        Returns an attribute value for the cell at *columnIndex*
        and *rowIndex*.
        
        :param jpype.JInt or int rowIndex: the row whose value is to be looked up
        :param jpype.JInt or int columnIndex: the column whose value is to be looked up
        :return: the value Object at the specified cell
        :rtype: java.lang.Object
        """

    def isAddAllowed(self, currentIndex: typing.Union[jpype.JInt, int], datatype: ghidra.program.model.data.DataType) -> bool:
        """
        Returns whether or not addition of the specified component is allowed
        at the specified index. the addition could be an insert or replace as
        determined by the state of the edit model.
        
        :param jpype.JInt or int currentIndex: index of the component in the structure.
        :param ghidra.program.model.data.DataType datatype: the data type to be inserted.
        """

    def isArrayAllowed(self) -> bool:
        """
        Returns whether or not the selection
        is allowed to be changed into an array.
        """

    def isInsertAllowed(self, currentIndex: typing.Union[jpype.JInt, int], datatype: ghidra.program.model.data.DataType) -> bool:
        """
        Returns whether or not insertion of the specified component is allowed
        at the specified index.
        
        :param jpype.JInt or int currentIndex: index of the component in the structure.
        :param ghidra.program.model.data.DataType datatype: the data type to be inserted.
        """

    def unpackage(self, rowIndex: typing.Union[jpype.JInt, int], monitor: ghidra.util.task.TaskMonitor):
        """
        Unpackage the selected component in the structure or array. This means replace the structure
        with the data types for its component parts. For an array replace the array with the data type
        for each array element.
        If the component isn't a structure or union then returns false.
        
        :param jpype.JInt or int rowIndex: the row
        :param ghidra.util.task.TaskMonitor monitor: the task monitor
        :raises UsrException: if the component can't be unpackaged.
        """

    @property
    def arrayAllowed(self) -> jpype.JBoolean:
        ...

    @property
    def maxAddLength(self) -> jpype.JInt:
        ...

    @property
    def rowCount(self) -> jpype.JInt:
        ...

    @property
    def maxReplaceLength(self) -> jpype.JInt:
        ...


class CompositeEditorPanel(javax.swing.JPanel, CompositeEditorModelListener, ComponentCellEditorListener, docking.dnd.Droppable, typing.Generic[T, M]):
    """
    Panel for editing a composite data type. Specific composite data type editors
    should extend this class.
    This provides a table with cell edit functionality and drag and drop capability.
    Below the table is an information area for non-component information about the
    composite data type. To add your own info panel override the createInfoPanel() method.
    """

    @typing.type_check_only
    class ComponentStringCellEditor(ComponentCellEditor):

        class_: typing.ClassVar[java.lang.Class]

        @typing.overload
        def __init__(self, textField: javax.swing.JTextField):
            ...

        @typing.overload
        def __init__(self):
            ...


    @typing.type_check_only
    class ComponentOffsetCellEditor(CompositeEditorPanel.ComponentStringCellEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def stopCellEditing(self) -> bool:
            """
            Calls ``fireEditingStopped`` and returns true.
            
            :return: true
            :rtype: bool
            """


    @typing.type_check_only
    class ComponentNameCellEditor(CompositeEditorPanel.ComponentStringCellEditor):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class ComponentDataTypeCellEditor(javax.swing.AbstractCellEditor, javax.swing.table.TableCellEditor, docking.widgets.table.FocusableEditor):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CompositeTableMouseListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CompositeEditorTable(docking.widgets.table.GTable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, model: javax.swing.table.TableModel):
            ...


    @typing.type_check_only
    class CompFocusTraversalPolicy(java.awt.FocusTraversalPolicy):
        """
        A simple traversal policy that allows this editor panel to control the order that components
        get focused when pressing Tab and Shift-Tab.
         
        
        Note: We typically do not use traversal policies in the application.  We do so here due to 
        the complicated nature of this widget.  It seemed easier to specify the policy than to 
        change the order of the widgets in the UI to get the expected traversal order.
         
        
        Note: This widget is a bit unusual in that not all focusable components are traversable using
        Tab and Shift-Tab.  Specifically, the radio button groups will only have one entry in the 
        list of traversal components.  Once one of the radio buttons is focused, the up and down 
        arrow keys can be used to navigate the radio buttons.  With this traversal policy, pressing 
        Tab when on these buttons will move to the next traversal component.
        
        
        .. seealso::
        
            | :obj:`.getFocusComponents()`
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, model: M, provider: CompositeEditorProvider[T, M]):
        ...

    def addAtPoint(self, p: java.awt.Point, dt: ghidra.program.model.data.DataType):
        """
        Add the object to the droppable component. The DragSrcAdapter calls this method from its
        drop() method.
        
        :param java.awt.Point p: the point of insert
        :param ghidra.program.model.data.DataType dt: the data type to insert
        """

    def addEditorModelListener(self, listener: CompositeEditorModelListener):
        ...

    def compositeEditStateChanged(self, type: typing.Union[jpype.JInt, int]):
        """
        CompositeEditorModelListener method called to handle lock/unlock or
        structure modification state change.
        This could also get called by a structure load or unload.
        
        :param jpype.JInt or int type: the type of state change: COMPOSITE_MODIFIED, COMPOSITE_UNMODIFIED,
        COMPOSITE_LOADED, NO_COMPOSITE_LOADED.
        """

    def dispose(self):
        ...

    def dragUnderFeedback(self, ok: typing.Union[jpype.JBoolean, bool], e: java.awt.dnd.DropTargetDragEvent):
        """
        Called from the DropTgtAdapter when the drag operation
        is going over a drop site; indicate when the drop is ok
        by providing appropriate feedback.
        
        :param jpype.JBoolean or bool ok: true means ok to drop
        """

    def getTable(self) -> javax.swing.JTable:
        ...

    def insertAtPoint(self, p: java.awt.Point, dt: ghidra.program.model.data.DataType):
        """
        Add the object to the droppable component. The DragSrcAdapter calls this method from its
        drop() method.
        
        :param java.awt.Point p: the point of insert
        :param ghidra.program.model.data.DataType dt: the data type to insert
        """

    def moveCellEditor(self, direction: typing.Union[jpype.JInt, int], value: typing.Union[java.lang.String, str]):
        """
        BEGIN ComponentCellEditorListener methods
        """

    def removeEditorModelListener(self, listener: CompositeEditorModelListener):
        ...

    def selectField(self, fieldName: typing.Union[java.lang.String, str]):
        """
        Select the field by the given name in this panel's table.
        
        :param java.lang.String or str fieldName: the field name
        """

    def setStatus(self, status: typing.Union[java.lang.String, str]):
        """
        Sets the currently displayed status message.
        
        :param java.lang.String or str status: non-html message string to be displayed.
        """

    def undoDragUnderFeedback(self):
        """
        Called from the DropTgtAdapter to revert any feedback
        changes back to normal.
        """

    @property
    def table(self) -> javax.swing.JTable:
        ...


class EditorModelListener(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]
    EDIT_STARTED: typing.Final = 5
    EDIT_ENDED: typing.Final = 6

    def editStateChanged(self, type: typing.Union[jpype.JInt, int]):
        ...


class UnpackageAction(CompositeEditorTableAction):
    """
    Action for use in the composite data type editor.
    This action has help associated with it.
    """

    class_: typing.ClassVar[java.lang.Class]
    ACTION_NAME: typing.Final = "Unpackage Component"

    def __init__(self, provider: StructureEditorProvider):
        ...


class EditorProvider(java.lang.Object):
    """
    Interface implemented by data type editors.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addEditorListener(self, listener: EditorListener):
        """
        Add an editor listener that will be notified when the edit window is closed.
        
        :param EditorListener listener: the listener
        """

    def checkForSave(self, allowCancel: typing.Union[jpype.JBoolean, bool]) -> bool:
        """
        Prompt the user if this editor has changes that need saving.
        
        :param jpype.JBoolean or bool allowCancel: true means that the user can cancel the edits
        :return: true if the user doesn't cancel.
        :rtype: bool
        """

    def dispose(self):
        """
        Dispose of resource that this editor may be using.
        """

    def getComponentProvider(self) -> docking.ComponentProvider:
        """
        Get the component provider for this editor.
        
        :return: the component provider for this editor
        :rtype: docking.ComponentProvider
        """

    def getDataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        """
        :return: the edited datatype's original datatype manager.
        :rtype: ghidra.program.model.data.DataTypeManager
        """

    def getDtPath(self) -> ghidra.program.model.data.DataTypePath:
        """
        Get the pathname of the data type being edited.
        
        :return: the pathname of the data type being edited
        :rtype: ghidra.program.model.data.DataTypePath
        """

    def getName(self) -> str:
        """
        Get the name of this editor.
        
        :return: the name of this editor
        :rtype: str
        """

    def isEditing(self, dtPath: ghidra.program.model.data.DataTypePath) -> bool:
        """
        Return whether this editor is editing the data type with the given path.
        
        :param ghidra.program.model.data.DataTypePath dtPath: path of a data type
        :return: true if the data type for the pathname is being edited
        :rtype: bool
        """

    def needsSave(self) -> bool:
        """
        Returns whether changes need to be saved.
        
        :return: whether changes need to be saved
        :rtype: bool
        """

    def show(self):
        """
        Show the editor.
        """

    @property
    def name(self) -> java.lang.String:
        ...

    @property
    def dtPath(self) -> ghidra.program.model.data.DataTypePath:
        ...

    @property
    def componentProvider(self) -> docking.ComponentProvider:
        ...

    @property
    def dataTypeManager(self) -> ghidra.program.model.data.DataTypeManager:
        ...

    @property
    def editing(self) -> jpype.JBoolean:
        ...



__all__ = ["ComponentStandAloneActionContext", "RedoChangeAction", "IDMapDB", "DuplicateAction", "ComponentCellEditorListener", "CycleGroupAction", "CompositeChangeListener", "EditFieldAction", "CompositeViewerDataTypeManager", "CreateInternalStructureAction", "ShowComponentPathAction", "PointerAction", "ShowDataTypeInTreeAction", "EditBitFieldAction", "CompositeEditorLockListener", "FavoritesAction", "BitFieldPlacementComponent", "CompEditorPanel", "StructureEditorProvider", "DataTypeCellRenderer", "CompositeEditorProvider", "UnionEditorPanel", "UnionEditorModel", "CompEditorModel", "ApplyAction", "EditorListener", "BitFieldEditorPanel", "MoveUpAction", "InsertUndefinedAction", "BitFieldEditorDialog", "ComponentCellEditor", "FindReferencesToStructureFieldAction", "MoveDownAction", "CompositeEditorModel", "DeleteAction", "StructureEditorPanel", "EditorActionListener", "UnionEditorProvider", "ArrayAction", "CompositeEditorTableAction", "CompositeModelDataListener", "AddBitFieldAction", "CompositeEditorModelListener", "CompositeEditorActionManager", "CompositeViewerModelListener", "SearchControlPanel", "CompositeEditorModelAdapter", "CompositeViewerModel", "CompositeModelStatusListener", "DndTableCellRenderer", "DuplicateMultipleAction", "ClearAction", "CompositeModelSelectionListener", "EditComponentAction", "ComponentContext", "UndoChangeAction", "DataTypeHelper", "OriginalCompositeListener", "HexNumbersAction", "ComponentProgramActionContext", "StructureEditorModel", "CompositeEditorPanel", "EditorModelListener", "UnpackageAction", "EditorProvider"]
