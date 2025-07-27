from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import docking.widgets.table.threaded
import ghidra.framework.model
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.util
import ghidra.util.datastruct
import ghidra.util.table
import ghidra.util.table.column
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing.table # type: ignore


T = typing.TypeVar("T")


class QuckFixTableProvider(docking.ComponentProvider):
    """
    Component Provider for displaying lists of :obj:`QuickFix`s and the actions to execute them
    in bulk or individually.
    """

    @typing.type_check_only
    class ApplyItemsTask(ghidra.program.util.ProgramTask):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, program: ghidra.program.model.listing.Program, title: typing.Union[java.lang.String, str], quickFixList: java.util.List[QuickFix]):
            ...


    @typing.type_check_only
    class QuickFixActionContext(docking.DefaultActionContext):

        class_: typing.ClassVar[java.lang.Class]

        def getSelectedRowCount(self) -> int:
            ...

        @property
        def selectedRowCount(self) -> jpype.JInt:
            ...


    @typing.type_check_only
    class QuickFixGhidraTable(ghidra.util.table.GhidraTable):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, model: docking.widgets.table.threaded.ThreadedTableModel[QuickFix, typing.Any]):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, title: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], program: ghidra.program.model.listing.Program, loader: TableDataLoader[QuickFix]):
        ...

    def applySelected(self):
        """
        Applies all the selected items.
        """

    def executeAll(self):
        ...

    def getSelectedRow(self) -> int:
        """
        Returns the selected row in the table
        
        :return: the selected row in the table
        :rtype: int
        """

    def getTableModel(self) -> QuickFixTableModel:
        """
        Returns the table model.
        
        :return: the table model
        :rtype: QuickFixTableModel
        """

    def isBusy(self, model: javax.swing.table.TableModel) -> bool:
        ...

    def programClosed(self, program: ghidra.program.model.listing.Program):
        ...

    def setSelection(self, start: typing.Union[jpype.JInt, int], end: typing.Union[jpype.JInt, int]):
        """
        Sets the selected rows in the table
        
        :param jpype.JInt or int start: the index of the first row to select
        :param jpype.JInt or int end: the index of the last row to select
        """

    @property
    def busy(self) -> jpype.JBoolean:
        ...

    @property
    def tableModel(self) -> QuickFixTableModel:
        ...

    @property
    def selectedRow(self) -> jpype.JInt:
        ...


class QuickFix(java.lang.Object):
    """
    Generic base class for executable items to be displayed in a table that can be executed in bulk or
    individually.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getActionName(self) -> str:
        """
        Returns the general name of the action to be performed.
        
        :return: the general name of the action to be performed
        :rtype: str
        """

    def getAddress(self) -> ghidra.program.model.address.Address:
        """
        Returns the address of the affected program element if applicable or null otherwise.
        
        :return: the address of the affected program element if applicable or null otherwise
        :rtype: ghidra.program.model.address.Address
        """

    def getCurrent(self) -> str:
        """
        Returns the current value of the affected program element.
        
        :return: the current value of the affected program element.
        :rtype: str
        """

    def getCustomToolTipData(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...

    def getItemType(self) -> str:
        """
        Returns the type of program element being affected (function, label, comment, etc.)
        
        :return: the type of program element being affected
        :rtype: str
        """

    def getOriginal(self) -> str:
        """
        Returns the original value of the affected program element.
        
        :return: the original value of the affected program element.
        :rtype: str
        """

    def getPath(self) -> str:
        """
        Returns a path (the meaning of the path varies with the item type) associated with the 
        affected program element if applicable or null otherwise.
        
        :return: a path associated with the affected program if applicable or null otherwise
        :rtype: str
        """

    def getPreview(self) -> str:
        """
        Returns a preview of what the affected element will be if this item is applied.
        
        :return: a preview of what the affected element will be if this item is applied
        :rtype: str
        """

    def getProgramLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    def getStatus(self) -> QuickFixStatus:
        """
        Returns the current :obj:`QuickFixStatus` of this item.
        
        :return: the current :obj:`QuickFixStatus` of this item
        :rtype: QuickFixStatus
        """

    def getStatusMessage(self) -> str:
        """
        Returns the current status message of this item.
        
        :return: the current status message of this item
        :rtype: str
        """

    def performAction(self):
        """
        Executes the primary action of this QuickFix.
        """

    @typing.overload
    def setStatus(self, status: QuickFixStatus):
        """
        Sets the status of this item
        
        :param QuickFixStatus status: the new :obj:`QuickFixStatus` for this item.
        """

    @typing.overload
    def setStatus(self, status: QuickFixStatus, message: typing.Union[java.lang.String, str]):
        """
        Sets both the :obj:`QuickFixStatus` and the status message for this item. Typically, used
        to indicate a warning or error.
        
        :param QuickFixStatus status: the new QuickFixStatus
        :param java.lang.String or str message: the status message associated with the new status.
        """

    @property
    def preview(self) -> java.lang.String:
        ...

    @property
    def path(self) -> java.lang.String:
        ...

    @property
    def itemType(self) -> java.lang.String:
        ...

    @property
    def current(self) -> java.lang.String:
        ...

    @property
    def original(self) -> java.lang.String:
        ...

    @property
    def customToolTipData(self) -> java.util.Map[java.lang.String, java.lang.String]:
        ...

    @property
    def address(self) -> ghidra.program.model.address.Address:
        ...

    @property
    def programLocation(self) -> ghidra.program.util.ProgramLocation:
        ...

    @property
    def statusMessage(self) -> java.lang.String:
        ...

    @property
    def status(self) -> QuickFixStatus:
        ...

    @status.setter
    def status(self, value: QuickFixStatus):
        ...

    @property
    def actionName(self) -> java.lang.String:
        ...


class TableDataLoader(java.lang.Object, typing.Generic[T]):
    """
    Generates table data for a :obj:`ThreadedTableModel`. Subclasses
    of ThreadedTableModel can call a TableLoader to supply data in the model's doLoad() method. Also
    has methods for the client to get feedback on the success of the load.
     
    
    The idea is that instead of having to subclass the table model to overload the doLoad() method,
    a general table model is sufficient and be handed a TableDataLoader to provide data to the model.
    """

    class_: typing.ClassVar[java.lang.Class]

    def didProduceData(self) -> bool:
        """
        Returns true if at least one item was added to the accumulator.
        
        :return: true if at least one item was added to the accumulator
        :rtype: bool
        """

    def loadData(self, accumulator: ghidra.util.datastruct.Accumulator[T], monitor: ghidra.util.task.TaskMonitor):
        """
        Loads data into the given accumulator
        
        :param ghidra.util.datastruct.Accumulator[T] accumulator: the accumulator for storing table data
        :param ghidra.util.task.TaskMonitor monitor: the :obj:`TaskMonitor`
        :raises CancelledException: if the operation is cancelled
        """

    def maxDataSizeReached(self) -> bool:
        """
        Returns true if the load was terminated because the maximum number of items was
        reached.
        
        :return: true if the load was terminated because the maximum number of items was
        reached.
        :rtype: bool
        """


class QuickFixTableModel(ghidra.util.table.GhidraProgramTableModel[QuickFix], ghidra.framework.model.DomainObjectListener):
    """
    Table model for :obj:`QuickFix`s
    """

    @typing.type_check_only
    class QuickFixStatusColumn(docking.widgets.table.AbstractDynamicTableColumnStub[QuickFix, QuickFixStatus]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TypeColumn(docking.widgets.table.AbstractDynamicTableColumnStub[QuickFix, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ActionColumn(docking.widgets.table.AbstractDynamicTableColumnStub[QuickFix, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CurrentValueColumn(docking.widgets.table.AbstractDynamicTableColumnStub[QuickFix, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class OriginalValueColumn(docking.widgets.table.AbstractDynamicTableColumnStub[QuickFix, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PreviewColumn(docking.widgets.table.AbstractDynamicTableColumnStub[QuickFix, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class AddressColumn(docking.widgets.table.AbstractDynamicTableColumnStub[QuickFix, ghidra.program.model.address.Address]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PathColumn(docking.widgets.table.AbstractDynamicTableColumnStub[QuickFix, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class QuickFixRenderer(ghidra.util.table.column.AbstractGhidraColumnRenderer[java.lang.String]):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]


class QuickFixStatusRenderer(ghidra.util.table.column.AbstractGhidraColumnRenderer[QuickFixStatus]):
    """
    Renderer for the :obj:`QuickFixStatus` column
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class QuickFixStatus(java.lang.Enum[QuickFixStatus]):
    """
    Enum for the possible status values of a :obj:`QuickFix`.
    """

    class_: typing.ClassVar[java.lang.Class]
    NONE: typing.Final[QuickFixStatus]
    WARNING: typing.Final[QuickFixStatus]
    CHANGED: typing.Final[QuickFixStatus]
    DELETED: typing.Final[QuickFixStatus]
    ERROR: typing.Final[QuickFixStatus]
    DONE: typing.Final[QuickFixStatus]

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> QuickFixStatus:
        ...

    @staticmethod
    def values() -> jpype.JArray[QuickFixStatus]:
        ...



__all__ = ["QuckFixTableProvider", "QuickFix", "TableDataLoader", "QuickFixTableModel", "QuickFixStatusRenderer", "QuickFixStatus"]
