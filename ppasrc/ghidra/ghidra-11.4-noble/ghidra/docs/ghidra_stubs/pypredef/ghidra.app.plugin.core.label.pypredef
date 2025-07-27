from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.table
import ghidra.app.context
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.program.model.symbol
import ghidra.util.task
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


@typing.type_check_only
class LabelHistoryListener(java.lang.Object):
    """
    Interface to define a method that is called when an address in the 
    Label History table is selected.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addressSelected(self, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address):
        """
        Notification that the given address was selected.
        """


class LabelHistoryInputDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program):
        ...


@typing.type_check_only
class RemoveLabelAction(ghidra.app.context.ListingContextAction):
    """
    ``RemoveLabelAction`` allows the user to remove a label.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class LabelHistoryPanel(javax.swing.JPanel):
    """
    Main panel that shows the history of labels at a specific address, or
    shows all history for all addresses. When all addresses are displayed, 
    the user can navigate by clicking on a row in the history table.
    """

    @typing.type_check_only
    class LabelCellRenderer(docking.widgets.table.GTableCellRenderer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class LabelHistoryAction(ghidra.app.context.ListingContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str]):
        ...


class LabelHistoryDialog(docking.DialogComponentProvider, LabelHistoryListener):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, addr: ghidra.program.model.address.Address, list: java.util.List[ghidra.program.model.symbol.LabelHistory]):
        ...

    @typing.overload
    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, program: ghidra.program.model.listing.Program, title: typing.Union[java.lang.String, str], list: java.util.List[ghidra.program.model.symbol.LabelHistory]):
        ...


class EditExternalLabelAction(ghidra.app.context.ListingContextAction):
    """
    A global listing action which facilitates editing an external location associated
    with an external reference on an operand field location.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: LabelMgrPlugin):
        """
        Creates the action for editing an existing external location or external function in the 
        listing.
        
        :param LabelMgrPlugin plugin: the label manager plugin, which owns this action.
        """


class OperandLabelDialog(docking.DialogComponentProvider):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, plugin: LabelMgrPlugin):
        ...

    def setOperandLabel(self, context: ghidra.app.context.ListingActionContext):
        ...


@typing.type_check_only
class SetOperandLabelAction(ghidra.app.context.ListingContextAction):
    """
    ``AddLabelAction`` allows the user to add a label.
    """

    class_: typing.ClassVar[java.lang.Class]

    def actionPerformed(self, context: ghidra.app.context.ListingActionContext):
        """
        Method called when the action is invoked.
        
        :param ActionEvent: details regarding the invocation of this action
        """


@typing.type_check_only
class AddLabelAction(ghidra.app.context.ListingContextAction):
    """
    ``AddLabelAction`` allows the user to add a label.
    """

    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class EditLabelAction(ghidra.app.context.ListingContextAction):
    """
    ``AddLabelAction`` allows the user to add a label.
    """

    class_: typing.ClassVar[java.lang.Class]


class AllHistoryAction(ghidra.app.context.ListingContextAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool, owner: typing.Union[java.lang.String, str]):
        ...


class LabelHistoryTask(ghidra.util.task.Task):
    ...
    class_: typing.ClassVar[java.lang.Class]


class LabelMgrPlugin(ghidra.framework.plugintool.Plugin):
    """
    Plugin to add and edit labels.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: ghidra.framework.plugintool.PluginTool):
        """
        Constructor
        
        :param ghidra.framework.plugintool.PluginTool tool: the tool
        """


@typing.type_check_only
class LabelHistoryTableModel(docking.widgets.table.AbstractSortedTableModel[ghidra.program.model.symbol.LabelHistory]):
    """
    Table model for showing label history.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["LabelHistoryListener", "LabelHistoryInputDialog", "RemoveLabelAction", "LabelHistoryPanel", "LabelHistoryAction", "LabelHistoryDialog", "EditExternalLabelAction", "OperandLabelDialog", "SetOperandLabelAction", "AddLabelAction", "EditLabelAction", "AllHistoryAction", "LabelHistoryTask", "LabelMgrPlugin", "LabelHistoryTableModel"]
