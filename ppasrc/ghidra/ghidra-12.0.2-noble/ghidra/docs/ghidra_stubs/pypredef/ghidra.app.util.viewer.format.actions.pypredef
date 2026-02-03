from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import ghidra.app.util.viewer.field
import ghidra.app.util.viewer.format
import java.lang # type: ignore


class InsertRowAction(docking.action.DockingAction):
    """
    Action class that inserts a new row into a FieldModel.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], panel: ghidra.app.util.viewer.format.FieldHeader):
        ...


class AddAllFieldAction(docking.action.DockingAction):
    """
    Action for adding all fields to the current format.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], panel: ghidra.app.util.viewer.format.FieldHeader):
        """
        Constructor takes the CodeBrowserPlugin that created it and the header
        component so that it can be repainted when fields are added.
        
        :param java.lang.String or str owner: the action owner
        :param ghidra.app.util.viewer.format.FieldHeader panel: the listing panel.
        """

    def actionPerformed(self, context: docking.ActionContext):
        """
        Method called when the action is invoked.
        """


class RemoveAllFieldsAction(docking.action.DockingAction):
    """
    Action for adding all fields to the current format.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], panel: ghidra.app.util.viewer.format.FieldHeader):
        """
        Constructor takes the CodeBrowserPlugin that created it and the header
        component so that it can be repainted when fields are added.
        
        :param java.lang.String or str owner: the action owner.
        :param ghidra.app.util.viewer.format.FieldHeader panel: the listing panel.
        """

    def actionPerformed(self, context: docking.ActionContext):
        """
        Method called when the action is invoked.
        """


class AddSpacerFieldAction(docking.action.DockingAction):
    """
    Action for adding SpacerFields to a FieldModel
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], panel: ghidra.app.util.viewer.format.FieldHeader):
        ...

    def actionPerformed(self, context: docking.ActionContext):
        """
        Method called when the action is invoked.
        """


class RemoveRowAction(docking.action.DockingAction):
    """
    Action for removing empty rows.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], panel: ghidra.app.util.viewer.format.FieldHeader):
        ...


class AddFieldAction(docking.action.DockingAction):
    """
    The action for adding a Field to the current format.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], fieldFactory: ghidra.app.util.viewer.field.FieldFactory, panel: ghidra.app.util.viewer.format.FieldHeader, formatModel: ghidra.app.util.viewer.format.FieldFormatModel):
        ...

    def actionPerformed(self, context: docking.ActionContext):
        """
        Method called when the action is invoked.
        """


class SetSpacerTextAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str]):
        ...


class EnableFieldAction(docking.action.DockingAction):
    """
    Action for enabling disabled fields
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], panel: ghidra.app.util.viewer.format.FieldHeader):
        """
        Constructor
        
        :param java.lang.String or str owner: the action owner
        """


class DisableFieldAction(docking.action.DockingAction):
    """
    Action for disabling a field.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], panel: ghidra.app.util.viewer.format.FieldHeader):
        """
        Constructor
        
        :param java.lang.String or str owner: the action owner
        """


class ResetFormatAction(docking.action.DockingAction):
    """
    Action for adding all fields to the current format.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], panel: ghidra.app.util.viewer.format.FieldHeader):
        """
        Constructor takes the CodeBrowserPlugin that created it and the header
        component so that it can be repainted when fields are added.
        
        :param java.lang.String or str owner: the action owner
        :param ghidra.app.util.viewer.format.FieldHeader panel: the listing panel.
        """

    def actionPerformed(self, context: docking.ActionContext):
        """
        Method called when the action is invoked.
        """


class RemoveFieldAction(docking.action.DockingAction):
    """
    Action for removing fields
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], panel: ghidra.app.util.viewer.format.FieldHeader):
        ...


class ResetAllFormatsAction(docking.action.DockingAction):
    """
    Action for adding all fields to the current format.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, owner: typing.Union[java.lang.String, str], formatMgr: ghidra.app.util.viewer.format.FormatManager, panel: ghidra.app.util.viewer.format.FieldHeader):
        """
        Constructor takes the CodeBrowserPlugin that created it and the header
        component so that it can be repainted when fields are added.
        
        :param java.lang.String or str owner: the action owner
        :param ghidra.app.util.viewer.format.FormatManager formatMgr: the format manager
        """

    def actionPerformed(self, context: docking.ActionContext):
        """
        Method called when the action is invoked.
        """



__all__ = ["InsertRowAction", "AddAllFieldAction", "RemoveAllFieldsAction", "AddSpacerFieldAction", "RemoveRowAction", "AddFieldAction", "SetSpacerTextAction", "EnableFieldAction", "DisableFieldAction", "ResetFormatAction", "RemoveFieldAction", "ResetAllFormatsAction"]
