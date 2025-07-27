from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets.list
import docking.widgets.searchlist
import java.beans # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


class ActionGroup(java.lang.Enum[ActionGroup]):
    """
    This enum defines the actions category groups. Actions displayed in the :obj:`ActionChooserDialog`
    will be organized into these groups.
    """

    class_: typing.ClassVar[java.lang.Class]
    LOCAL_TOOLBAR: typing.Final[ActionGroup]
    LOCAL_MENU: typing.Final[ActionGroup]
    POPUP: typing.Final[ActionGroup]
    KEYBINDING_ONLY: typing.Final[ActionGroup]
    GLOBAL_TOOLBAR: typing.Final[ActionGroup]
    GLOBAL_MENU: typing.Final[ActionGroup]

    @staticmethod
    def getActionByDisplayName(name: typing.Union[java.lang.String, str]) -> ActionGroup:
        """
        Returns the ActionGroup that has the given display name.
        
        :param java.lang.String or str name: the display name for which to find its corresponding group
        :return: the ActionGroup that has the given display name
        :rtype: ActionGroup
        """

    def getDisplayName(self) -> str:
        """
        Returns the display name for the action group.
        
        :return: the display name for the action group
        :rtype: str
        """

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ActionGroup:
        ...

    @staticmethod
    def values() -> jpype.JArray[ActionGroup]:
        ...

    @property
    def displayName(self) -> java.lang.String:
        ...


class ActionDisplayLevel(java.lang.Enum[ActionDisplayLevel]):
    """
    An enum for specifying which actions should be displayed in the :obj:`ActionChooserDialog`. Each
    successive level is less restrictive and includes more actions to display.
    """

    class_: typing.ClassVar[java.lang.Class]
    LOCAL: typing.Final[ActionDisplayLevel]
    GLOBAL: typing.Final[ActionDisplayLevel]
    ALL: typing.Final[ActionDisplayLevel]

    def getNextLevel(self) -> ActionDisplayLevel:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> ActionDisplayLevel:
        ...

    @staticmethod
    def values() -> jpype.JArray[ActionDisplayLevel]:
        ...

    @property
    def nextLevel(self) -> ActionDisplayLevel:
        ...


class ActionChooserDialog(docking.DialogComponentProvider):
    """
    Dialog for displaying and invoking docking actions. The dialog will display a mix of local
    and global actions that varies depending on its current :obj:`ActionDisplayLevel`.
    """

    @typing.type_check_only
    class ActionRunner(java.beans.PropertyChangeListener):
        """
        Class for actually invoking the selected action. Creating an instance of this class
        causes a listener to be added for when focus changes. This is because we don't want
        to invoke the selected action until after this dialog has finished closing and focus
        has been returned to the original component that had focus before this dialog was invoked.
        """

        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ActionRenderer(docking.widgets.list.GListCellRenderer[docking.widgets.searchlist.SearchListEntry[docking.action.DockingActionIf]]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ActionsFilter(java.util.function.BiPredicate[docking.action.DockingActionIf, java.lang.String]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, model: ActionsModel):
        """
        Constructor given an ActionsModel.
        
        :param ActionsModel model: the ActionsModel to use in the dialog
        """

    @typing.overload
    def __init__(self, tool: docking.Tool, provider: docking.ComponentProvider, context: docking.ActionContext):
        """
        Constructor for when a :obj:`ComponentProvider` has focus
        
        :param docking.Tool tool: the active tool
        :param docking.ComponentProvider provider: the ComponentProvider that has focus
        :param docking.ActionContext context: the ActionContext that is active and will be used to invoke the chosen action
        """

    @typing.overload
    def __init__(self, tool: docking.Tool, dialog: docking.DialogComponentProvider, context: docking.ActionContext):
        """
        Constructor for when a :obj:`DialogComponentProvider` has focus
        
        :param docking.Tool tool: the active tool
        :param docking.DialogComponentProvider dialog: the DialogComponentProvider that has focus
        :param docking.ActionContext context: the ActionContext that is active and will be used to invoke the chosen action
        """

    def getActionDisplayLevel(self) -> ActionDisplayLevel:
        """
        Returns the current :obj:`ActionDisplayLevel`
        
        :return: the current action display level
        :rtype: ActionDisplayLevel
        """

    def setActionDisplayLevel(self, level: ActionDisplayLevel):
        """
        Sets the :obj:`ActionDisplayLevel` for the dialog which determines which actions to display
        
        :param ActionDisplayLevel level: the action display level to use.
        """

    @property
    def actionDisplayLevel(self) -> ActionDisplayLevel:
        ...

    @actionDisplayLevel.setter
    def actionDisplayLevel(self, value: ActionDisplayLevel):
        ...


class ActionsModel(docking.widgets.searchlist.DefaultSearchListModel[docking.action.DockingActionIf]):
    """
    Model for the SearchList used by the :obj:`ActionChooserDialog`.  This model is constructed
    with two sets of actions; local and global. The local actions are actions that are specific to
    the currently focused :obj:`ComponentProvider` or :obj:`DialogComponentProvider`. Global 
    actions are actions that are added at the tool level and are not specific to a ComponentProvider
    or DialogComponentProvider.
     
    
    The model supports the concept of a :obj:`ActionDisplayLevel`. The display level determines
    which combination of local and global actions to display and takes into account if they are
    valid for the current context, are enabled for the current context and, for popups, the value of
    the "addToPopup" value. Each higher display level is less restrictive and adds more actions in
    the displayed list. See the :obj:`ActionDisplayLevel` for a description of which actions are
    displayed for each level
    """

    @typing.type_check_only
    class ActionNameComparator(java.util.Comparator[docking.action.DockingActionIf]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ActionMenuPathComparator(java.util.Comparator[docking.action.DockingActionIf]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ActionPopupPathComparator(java.util.Comparator[docking.action.DockingActionIf]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def getActionDisplayLevel(self) -> ActionDisplayLevel:
        """
        Returns the current :obj:`ActionDisplayLevel` of the dialog.
        
        :return: the current display level of the dialog
        :rtype: ActionDisplayLevel
        """

    def isDisposed(self) -> bool:
        ...

    def setDisplayLevel(self, level: ActionDisplayLevel):
        """
        Sets the display level for the actions dialog. Each higher level includes more actions
        in the displayed list of actions.
        
        :param ActionDisplayLevel level: the :obj:`ActionDisplayLevel`
        """

    @property
    def disposed(self) -> jpype.JBoolean:
        ...

    @property
    def actionDisplayLevel(self) -> ActionDisplayLevel:
        ...



__all__ = ["ActionGroup", "ActionDisplayLevel", "ActionChooserDialog", "ActionsModel"]
