from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.menu
import docking.widgets
import ghidra.util
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


AC2 = typing.TypeVar("AC2")
B = typing.TypeVar("B")
B2 = typing.TypeVar("B2")
C = typing.TypeVar("C")
T = typing.TypeVar("T")


class AbstractActionBuilder(java.lang.Object, typing.Generic[T, C, B]):
    """
    Base class for DockingAction builders.
     
     
    Building an action requires a few steps.  One of the few required calls when using a builder
    is :meth:`onAction(Consumer) <.onAction>`.   This is the callback used when the action is invoked.   A
    typical action will also complete the :meth:`enabledWhen(Predicate) <.enabledWhen>` method, which tells the
    tool when an action is valid.
     
     
    To see more detailed documentation for a given method of this builder, or to understand
    how actions are used in the tool, see the :obj:`DockingActionIf` 
    interface.
    """

    class When(java.lang.Enum[AbstractActionBuilder.When]):
        """
        For use with the :meth:`AbstractActionBuilder.inWindow(When) <AbstractActionBuilder.inWindow>` method to specify which windows (main window
        or secondary windows) a global tool bar or menu action will appear in.
        """

        class_: typing.ClassVar[java.lang.Class]
        MAIN_WINDOW: typing.Final[AbstractActionBuilder.When]
        ALWAYS: typing.Final[AbstractActionBuilder.When]
        CONTEXT_MATCHES: typing.Final[AbstractActionBuilder.When]

        @staticmethod
        def valueOf(name: typing.Union[java.lang.String, str]) -> AbstractActionBuilder.When:
            ...

        @staticmethod
        def values() -> jpype.JArray[AbstractActionBuilder.When]:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        """
        Builder constructor
        
        :param java.lang.String or str name: the name of the action to be built
        :param java.lang.String or str owner: the owner of the action to be built
        """

    def build(self) -> T:
        """
        Builds the action.  To build and install the action in one step, use 
        :meth:`buildAndInstall(Tool) <.buildAndInstall>` or :meth:`buildAndInstallLocal(ComponentProvider) <.buildAndInstallLocal>`.
        :meth:`inWindow(When) <.inWindow>`
        
        :return: the newly build action
        :rtype: T
        """

    def buildAndInstall(self, tool: docking.Tool) -> T:
        """
        Builds and adds the action globally to the tool
        
        :param docking.Tool tool: the tool to add the action to
        :return: the newly created action
        :rtype: T
        
        .. seealso::
        
            | :obj:`.build()`
        
            | :obj:`.buildAndInstallLocal(ComponentProvider)`
        """

    def buildAndInstallLocal(self, provider: docking.ComponentProvider) -> T:
        """
        Builds and adds the action as a local action for the given provider
        
        :param docking.ComponentProvider provider: the provider to add the action to
        :return: the newly created action
        :rtype: T
        
        .. seealso::
        
            | :obj:`.build()`
        
            | :obj:`.buildAndInstall(Tool)`
        """

    def description(self, text: typing.Union[java.lang.String, str]) -> B:
        """
        Configure the description for the action.  This description will appear as a tooltip
        over tool bar buttons.
        
        :param java.lang.String or str text: the description
        :return: this builder (for chaining)
        :rtype: B
        """

    def enabled(self, b: typing.Union[jpype.JBoolean, bool]) -> B:
        """
        Configure whether this ``DockingAction`` is enabled.
         
         
        **Note: most clients do not need to use this method.  Enablement is controlled by 
        :meth:`validContextWhen(Predicate) <.validContextWhen>`.
        **
        
        :param jpype.JBoolean or bool b: ``true`` if enabled
        :return: this builder (for chaining)
        :rtype: B
        
        .. seealso::
        
            | :obj:`.validContextWhen(Predicate)`
        """

    def enabledWhen(self, predicate: java.util.function.Predicate[C]) -> B:
        """
        Sets a predicate for dynamically determining the action's enabled state.  See 
        :meth:`DockingActionIf.isEnabledForContext(ActionContext) <DockingActionIf.isEnabledForContext>`
         
         
        If this predicate is not set, the action's enable state must be controlled 
        directly using the :meth:`DockingAction.setEnabled(boolean) <DockingAction.setEnabled>` method.  We do not recommend
        controlling enablement directly. And, of course, if you do set this predicate, you should 
        not later call :meth:`DockingAction.setEnabled(boolean) <DockingAction.setEnabled>` to manually manage enablement.
        
        :param java.util.function.Predicate[C] predicate: the predicate that will be used to dynamically determine an action's 
                enabled state
        :return: this builder (for chaining)
        :rtype: B
        """

    def helpLocation(self, help: ghidra.util.HelpLocation) -> B:
        """
        Configure :obj:`HelpLocation` for this ``DockingAction``
         
         
        Clients are free to specify their help location directly, but many do not.  A default
        help location is created that uses the action name as the anchor name and the action
        owner as the topic.   If your anchor or topic do not follow this convention, then you 
        need to set help topic yourself.
        
        :param ghidra.util.HelpLocation help: the :obj:`HelpLocation` to configure
        :return: this builder (for chaining)
        :rtype: B
        """

    def inWindow(self, when: AbstractActionBuilder.When) -> B:
        """
        Specifies when a global action should appear in a window (main or secondary).
         
        
        Global menu or toolbar actions can be configured to appear in 1) only the main 
        window, or 2) all windows, or 3) any window that has a provider that
        generates an action context that matches the context that this action
        consumes. If the "context matches" options is chosen, then the 
        :meth:`withContext(Class) <.withContext>` method must also be called to specify the matching
        context; otherwise an exception will be thrown when the action is built.
         
        
        The default is that the action will only appear in the main window.
        
        :param AbstractActionBuilder.When when: use the :obj:`When` enum to specify the windowing behavior
        of the action.
        :return: this builder (for chaining)
        :rtype: B
        """

    @typing.overload
    def keyBinding(self, keyStroke: javax.swing.KeyStroke) -> B:
        """
        Sets the key binding for this action
        
        :param javax.swing.KeyStroke keyStroke: the KeyStroke to bind to this action
        :return: this builder (for chaining)
        :rtype: B
        """

    @typing.overload
    def keyBinding(self, keyStrokeString: typing.Union[java.lang.String, str]) -> B:
        """
        Sets the key binding for this action
        
        :param java.lang.String or str keyStrokeString: the string to parse as a KeyStroke. See
        :meth:`KeyStroke.getKeyStroke(String) <KeyStroke.getKeyStroke>` for the format of the string.
        :return: this builder (for chaining)
        :rtype: B
        """

    @typing.overload
    def menuGroup(self, group: typing.Union[java.lang.String, str]) -> B:
        """
        Sets the group for the action in the menu bar.  Actions in the same group will appear
        next to other actions in the same group and actions in different groups will be separated
        by menu dividers.
        
        :param java.lang.String or str group: for this action
        :return: this builder (for chaining)
        :rtype: B
        """

    @typing.overload
    def menuGroup(self, group: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]) -> B:
        """
        Sets the group and sub-group for the action in the menu bar.  Actions in the same group 
        will appear next to other actions in the same group and actions in different groups will 
        be separated by menu dividers.  The sub-group is used to order the actions within the group.
        
        :param java.lang.String or str group: the group used to clump actions together
        :param java.lang.String or str subGroup: the sub-group used to order actions within a group
        :return: this builder (for chaining)
        :rtype: B
        
        .. seealso::
        
            | :obj:`.menuGroup(String)`
        """

    def menuIcon(self, icon: javax.swing.Icon) -> B:
        """
        Sets the icon to use in this action's menu bar item
        
        :param javax.swing.Icon icon: the icon to use in the action's menu bar item
        :return: this builder (for chaining)
        :rtype: B
        """

    def menuMnemonic(self, mnemonic: typing.Union[jpype.JInt, int]) -> B:
        """
        Sets the mnemonic to use in this action's menu bar item
        
        :param jpype.JInt or int mnemonic: the mnemonic to use for this action's menu bar item.
        :return: this builder (for chaining)
        :rtype: B
        """

    def menuPath(self, *pathElement: typing.Union[java.lang.String, str]) -> B:
        """
        Sets the menu bar path for the action.  Setting this attribute is what causes the action
        to appear on the tools menu bar.
        
        :param jpype.JArray[java.lang.String] pathElement: the menu bar path for the action
        :return: this builder (for chaining)
        :rtype: B
        """

    def onAction(self, action: java.util.function.Consumer[C]) -> B:
        """
        Sets the primary callback to be executed when this action is invoked.  This builder will
        throw an :obj:`IllegalStateException` if one of the build methods is called without
        providing this callback.
        
        :param java.util.function.Consumer[C] action: the callback to execute when the action is invoked
        :return: this builder (for chaining)
        :rtype: B
        """

    @typing.overload
    def popupMenuGroup(self, group: typing.Union[java.lang.String, str]) -> B:
        """
        Sets the group for the action in the pop-up menu.  Actions in the same group will appear
        next to other actions in the same group and actions in different groups will be separated
        by menu dividers.
        
        :param java.lang.String or str group: for this action
        :return: this builder (for chaining)
        :rtype: B
        """

    @typing.overload
    def popupMenuGroup(self, group: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]) -> B:
        """
        Sets the group and sub-group for the action in the pop-up menu.  Actions in the same group
        will appear next to other actions in the same group and actions in different groups will
        be separated by menu dividers.  The sub-group is used to order the actions within the group
        
        :param java.lang.String or str group: the group used to clump actions together
        :param java.lang.String or str subGroup: the sub-group used to order actions within a group
        :return: this builder (for chaining)
        :rtype: B
        
        .. seealso::
        
            | :obj:`.popupMenuGroup(String)`
        """

    def popupMenuIcon(self, icon: javax.swing.Icon) -> B:
        """
        Sets the icon to use in this action's pop-up menu item
        
        :param javax.swing.Icon icon: the icon to use in the action's pop-up menu item
        :return: this builder (for chaining)
        :rtype: B
        """

    def popupMenuPath(self, *pathElement: typing.Union[java.lang.String, str]) -> B:
        """
        Sets the pop-up menu path for the action.  Setting this attribute is what causes the action
        to appear on the tool's pop-up menu (assuming it is applicable for the context).
        
        :param jpype.JArray[java.lang.String] pathElement: the menu path for the action in the pop-up menu
        :return: this builder (for chaining)
        :rtype: B
        
        .. seealso::
        
            | :obj:`.popupMenuGroup(String)`
        """

    def popupWhen(self, predicate: java.util.function.Predicate[C]) -> B:
        """
        Sets a predicate for dynamically determining if this action should be included in
        an impending pop-up menu.  If this predicate is not set, the action will be included
        in an impending pop-up if it is enabled. See :meth:`DockingActionIf.isAddToPopup(ActionContext) <DockingActionIf.isAddToPopup>`.
         
         
        Note: use this method when you wish for an action to be added to a popup menu regardless
        of whether it is enabled.  As mentioned above, standard popup actions will only be added
        to the popup when they are enabled. 
          
         
        Note: using this method is not sufficient to cause the action to appear in a popup 
        menu.  You must also use :meth:`popupMenuPath(String...) <.popupMenuPath>`.
        
        :param java.util.function.Predicate[C] predicate: the predicate that will be used to dynamically determine whether an 
                action is added to a popup menu
        :return: this builder (for chaining)
        :rtype: B
        
        .. seealso::
        
            | :obj:`.popupMenuPath(String...)`
        """

    def sharedKeyBinding(self) -> B:
        """
        Marks this action as one that shares a key binding with other actions in the tool.  This
        allows multiple clients to supply actions that use the same key binding, each working
        within its respective action context.  See :obj:`KeyBindingType`.
         
         
        Actions are not shared by default; they are :obj:`KeyBindingType.INDIVIDUAL`.  This 
        means that each action must have its key binding assigned individually.
        
        :return: this builder (for chaining)
        :rtype: B
        """

    @typing.overload
    def toolBarGroup(self, group: typing.Union[java.lang.String, str]) -> B:
        """
        Sets the group for the action in the tool bar.  Actions in the same group will appear
        next to other actions in the same group and actions in different groups will be separated
        by menu dividers.
         
         
        **Note: you must call :meth:`toolBarIcon(Icon) <.toolBarIcon>` or :meth:`toolBarIcon(String) <.toolBarIcon>` for
        this action to appear in the toolbar.  Calling this method without the other will not 
        cause this action to be placed in the tool bar.
        **
        
        :param java.lang.String or str group: for this action
        :return: this builder (for chaining)
        :rtype: B
        
        .. seealso::
        
            | :obj:`.toolBarGroup(String, String)`
        """

    @typing.overload
    def toolBarGroup(self, group: typing.Union[java.lang.String, str], subGroup: typing.Union[java.lang.String, str]) -> B:
        """
        Sets the group and sub-group for the action in the tool bar.  Actions in the same group
        will appear next to other actions in the same group and actions in different groups will
        be separated by menu dividers.  The sub-group is used to order the actions within the group.
         
         
        **Note: you must call :meth:`toolBarIcon(Icon) <.toolBarIcon>` or :meth:`toolBarIcon(String) <.toolBarIcon>` for
        this action to appear in the toolbar.  Calling this method without the other will not 
        cause this action to be placed in the tool bar.
        **
        
        :param java.lang.String or str group: the group used to clump actions together.
        :param java.lang.String or str subGroup: the sub-group used to order actions within a group.
        :return: this builder (for chaining)
        :rtype: B
        
        .. seealso::
        
            | :obj:`.toolBarGroup(String)`
        """

    @typing.overload
    def toolBarIcon(self, icon: javax.swing.Icon) -> B:
        """
        Sets the icon to use in this action's tool bar button.  Setting this attribute is what 
        causes the action to appear on the tool's or component provider's action tool bar.
        
        :param javax.swing.Icon icon: the icon to use in the action's tool bar
        :return: this builder (for chaining)
        :rtype: B
        
        .. seealso::
        
            | :obj:`.toolBarIcon(String)`
        """

    @typing.overload
    def toolBarIcon(self, iconFilepath: typing.Union[java.lang.String, str]) -> B:
        """
        Sets the path for the icon to use in this action's tool bar button.  Setting this attribute
        causes the action to appear on the tool's or component provider's action tool bar.
        
        :param java.lang.String or str iconFilepath: the module-relative path for the icon to use in the action's tool bar
        :return: this builder (for chaining)
        :rtype: B
        
        .. seealso::
        
            | :obj:`.toolBarIcon(Icon)`
        """

    @deprecated("use validWhen(Predicate)")
    def validContextWhen(self, predicate: java.util.function.Predicate[C]) -> B:
        """
        
        
        :param java.util.function.Predicate[C] predicate: the predicate
        :return: this builder (for chaining)
        :rtype: B
        
        .. deprecated::
        
        use :meth:`validWhen(Predicate) <.validWhen>`
        """

    def validWhen(self, predicate: java.util.function.Predicate[C]) -> B:
        """
        Sets a predicate for dynamically determining if this action is valid for the current 
        :obj:`ActionContext`.  See :meth:`DockingActionIf.isValidContext(ActionContext) <DockingActionIf.isValidContext>`.
         
         
        Note: most actions will not use this method, but rely instead on 
        :meth:`enabledWhen(Predicate) <.enabledWhen>`. 
         
         
        Note: this triggers automatic action enablement so you should not later call 
        :meth:`DockingAction.setEnabled(boolean) <DockingAction.setEnabled>` to manually manage action enablement.
        
        :param java.util.function.Predicate[C] predicate: the predicate that will be used to dynamically determine an action's 
        validity for a given :obj:`ActionContext`
        :return: this builder (for chaining)
        :rtype: B
        """

    @typing.overload
    def withContext(self, newActionContextClass: java.lang.Class[AC2]) -> B2:
        """
        Sets the action context for this action. If this context is set, then this action is only
        valid when the current context is that type or extends that type.
         
        
        After this method has been called, any the following methods will use this new context type 
        in the method signature: (:meth:`validContextWhen(Predicate) <.validContextWhen>`, 
        :meth:`enabledWhen(Predicate) <.enabledWhen>`, and 
        :meth:`popupWhen(Predicate) <.popupWhen>`).
         
        
        For example, assume you have an action that is only enabled when the context is of type
        FooContext.  If you don't call this method to set the action context type,  you would
        have to write your predicate something like this:
         
        builder.enabledWhen(context ->{
            if (!(context instanceof FooContext)) {
                return false;
            }
            return ((FooContext) context).isAwesome();
        });
         
        But by first calling the builder method ``withContext(FooContext.class)``, then the
        context will be the new type and you can simply write:
        
         
        builder.enabledWhen(context -> context.isAwesome())
         
        
         
        Note: this triggers automatic action enablement based on context for the action, so you 
        should not later manually manage action enablement using the action's 
        :meth:`DockingAction.setEnabled(boolean) <DockingAction.setEnabled>` method.
         
        
        For more details on how the action context system works, see :obj:`ActionContext`.
        
        :param java.lang.Class[AC2] newActionContextClass: the more specific ActionContext type.
        :param AC2: The new ActionContext type (as determined by the newActionContextClass) that
        the returned builder will have.:param B2: the new builder type.:return: an ActionBuilder whose generic types have been modified to match the new ActionContext.
        It still contains all the configuration that has been applied so far.
        :rtype: B2
        """

    @typing.overload
    def withContext(self, newActionContextClass: java.lang.Class[AC2], useDefaultContext: typing.Union[jpype.JBoolean, bool]) -> B2:
        """
        Sets the action context for this action and whether or not this action supports default
        context as explained in :obj:`ActionContext`. If this context is set, then this 
        action is only valid when the current context is that type or extends that type.
         
        
        After this method has been called, any the following methods will use this new context type 
        in the method signature: (:meth:`validContextWhen(Predicate) <.validContextWhen>`, 
        :meth:`enabledWhen(Predicate) <.enabledWhen>`, and 
        :meth:`popupWhen(Predicate) <.popupWhen>`).
         
        
        For example, assume you have an action that is only enabled when the context is of type
        FooContext.  If you don't call this method to set the action context type,  you would
        have to write your predicate something like this:
         
        builder.enabledWhen(context ->{
            if (!(context instanceof FooContext)) {
                return false;
            }
            return ((FooContext) context).isAwesome();
        });
         
        But by first calling the builder method ``withContext(FooContext.class)``, then the
        context will be the new type and you can simply write:
        
         
        builder.enabledWhen(context -> context.isAwesome())
         
        
         
        Note: this triggers automatic action enablement based on context for the action, so you 
        should not later manually manage action enablement using the action's 
        :meth:`DockingAction.setEnabled(boolean) <DockingAction.setEnabled>` method.
         
        
        For more details on how the action context system works, see :obj:`ActionContext`.
        
        :param java.lang.Class[AC2] newActionContextClass: the more specific ActionContext type.
        :param AC2: The new ActionContext type (as determined by the newActionContextClass) that
        the returned builder will have.:param B2: the new builder type.:param jpype.JBoolean or bool useDefaultContext: if true, then this action also supports operating on a default
        context other than the active (focused) provider's context
        :return: an ActionBuilder whose generic types have been modified to match the new ActionContext.
        It still contains all the configuration that has been applied so far
        :rtype: B2
        """


class ToggleActionBuilder(AbstractActionBuilder[docking.action.ToggleDockingAction, docking.ActionContext, ToggleActionBuilder]):
    """
    Builder for :obj:`ToggleDockingAction`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        """
        Builder constructor
        
        :param java.lang.String or str name: the name of the action to be built
        :param java.lang.String or str owner: the owner of the action to be build
        """

    def selected(self, b: typing.Union[jpype.JBoolean, bool]) -> ToggleActionBuilder:
        """
        Configure the initial select state for the toggle action.
        
        :param jpype.JBoolean or bool b: the initial select state
        :return: self Builder (for chaining)
        :rtype: ToggleActionBuilder
        """


class MultiActionBuilder(AbstractActionBuilder[docking.menu.MultiActionDockingAction, docking.ActionContext, MultiActionBuilder]):
    """
    Builder for :obj:`MultiActionDockingAction`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        """
        Builder constructor
        
        :param java.lang.String or str name: the name of the action to be built
        :param java.lang.String or str owner: the owner of the action to be build
        """

    def withActions(self, list: java.util.List[docking.action.DockingActionIf]) -> MultiActionBuilder:
        """
        Configure a :obj:`List` of :obj:`DockingActionIf` to provide to the :obj:`MultiActionDockingAction`
        
        :param java.util.List[docking.action.DockingActionIf] list: a :obj:`List` of :obj:`DockingActionIf` to provide to the :obj:`MultiActionDockingAction`
        :return: this MultiActionDockingActionBuilder (for chaining)
        :rtype: MultiActionBuilder
        """


class MultiStateActionBuilder(AbstractActionBuilder[docking.menu.MultiStateDockingAction[T], docking.ActionContext, MultiStateActionBuilder[T]], typing.Generic[T]):
    """
    Builder for :obj:`MultiStateDockingAction`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        """
        Builder constructor
        
        :param java.lang.String or str name: the name of the action to be built
        :param java.lang.String or str owner: the owner of the action to be build
        """

    @typing.overload
    def addState(self, displayName: typing.Union[java.lang.String, str], icon: javax.swing.Icon, userData: T) -> MultiStateActionBuilder[T]:
        """
        Add an action state
        
        :param java.lang.String or str displayName: the name to appear in the action menu
        :param javax.swing.Icon icon: the icon to appear in the action menu
        :param T userData: the data associated with this state
        :return: this MultiActionDockingActionBuilder (for chaining)
        :rtype: MultiStateActionBuilder[T]
        """

    @typing.overload
    def addState(self, actionState: docking.menu.ActionState[T]) -> MultiStateActionBuilder[T]:
        """
        Add an action state
        
        :param docking.menu.ActionState[T] actionState: the action state to add
        :return: this MultiActionDockingActionBuilder (for chaining)
        :rtype: MultiStateActionBuilder[T]
        """

    def addStates(self, list: java.util.List[docking.menu.ActionState[T]]) -> MultiStateActionBuilder[T]:
        """
        Add a list of action states
        
        :param java.util.List[docking.menu.ActionState[T]] list: a list of ActionStates;
        :return: this MultiActionDockingActionBuilder (for chaining)
        :rtype: MultiStateActionBuilder[T]
        """

    def onActionStateChanged(self, biConsumer: java.util.function.BiConsumer[docking.menu.ActionState[T], docking.widgets.EventTrigger]) -> MultiStateActionBuilder[T]:
        """
        Sets the primary callback to be executed when this action changes its action state.
         
         
        
        This builder will throw an :obj:`IllegalStateException` if one of the build methods is
        called without providing this callback.
        
        :param java.util.function.BiConsumer[docking.menu.ActionState[T], docking.widgets.EventTrigger] biConsumer: the callback to execute when the selected action state is changed.
        :return: this builder (for chaining)
        :rtype: MultiStateActionBuilder[T]
        """

    def stateGenerator(self, generator: java.util.function.Supplier[java.util.List[docking.menu.ActionState[T]]]) -> MultiStateActionBuilder[T]:
        """
        Generate the states dynamically upon the user clicking the button
         
         
        
        It is highly recommended that the current state is included in the list of available states.
        Otherwise, the user could become confused or frustrated.
        
        :param java.util.function.Supplier[java.util.List[docking.menu.ActionState[T]]] generator: a function from action context to available states
        :return: this MultiActionDockingActionBuilder (for chaining)
        :rtype: MultiStateActionBuilder[T]
        """

    def useCheckboxForIcons(self, b: typing.Union[jpype.JBoolean, bool]) -> MultiStateActionBuilder[T]:
        """
        Overrides the default icons for actions shown in popup menu of the multi-state action.
         
         
        
        By default, the popup menu items will use the icons as provided by the :obj:`ActionState`.
        By passing true to this method, icons will not be used in the popup menu. Instead, a checkbox
        icon will be used to show the active action state.
        
        :param jpype.JBoolean or bool b: true to use a checkbox
        :return: this MultiActionDockingActionBuilder (for chaining)
        :rtype: MultiStateActionBuilder[T]
        """


class ActionBuilder(AbstractActionBuilder[docking.action.DockingAction, docking.ActionContext, ActionBuilder]):
    """
    Builder for :obj:`DockingAction`s
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str]):
        """
        Builder constructor
        
        :param java.lang.String or str name: the name of the action to be built
        :param java.lang.String or str owner: the owner of the action to be build
        """



__all__ = ["AbstractActionBuilder", "ToggleActionBuilder", "MultiActionBuilder", "MultiStateActionBuilder", "ActionBuilder"]
