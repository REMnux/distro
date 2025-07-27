from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import ghidra.framework.options
import gui.event
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.beans # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class ActionAdapter(javax.swing.Action, java.beans.PropertyChangeListener):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, dockingAction: docking.action.DockingActionIf):
        """
        This is only for use when converting actions from docking actions to those to be used
        in Swing components.  The context system does not work as expected in this case.
         
         
        Most clients should use :meth:`ActionAdapter(DockingActionIf, ActionContextProvider) <.ActionAdapter>`
        
        :param docking.action.DockingActionIf dockingAction: the action to adapt
        """

    @typing.overload
    def __init__(self, dockingAction: docking.action.DockingActionIf, provider: docking.action.ActionContextProvider):
        ...

    def setDefaultAction(self, defaultAction: javax.swing.Action):
        ...


class SharedDockingActionPlaceholder(java.lang.Object):
    """
    A marker interface to signal that the implementing action serves as an action that should
    not itself be used in the tool, but should only be used to register and manage keybindings.
     
     
     
    This action is merely a tool by which transient components can ensure that their actions
    are correctly managed when the component is created.  Normal actions will get registered when
    the tool first starts-up.  Alternatively, transient components only appear when called upon
    by some event, such as a user request.  The issue heretofore was that the tool will remove
    any options that are not longer used. Thus, if an action belonging to a transient component
    does not get registered every time the tool is used, then the options (and key bindings) for
    that action are removed from the too.   This interface allows a second-party to register 
    an action on behalf of a transient provider, thus preventing the tool from removing any 
    previously applied options.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getKeyBinding(self) -> javax.swing.KeyStroke:
        """
        The default key binding for the action represented by this placeholder
        
        :return: the key binding; may be null
        :rtype: javax.swing.KeyStroke
        """

    def getName(self) -> str:
        """
        The action name.  This name must exactly match the name of the action represented by 
        this placeholder.
        
        :return: the name
        :rtype: str
        """

    def getOwner(self) -> str:
        """
        Returns an owner name to use in place of :const:`ToolConstants.SHARED_OWNER`.  
        This should only be used when the client knows for certain that all shared actions are 
        shared by a single owner.  This is not typical for shared actions.  This can happen when one
        owner (such as a plugin) has multiple component providers that share action key  bindings.
        
        :return: the owner
        :rtype: str
        """

    @property
    def owner(self) -> java.lang.String:
        ...

    @property
    def keyBinding(self) -> javax.swing.KeyStroke:
        ...

    @property
    def name(self) -> java.lang.String:
        ...


class KeyEntryDialog(docking.DialogComponentProvider):
    """
    Dialog to set the key binding on an action. It is triggered by the F4 key.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: docking.Tool, action: docking.action.DockingActionIf):
        ...

    def setKeyStroke(self, ks: javax.swing.KeyStroke):
        """
        Sets the given keystroke value into the text field of this dialog
        
        :param javax.swing.KeyStroke ks: the keystroke to set
        """


class ToolActions(DockingToolActions, java.beans.PropertyChangeListener):
    """
    An class to manage actions registered with the tool
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: docking.Tool, actionToGuiHelper: docking.ActionToGuiHelper):
        """
        Construct an ActionManager
        
        :param docking.Tool tool: tool using this ActionManager
        :param docking.ActionToGuiHelper actionToGuiHelper: the class that takes actions and maps them to GUI widgets
        """

    def addLocalAction(self, provider: docking.ComponentProvider, action: docking.action.DockingActionIf):
        """
        Add an action that works specifically with a component provider.
        
        :param docking.ComponentProvider provider: provider associated with the action
        :param docking.action.DockingActionIf action: local action to the provider
        """

    def dispose(self):
        ...

    @typing.overload
    def getAction(self, ks: javax.swing.KeyStroke) -> javax.swing.Action:
        ...

    @typing.overload
    def getAction(self, mb: gui.event.MouseBinding) -> javax.swing.Action:
        ...

    def optionsRebuilt(self):
        ...

    def registerSharedActionPlaceholder(self, placeholder: SharedDockingActionPlaceholder):
        """
        Allows clients to register an action by using a placeholder.  This is useful when
        an API wishes to have a central object (like a plugin) register actions for transient
        providers, that may not be loaded until needed.
        
         
        This method may be called multiple times with the same conceptual placeholder--the
        placeholder will only be added once.
        
        :param SharedDockingActionPlaceholder placeholder: the placeholder containing information related to the action it represents
        """

    def removeLocalAction(self, provider: docking.ComponentProvider, action: docking.action.DockingActionIf):
        """
        Remove an action that works specifically with a component provider.
        
        :param docking.ComponentProvider provider: provider associated with the action
        :param docking.action.DockingActionIf action: local action to the provider
        """

    def validateActionKeyBinding(self, action: docking.action.DockingActionIf, ks: javax.swing.KeyStroke) -> str:
        """
        Checks whether the given key stroke can be used for the given action for restrictions such as
        those for System level actions.
        
        :param docking.action.DockingActionIf action: the action; may be null
        :param javax.swing.KeyStroke ks: the key stroke
        :return: A null value if valid; a non-null error message if invalid
        :rtype: str
        """

    @property
    def action(self) -> javax.swing.Action:
        ...


class DockingToolActions(java.lang.Object):
    """
    Represents the collection of actions registered with the tool, along with method for adding
    and removing actions.
    """

    class_: typing.ClassVar[java.lang.Class]

    def addGlobalAction(self, action: docking.action.DockingActionIf):
        """
        Adds the given action that is enabled, regardless of the active provider
        
        :param docking.action.DockingActionIf action: the action
        """

    def addLocalAction(self, provider: docking.ComponentProvider, action: docking.action.DockingActionIf):
        """
        Adds the given action that enabled when the given provider is active
        
        :param docking.ComponentProvider provider: the provider
        :param docking.action.DockingActionIf action: the action
        """

    def getActions(self, owner: typing.Union[java.lang.String, str]) -> java.util.Set[docking.action.DockingActionIf]:
        """
        Returns all actions with the given owner
        
        :param java.lang.String or str owner: the owner
        :return: the actions
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    def getAllActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        """
        Returns all actions known to the tool.
        
        :return: the actions
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    def getGlobalActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        """
        Returns all global actions known to the tool
        
        :return: the global actions known to the tool
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    def getLocalAction(self, provider: docking.ComponentProvider, actionName: typing.Union[java.lang.String, str]) -> docking.action.DockingActionIf:
        """
        Gets the provider action by the given name
        
        :param docking.ComponentProvider provider: the provider
        :param java.lang.String or str actionName: the action name
        :return: the action
        :rtype: docking.action.DockingActionIf
        """

    def getLocalActions(self, provider: docking.ComponentProvider) -> java.util.Set[docking.action.DockingActionIf]:
        """
        Gets all the local actions registered for the given ComponentProvider.
        
        :param docking.ComponentProvider provider: the ComponentProvider for which to get its local actions
        :return: all the local actions registered for the given ComponentProvider
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    def registerSharedActionPlaceholder(self, placeholder: SharedDockingActionPlaceholder):
        """
        Allows clients to register an action by using a placeholder.  This is useful when 
        an API wishes to have a central object (like a plugin) register actions for transient
        providers, that may not be loaded until needed.
         
         
        This method may be called multiple times with the same conceptual placeholder--the
        placeholder will only be added once.
        
        :param SharedDockingActionPlaceholder placeholder: the placeholder containing information related to the action it represents
        """

    @typing.overload
    def removeActions(self, owner: typing.Union[java.lang.String, str]):
        """
        Removes all global actions for the given owner
        
        :param java.lang.String or str owner: the owner
        """

    @typing.overload
    def removeActions(self, provider: docking.ComponentProvider):
        """
        Removes all local actions for the given provider
        
        :param docking.ComponentProvider provider: the provider
        """

    def removeGlobalAction(self, action: docking.action.DockingActionIf):
        """
        Removes the given global action
        
        :param docking.action.DockingActionIf action: the action
        """

    def removeLocalAction(self, provider: docking.ComponentProvider, action: docking.action.DockingActionIf):
        """
        Removes the given provider's local action
        
        :param docking.ComponentProvider provider: the provider
        :param docking.action.DockingActionIf action: the action
        """

    @property
    def localActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...

    @property
    def allActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...

    @property
    def globalActions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...

    @property
    def actions(self) -> java.util.Set[docking.action.DockingActionIf]:
        ...


class KeyBindingUtils(java.lang.Object):
    """
    A class to provide utilities for system key bindings, such as importing and
    exporting key binding configurations.
    
    
    .. versionadded:: Tracker Id 329
    """

    class_: typing.ClassVar[java.lang.Class]
    PREFERENCES_FILE_EXTENSION: typing.Final = ".kbxml"

    @staticmethod
    def adaptDockingActionToNonContextAction(action: docking.action.DockingAction) -> javax.swing.Action:
        """
        Takes the existing docking action and allows it to be registered with
        Swing components
        
         
        
        The new action will not be correctly wired into the Docking Action
        Context system. This means that the given docking action should not rely
        on :meth:`DockingAction.isEnabledForContext(docking.ActionContext) <DockingAction.isEnabledForContext>` to
        work when called from the Swing widget.
        
        :param docking.action.DockingAction action: the docking action to adapt to a Swing :obj:`Action`
        :return: the new action
        :rtype: javax.swing.Action
        """

    @staticmethod
    @typing.overload
    def clearKeyBinding(component: javax.swing.JComponent, action: docking.action.DockingActionIf):
        """
        Allows the client to clear Java key bindings when the client is creating a docking
        action.   Without this call, any actions bound to the given component will prevent an
        action with the same key binding from firing.  This is useful when your
        application is using tool-level key bindings that share the same
        keystroke as a built-in Java action, such as Ctrl-C for the copy action.
        
        :param javax.swing.JComponent component: the component for which to clear the key binding
        :param docking.action.DockingActionIf action: the action from which to get the key binding
        """

    @staticmethod
    @typing.overload
    def clearKeyBinding(component: javax.swing.JComponent, keyStroke: javax.swing.KeyStroke):
        """
        Allows clients to clear Java key bindings. This is useful when your
        application is using tool-level key bindings that share the same
        keystroke as a built-in Java action, such as Ctrl-C for the copy action.
         
        
        Note: this method clears the key binding for the
        :obj:`JComponent.WHEN_FOCUSED` and
        :obj:`JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT` focus conditions.
        
        :param javax.swing.JComponent component: the component for which to clear the key binding
        :param javax.swing.KeyStroke keyStroke: the keystroke of the binding to be cleared
        
        .. seealso::
        
            | :obj:`.clearKeyBinding(JComponent, KeyStroke, int)`
        """

    @staticmethod
    @typing.overload
    def clearKeyBinding(component: javax.swing.JComponent, keyStroke: javax.swing.KeyStroke, focusCondition: typing.Union[jpype.JInt, int]):
        """
        Allows clients to clear Java key bindings. This is useful when your
        application is using tool-level key bindings that share the same
        keystroke as a built-in Java action, such as Ctrl-C for the copy action.
        
        :param javax.swing.JComponent component: the component for which to clear the key binding
        :param javax.swing.KeyStroke keyStroke: the keystroke of the binding to be cleared
        :param jpype.JInt or int focusCondition: the particular focus condition under which the
                    given keystroke is used (see
                    :meth:`JComponent.getInputMap(int) <JComponent.getInputMap>`).
        """

    @staticmethod
    @typing.overload
    def clearKeyBinding(component: javax.swing.JComponent, actionName: typing.Union[java.lang.String, str]):
        """
        Clears the currently assigned Java key binding for the action by the given name.  This
        method will find the currently assigned key binding, if any, and then remove it.
        
        :param javax.swing.JComponent component: the component for which to clear the key binding
        :param java.lang.String or str actionName: the name of the action that should not have a key binding
        
        .. seealso::
        
            | :obj:`LookAndFeel`
        """

    @staticmethod
    def createOptionsforKeybindings(inputStream: java.io.InputStream) -> ghidra.framework.options.ToolOptions:
        """
        Imports key bindings from a location selected by the user.
         
        
        If there is a problem reading the data then the user will be shown an
        error dialog.
        
        :param java.io.InputStream inputStream: the input stream from which to read options
        :return: An options object that is composed of key binding names and their
                associated keystrokes.
        :rtype: ghidra.framework.options.ToolOptions
        """

    @staticmethod
    def exportKeyBindings(keyBindingOptions: ghidra.framework.options.ToolOptions):
        """
        Saves the key bindings from the provided options object to a file chosen
        by the user.
         
        
        If there is a problem writing the data then the user will be shown an
        error dialog.
        
        :param ghidra.framework.options.ToolOptions keyBindingOptions: The options that contains key binding data.
        """

    @staticmethod
    def getAction(component: javax.swing.JComponent, keyStroke: javax.swing.KeyStroke, focusCondition: typing.Union[jpype.JInt, int]) -> javax.swing.Action:
        """
        Returns the registered action for the given keystroke, or null of no
        action is bound to that keystroke.
        
        :param javax.swing.JComponent component: the component for which to check the binding
        :param javax.swing.KeyStroke keyStroke: the keystroke for which to find a bound action
        :param jpype.JInt or int focusCondition: the focus condition under which to check for the
                    binding (:meth:`JComponent.getInputMap(int) <JComponent.getInputMap>`)
        :return: the action registered to the given keystroke, or null of no
                action is registered
        :rtype: javax.swing.Action
        """

    @staticmethod
    def getActions(allActions: java.util.Set[docking.action.DockingActionIf], owner: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> java.util.Set[docking.action.DockingActionIf]:
        """
        Returns all actions that match the given owner and name
        
        :param java.util.Set[docking.action.DockingActionIf] allActions: the universe of actions
        :param java.lang.String or str owner: the owner
        :param java.lang.String or str name: the name
        :return: the actions
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    @staticmethod
    def getAllActionsByFullName(tool: docking.Tool) -> java.util.Map[java.lang.String, java.util.List[docking.action.DockingActionIf]]:
        """
        A utility method to get all key binding actions.  This method will
        only return actions that support :obj:`key bindings <KeyBindingType>`.
        
         
        The mapping returned provides a list of items because it is possible for there to
        exists multiple actions with the same name and owner.  (This can happen when multiple copies
        of a component provider are shown, each with their own set of actions that share the
        same name.)
        
        :param docking.Tool tool: the tool containing the actions
        :return: the actions mapped by their full name (e.g., 'Name (OwnerName)')
        :rtype: java.util.Map[java.lang.String, java.util.List[docking.action.DockingActionIf]]
        """

    @staticmethod
    def getKeyBindingActionsForOwner(tool: docking.Tool, owner: typing.Union[java.lang.String, str]) -> java.util.Set[docking.action.DockingActionIf]:
        """
        A utility method to get all key binding actions that have the given owner.
        This method will remove duplicate actions and will only return actions
        that support :obj:`key bindings <KeyBindingType>`.
        
        :param docking.Tool tool: the tool containing the actions
        :param java.lang.String or str owner: the action owner name
        :return: the actions
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    @staticmethod
    def importKeyBindings() -> ghidra.framework.options.ToolOptions:
        ...

    @staticmethod
    @typing.overload
    def parseKeyStroke(keyStroke: javax.swing.KeyStroke) -> str:
        """
        Convert the toString() form of the keyStroke.
         
        In Java 1.4.2 and earlier, Ctrl-M is returned as "keyCode CtrlM-P"
        and we want it to look like: "Ctrl-M".
         
        In Java 1.5.0, Ctrl-M is returned as "ctrl pressed M"
        and we want it to look like: "Ctrl-M".
         
        In Java 11 we have seen toString() values get printed with repeated text, such
        as: "shift ctrl pressed SHIFT".  We want to trim off the repeated modifiers.
        
        :param javax.swing.KeyStroke keyStroke: the key stroke
        :return: the string value; the empty string if the key stroke is null
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def parseKeyStroke(keyStroke: typing.Union[java.lang.String, str]) -> javax.swing.KeyStroke:
        """
        Parses the given text into a KeyStroke.  This method relies upon
        :meth:`KeyStroke.getKeyStroke(String) <KeyStroke.getKeyStroke>` for parsing.  Before making that call, this method
        will perform fixup on the given text for added flexibility.  For example, the given
        text may contain spaces or dashes as the separators between parts in the string.  Also,
        the text is converted such that it is not case-sensitive.  So, the following example
        formats are allowed:
         
            Alt-F
            alt p
            Ctrl-Alt-Z
            ctrl Z
         
        
         
        **Note:** The returned keystroke will always correspond to a ``pressed`` event,
        regardless of the value passed in (pressed, typed or released).
        
        :param java.lang.String or str keyStroke: the key stroke
        :return: the new key stroke (as returned by  :meth:`KeyStroke.getKeyStroke(String) <KeyStroke.getKeyStroke>`
        :rtype: javax.swing.KeyStroke
        """

    @staticmethod
    @typing.overload
    def registerAction(component: javax.swing.JComponent, action: docking.action.DockingAction):
        """
        A convenience method to register the given action with the given
        component. This is not usually done, as the action system is usually
        managed by the application's tool. However, for actions that are not
        registered with a tool, they can instead be bound to a component, hence
        this method.
         
        
        The given action must have a keystroke assigned, or this method will do
        nothing.
        
        :param javax.swing.JComponent component: the component to which the given action will be bound
        :param docking.action.DockingAction action: the action to bind
        """

    @staticmethod
    @typing.overload
    def registerAction(component: javax.swing.JComponent, action: docking.action.DockingAction, contextProvider: docking.action.ActionContextProvider):
        """
        A convenience method to register the given action with the given
        component. This is not usually done, as the action system is usually
        managed by the application's tool. However, for actions that are not
        registered with a tool, they can instead be bound to a component, hence
        this method.
         
        
        The given action must have a keystroke assigned, or this method will do
        nothing.
        
         
        
        A typical use-case is to register an existing docking action with a text
        component, which is needed because the docking key event processing will
        not execute docking- registered actions if a text component has focus.
        
        :param javax.swing.JComponent component: the component to which the given action will be bound
        :param docking.action.DockingAction action: the action to bind
        :param docking.action.ActionContextProvider contextProvider: the provider of the context
        """

    @staticmethod
    @typing.overload
    def registerAction(component: javax.swing.JComponent, action: docking.action.DockingAction, contextProvider: docking.action.ActionContextProvider, focusCondition: typing.Union[jpype.JInt, int]):
        """
        A convenience method to register the given action with the given
        component. This is not usually done, as the action system is usually
        managed by the application's tool. However, for actions that are not
        registered with a tool, they can instead be bound to a component, hence
        this method.
         
        
        The given action must have a keystroke assigned, or this method will do
        nothing.
        
         
        
        A typical use-case is to register an existing docking action with a text
        component, which is needed because the docking key event processing will
        not execute docking- registered actions if a text component has focus.
        
        :param javax.swing.JComponent component: the component to which the given action will be bound
        :param docking.action.DockingAction action: the action to bind
        :param docking.action.ActionContextProvider contextProvider: the provider of the context
        :param jpype.JInt or int focusCondition: see :obj:`JComponent` for more info; the default
                    is usually :obj:`JComponent.WHEN_FOCUSED`
        """

    @staticmethod
    @typing.overload
    def registerAction(component: javax.swing.JComponent, keyStroke: javax.swing.KeyStroke, action: javax.swing.Action, focusCondition: typing.Union[jpype.JInt, int]):
        """
        Registers the given action with the given key binding on the given
        component.
        
        :param javax.swing.JComponent component: the component to which the action will be registered
        :param javax.swing.KeyStroke keyStroke: the keystroke for to which the action will be bound
        :param javax.swing.Action action: the action to execute when the given keystroke is triggered
        :param jpype.JInt or int focusCondition: the focus condition under which to bind the action
                    (:meth:`JComponent.getInputMap(int) <JComponent.getInputMap>`).  See :obj:`JComponent` for more info;
                    the default is usually :obj:`JComponent.WHEN_FOCUSED`
        """

    @staticmethod
    def retargetEvent(newSource: java.awt.Component, e: java.awt.event.KeyEvent):
        """
        Changes the given key event to the new source component and then dispatches that event.
        This method is intended for clients that wish to effectively take a key event given to
        one component and give it to another component.
        
         
        This method exists to deal with the complicated nature of key event processing and
        how our (not Java's) framework processes key event bindings to trigger actions.  If not
        for our special processing of action key bindings, then this method would not be
        necessary.
        
         
        **This is seldom-used code; if you don't know when to use this code, then don't.**
        
        :param java.awt.Component newSource: the new target of the event
        :param java.awt.event.KeyEvent e: the existing event
        """

    @staticmethod
    def validateKeyStroke(keyStroke: javax.swing.KeyStroke) -> javax.swing.KeyStroke:
        """
        Updates the given data with system-independent versions of key modifiers.  For example,
        the ``control`` key will be converted to the ``command`` key on the Mac.
        
        :param javax.swing.KeyStroke keyStroke: the keystroke to validate
        :return: the potentially changed keystroke
        :rtype: javax.swing.KeyStroke
        """


class PopupActionProvider(java.lang.Object):
    """
    Provides notification when the popup action menu is displayed.   This interface allows 
    temporary/transient actions (those not registered with the tool via 
    :meth:`Tool.addAction(DockingActionIf) <Tool.addAction>`) to be used in the popup context menu.   
     
     
    
    Most clients will register actions directly with the tool.   However, clients that have numerous
    actions that vary greatly with the context can use this method to only create those actions
    on demand as the popup is about to be shown, and only if their context is active.   This 
    mechanism can reduce the tool's action management overhead.    Once you have created an
    implementation of this class, you must register it with
    :meth:`Tool.addPopupActionProvider(PopupActionProvider) <Tool.addPopupActionProvider>`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def getPopupActions(self, tool: docking.Tool, context: docking.ActionContext) -> java.util.List[docking.action.DockingActionIf]:
        """
        Provides notification that the popup menu is about to be displayed and allows a set of 
        temporary actions to be included in the popup menu.  Actions returned will be 
        included in the menu if they have a valid popup menu path and respond true to the 
        :meth:`DockingActionIf.isValidContext(ActionContext) <DockingActionIf.isValidContext>` call.
        
        :param docking.Tool tool: the tool requesting the actions
        :param docking.ActionContext context: the ActionContext
        :return: list of temporary popup actions; return null if there are no popup actions
        :rtype: java.util.List[docking.action.DockingActionIf]
        """


class SharedActionRegistry(java.lang.Object):
    """
    A place used to hold :obj:`DockingActionIf`s that are meant to be used by components.  Some
    components do not have access to the tool that is required to register their actions.  This
    class helps those components by enabling the installation of shared actions for those
    components.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def installSharedActions(tool: docking.Tool, toolActions: ToolActions):
        """
        Install all known shared actions into the given tool
        
        :param docking.Tool tool: the tool
        :param ToolActions toolActions: the tool action manager
        """


class KeyBindings(java.lang.Object):
    """
    An object that maps actions to key strokes and mouse bindings.
     
    
    This class knows how to load all system actions and how to load any key and mouse bindings for
    those actions from the tool's options.   Clients can make changes to the state of this class that
    can then be applied to the system by calling :meth:`applyChanges() <.applyChanges>`.
    """

    @typing.type_check_only
    class ActionKeyBindingState(java.lang.Object):
        """
        A class to store current and original values for key strokes and mouse bindings.  This is 
        used to apply changes and restore default values.
        """

        class_: typing.ClassVar[java.lang.Class]

        def apply(self, keyStrokeOptions: ghidra.framework.options.ToolOptions):
            ...

        def cancelChanges(self):
            ...

        def getCurrentKeyStroke(self) -> javax.swing.KeyStroke:
            ...

        def getCurrentMouseBinding(self) -> gui.event.MouseBinding:
            ...

        def getRepresentativeAction(self) -> docking.action.DockingActionIf:
            ...

        def restore(self, options: ghidra.framework.options.ToolOptions):
            ...

        def setCurrentKeyStroke(self, newKeyStroke: javax.swing.KeyStroke):
            ...

        def setCurrentMouseBinding(self, newMouseBinding: gui.event.MouseBinding):
            ...

        @property
        def currentMouseBinding(self) -> gui.event.MouseBinding:
            ...

        @currentMouseBinding.setter
        def currentMouseBinding(self, value: gui.event.MouseBinding):
            ...

        @property
        def currentKeyStroke(self) -> javax.swing.KeyStroke:
            ...

        @currentKeyStroke.setter
        def currentKeyStroke(self, value: javax.swing.KeyStroke):
            ...

        @property
        def representativeAction(self) -> docking.action.DockingActionIf:
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tool: docking.Tool):
        ...

    def applyChanges(self):
        """
        Applies any pending changes.
        """

    def cancelChanges(self):
        """
        Cancels any pending changes that have not yet been applied.
        """

    def containsAction(self, fullName: typing.Union[java.lang.String, str]) -> bool:
        ...

    def getActionForMouseBinding(self, mouseBinding: gui.event.MouseBinding) -> str:
        ...

    def getActionsForKeyStrokeText(self, keyStroke: javax.swing.KeyStroke) -> str:
        ...

    def getKeyStroke(self, fullName: typing.Union[java.lang.String, str]) -> javax.swing.KeyStroke:
        ...

    def getKeyStrokesByFullActionName(self) -> java.util.Map[java.lang.String, javax.swing.KeyStroke]:
        ...

    def getLongestActionName(self) -> str:
        ...

    def getMouseBinding(self, fullName: typing.Union[java.lang.String, str]) -> gui.event.MouseBinding:
        ...

    def getUniqueActions(self) -> java.util.List[docking.action.DockingActionIf]:
        ...

    def isMouseBindingInUse(self, fullName: typing.Union[java.lang.String, str], newBinding: gui.event.MouseBinding) -> bool:
        ...

    def removeKeyStroke(self, fullName: typing.Union[java.lang.String, str]) -> bool:
        ...

    def restoreOptions(self):
        """
        Restores the tool options key bindings to the default values originally loaded when the
        system started.
        """

    def setActionKeyStroke(self, fullName: typing.Union[java.lang.String, str], newKs: javax.swing.KeyStroke) -> bool:
        ...

    def setActionMouseBinding(self, fullName: typing.Union[java.lang.String, str], newBinding: gui.event.MouseBinding) -> bool:
        ...

    @property
    def mouseBinding(self) -> gui.event.MouseBinding:
        ...

    @property
    def longestActionName(self) -> java.lang.String:
        ...

    @property
    def uniqueActions(self) -> java.util.List[docking.action.DockingActionIf]:
        ...

    @property
    def keyStroke(self) -> javax.swing.KeyStroke:
        ...

    @property
    def keyStrokesByFullActionName(self) -> java.util.Map[java.lang.String, javax.swing.KeyStroke]:
        ...

    @property
    def actionsForKeyStrokeText(self) -> java.lang.String:
        ...

    @property
    def actionForMouseBinding(self) -> java.lang.String:
        ...


class SetKeyBindingAction(docking.action.DockingAction):

    class_: typing.ClassVar[java.lang.Class]
    NAME: typing.ClassVar[java.lang.String]

    def __init__(self, tool: docking.Tool, keyStroke: javax.swing.KeyStroke):
        ...


class AutoGeneratedDockingAction(java.lang.Object):
    """
    A marker interface to signal that the implementing action is temporary and gets built 
    automatically by the tool
    """

    class_: typing.ClassVar[java.lang.Class]


class SharedStubKeyBindingAction(docking.action.DockingAction, ghidra.framework.options.OptionsChangeListener):
    """
    A stub action that allows key bindings to be edited through the key bindings options.  This 
    allows plugins to create actions that share keybindings without having to manage those 
    keybindings themselves.
     
     
    Some ways this class is used:
     
    1. As a central action to manage key bindings for multiple actions from different clients 
        (plugins) that are conceptually the same.  When the plugins are loaded
        these actions get registered and are wired to listen to key binding changes to this stub.
    
    2. As a placeholder action to manage key bindings for actions that have not yet been 
        registered and may not get registered during the lifetime of a single tool session.
        This can happen when a plugin has transient component providers that only get shown
        upon a user request.  This stub allows the key binding for those actions to be managed,
        even if they do not get registered when the tool is shown.
    
    
     
     
    Clients should not be using this class directly.
    """

    class_: typing.ClassVar[java.lang.Class]



__all__ = ["ActionAdapter", "SharedDockingActionPlaceholder", "KeyEntryDialog", "ToolActions", "DockingToolActions", "KeyBindingUtils", "PopupActionProvider", "SharedActionRegistry", "KeyBindings", "SetKeyBindingAction", "AutoGeneratedDockingAction", "SharedStubKeyBindingAction"]
