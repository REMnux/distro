from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.action
import docking.widgets
import docking.widgets.filechooser
import docking.widgets.table.threaded
import docking.widgets.tree
import generic.test
import ghidra.util
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class TestKeyEventDispatcher(java.lang.Object):
    """
    A class that helps to delegate key events to the system override key event dispatcher.  This
    class exists to avoid package restrictions.
    """

    @typing.type_check_only
    class TestFocusOwnerProvider(docking.FocusOwnerProvider):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def dispatchKeyEvent(event: java.awt.event.KeyEvent) -> bool:
        """
        Uses the system-overridden :obj:`KeyEventDispatcher` to send the event.
        
        :param java.awt.event.KeyEvent event: the event
        :return: false if the event was not handled by this class and should continue to be
                processed; true if the event was handled and no further processing is needed
        :rtype: bool
        """


class TestFailingErrorDisplayWrapper(ghidra.util.ErrorDisplay):
    """
    An error display wrapper that allows us to fail tests when errors are encountered.  This is 
    a way for us to fail for exceptions that come from client code, but are handled by the 
    error display service, while running tests.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def setErrorDisplayDelegate(self, delegate: ghidra.util.ErrorDisplay):
        ...


class AbstractDockingTest(generic.test.AbstractGuiTest):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def assertEnabled(component: javax.swing.JComponent, enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Checks the enablement state of a JComponent in a thread safe way.
        
        :param javax.swing.JComponent component: the component for which to check the enablement state.
        :param jpype.JBoolean or bool enabled: the expected enablement state for the component.
        """

    def assertIconsEqual(self, expected: javax.swing.Icon, actual: javax.swing.Icon):
        """
        Asserts that the two icons are or refer to the same icon (handles GIcon)
        
        :param javax.swing.Icon expected: the expected icon
        :param javax.swing.Icon actual: the actual icon
        """

    @staticmethod
    def assertToggleButtonSelected(button: javax.swing.JToggleButton, selected: typing.Union[jpype.JBoolean, bool]):
        """
        Checks the selected state of a JToggleButton in a thread safe way.
        
        :param javax.swing.JToggleButton button: the toggle button for which to check the selected state.
        :param jpype.JBoolean or bool selected: the expected state of the toggle button.
        """

    def capture(self, c: java.awt.Component, name: typing.Union[java.lang.String, str]):
        """
        Creates and writes to file an image of the given component.  The file will be written
        to the reports directory (this differs depending upon how the test was run), nested
        inside a directory structure of the form {test class name}/{test name}.  A console
        statement will be written indicating the location of the written file.
        
        :param java.awt.Component c: the component to capture
        :param java.lang.String or str name: the file name suffix
        :raises java.lang.Exception: if there is any issue capturing the component
        """

    @staticmethod
    @typing.overload
    def clickComponentProvider(provider: docking.ComponentProvider) -> java.awt.Component:
        """
        Performs a single left mouse click in the center of the given provider.  This is
        useful when trying to  make a provider the active provider, while making sure
        that one of the provider's components has focus.
        
        :param docking.ComponentProvider provider: The provider to click
        :return: the actual Java JComponent that was clicked.
        :rtype: java.awt.Component
        
        .. seealso::
        
            | :obj:`.clickComponentProvider(ComponentProvider, int, int, int, int, int, boolean)`
        """

    @staticmethod
    @typing.overload
    def clickComponentProvider(provider: docking.ComponentProvider, button: typing.Union[jpype.JInt, int], x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int], clickCount: typing.Union[jpype.JInt, int], modifiers: typing.Union[jpype.JInt, int], popupTrigger: typing.Union[jpype.JBoolean, bool]) -> java.awt.Component:
        """
        Clicks the JComponent at the given point from within the given provider.
        
        :param docking.ComponentProvider provider: The provider to be clicked.
        :param jpype.JInt or int button: The mouse button to use (left, center, right)
        :param jpype.JInt or int x: the x location of the click
        :param jpype.JInt or int y: the y location of the click
        :param jpype.JInt or int clickCount: the number of times to click
        :param jpype.JInt or int modifiers: the modifiers to apply (Ctrl, Alt, etc; 0 is none)
        :param jpype.JBoolean or bool popupTrigger: true if this click should show a popup menu
        :return: the actual Java JComponent that was clicked
        :rtype: java.awt.Component
        """

    @typing.overload
    def close(self, dialog: docking.DialogComponentProvider):
        ...

    @typing.overload
    def close(self, w: java.awt.Window):
        ...

    @staticmethod
    @typing.overload
    def closeAllWindows(showError: typing.Union[jpype.JBoolean, bool]):
        ...

    @staticmethod
    @typing.overload
    def closeAllWindows():
        """
        A convenience method to close all of the windows and frames that the current Java
        windowing environment knows about
        """

    @staticmethod
    @deprecated("instead call the new closeAllWindows()")
    def closeAllWindowsAndFrames():
        """
        A convenience method to close all of the windows and frames that the current Java
        windowing environment knows about
        
        
        .. deprecated::
        
        instead call the new :meth:`closeAllWindows() <.closeAllWindows>`
        """

    def closeProvider(self, p: docking.ComponentProvider):
        """
        Closes the given provider.  You could just call
        :meth:`Tool.removeComponentProvider(ComponentProvider) <Tool.removeComponentProvider>`, but some providers have extra
        logic that happens when :meth:`ComponentProvider.closeComponent() <ComponentProvider.closeComponent>` is called.   This will
        likely change in the future.
        
        :param docking.ComponentProvider p: the provider to close
        """

    @staticmethod
    def closeSaveChangesDialog():
        """
        Will try to close dialogs prompting for changes to be saved, whether from program changes
        or from tool config changes.
        """

    @typing.overload
    def createContext(self, contextObject: java.lang.Object) -> docking.ActionContext:
        """
        Creates a generic action context with no provider, with the given context object
        
        :param java.lang.Object contextObject: the generic object to put in the context
        :return: the new context
        :rtype: docking.ActionContext
        """

    @typing.overload
    def createContext(self, provider: docking.ComponentProvider, contextObject: java.lang.Object) -> docking.ActionContext:
        """
        Creates a generic action context with the given provider, with the given context object
        
        :param docking.ComponentProvider provider: the provider
        :param java.lang.Object contextObject: the generic object to put in the context
        :return: the new context
        :rtype: docking.ActionContext
        """

    @staticmethod
    def createRenderedImage(c: java.awt.Component) -> java.awt.Image:
        ...

    @staticmethod
    def createScreenImage(c: java.awt.Component) -> java.awt.Image:
        """
        Creates a png of the given component **by capturing a screenshot of the image**.  This
        differs from creating the image by rendering it via a :obj:`Graphics` object.
        
        :param java.awt.Component c: the component
        :return: the new image
        :rtype: java.awt.Image
        :raises AWTException: if there is a problem creating the image
        """

    @staticmethod
    def disposeErrorGUI():
        """
        Turns off the gui displays for errors.  This does not change the "isUseErrorGUI()" value for
        other tests in the TestCase.
        """

    def dockingSetUp(self):
        ...

    def dockingTearDown(self):
        ...

    @staticmethod
    def expandPath(tree: docking.widgets.tree.GTree, *path: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def expandTree(tree: docking.widgets.tree.GTree, *path: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def findButtonByActionName(container: java.awt.Container, name: typing.Union[java.lang.String, str]) -> javax.swing.JButton:
        ...

    @staticmethod
    def findButtonByIcon(provider: docking.DialogComponentProvider, icon: javax.swing.Icon) -> javax.swing.JButton:
        ...

    @staticmethod
    def findButtonByName(provider: docking.DialogComponentProvider, name: typing.Union[java.lang.String, str]) -> javax.swing.AbstractButton:
        """
        Searches the component and subcomponents of the indicated provider and returns the
        component with the specified name.
        
        :param docking.DialogComponentProvider provider: the provider of the component to search
        :param java.lang.String or str name: the name of the desired component
        :return: the component, or null if not found
        :rtype: javax.swing.AbstractButton
        """

    @staticmethod
    def findButtonByText(provider: docking.DialogComponentProvider, text: typing.Union[java.lang.String, str]) -> javax.swing.JButton:
        ...

    @staticmethod
    def findComponent(provider: docking.DialogComponentProvider, desiredClass: java.lang.Class[T]) -> T:
        """
        Returns the first :obj:`Component` of the given type inside of the given dialog
        
        :param docking.DialogComponentProvider provider: the dialog
        :param java.lang.Class[T] desiredClass: the class of the component
        :return: the component; null if none was found
        :rtype: T
        """

    @staticmethod
    def findComponentByName(provider: docking.DialogComponentProvider, name: typing.Union[java.lang.String, str]) -> java.awt.Component:
        """
        Searches the component and subcomponents of the indicated provider and returns the
        component with the specified name.
        
        :param docking.DialogComponentProvider provider: the provider of the component to search
        :param java.lang.String or str name: the name of the desired component
        :return: the component, or null if not found
        :rtype: java.awt.Component
        """

    @staticmethod
    @typing.overload
    def getAction(tool: docking.Tool, name: typing.Union[java.lang.String, str]) -> docking.action.DockingActionIf:
        """
        Finds the singular tool action by the given name.  If more than one action exists with
        that name, then an exception is thrown.  If you want more than one matching action,
        the call :meth:`getActionsByName(Tool, String) <.getActionsByName>` instead.
        
         
        Note: more specific test case subclasses provide other methods for finding actions
        when you have an owner name (which is usually the plugin name).
        
        :param docking.Tool tool: the tool containing all system actions
        :param java.lang.String or str name: the name to match
        :return: the matching action; null if no matching action can be found
        :rtype: docking.action.DockingActionIf
        """

    @staticmethod
    @typing.overload
    def getAction(tool: docking.Tool, owner: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> docking.action.DockingActionIf:
        """
        Finds the action by the given owner name and action name.
        If you do not know the owner name, then use
        the call :meth:`getActionsByName(Tool, String) <.getActionsByName>` instead  (this will not include
        reserved system actions).
        
         
        Note: more specific test case subclasses provide other methods for finding actions
        when you have an owner name (which is usually the plugin name).
        
        :param docking.Tool tool: the tool containing all system actions
        :param java.lang.String or str owner: the owner of the action
        :param java.lang.String or str name: the name to match
        :return: the matching action; null if no matching action can be found
        :rtype: docking.action.DockingActionIf
        """

    @staticmethod
    @typing.overload
    def getAction(provider: docking.DialogComponentProvider, actionName: typing.Union[java.lang.String, str]) -> docking.action.DockingActionIf:
        """
        Returns the given dialog's action that has the given name
        
        :param docking.DialogComponentProvider provider: the dialog provider
        :param java.lang.String or str actionName: the name of the action
        :return: the action
        :rtype: docking.action.DockingActionIf
        """

    @staticmethod
    def getActionsByName(tool: docking.Tool, name: typing.Union[java.lang.String, str]) -> java.util.Set[docking.action.DockingActionIf]:
        """
        A helper method to find all actions with the given name
        
        :param docking.Tool tool: the tool containing all system actions
        :param java.lang.String or str name: the name to match
        :return: the matching actions; empty list if no matches
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    @staticmethod
    def getActionsByOwner(tool: docking.Tool, name: typing.Union[java.lang.String, str]) -> java.util.Set[docking.action.DockingActionIf]:
        """
        A helper method to find all actions with the given owner's name (this will not include
        reserved system actions)
        
        :param docking.Tool tool: the tool containing all system actions
        :param java.lang.String or str name: the owner's name to match
        :return: the matching actions; empty list if no matches
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    @staticmethod
    def getActionsByOwnerAndName(tool: docking.Tool, owner: typing.Union[java.lang.String, str], name: typing.Union[java.lang.String, str]) -> java.util.Set[docking.action.DockingActionIf]:
        """
        A helper method to find all actions by name, with the given owner's name (this will not
        include reserved system actions)
        
        :param docking.Tool tool: the tool containing all system actions
        :param java.lang.String or str owner: the owner's name
        :param java.lang.String or str name: the owner's name to match
        :return: the matching actions; empty list if no matches
        :rtype: java.util.Set[docking.action.DockingActionIf]
        """

    def getClipboardText(self) -> str:
        """
        Gets any current text on the clipboard
        
        :return: the text on the clipboard; null if no text is on the clipboard
        :rtype: str
        :raises java.lang.Exception: if there are any issues copying from the clipboard
        """

    @staticmethod
    def getComponentProvider(clazz: java.lang.Class[T]) -> T:
        """
        Searches for the first occurrence of a :obj:`ComponentProvider` that is an instance of
        the given ``providerClass``.
        
        :param java.lang.Class[T] clazz: The class of the ComponentProvider to locate
        :return: The component provider, or null if one cannot be found
        :rtype: T
        """

    @staticmethod
    def getDialogComponent(ghidraClass: java.lang.Class[T]) -> T:
        """
        Gets a dialog component provider of the given type
        
        :param java.lang.Class[T] ghidraClass: the class of the desired :obj:`DialogComponentProvider`.
        :return: the dialog or null if it cannot be found
        :rtype: T
        """

    @staticmethod
    def getLocalAction(provider: docking.ComponentProvider, actionName: typing.Union[java.lang.String, str]) -> docking.action.DockingActionIf:
        """
        Returns the action by the given name that belongs to the given provider
        
        :param docking.ComponentProvider provider: the provider
        :param java.lang.String or str actionName: the action name
        :return: the action
        :rtype: docking.action.DockingActionIf
        """

    @staticmethod
    def getMessageText(w: java.awt.Window) -> str:
        """
        Check for and display message component text associated with OptionDialog windows
        
        :param java.awt.Window w: any window
        :return: the message string if one can be found; ``null`` otherwise
        :rtype: str
        """

    @staticmethod
    def getNode(tree: docking.widgets.tree.GTree, *path: typing.Union[java.lang.String, str]) -> docking.widgets.tree.GTreeNode:
        ...

    @staticmethod
    def getOpenWindowsAsString() -> str:
        """
        Returns a pretty-print string of all found windows that are showing, nesting by
        parent-child relationship.
        
        :return: the result string
        :rtype: str
        """

    @staticmethod
    def getStatusText(provider: docking.DialogComponentProvider) -> str:
        """
        Get the dialog provider's status text
        
        :param docking.DialogComponentProvider provider: dialog component provider
        :return: status text
        :rtype: str
        """

    @staticmethod
    def getTitleForWindow(window: java.awt.Window) -> str:
        ...

    def getURL(self, icon: javax.swing.Icon) -> java.net.URL:
        """
        Gets the URL for the given icon
        
        :param javax.swing.Icon icon: the icon to get a URL for
        :return: the URL for the given icon
        :rtype: java.net.URL
        """

    @staticmethod
    def getWindowByTitleContaining(parentWindow: java.awt.Window, text: typing.Union[java.lang.String, str]) -> java.awt.Window:
        ...

    @staticmethod
    @typing.overload
    def isEnabled(action: docking.action.DockingActionIf) -> bool:
        ...

    @staticmethod
    @typing.overload
    def isEnabled(action: docking.action.DockingActionIf, contextProvider: docking.action.ActionContextProvider) -> bool:
        ...

    @staticmethod
    @typing.overload
    def isEnabled(button: javax.swing.AbstractButton) -> bool:
        ...

    @staticmethod
    def isSelected(button: javax.swing.AbstractButton) -> bool:
        ...

    @staticmethod
    def isToggleButttonSelected(container: java.awt.Container, buttonName: typing.Union[java.lang.String, str]) -> bool:
        """
        Finds the toggle button with the given name inside of the given container and then
        gets the selected state of the button.
         
        
        Note: this works for any instanceof :obj:`JToggleButton`, such as:
         
        * :obj:`JCheckBox`
        * :obj:`JRadioButton`
        
        as well as :obj:`EmptyBorderToggleButton`s.
        
        :param java.awt.Container container: a container that has the desired button as a descendant
        :param java.lang.String or str buttonName: the name of the button (you must set this on the button when it is
                        constructed; if there is no button with the given name found, then this
                        method will search for a button with the given text
        :return: true if the button is selected
        :rtype: bool
        """

    @staticmethod
    def isUseErrorGUI() -> bool:
        ...

    @staticmethod
    @typing.overload
    def performAction(action: docking.action.DockingActionIf):
        """
        Performs the specified action within the Swing Thread.  This method will block until the
        action completes.  Do not use this method if the given actions triggers a modal
        dialog.  Instead, call :meth:`performAction(DockingActionIf, boolean) <.performAction>` with a false
        value.
        
         
        If the action results in a modal dialog, then call
        :meth:`performAction(DockingActionIf, boolean) <.performAction>` with a value of false.
        
        :param docking.action.DockingActionIf action: action to be performed (event will be null)
        """

    @staticmethod
    @typing.overload
    def performAction(action: docking.action.DockingActionIf, waitForCompletion: typing.Union[jpype.JBoolean, bool]):
        """
        Performs the specified action within the Swing Thread.  If the action results
        in a modal dialog, waitForCompletion must be false.
        
        :param docking.action.DockingActionIf action: action to be performed
        :param jpype.JBoolean or bool waitForCompletion: if true wait for action to complete before returning,
        otherwise schedule action to be performed and return immediately.
        """

    @staticmethod
    @typing.overload
    def performAction(action: docking.action.DockingActionIf, provider: docking.ComponentProvider, wait: typing.Union[jpype.JBoolean, bool]):
        """
        Performs the specified action with context within the Swing Thread.  If the action results
        in a modal dialog, waitForCompletion must be false.
        
        :param docking.action.DockingActionIf action: action to be performed
        :param docking.ComponentProvider provider: the component provider from which to get action context; if null,
                then an empty context will used
        :param jpype.JBoolean or bool wait: if true wait for action to complete before returning,
                otherwise schedule action to be performed and return immediately.
        """

    @staticmethod
    @typing.overload
    def performAction(action: docking.action.DockingActionIf, context: docking.ActionContext, wait: typing.Union[jpype.JBoolean, bool]):
        """
        Performs the specified action with context within the Swing Thread.  If the action results
        in a modal dialog, waitForCompletion must be false.
        
        :param docking.action.DockingActionIf action: action to be performed
        :param docking.ActionContext context: the context to use with the action
        :param jpype.JBoolean or bool wait: if true wait for action to complete before returning,
                otherwise schedule action to be performed and return immediately.
        """

    @staticmethod
    def performDialogAction(action: docking.action.DockingActionIf, provider: docking.DialogComponentProvider, wait: typing.Union[jpype.JBoolean, bool]):
        """
        Performs the specified action with context within the Swing Thread.  If the action results
        in a modal dialog, waitForCompletion must be false.
        
        :param docking.action.DockingActionIf action: action to be performed
        :param docking.DialogComponentProvider provider: the component provider from which to get action context
        :param jpype.JBoolean or bool wait: if true wait for action to complete before returning,
                otherwise schedule action to be performed and return immediately.
        """

    @staticmethod
    @typing.overload
    def pressButtonByText(provider: docking.DialogComponentProvider, buttonText: typing.Union[java.lang.String, str]):
        """
        Finds the button with the indicated TEXT that is a sub-component
        of the indicated container, and then programmatically presses
        the button.
         
        The following is a sample JUnit test use:
         
            env.showTool();
            OptionDialog dialog = (OptionDialog)env.waitForDialog(OptionDialog.class, 1000);
            assertNotNull(dialog);
            pressButtonByText(dialog, "OK");
         
        
        :param docking.DialogComponentProvider provider: the DialogComponentProvider containing the button.
        :param java.lang.String or str buttonText: the text on the desired JButton.
        """

    @staticmethod
    @typing.overload
    def pressButtonByText(provider: docking.DialogComponentProvider, buttonText: typing.Union[java.lang.String, str], waitForCompletion: typing.Union[jpype.JBoolean, bool]):
        """
        Finds the button with the indicated TEXT that is a sub-component
        of the indicated container, and then programmatically presses
        the button.
        
        :param docking.DialogComponentProvider provider: the DialogComponentProvider containing the button.
        :param java.lang.String or str buttonText: the text on the desired JButton.
        :param jpype.JBoolean or bool waitForCompletion: if true wait for action to complete before returning,
        otherwise schedule action to be performed and return immediately.
        """

    @staticmethod
    def printOpenWindows():
        """
        Prints all found windows that are showing, nesting by parent-child relationship.
        """

    @staticmethod
    def selectPath(tree: docking.widgets.tree.GTree, *path: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def setErrorGUIEnabled(enable: typing.Union[jpype.JBoolean, bool]):
        """
        By default Ghidra will use a modal error dialog to display errors when running tests.  This
        method should be used to disable this feature, as opposed to calling:
         
            Err.setErrorDisplay( new ConsoleErrorDisplay() );
         
        
        :param jpype.JBoolean or bool enable: true to use the GUI; false to use the error console
        """

    @staticmethod
    @typing.overload
    def setToggleActionSelected(toggleAction: docking.action.ToggleDockingActionIf, context: docking.ActionContext, selected: typing.Union[jpype.JBoolean, bool]):
        """
        Ensures the given toggle action is in the given selected state.  If it is not, then the
        action will be performed.  This call will wait for the action to finish.
        
        :param docking.action.ToggleDockingActionIf toggleAction: the action
        :param docking.ActionContext context: the context for the action
        :param jpype.JBoolean or bool selected: true if the action is to be selected; false for not selected
        """

    @staticmethod
    @typing.overload
    def setToggleActionSelected(toggleAction: docking.action.ToggleDockingActionIf, context: docking.ActionContext, selected: typing.Union[jpype.JBoolean, bool], wait: typing.Union[jpype.JBoolean, bool]):
        """
        Ensures the given toggle action is in the given selected state.  If it is not, then the
        action will be performed.  This call will wait for the action to finish.
        
        :param docking.action.ToggleDockingActionIf toggleAction: the action
        :param docking.ActionContext context: the context for the action
        :param jpype.JBoolean or bool selected: true if the action is to be selected; false for not selected
        :param jpype.JBoolean or bool wait: true to wait for the action to finish; false to invoke later
        """

    @staticmethod
    @typing.overload
    def setToggleButtonSelected(container: java.awt.Container, buttonName: typing.Union[java.lang.String, str], selected: typing.Union[jpype.JBoolean, bool]):
        """
        Finds the toggle button with the given name inside of the given container and then
        ensures that the selected state of the button matches ``selected``.
         
        
        Note: this works for any instanceof :obj:`JToggleButton`, such as:
         
        * :obj:`JCheckBox`
        * :obj:`JRadioButton`
        
        as well as :obj:`EmptyBorderToggleButton`s.
        
        :param java.awt.Container container: a container that has the desired button as a descendant
        :param java.lang.String or str buttonName: the name of the button (you must set this on the button when it is
                        constructed; if there is no button with the given name found, then this
                        method will search for a button with the given text
        :param jpype.JBoolean or bool selected: true to toggle the button to selected; false for de-selected
        """

    @staticmethod
    @typing.overload
    def setToggleButtonSelected(button: javax.swing.AbstractButton, selected: typing.Union[jpype.JBoolean, bool]):
        """
        Ensures that the selected state of the button matches ``selected``.
         
        
        Note: this works for most toggle button implementations which are derived from
        AbstractButton and relay on :meth:`AbstractButton.isSelected() <AbstractButton.isSelected>` and
        :meth:`AbstractButton.doClick() <AbstractButton.doClick>` for toggling, such as:
         
        * :obj:`JCheckBox`
        * :obj:`JRadioButton`
        * :obj:`EmptyBorderToggleButton`
        
        
        :param javax.swing.AbstractButton button: the button to select
        :param jpype.JBoolean or bool selected: true to toggle the button to selected; false for de-selected
        """

    def showProvider(self, tool: docking.Tool, name: typing.Union[java.lang.String, str]) -> docking.ComponentProvider:
        """
        Shows the provider by the given name.
        
        :param docking.Tool tool: the tool in which the provider lives
        :param java.lang.String or str name: the name of the provider to show
        :return: the newly shown provider
        :rtype: docking.ComponentProvider
        """

    @staticmethod
    @typing.overload
    def triggerActionKey(c: java.awt.Component, modifiers: typing.Union[jpype.JInt, int], keyCode: typing.Union[jpype.JInt, int]):
        """
        Simulates a user typing a single key.
        
        This method should used for the special keyboard keys
        (ARROW, F1, END, etc) and alpha keys when associated with actions.
        
        :param java.awt.Component c: the component that should be the receiver of the key event; the event source
        :param jpype.JInt or int modifiers: the modifier keys down during event (shift, ctrl, alt, meta)
                        Either extended _DOWN_MASK or old _MASK modifiers
                        should be used, but both models should not be mixed
                        in one event. Use of the extended modifiers is
                        preferred.
        :param jpype.JInt or int keyCode: the integer code for an actual key.
        """

    @staticmethod
    @typing.overload
    def triggerActionKey(destination: java.awt.Component, action: docking.action.DockingActionIf):
        """
        Simulates a user initiated keystroke using the keybinding of the given action
        
        :param java.awt.Component destination: the component for the action being executed
        :param docking.action.DockingActionIf action: The action to simulate pressing
        """

    @staticmethod
    def triggerBackspace(c: java.awt.Component):
        ...

    @staticmethod
    def triggerEnter(c: java.awt.Component):
        """
        Simulates the user pressing the 'Enter' key on the given text field
        
        :param java.awt.Component c: the component
        """

    @staticmethod
    def triggerEscape(c: java.awt.Component):
        ...

    @staticmethod
    @typing.overload
    def triggerKey(c: java.awt.Component, ks: javax.swing.KeyStroke):
        """
        Fires a :meth:`KeyListener.keyPressed(KeyEvent) <KeyListener.keyPressed>`,
        :meth:`KeyListener.keyTyped(KeyEvent) <KeyListener.keyTyped>`
        and :meth:`KeyListener.keyReleased(KeyEvent) <KeyListener.keyReleased>` for the given key stroke
        
        :param java.awt.Component c: the destination component
        :param javax.swing.KeyStroke ks: the key stroke
        """

    @staticmethod
    @typing.overload
    def triggerKey(c: java.awt.Component, modifiers: typing.Union[jpype.JInt, int], keyCode: typing.Union[jpype.JInt, int], keyChar: typing.Union[jpype.JChar, int, str]):
        """
        Fires a :meth:`KeyListener.keyPressed(KeyEvent) <KeyListener.keyPressed>`, :meth:`KeyListener.keyTyped(KeyEvent) <KeyListener.keyTyped>`
        and :meth:`KeyListener.keyReleased(KeyEvent) <KeyListener.keyReleased>` for the given key code and char.
        
         
        If the key you need is not a character, but is an action, pass
        :obj:`KeyEvent.CHAR_UNDEFINED` for the ``keyChar`` parameter.
        
        :param java.awt.Component c: the destination component
        :param jpype.JInt or int modifiers: any modifiers, like Control
        :param jpype.JInt or int keyCode: the key code (see :obj:`KeyEvent`'s VK_xyz values)
        :param jpype.JChar or int or str keyChar: the key char or :obj:`KeyEvent.CHAR_UNDEFINED`
        """

    @staticmethod
    @typing.overload
    def triggerKey(c: java.awt.Component, modifiers: typing.Union[jpype.JInt, int], keyCode: typing.Union[jpype.JInt, int], keyChar: typing.Union[jpype.JChar, int, str], consumer: java.util.function.BiConsumer[java.awt.Component, java.awt.event.KeyEvent]):
        ...

    @staticmethod
    @typing.overload
    def triggerText(destination: java.awt.Component, string: typing.Union[java.lang.String, str]):
        """
        Types the indicated string using the
        :meth:`triggerKey(Component, int, int, char) <.triggerKey>` method.
        
        This method should be used when typing into
        text components. For example, JTextFields and JTextAreas.
        All three events are fired, KEY_PRESSED, KEY_TYPED, and KEY_RELEASED.
        
         
        Note: Handles the following characters:
         
        
         
        ABCDEFGHIJKLMNOPQRSTUVWXYZ
         
        abcdefghijklmnopqrstuvwxyz
         
        `1234567890-=[]\;',./
         
        ~!@#$%^&*()_+{}|:"<>?
         
        
         
        It also handles '\n', '\t', and '\b'.
        
        :param java.awt.Component destination: the component to receive the events
        :param java.lang.String or str string: the string to be typed.
        """

    @staticmethod
    @typing.overload
    def triggerText(destination: java.awt.Component, string: typing.Union[java.lang.String, str], consumer: java.util.function.BiConsumer[java.awt.Component, java.awt.event.KeyEvent]):
        """
        Types the indicated string using the
        :meth:`triggerKey(Component, int, int, char) <.triggerKey>` method.
        
        This method should be used when typing into
        text components. For example, JTextFields and JTextAreas.
        All three events are fired, KEY_PRESSED, KEY_TYPED, and KEY_RELEASED.
        
         
        Note: Handles the following characters:
         
        
         
        ABCDEFGHIJKLMNOPQRSTUVWXYZ
         
        abcdefghijklmnopqrstuvwxyz
         
        `1234567890-=[]\;',./
         
        ~!@#$%^&*()_+{}|:"<>?
         
        
         
        It also handles '\n', '\t', and '\b'.
        
        :param java.awt.Component destination: the component to receive the events
        :param java.lang.String or str string: the string to be typed.
        :param java.util.function.BiConsumer[java.awt.Component, java.awt.event.KeyEvent] consumer: the consumer of the text to be generated
        """

    @staticmethod
    @typing.overload
    def waitForComponentProvider(clazz: java.lang.Class[T]) -> T:
        """
        Searches for the first occurrence of a :obj:`ComponentProvider` that is an instance of
        the given ``providerClass``.  This method will repeat the search every
        :obj:`.DEFAULT_WAIT_DELAY` milliseconds
        until the provider is found, or the maximum number of searches has been reached, where
        ``maximum number of searches = MaxTimeMS / :obj:`.DEFAULT_WAIT_DELAY```
        
        :param java.lang.Class[T] clazz: The class of the ComponentProvider to locate
        :return: The component provider, or null if one cannot be found
        :rtype: T
        """

    @staticmethod
    @typing.overload
    def waitForComponentProvider(clazz: java.lang.Class[T], title: typing.Union[java.lang.String, str]) -> T:
        """
        Allows you to find a component provider **with the given title**.  Most plugins will
        only ever have a single provider.   In those cases, use
        :meth:`waitForComponentProvider(Class) <.waitForComponentProvider>`.  This version of that method is to allow you to
        differentiate between multiple instances of a given provider that have different titles.
        
        :param java.lang.Class[T] clazz: The class of the ComponentProvider to locate
        :param java.lang.String or str title: the title of the component provider
        :return: The component provider, or null if one cannot be found
        :rtype: T
        """

    @staticmethod
    @typing.overload
    @deprecated("Instead call one of the methods that does not take a timeout\n             (we are standardizing timeouts).  The timeouts passed to this method will\n             be ignored in favor of the standard value.")
    def waitForComponentProvider(parentWindow: java.awt.Window, providerClass: java.lang.Class[T], maxTimeMS: typing.Union[jpype.JInt, int]) -> T:
        """
        Searches for the first occurrence of a :obj:`ComponentProvider` that is an instance of
        the given ``providerClass``.  This method will repeat the search every
        :obj:`.DEFAULT_WAIT_DELAY` milliseconds
        until the provider is found, or the maximum number of searches has been reached, where
        ``maximum number of searches = MaxTimeMS / :obj:`.DEFAULT_WAIT_DELAY```
        
        :param java.awt.Window parentWindow: The window that will become the parent window of the provider (this is
                typically the tool's frame).
        :param java.lang.Class[T] providerClass: The class of the ComponentProvider to locate.
        :param jpype.JInt or int maxTimeMS: The maximum amount of time to wait.  This is an approximation (see above).
        :return: The component provider, or null if one cannot be found
        :rtype: T
        
        .. deprecated::
        
        Instead call one of the methods that does not take a timeout
                    (we are standardizing timeouts).  The timeouts passed to this method will
                    be ignored in favor of the standard value.
        """

    @staticmethod
    @typing.overload
    def waitForDialogComponent(title: typing.Union[java.lang.String, str]) -> docking.DialogComponentProvider:
        """
        Returns the :obj:`DialogComponentProvider` with the given title.  This method is
        not preferred, but instead you should use a :meth:`waitForDialogComponent(Class) <.waitForDialogComponent>`
        that takes a class so that you can get the correct return type.  This method is meant
        for clients that need a dialog, but that type is private of package restricted and thus
        cannot be referenced by a test.   Also, code that relies on a title is more subject to
        breaking when code is refactored; code that relies on class types will get refactored
        along side the referenced code.
        
         
        This method will fail if no dialog can be found
        
        :param java.lang.String or str title: the title of the desired dialog
        :return: the dialog
        :rtype: docking.DialogComponentProvider
        """

    @staticmethod
    @typing.overload
    def waitForDialogComponent(ghidraClass: java.lang.Class[T]) -> T:
        """
        Waits for the first window of the given class.
        
        :param java.lang.Class[T] ghidraClass: The class of the dialog the user desires
        :return: The first occurrence of a dialog that extends the given ``ghidraClass``
        :rtype: T
        
        .. seealso::
        
            | :obj:`.waitForDialogComponent(Window, Class, int)`
        """

    @staticmethod
    @typing.overload
    @deprecated("Instead call one of the methods that does not take a timeout\n             (we are standardizing timeouts).  The timeouts passed to this method will\n             be ignored in favor of the standard value.")
    def waitForDialogComponent(parentWindow: java.awt.Window, clazz: java.lang.Class[T], timeoutMS: typing.Union[jpype.JInt, int]) -> T:
        """
        Waits for the first window of the given class.  This method assumes that the desired dialog
        is parented by ``parentWindow``.
        
        :param java.awt.Window parentWindow: The parent of the desired dialog; may be null
        :param java.lang.Class[T] clazz: The class of the dialog the user desires
        :param jpype.JInt or int timeoutMS: The max amount of time in milliseconds to wait for the requested dialog
                to appear.
        :return: The first occurrence of a dialog that extends the given ``ghidraClass``
        :rtype: T
        
        .. deprecated::
        
        Instead call one of the methods that does not take a timeout
                    (we are standardizing timeouts).  The timeouts passed to this method will
                    be ignored in favor of the standard value.
        """

    @staticmethod
    def waitForErrorDialog() -> docking.AbstractErrDialog:
        """
        Waits for the system error dialog to appear
        
        :return: the dialog
        :rtype: docking.AbstractErrDialog
        """

    @staticmethod
    def waitForInfoDialog() -> docking.widgets.OkDialog:
        """
        Waits for the system info dialog to appear
        
        :return: the dialog
        :rtype: docking.widgets.OkDialog
        """

    @staticmethod
    @typing.overload
    def waitForJDialog(title: typing.Union[java.lang.String, str]) -> javax.swing.JDialog:
        """
        Waits for the JDialog with the given title
         
        
        Note: Sometimes the task dialog might have the same title as the dialog you pop up and
        you want to get yours instead of the one for the task monitor.
        
        :param java.lang.String or str title: the title of the dialog
        :return: the dialog
        :rtype: javax.swing.JDialog
        """

    @staticmethod
    @typing.overload
    @deprecated("use waitForJDialog(String) instead")
    def waitForJDialog(window: java.awt.Window, title: typing.Union[java.lang.String, str], timeoutMS: typing.Union[jpype.JInt, int]) -> javax.swing.JDialog:
        """
        Waits for the JDialog with the indicated title and that is parented to the indicated window
         
        
        Note: Sometimes the task dialog might have the same title as the dialog you pop up and
        you want to get yours instead of the one for the task monitor.
        
        :param java.awt.Window window: the parent window
        :param java.lang.String or str title: the title of the dialog
        :param jpype.JInt or int timeoutMS: Maximum time to wait for the dialog
        :return: the dialog
        :rtype: javax.swing.JDialog
        
        .. deprecated::
        
        use :meth:`waitForJDialog(String) <.waitForJDialog>` instead
        """

    @staticmethod
    def waitForTableModel(model: docking.widgets.table.threaded.ThreadedTableModel[T, typing.Any]):
        ...

    @staticmethod
    def waitForTree(gTree: docking.widgets.tree.GTree):
        ...

    @staticmethod
    def waitForUpdateOnChooser(chooser: docking.widgets.filechooser.GhidraFileChooser):
        ...

    @staticmethod
    @typing.overload
    def waitForWindow(windowClass: java.lang.Class[typing.Any]) -> java.awt.Window:
        ...

    @staticmethod
    @typing.overload
    @deprecated("Instead call one of the methods that does not take a timeout\n             (we are standardizing timeouts).  The timeouts passed to this method will\n             be ignored in favor of the standard value.")
    def waitForWindow(title: typing.Union[java.lang.String, str], timeoutMS: typing.Union[jpype.JInt, int]) -> java.awt.Window:
        """
        Waits for a window with the given name.
        
        :param java.lang.String or str title: The title of the window for which to search
        :param jpype.JInt or int timeoutMS: The timeout after which this method will wait no more
        :return: The window, if found, null otherwise.
        :rtype: java.awt.Window
        
        .. deprecated::
        
        Instead call one of the methods that does not take a timeout
                    (we are standardizing timeouts).  The timeouts passed to this method will
                    be ignored in favor of the standard value.
        """

    @staticmethod
    @typing.overload
    def waitForWindow(title: typing.Union[java.lang.String, str]) -> java.awt.Window:
        """
        Waits for a window with the given name
        
        :param java.lang.String or str title: The title of the window for which to search
        :return: The window, if found, null otherwise.
        :rtype: java.awt.Window
        """

    @staticmethod
    def waitForWindowByName(name: typing.Union[java.lang.String, str]) -> java.awt.Window:
        """
        Waits for a window with the given name.
        
        :param java.lang.String or str name: The name of the window for which to search
        :return: The window, if found, null otherwise
        :rtype: java.awt.Window
        """

    @staticmethod
    def waitForWindowByTitleContaining(text: typing.Union[java.lang.String, str]) -> java.awt.Window:
        ...

    @staticmethod
    def writeImage(image: java.awt.Image, imageFile: jpype.protocol.SupportsPath):
        """
        Writes the given image to the given file
        
        :param java.awt.Image image: the image
        :param jpype.protocol.SupportsPath imageFile: the file
        :raises IOException: if there is any issue writing the image
        """

    @property
    def clipboardText(self) -> java.lang.String:
        ...

    @property
    def uRL(self) -> java.net.URL:
        ...



__all__ = ["TestKeyEventDispatcher", "TestFailingErrorDisplayWrapper", "AbstractDockingTest"]
