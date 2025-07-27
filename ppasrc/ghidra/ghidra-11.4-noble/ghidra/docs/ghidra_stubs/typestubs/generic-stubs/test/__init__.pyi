from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.lang.reflect # type: ignore
import java.util # type: ignore
import java.util.concurrent # type: ignore
import java.util.concurrent.atomic # type: ignore
import java.util.function # type: ignore
import javax.swing # type: ignore
import javax.swing.table # type: ignore
import javax.swing.text # type: ignore
import javax.swing.tree # type: ignore
import org.junit.rules # type: ignore
import org.junit.runners.model # type: ignore
import utility.function


E = typing.TypeVar("E")
T = typing.TypeVar("T")


class AbstractGuiTest(AbstractGenericTest):
    """
    Base class for tests that need swing support methods. Tests that don't involve Swing/Gui elements
    should use AbstractGenericTest instead
    """

    @typing.type_check_only
    class ExceptionHandlingRunner(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def assertColorsEqual(self, expected: java.awt.Color, actual: java.awt.Color):
        """
        Asserts that the two colors have the same rgb values (handles GColor)
        
        :param java.awt.Color expected: the expected color
        :param java.awt.Color actual: the actual color
        """

    @staticmethod
    def clickListRange(list: javax.swing.JList[typing.Any], row: typing.Union[jpype.JInt, int], count: typing.Union[jpype.JInt, int]):
        """
        Clicks a range of items in a list (simulates holding SHIFT and selecting
        each item in the range in-turn)
        
        :param javax.swing.JList[typing.Any] list: the list to select from
        :param jpype.JInt or int row: the initial index
        :param jpype.JInt or int count: the number of rows to select
        """

    @staticmethod
    @typing.overload
    def clickMouse(comp: java.awt.Component, button: typing.Union[jpype.JInt, int], x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int], clickCount: typing.Union[jpype.JInt, int], modifiers: typing.Union[jpype.JInt, int], popupTrigger: typing.Union[jpype.JBoolean, bool]):
        """
        Simulates click the mouse button.
        
        :param java.awt.Component comp: the component to click on.
        :param jpype.JInt or int button: the mouse button (1, 2, or 3)
        :param jpype.JInt or int x: the x coordinate of the click location
        :param jpype.JInt or int y: the y coordinate of the click location
        :param jpype.JInt or int clickCount: the number of clicks (2 = double click)
        :param jpype.JInt or int modifiers: additional modifiers (e.g. MouseEvent.SHIFT_MASK)
        :param jpype.JBoolean or bool popupTrigger: a boolean, true if this event is a trigger for a
                    popup menu
        """

    @staticmethod
    @typing.overload
    def clickMouse(comp: java.awt.Component, button: typing.Union[jpype.JInt, int], x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int], clickCount: typing.Union[jpype.JInt, int], modifiers: typing.Union[jpype.JInt, int]):
        """
        Simulates click the mouse button.
        
        :param java.awt.Component comp: the component to click on.
        :param jpype.JInt or int button: the mouse button (1, 2, or 3)
        :param jpype.JInt or int x: the x coordinate of the click location
        :param jpype.JInt or int y: the y coordinate of the click location
        :param jpype.JInt or int clickCount: the number of clicks (2 = double click)
        :param jpype.JInt or int modifiers: additional modifiers (e.g. MouseEvent.SHIFT_MASK)
        """

    @staticmethod
    def clickTableCell(table: javax.swing.JTable, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int], clickCount: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def clickTableRange(table: javax.swing.JTable, row: typing.Union[jpype.JInt, int], count: typing.Union[jpype.JInt, int]):
        """
        Clicks a range of items in a table (simulates holding SHIFT and selecting
        each item in the range)
        
        :param javax.swing.JTable table: the table to select
        :param jpype.JInt or int row: the starting row index
        :param jpype.JInt or int count: the number of rows to select
        """

    @staticmethod
    def doubleClick(comp: javax.swing.JComponent, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def dragMouse(comp: java.awt.Component, button: typing.Union[jpype.JInt, int], startX: typing.Union[jpype.JInt, int], startY: typing.Union[jpype.JInt, int], endX: typing.Union[jpype.JInt, int], endY: typing.Union[jpype.JInt, int], modifiers: typing.Union[jpype.JInt, int]):
        """
        Simulates a mouse drag action
        
        :param java.awt.Component comp: the component to drag on.
        :param jpype.JInt or int button: the mouse button (1, 2, or 3)
        :param jpype.JInt or int startX: the x coordinate of the start drag location
        :param jpype.JInt or int startY: the y coordinate of the start drag location
        :param jpype.JInt or int endX: the x coordinate of the end drag location
        :param jpype.JInt or int endY: the y coordinate of the end drag location
        :param jpype.JInt or int modifiers: additional modifiers (e.g. MouseEvent.SHIFT_MASK)
        """

    @staticmethod
    def editCell(table: javax.swing.JTable, row: typing.Union[jpype.JInt, int], col: typing.Union[jpype.JInt, int]) -> javax.swing.table.TableCellEditor:
        ...

    @staticmethod
    def executeOnSwingWithoutBlocking(runnable: java.lang.Runnable):
        """
        Launches the runnable on a new thread so as to not block the calling
        thread. This is very useful for performing actions on the Swing thread
        that show modal dialogs, which would otherwise block the calling thread,
        such as a testing thread.
        
        :param java.lang.Runnable runnable: The runnable that will be executed in a new Thread that
                    will place the runnable on the Swing thread.
        """

    @staticmethod
    def findAbstractButtonByName(container: java.awt.Container, name: typing.Union[java.lang.String, str]) -> javax.swing.AbstractButton:
        """
        Searches the sub-components of the given container and returns the
        AbstractButton that has the specified name.
        
        :param java.awt.Container container: container to search
        :param java.lang.String or str name: the button name (you must set this manually).
        :return: null if the button was not found
        :rtype: javax.swing.AbstractButton
        """

    @staticmethod
    def findAbstractButtonByText(container: java.awt.Container, text: typing.Union[java.lang.String, str]) -> javax.swing.AbstractButton:
        """
        Searches the sub-components of the given container and returns the
        AbstractButton that has the specified text.
         
        
        This differs from :meth:`findButtonByText(Container, String) <.findButtonByText>` in that
        this method will find buttons that do not extend from :obj:`JButton`.
        That method is convenient when you do not wish to cast the result from
        AbstractButton to JButton. Other than that, this method can handle all
        cases the other method cannot.
        
        :param java.awt.Container container: container to search
        :param java.lang.String or str text: button text
        :return: null if the button was not found
        :rtype: javax.swing.AbstractButton
        """

    @staticmethod
    def findButtonByIcon(container: java.awt.Container, icon: javax.swing.Icon) -> javax.swing.JButton:
        ...

    @staticmethod
    def findButtonByName(container: java.awt.Container, name: typing.Union[java.lang.String, str]) -> javax.swing.AbstractButton:
        """
        Searches the sub-components of the given container and returns the AbstractButton that has 
        the specified name.
        
        :param java.awt.Container container: container to search
        :param java.lang.String or str name: the button name
        :return: null if the button was not found
        :rtype: javax.swing.AbstractButton
        """

    @staticmethod
    def findButtonByText(container: java.awt.Container, text: typing.Union[java.lang.String, str]) -> javax.swing.JButton:
        """
        Searches the subcomponents of the given container and returns the
        JButton that has the specified text.
        
        :param java.awt.Container container: the container to search
        :param java.lang.String or str text: the button text
        :return: the JButton, or null the button was not found
        :rtype: javax.swing.JButton
        """

    @staticmethod
    @typing.overload
    def findComponent(parent: java.awt.Container, desiredClass: java.lang.Class[T]) -> T:
        ...

    @staticmethod
    @typing.overload
    def findComponent(parent: java.awt.Container, desiredClass: java.lang.Class[T], checkOwnedWindows: typing.Union[jpype.JBoolean, bool]) -> T:
        ...

    @staticmethod
    @typing.overload
    def findComponentByName(container: java.awt.Container, componentName: typing.Union[java.lang.String, str]) -> java.awt.Component:
        """
        Searches the subcomponents of the indicated container and returns the
        component with the specified name.
        
        :param java.awt.Container container: the container to search
        :param java.lang.String or str componentName: the name of the desired component
        :return: the component, or null if not found
        :rtype: java.awt.Component
        """

    @staticmethod
    @typing.overload
    def findComponentByName(container: java.awt.Container, componentName: typing.Union[java.lang.String, str], checkOwnedWindows: typing.Union[jpype.JBoolean, bool]) -> java.awt.Component:
        ...

    @staticmethod
    @typing.overload
    def findComponents(parent: java.awt.Container, desiredClass: java.lang.Class[T]) -> java.util.List[T]:
        ...

    @staticmethod
    @typing.overload
    def findComponents(parent: java.awt.Container, desiredClass: java.lang.Class[T], checkOwnedWindows: typing.Union[jpype.JBoolean, bool]) -> java.util.List[T]:
        ...

    @staticmethod
    def findOwnedWindows(win: java.awt.Window, winList: java.util.Set[java.awt.Window]):
        ...

    @staticmethod
    def findTreePathToText(tree: javax.swing.JTree, text: typing.Union[java.lang.String, str]) -> javax.swing.tree.TreePath:
        """
        Finds the path of a tree node in the indicated tree with the specified
        text. The matching tree node is determined by comparing the specified
        text with the string returned by the tree node's toString() method. 
        
        Note: This method affects the expansion state of the tree. It will expand
        nodes starting at the root until a match is found or all of the tree is
        checked.
        
        :param javax.swing.JTree tree: the tree
        :param java.lang.String or str text: the tree node's text
        :return: the tree path
        :rtype: javax.swing.tree.TreePath
        """

    @staticmethod
    def fixupGUI():
        """
        Invoke ``fixupGUI`` at the beginning of your JUnit test or in
        its setup() method to make your GUI for the JUnit test appear using the
        system Look and Feel. The system look and feel is the default that Ghidra
        uses. This will also change the default fonts for the JUnit test to be
        the same as those in Ghidra.
        
        :raises java.lang.InterruptedException: if we're interrupted while waiting for
                        the event dispatching thread to finish excecuting
                        ``doRun.run()``
        :raises java.lang.reflect.InvocationTargetException: if an exception is thrown while
                        running ``doRun``
        """

    @staticmethod
    def getAllWindows() -> java.util.Set[java.awt.Window]:
        """
        Gets all windows in the system (including Frames).
        
        :return: all windows
        :rtype: java.util.Set[java.awt.Window]
        """

    @staticmethod
    def getRenderedTableCellValue(table: javax.swing.JTable, row: typing.Union[jpype.JInt, int], column: typing.Union[jpype.JInt, int]) -> str:
        """
        Gets the rendered value for the specified table cell.  The actual value at the cell may
        not be a String.  This method will get the String display value, as created by the table.
        
        :param javax.swing.JTable table: the table to query
        :param jpype.JInt or int row: the row to query
        :param jpype.JInt or int column: the column to query
        :return: the String value
        :rtype: str
        :raises IllegalArgumentException: if there is no renderer or the rendered component is
                something from which this method can get a String (such as a JLabel)
        """

    @staticmethod
    def getSwing(s: java.util.function.Supplier[T]) -> T:
        """
        Returns the value from the given :obj:`Supplier`, invoking the call in
        the Swing thread. This is useful when you may have values that are being
        changed on the Swing thread and you need the test thread to see the
        changes.
        
        :param java.util.function.Supplier[T] s: the supplier
        :return: the value returned by the supplier
        :rtype: T
        """

    @staticmethod
    def getText(field: javax.swing.text.JTextComponent) -> str:
        ...

    @staticmethod
    def leftClick(comp: javax.swing.JComponent, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def middleClick(comp: javax.swing.JComponent, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def moveMouse(comp: java.awt.Component, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        """
        Fire a mouse moved event for the given component.
        
        :param java.awt.Component comp: source of the event.
        :param jpype.JInt or int x: x position relative to the component
        :param jpype.JInt or int y: y position relative to the component
        """

    @staticmethod
    def postEvent(ev: java.awt.AWTEvent):
        ...

    @staticmethod
    @typing.overload
    def pressButton(button: javax.swing.AbstractButton):
        """
        Programmatically presses the indicated button.
        
        :param javax.swing.AbstractButton button: the button
        """

    @staticmethod
    @typing.overload
    def pressButton(button: javax.swing.AbstractButton, waitForCompletion: typing.Union[jpype.JBoolean, bool]):
        """
        Programmatically presses the indicated button.
        
        :param javax.swing.AbstractButton button: the button
        :param jpype.JBoolean or bool waitForCompletion: if true wait for action to complete before
                    returning, otherwise schedule action to be performed and
                    return immediately.
        """

    @staticmethod
    @typing.overload
    def pressButtonByName(container: java.awt.Container, buttonName: typing.Union[java.lang.String, str]):
        """
        Finds the button with the indicated NAME that is a subcomponent of the
        indicated container, and then programmatically presses the button.
        
        :param java.awt.Container container: the container to search. (Typically a dialog)
        :param java.lang.String or str buttonName: the name on the desired AbstractButton (see
                    Component.setName())
        """

    @staticmethod
    @typing.overload
    def pressButtonByName(container: java.awt.Container, buttonName: typing.Union[java.lang.String, str], waitForCompletion: typing.Union[jpype.JBoolean, bool]):
        """
        Finds the button with the indicated NAME that is a subcomponent of the
        indicated container, and then programmatically presses the button.
        
        :param java.awt.Container container: the container to search. (Typically a dialog.)
        :param java.lang.String or str buttonName: the name on the desired AbstractButton (see
                    Component.setName()).
        :param jpype.JBoolean or bool waitForCompletion: if true wait for action to complete before
                    returning, otherwise schedule action to be performed and
                    return immediately
        """

    @staticmethod
    @typing.overload
    def pressButtonByText(container: java.awt.Container, buttonText: typing.Union[java.lang.String, str]):
        """
        Finds the button with the indicated TEXT that is a sub-component of the
        indicated container, and then programmatically presses the button. 
        
        The following is a sample JUnit test use:
        
         
        env.showTool();
        OptionDialog dialog = (OptionDialog) env.waitForDialog(OptionDialog.class, 1000);
        assertNotNull(dialog);
        pressButtonByText(dialog, "OK");
         
        
        :param java.awt.Container container: the container to search. (Typically a dialog.)
        :param java.lang.String or str buttonText: the text on the desired JButton.
        :raises AssertionError: if the button isn't found, isn't showing or isn't
                    enabled
        """

    @staticmethod
    @typing.overload
    def pressButtonByText(container: java.awt.Container, buttonText: typing.Union[java.lang.String, str], waitForCompletion: typing.Union[jpype.JBoolean, bool]):
        """
        Finds the button with the indicated TEXT that is a sub-component of the
        indicated container, and then programmatically presses the button.
        
        :param java.awt.Container container: the container to search. (Typically a dialog.)
        :param java.lang.String or str buttonText: the text on the desired JButton.
        :param jpype.JBoolean or bool waitForCompletion: if true wait for action to complete before
                    returning, otherwise schedule action to be performed and
                    return immediately.
        :raises AssertionError: if the button isn't found, isn't showing or isn't
                    enabled
        """

    @staticmethod
    def printMemory():
        ...

    @staticmethod
    @deprecated("This is not a test writer\'s method, but instead an\n             infrastructure method.")
    def privatewaitForSwing_SwingSafe():
        """
        This is only for internal use. If you need to wait for the Swing thread
        from your test, then use :meth:`waitForSwing() <.waitForSwing>`.
        
        
        .. deprecated::
        
        This is not a test writer's method, but instead an
                    infrastructure method.
        """

    @staticmethod
    def rightClick(comp: javax.swing.JComponent, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    @typing.overload
    def runSwing(s: java.util.function.Supplier[T]) -> T:
        """
        Returns the value from the given :obj:`Supplier`, invoking the call in
        the Swing thread. This is useful when you may have values that are being
        changed on the Swing thread and you need the test thread to see the
        changes.
        
        :param java.util.function.Supplier[T] s: the supplier
        :return: the value returned by the supplier
        :rtype: T
        
        .. seealso::
        
            | :obj:`.getSwing(Supplier)`
        """

    @staticmethod
    @typing.overload
    def runSwing(r: java.lang.Runnable):
        """
        Run the given code snippet on the Swing thread and wait for it to finish
        
        :param java.lang.Runnable r: the runnable code snippet
        """

    @staticmethod
    @typing.overload
    def runSwing(runnable: java.lang.Runnable, wait: typing.Union[jpype.JBoolean, bool]):
        ...

    def runSwingLater(self, r: java.lang.Runnable):
        """
        Run the given code snippet on the Swing thread later, not blocking the current thread.  Use
        this if the code snippet causes a blocking operation.
        
         
        This is a shortcut for ``runSwing(r, false);``.
        
        :param java.lang.Runnable r: the runnable code snippet
        """

    @staticmethod
    def runSwingWithException(callback: utility.function.ExceptionalCallback[E]):
        """
        Call this version of :meth:`runSwing(Runnable) <.runSwing>` when you expect your runnable **may**
        throw exceptions
        
        :param utility.function.ExceptionalCallback[E] callback: the runnable code snippet to call
        :raises java.lang.Exception: any exception that is thrown on the Swing thread
        """

    @staticmethod
    def setComboBoxSelection(comboField: javax.swing.JComboBox[T], selection: T):
        ...

    @staticmethod
    def setText(field: javax.swing.text.JTextComponent, text: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def waitForExpiringSwingTimers() -> bool:
        ...

    @staticmethod
    @deprecated("Use waitForSwing() instead")
    def waitForPostedSwingRunnables():
        """
        
        
        
        .. deprecated::
        
        Use :meth:`waitForSwing() <.waitForSwing>` instead
        """

    @staticmethod
    def waitForSwing() -> bool:
        """
        Waits for the Swing thread to process any pending events. This method
        also waits for any :obj:`SwingUpdateManager`s that have pending events
        to be flushed.
        
        :return: true if the any :obj:`SwingUpdateManager`s were busy.
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def waitForTasks():
        """
        Waits for all system tasks to complete. These tasks are tracked by the
        SystemUtilities during testing only.
        
        :raises AssertionFailedError: if the timeout period expires while waiting
                    for tasks
        """

    @staticmethod
    @typing.overload
    def waitForTasks(timeout: typing.Union[jpype.JLong, int]):
        ...


class TestThread(java.lang.Thread):

    class_: typing.ClassVar[java.lang.Class]
    NAME_PREFIX: typing.Final = "Test-"

    @staticmethod
    def filterTrace(trace: jpype.JArray[java.lang.StackTraceElement]) -> jpype.JArray[java.lang.StackTraceElement]:
        """
        Filters the given stack trace to remove entries known to be present in the test 
        thread that offer little forensic value
        
        :param jpype.JArray[java.lang.StackTraceElement] trace: the trace to filter
        :return: the filtered trace
        :rtype: jpype.JArray[java.lang.StackTraceElement]
        """

    @staticmethod
    @typing.overload
    def isTestThread() -> bool:
        """
        Returns true if the current thread is the test thread
        
        :return: true if the current thread is the test thread
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isTestThread(t: java.lang.Thread) -> bool:
        """
        Returns true if the given thread is the test thread
        
        :param java.lang.Thread t: the thread to check
        :return: true if the given thread is the test thread
        :rtype: bool
        """

    @staticmethod
    def isTestThreadName(name: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given thread name is the test thread name
        
        :param java.lang.String or str name: the thread name to check
        :return: true if the given thread name is the test thread name
        :rtype: bool
        """


class TestReportingException(java.lang.RuntimeException):
    """
    A :obj:`RuntimeException` that will print a custom stack trace.  
     
     
    This class will print not only the trace info for the exception passed at construction 
    time, but will also print a trace for the test thread at the time of the exception.  Also,
    the trace information printed will be filtered of entries that are not useful for 
    debugging, like Java class entries.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def fromSwingThread(message: typing.Union[java.lang.String, str], t: java.lang.Throwable) -> TestReportingException:
        """
        Creates a new :obj:`TestReportingException` using an exception that was generated on 
        the Swing thread.
        
        :param java.lang.String or str message: an optional custom message that will be printed first in the stack trace
        :param java.lang.Throwable t: the original exception
        :return: the new :obj:`TestReportingException`
        :rtype: TestReportingException
        """

    @staticmethod
    def getSwingThreadTraceString(throwable: java.lang.Throwable) -> str:
        ...


class AbstractGenericTest(AbstractGTest):
    """
    Base class for tests that provide some helper methods that are useful for tests that don't
    require swing/gui support.
    """

    class_: typing.ClassVar[java.lang.Class]
    TESTDATA_DIRECTORY_NAME: typing.Final = "testdata"
    DEFAULT_TOOL_NAME: typing.Final = "CodeBrowser"
    DEFAULT_TEST_TOOL_NAME: typing.Final = "TestCodeBrowser"
    watchman: org.junit.rules.TestWatcher
    concurrentTestExceptionRule: org.junit.rules.TestRule
    ruleChain: org.junit.rules.RuleChain

    def __init__(self):
        ...

    @staticmethod
    def createStackTraceForAllThreads() -> str:
        """
        Returns a string which is a printout of a stack trace for each thread running in the current
        JVM
        
        :return: the stack trace string
        :rtype: str
        """

    @staticmethod
    def createTempDirectory(name: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Creates a **sub-directory** with the given name as a child of the Java temp directory. The
        given name will be the prefix of the new directory name, with any additional text as created
        by :meth:`Files.createTempDirectory(Path, String, java.nio.file.attribute.FileAttribute...) <Files.createTempDirectory>`.
        Any left-over test directories will be cleaned-up before creating the new directory.
        
         
        
        Note: you should not call this method multiple times, as each call will cleanup the
        previously created directories.
        
        :param java.lang.String or str name: the name of the directory to create
        :return: the newly created directory
        :rtype: java.io.File
        :raises IOException: of there is a problem creating the new directory
        """

    @typing.overload
    def createTempFile(self, name: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Creates a file in the Application temp directory using the given name as a prefix and the
        given suffix. The final filename will also include the current test name, as well as any data
        added by :meth:`File.createTempFile(String, String, File) <File.createTempFile>`. The file suffix will be
        ``.tmp``
         
        
        The file will be marked to delete on JVM exit. This will not work if the JVM is taken down
        the hard way, as when pressing the stop button in Eclipse.
        
        :param java.lang.String or str name: the prefix to put on the file, before the test name
        :return: the newly created file
        :rtype: java.io.File
        :raises IOException: if there is a problem creating the new file
        
        .. seealso::
        
            | :obj:`.createTempFile(String, String)`
        """

    @typing.overload
    def createTempFile(self, name: typing.Union[java.lang.String, str], suffix: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Creates a file in the Application temp directory using the given name as a prefix and the
        given suffix. The final filename will also include the current test name, as well as any data
        added by :meth:`File.createTempFile(String, String, File) <File.createTempFile>`.
         
        
        The file will be marked to delete on JVM exit. This will not work if the JVM is taken down
        the hard way, as when pressing the stop button in Eclipse.
         
        
        Note: This method **will** create the file on disk! If you need the file to not exist,
        then you must delete the file yourself. Alternatively, you could instead call
        :meth:`createTempFilePath(String, String) <.createTempFilePath>`, which will ensure that the created temp file is
        deleted.
        
         
        
        Finally, this method will delete any files that match the given name and suffix values before
        creating the given temp file. **This is important, as it will delete any files already
        created by the test that match this info.**
        
        :param java.lang.String or str name: the prefix to put on the file, before the test name
        :param java.lang.String or str suffix: the file suffix
        :return: the newly created file
        :rtype: java.io.File
        :raises IOException: if there is a problem creating the new file
        
        .. seealso::
        
            | :obj:`.createTempFile(String)`
        """

    @typing.overload
    def createTempFileForTest(self) -> java.io.File:
        """
        Creates a temp file for the current test, using the test name as a prefix for the filename.
        This method calls :meth:`createTempFile(String) <.createTempFile>`, which will cleanup any pre-existing temp
        files whose name pattern matches this test name. This helps to avoid old temp files from
        accumulating.
        
        :return: the new temp file
        :rtype: java.io.File
        :raises IOException: if there is a problem creating the new file
        """

    @typing.overload
    def createTempFileForTest(self, suffix: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Creates a temp file for the current test, using the test name as a prefix for the filename.
        This method calls :meth:`createTempFile(String) <.createTempFile>`, which will cleanup any pre-existing temp
        files whose name pattern matches this test name. This helps to avoid old temp files from
        accumulating.
        
        :param java.lang.String or str suffix: the suffix to provide for the temp file
        :return: the new temp file
        :rtype: java.io.File
        :raises IOException: if there is a problem creating the new file
        """

    @typing.overload
    def createTempFilePath(self, name: typing.Union[java.lang.String, str]) -> str:
        """
        Creates a file path with a filename that is under the system temp directory. The path
        returned will not point to an existing file. The suffix of the file will be
        ``.tmp``.
        
        :param java.lang.String or str name: the filename
        :return: a new file path
        :rtype: str
        :raises IOException: if there is any problem ensuring that the created path is non-existent
        
        .. seealso::
        
            | :obj:`.createTempFilePath(String, String)`
        """

    @typing.overload
    def createTempFilePath(self, name: typing.Union[java.lang.String, str], extension: typing.Union[java.lang.String, str]) -> str:
        """
        Creates a file path with a filename that is under the system temp directory. The path
        returned will not point to an existing file. This method is the same as
        :meth:`createTempFilePath(String) <.createTempFilePath>`, except that you must provide the extension.
        
        :param java.lang.String or str name: the filename
        :param java.lang.String or str extension: the file extension
        :return: a new file path
        :rtype: str
        :raises IOException: if there is any problem ensuring that the created path is non-existent
        
        .. seealso::
        
            | :obj:`.createTempFile(String, String)`
        """

    @staticmethod
    def deleteMatchingTempFiles(namePattern: typing.Union[java.lang.String, str]):
        """
        Delete any files under the this test case's specific temp directory that match the give regex
        :obj:`Pattern`
        
        :param java.lang.String or str namePattern: the pattern to match against the files
        
        .. seealso::
        
            | :obj:`.deleteSimilarTempFiles(String)`
        """

    @staticmethod
    def deleteSimilarTempFiles(nameText: typing.Union[java.lang.String, str]):
        """
        Delete any files under the Java temp directory that have the given text in their name.
        
        :param java.lang.String or str nameText: the partial name text to match against the files
        
        .. seealso::
        
            | :obj:`.deleteMatchingTempFiles(String)`
        """

    @staticmethod
    def findTestDataFile(path: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Returns the file within the data directory of the TestResources module that matches the given
        relative path.
         
        
        Null is returned if the file could not be found.
        
        :param java.lang.String or str path: path relative to the data directory of the TestResources module.
        :return: the file within the data directory of the TestResources module that matches the given
                relative path
        :rtype: java.io.File
        """

    @staticmethod
    def getDebugFileDirectory() -> java.io.File:
        """
        Returns the directory into which tests can write debug files, such as files containing print
        statements or image files.
        
         
        
        This is not a temporary directory that will be deleted between tests, which is useful in that
        the debug files will persist after a test run.
        
         
        
        Examples of this directory:
         
        * server: {share dir}/junits.new/JunitTest_version/reports
        * local gradle: {user home}/git/{repo}/ghidra/build/JUnit/reports
        * eclipse: {module}/bin/
        
        
        :return: the directory
        :rtype: java.io.File
        """

    @staticmethod
    def getFontMetrics(font: java.awt.Font) -> java.awt.FontMetrics:
        """
        Returns a font metrics for the given font using a generic buffered image graphics context.
        
        :param java.awt.Font font: the font
        :return: the font metrics
        :rtype: java.awt.FontMetrics
        """

    @staticmethod
    def getInstanceField(fieldName: typing.Union[java.lang.String, str], ownerInstance: java.lang.Object) -> java.lang.Object:
        """
        Gets the instance field by the given name on the given object instance. The value is a
        primitive wrapper if it is a primitive type.
         
        
        Note: if the field is static, then the ``ownerInstance`` field can be the class of
        the object that contains the variable.
        
        :param java.lang.String or str fieldName: The name of the field to retrieve.
        :param java.lang.Object ownerInstance: The object instance from which to get the variable instance.
        :return: The field instance.
        :rtype: java.lang.Object
        :raises java.lang.RuntimeException: if there is a problem accessing the field using reflection. A
                    RuntimeException is used so that calling tests can avoid using a try/catch block,
                    but will still fail when an error is encountered.
        
        .. versionadded:: Tracker Id 267
        
        .. seealso::
        
            | :obj:`Field.get(java.lang.Object)`
        """

    @staticmethod
    def getInstanceFieldByClassType(classType: java.lang.Class[T], ownerInstance: java.lang.Object) -> T:
        """
        Get the first field object contained within object ownerInstance which has the type
        classType. This method is only really useful if it is known that only a single field of
        classType exists within the ownerInstance.
        
        :param T: the type:param java.lang.Class[T] classType: the class type of the desired field
        :param java.lang.Object ownerInstance: the object instance that owns the field
        :return: field object of type classType or null
        :rtype: T
        """

    @staticmethod
    def getTestDataDir(relativePath: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Returns a file that points to the location on disk of the given relative path name. The path
        is relative to the test resources directory.
        
        :param java.lang.String or str relativePath: the path of the file
        :return: a file that points to the location on disk of the relative path.
        :rtype: java.io.File
        :raises FileNotFoundException: If the directory does not exist
        :raises IOException: if the given path does not represent a directory
        """

    @staticmethod
    def getTestDataDirectory() -> java.io.File:
        """
        Returns the data directory containing test programs and data
        
        :return: the data directory containing test programs and data
        :rtype: java.io.File
        """

    @staticmethod
    def getTestDataFile(path: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Returns the file within the data directory of the TestResources module that matches the given
        relative path
         
        
        A :obj:`FileNotFoundException` is throw if the file does not exist.
        
        :param java.lang.String or str path: path relative to the data directory of the TestResources module.
        :return: the file within the data directory of the TestResources module that matches the given
                relative path
        :rtype: java.io.File
        :raises FileNotFoundException: if the given file does not exist
        """

    @staticmethod
    def invokeConstructor(containingClass: java.lang.Class[typing.Any], parameterTypes: jpype.JArray[java.lang.Class[typing.Any]], args: jpype.JArray[java.lang.Object]) -> java.lang.Object:
        """
        Uses reflection to execute the constructor for the given class with the given parameters. The
        new instance of the given class will be returned.
        
        :param java.lang.Class[typing.Any] containingClass: The class that contains the desired constructor.
        :param jpype.JArray[java.lang.Class[typing.Any]] parameterTypes: The parameter **types** that the constructor takes. This value can
                    be null or zero length if there are no parameters to pass
        :param jpype.JArray[java.lang.Object] args: The parameter values that should be passed to the constructor. This value can be
                    null or zero length if there are no parameters to pass
        :return: The new class instance
        :rtype: java.lang.Object
        :raises java.lang.RuntimeException: if there is a problem accessing the constructor using reflection. A
                    RuntimeException is used so that calling tests can avoid using a try/catch block,
                    but will still fail when an error is encountered.
        """

    @staticmethod
    @typing.overload
    def invokeInstanceMethod(methodName: typing.Union[java.lang.String, str], ownerInstance: java.lang.Object, parameterTypes: jpype.JArray[java.lang.Class[typing.Any]], args: jpype.JArray[java.lang.Object]) -> java.lang.Object:
        """
        Uses reflection to execute the method denoted by the given method name. If any value is
        returned from the method execution, then it will be returned from this method. Otherwise,
        ``null`` is returned.
         
        
        Note: if the method is static, then the ``ownerInstance`` field can be the class of
        the object that contains the method.
        
        :param java.lang.String or str methodName: The name of the method to execute.
        :param java.lang.Object ownerInstance: The object instance of which the method will be executed.
        :param jpype.JArray[java.lang.Class[typing.Any]] parameterTypes: The parameter **types** that the method takes.
        :param jpype.JArray[java.lang.Object] args: The parameter values that should be passed to the method. This value can be null
                    or zero length if there are no parameters to pass
        :return: The return value as returned from executing the method.
        :rtype: java.lang.Object
        :raises java.lang.RuntimeException: if there is a problem accessing the field using reflection. A
                    RuntimeException is used so that calling tests can avoid using a try/catch block,
                    but will still fail when an error is encountered.
        
        .. versionadded:: Tracker Id 267
        
        .. seealso::
        
            | :obj:`Method.invoke(java.lang.Object, java.lang.Object[])`
        """

    @staticmethod
    @typing.overload
    def invokeInstanceMethod(methodName: typing.Union[java.lang.String, str], ownerInstance: java.lang.Object) -> java.lang.Object:
        """
        This method is just a "pass through" method for
        :meth:`invokeInstanceMethod(String, Object, Class[], Object[]) <.invokeInstanceMethod>` so that callers do not need
        to pass null to that method when the underlying instance method does not have any parameters.
        
        :param java.lang.String or str methodName: The name of the method to execute.
        :param java.lang.Object ownerInstance: The object instance of which the method will be executed.
        :return: The return value as returned from executing the method.
        :rtype: java.lang.Object
        :raises java.lang.RuntimeException: if there is a problem accessing the field using reflection. A
                    RuntimeException is used so that calling tests can avoid using a try/catch block,
                    but will still fail when an error is encountered.
        
        .. seealso::
        
            | :obj:`Method.invoke(java.lang.Object, java.lang.Object[])`
        
            | :obj:`.invokeInstanceMethod(String, Object, Class[], Object[])`
        """

    @staticmethod
    @typing.overload
    def loadTextResource(cls: java.lang.Class[typing.Any], name: typing.Union[java.lang.String, str]) -> java.util.List[java.lang.String]:
        """
        Load a text resource file into an ArrayList. Each line of the file is stored as an item in
        the list.
        
        :param java.lang.Class[typing.Any] cls: class where resource exists
        :param java.lang.String or str name: resource filename
        :return: list of lines contained in file
        :rtype: java.util.List[java.lang.String]
        :raises IOException: if an exception occurs reading the given resource
        """

    @staticmethod
    @typing.overload
    def loadTextResource(name: typing.Union[java.lang.String, str]) -> java.util.List[java.lang.String]:
        ...

    def resetLogging(self):
        ...

    @staticmethod
    def setErrorsExpected(expected: typing.Union[jpype.JBoolean, bool]):
        """
        Signals that the client expected the System Under Test (SUT) to report errors. Use this when
        you wish to verify that errors are reported and you do not want those errors to fail the
        test. The default value for this setting is false, which means that any errors reported will
        fail the running test.
        
        :param jpype.JBoolean or bool expected: true if errors are expected.
        """

    @staticmethod
    def setInstanceField(fieldName: typing.Union[java.lang.String, str], ownerInstance: java.lang.Object, value: java.lang.Object):
        """
        Sets the instance field by the given name on the given object instance.
         
        
        Note: if the field is static, then the ``ownerInstance`` field can be the class of
        the object that contains the variable.
        
        :param java.lang.String or str fieldName: The name of the field to retrieve.
        :param java.lang.Object ownerInstance: The object instance from which to get the variable instance.
        :param java.lang.Object value: The value to use when setting the given field
        :raises java.lang.RuntimeException: if there is a problem accessing the field using reflection. A
                    RuntimeException is used so that calling tests can avoid using a try/catch block,
                    but will still fail when an error is encountered.
        
        .. seealso::
        
            | :obj:`Field.set(Object, Object)`
        """

    @staticmethod
    def toString(collection: collections.abc.Sequence) -> str:
        """
        Prints the contents of the given collection by way of the :meth:`Object.toString() <Object.toString>` method.
        
        :param collections.abc.Sequence collection: The contents of which to print
        :return: A string representation of the given collection
        :rtype: str
        """

    @staticmethod
    def windowForComponent(c: java.awt.Component) -> java.awt.Window:
        """
        Returns the window parent of c. If c is a window, then c is returned.
        
         
        
        Warning: this differs from :meth:`SwingUtilities.windowForComponent(Component) <SwingUtilities.windowForComponent>` in that the
        latter method will not return the given component if it is a window.
        
        :param java.awt.Component c: the component
        :return: the window
        :rtype: java.awt.Window
        """


class ConcurrentTestExceptionStatement(org.junit.runners.model.Statement):

    class_: typing.ClassVar[java.lang.Class]
    DISABLE_TEST_TIMEOUT_PROPERTY: typing.Final = "ghidra.test.property.timeout.disable"
    TEST_TIMEOUT_MILLIS_PROPERTY: typing.Final = "ghidra.test.property.timeout.milliseconds"

    def __init__(self, originalStatement: org.junit.runners.model.Statement):
        ...


class AbstractGTest(java.lang.Object):
    """
    A root for system tests that provides known system information.
    
     
    
    This class exists so that fast unit tests have a place to share data without having the slowness
    of more heavy weight concepts like :obj:`Application`, logging, etc.
    
     
    
    !! WARNING !! This test is meant to initialize quickly. All file I/O should be avoided.
    """

    class_: typing.ClassVar[java.lang.Class]
    BATCH_MODE: typing.Final[jpype.JBoolean]
    DEFAULT_WAIT_DELAY: typing.Final[jpype.JInt]
    DEFAULT_WAIT_TIMEOUT: typing.Final[jpype.JInt]
    DEFAULT_WINDOW_TIMEOUT: typing.Final[jpype.JInt]
    testName: org.junit.rules.TestName
    repeatedRule: org.junit.rules.TestRule
    """
    This rule handles the :obj:`Repeated` annotation
    
     
    
    During batch mode, this rule should never be needed. This rule is included here as a
    convenience, in case a developer wants to use the :obj:`Repeated` annotation to diagnose a
    non-deterministic test failure. Without this rule, the annotation would be silently ignored.
    """

    ignoreUnfinishedRule: org.junit.rules.TestRule
    """
    This rule handles the :obj:`IgnoreUnfinished` annotation
    """


    def __init__(self):
        ...

    @staticmethod
    def assertArraysEqualOrdered(message: typing.Union[java.lang.String, str], expected: jpype.JArray[java.lang.Object], actual: jpype.JArray[java.lang.Object]):
        """
        Compares the contents of two arrays to determine if they are equal. The contents must match
        in the same order. If ``message`` is ``null``, then a generic error message
        will be printed.
        
        :param java.lang.String or str message: The message to print upon failure; can be null
        :param jpype.JArray[java.lang.Object] expected: The expected array.
        :param jpype.JArray[java.lang.Object] actual: The actual array.
        """

    @staticmethod
    @typing.overload
    def assertArraysEqualUnordered(message: typing.Union[java.lang.String, str], expected: jpype.JArray[java.lang.Object], actual: jpype.JArray[java.lang.Object]):
        """
        Compares the contents of two arrays to determine if they are equal. The contents do not have
        to be in the same order. If ``message`` is ``null``, then a generic error
        message will be printed.
        
        :param java.lang.String or str message: The message to print upon failure; can be null
        :param jpype.JArray[java.lang.Object] expected: The expected array.
        :param jpype.JArray[java.lang.Object] actual: The actual array.
        """

    @staticmethod
    @typing.overload
    def assertArraysEqualUnordered(expected: jpype.JArray[java.lang.String], actual: jpype.JArray[java.lang.String]):
        """
        Compares the contents of two arrays to determine if they are equal
        
        :param jpype.JArray[java.lang.String] expected: The expected array.
        :param jpype.JArray[java.lang.String] actual: The actual array.
        """

    @staticmethod
    @typing.overload
    def assertContainsExactly(collection: collections.abc.Sequence, *expected: T):
        ...

    @staticmethod
    @typing.overload
    def assertContainsExactly(expected: collections.abc.Sequence, actual: collections.abc.Sequence):
        ...

    @staticmethod
    def assertContainsString(expected: typing.Union[java.lang.String, str], actual: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def assertContainsStringIgnoringCase(expected: typing.Union[java.lang.String, str], actual: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    @typing.overload
    def assertListEqualOrdered(expected: java.util.List[typing.Any], actual: java.util.List[typing.Any]):
        ...

    @staticmethod
    @typing.overload
    def assertListEqualOrdered(message: typing.Union[java.lang.String, str], expected: java.util.List[typing.Any], actual: java.util.List[typing.Any]):
        ...

    @staticmethod
    def assertListEqualUnordered(message: typing.Union[java.lang.String, str], expected: java.util.List[typing.Any], actual: java.util.List[typing.Any]):
        ...

    @staticmethod
    def assertListEqualsArrayOrdered(actual: java.util.List[T], *expected: T):
        ...

    @staticmethod
    def assertListEqualsArrayUnordered(actual: java.util.List[typing.Any], *expected: java.lang.Object):
        ...

    @staticmethod
    def bytes(*unsignedBytes: typing.Union[jpype.JInt, int]) -> jpype.JArray[jpype.JByte]:
        """
        Friendly way to create an array of bytes with static values.
        
        :param jpype.JArray[jpype.JInt] unsignedBytes: var-args list of unsigned byte values (ie. 0..255)
        :return: array of bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    @staticmethod
    def failWithException(message: typing.Union[java.lang.String, str], e: java.lang.Throwable):
        ...

    def getName(self) -> str:
        """
        Returns the current test method name
        
        :return: the current test method name
        :rtype: str
        """

    @staticmethod
    @typing.overload
    def getRandomInt() -> int:
        ...

    @staticmethod
    @typing.overload
    def getRandomInt(min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]) -> int:
        ...

    @staticmethod
    @typing.overload
    def getRandomString() -> str:
        ...

    @staticmethod
    @typing.overload
    def getRandomString(min: typing.Union[jpype.JInt, int], max: typing.Union[jpype.JInt, int]) -> str:
        ...

    @staticmethod
    def getTestDirectoryPath() -> str:
        ...

    @staticmethod
    def sleep(timeMs: typing.Union[jpype.JLong, int]) -> int:
        ...

    @staticmethod
    @typing.overload
    def waitFor(latch: java.util.concurrent.CountDownLatch):
        """
        Waits for the given latch to be counted-down
        
        :param java.util.concurrent.CountDownLatch latch: the latch to await
        :raises AssertionFailedError: if the condition is not met within the timeout period
        """

    @staticmethod
    @typing.overload
    def waitFor(ab: java.util.concurrent.atomic.AtomicBoolean):
        """
        Waits for the given AtomicBoolean to return true. This is a convenience method for
        :meth:`waitFor(BooleanSupplier) <.waitFor>`.
        
        :param java.util.concurrent.atomic.AtomicBoolean ab: the atomic boolean
        :raises AssertionFailedError: if the condition is not met within the timeout period
        """

    @staticmethod
    @typing.overload
    def waitFor(condition: java.util.function.BooleanSupplier):
        """
        Waits for the given condition to return true
        
        :param java.util.function.BooleanSupplier condition: the condition that returns true when satisfied
        :raises AssertionFailedError: if the condition is not met within the timeout period
        """

    @staticmethod
    @typing.overload
    def waitFor(supplier: java.util.function.Supplier[T], failureMessage: typing.Union[java.lang.String, str]) -> T:
        """
        Waits for the value returned by the supplier to be non-null, throwing an exception if that
        does not happen by the default timeout.
        
        :param java.util.function.Supplier[T] supplier: the supplier of the value
        :param java.lang.String or str failureMessage: the message to print upon the timeout being reached
        :return: the non-null value
        :rtype: T
        :raises AssertionFailedError: if a non-null value is not returned within the timeout period
        """

    @staticmethod
    @typing.overload
    def waitFor(supplier: java.util.function.Supplier[T]) -> T:
        """
        Waits for the value returned by the supplier to be non-null, throwing an exception if that
        does not happen by the default timeout.
        
        :param java.util.function.Supplier[T] supplier: the supplier of the value
        :return: the non-null value
        :rtype: T
        :raises AssertionFailedError: if a non-null value is not returned within the timeout period
        """

    @staticmethod
    @typing.overload
    def waitForCondition(condition: java.util.function.BooleanSupplier):
        """
        Waits for the given condition to return true
        
        :param java.util.function.BooleanSupplier condition: the condition that returns true when satisfied
        :raises AssertionFailedError: if the condition is not met within the timeout period
        """

    @staticmethod
    @typing.overload
    def waitForCondition(condition: java.util.function.BooleanSupplier, failureMessage: typing.Union[java.lang.String, str]):
        """
        Waits for the given condition to return true
        
        :param java.util.function.BooleanSupplier condition: the condition that returns true when satisfied
        :param java.lang.String or str failureMessage: the message to print upon the timeout being reached
        :raises AssertionFailedError: if the condition is not met within the timeout period
        """

    @staticmethod
    @typing.overload
    def waitForCondition(condition: java.util.function.BooleanSupplier, failureMessageSupplier: java.util.function.Supplier[java.lang.String]):
        """
        Waits for the given condition to return true
        
        :param java.util.function.BooleanSupplier condition: the condition that returns true when satisfied
        :param java.util.function.Supplier[java.lang.String] failureMessageSupplier: the function that will supply the failure message in the event
                    of a timeout.
        :raises AssertionFailedError: if the condition is not met within the timeout period
        """

    @staticmethod
    def waitForConditionWithoutFailing(supplier: java.util.function.BooleanSupplier):
        """
        Waits for the given condition to return true. Most of the ``waitForCondition()``
        methods throw an :obj:`AssertionFailedError` if the timeout period expires. This method
        allows you to setup a longer wait period by repeatedly calling this method.
        
         
        
        Most clients should use :meth:`waitForCondition(BooleanSupplier) <.waitForCondition>`.
        
        :param java.util.function.BooleanSupplier supplier: the supplier that returns true when satisfied
        """

    @staticmethod
    def waitForValue(supplier: java.util.function.Supplier[T]) -> T:
        """
        Waits for the value returned by the supplier to be non-null, throwing an exception if that
        does not happen by the default timeout.
        
        :param java.util.function.Supplier[T] supplier: the supplier of the value
        :return: the non-null value
        :rtype: T
        :raises AssertionFailedError: if a non-null value is not returned within the timeout period
        """

    @staticmethod
    def waitForValueWithoutFailing(supplier: java.util.function.Supplier[T]) -> T:
        """
        Waits for the value returned by the supplier to be non-null. If the timeout period expires,
        then null will be returned. Most of the ``waitXyz()`` methods throw an
        :obj:`AssertionFailedError` if the timeout period expires. This method allows you to setup a
        longer wait period by repeatedly calling this method.
        
         
        
        Most clients should use :meth:`waitForValue(Supplier) <.waitForValue>`.
        
        :param java.util.function.Supplier[T] supplier: the supplier of the value
        :return: the value; may be null
        :rtype: T
        
        .. seealso::
        
            | :obj:`.waitForValue(Supplier)`
        """

    @property
    def name(self) -> java.lang.String:
        ...


class TestExceptionTracker(java.lang.Object):
    """
    A class to take an exception and capture test system state for later reporting.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, threadName: typing.Union[java.lang.String, str], t: java.lang.Throwable):
        ...

    def getCombinedException(self) -> java.lang.Throwable:
        ...

    def getException(self) -> java.lang.Throwable:
        ...

    def getExceptionMessage(self) -> str:
        ...

    def getStackTrace(self) -> jpype.JArray[java.lang.StackTraceElement]:
        ...

    def getThreadName(self) -> str:
        ...

    def printStackTrace(self):
        ...

    @property
    def exception(self) -> java.lang.Throwable:
        ...

    @property
    def combinedException(self) -> java.lang.Throwable:
        ...

    @property
    def stackTrace(self) -> jpype.JArray[java.lang.StackTraceElement]:
        ...

    @property
    def threadName(self) -> java.lang.String:
        ...

    @property
    def exceptionMessage(self) -> java.lang.String:
        ...


class TestUtils(java.lang.Object):
    """
    Actually, not.  At least not soon...all the *TestCase classes now can
    be split apart into static-style utility methods, and instance-type
    test harness/scaffold methods, but they will need to live at their
    respective layer, not all here in Base.
     
    Future home of utility methods (many methods of TestCase can be put here).
     
    
    A primary motivating factor for creating this class is to gain access to some of the myriad 
    functionality in TestCase without loading its static data.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def argTypes(*classes: java.lang.Class[typing.Any]) -> jpype.JArray[java.lang.Class[typing.Any]]:
        """
        A convenience method that can be statically  imported to use with the class, allowing 
        you to avoid your own ugly manual array creation.
        
        :param jpype.JArray[java.lang.Class[typing.Any]] classes: the classes
        :return: the classes array
        :rtype: jpype.JArray[java.lang.Class[typing.Any]]
        """

    @staticmethod
    def args(*objects: java.lang.Object) -> jpype.JArray[java.lang.Object]:
        """
        A convenience method that can be statically  imported to use with the class, allowing 
        you to avoid your own ugly manual array creation.
        
        :param jpype.JArray[java.lang.Object] objects: the objects
        :return: the objects array
        :rtype: jpype.JArray[java.lang.Object]
        """

    @staticmethod
    def createStackTraceForAllThreads() -> str:
        """
        Returns a string which is a printout of a stack trace for each thread running in the
        current JVM
        
        :return: the stack trace string
        :rtype: str
        """

    @staticmethod
    def getAllInstanceFields(ownerInstance: java.lang.Object) -> java.util.List[java.lang.Object]:
        """
        Gets all fields of the given object.  Only objects on the immediate instance are 
        returned.
        
        :param java.lang.Object ownerInstance: the object from which to get fields
        :return: the fields
        :rtype: java.util.List[java.lang.Object]
        """

    @staticmethod
    def getInstanceField(fieldName: typing.Union[java.lang.String, str], ownerInstance: java.lang.Object) -> java.lang.Object:
        """
        Gets the instance field by the given name on the given object 
        instance.  The value is a primitive wrapper if it is a primitive type.
         
        
        Note: if the field is static, then the ``ownerInstance`` field 
        can be the class of the object that contains the variable.
        
        :param java.lang.String or str fieldName: The name of the field to retrieve.
        :param java.lang.Object ownerInstance: The object instance from which to get the 
                variable instance.
        :return: The field instance.
        :rtype: java.lang.Object
        :raises java.lang.RuntimeException: if there is a problem accessing the field
                using reflection.  A RuntimeException is used so that calling
                tests can avoid using a try/catch block, but will still fail
                when an error is encountered.
        
        .. versionadded:: Tracker Id 267
        
        .. seealso::
        
            | :obj:`Field.get(java.lang.Object)`
        """

    @staticmethod
    def getInstanceFieldByClassType(classType: java.lang.Class[T], ownerInstance: java.lang.Object) -> T:
        """
        Get the first field object contained within object ownerInstance which has the type classType.
        This method is only really useful if it is known that only a single field of 
        classType exists within the ownerInstance.
        
        :param T: the type:param java.lang.Class[T] classType: the class type of the desired field
        :param java.lang.Object ownerInstance: the object instance that owns the field
        :return: field object of type classType or null
        :rtype: T
        """

    @staticmethod
    def invokeConstructor(containingClass: java.lang.Class[typing.Any], parameterTypes: jpype.JArray[java.lang.Class[typing.Any]], args: jpype.JArray[java.lang.Object]) -> java.lang.Object:
        """
        Uses reflection to execute the constructor for the given class with the given parameters.
        The new instance of the given class will be returned.
        
        :param java.lang.Class[typing.Any] containingClass: The class that contains the desired constructor.
        :param jpype.JArray[java.lang.Class[typing.Any]] parameterTypes: The parameter **types** that the constructor takes.
                This value can be null or zero length if there are no parameters
                to pass
        :param jpype.JArray[java.lang.Object] args: The parameter values that should be passed to the constructor.
                This value can be null or zero length if there are no parameters
                to pass
        :return: The new class instance
        :rtype: java.lang.Object
        :raises java.lang.RuntimeException: if there is a problem accessing the constructor
                using reflection.  A RuntimeException is used so that calling
                tests can avoid using a try/catch block, but will still fail
                when an error is encountered.
        """

    @staticmethod
    @typing.overload
    def invokeInstanceMethod(methodName: typing.Union[java.lang.String, str], ownerInstance: java.lang.Object, parameterTypes: jpype.JArray[java.lang.Class[typing.Any]], args: jpype.JArray[java.lang.Object]) -> java.lang.Object:
        """
        Uses reflection to execute the method denoted by the given method
        name.  If any value is returned from the method execution, then it 
        will be returned from this method.  Otherwise, ``null`` is returned.
         
        
        Note: if the method is static, then the ``ownerInstance`` field 
        can be the class of the object that contains the method.
        
        :param java.lang.String or str methodName: The name of the method to execute.
        :param java.lang.Object ownerInstance: The object instance of which the method will be
                executed.
        :param jpype.JArray[java.lang.Class[typing.Any]] parameterTypes: The parameter **types** that the method takes.
        :param jpype.JArray[java.lang.Object] args: The parameter values that should be passed to the method.
                This value can be null or zero length if there are no parameters
                to pass
        :return: The return value as returned from executing the method.
        :rtype: java.lang.Object
        :raises java.lang.RuntimeException: if there is a problem accessing the field
                using reflection.  A RuntimeException is used so that calling
                tests can avoid using a try/catch block, but will still fail
                when an error is encountered.
        
        .. versionadded:: Tracker Id 267
        
        .. seealso::
        
            | :obj:`Method.invoke(java.lang.Object, java.lang.Object[])`
        """

    @staticmethod
    @typing.overload
    def invokeInstanceMethod(methodName: typing.Union[java.lang.String, str], ownerInstance: java.lang.Object, parameterTypes: java.util.List[java.lang.Class[typing.Any]], args: java.util.List[java.lang.Object]) -> java.lang.Object:
        """
        Uses reflection to execute the method denoted by the given method
        name.  If any value is returned from the method execution, then it 
        will be returned from this method.  Otherwise, ``null`` is returned.
         
        
        Note: if the method is static, then the ``ownerInstance`` field 
        can be the class of the object that contains the method.
         
         
        This method is just a convenience for calling 
        :meth:`invokeInstanceMethod(String, Object, Class[], Object[]) <.invokeInstanceMethod>`.  As the following 
        example shows, this method's uses is a bit cleaner:
         
            // The call below is equivalent to calling: `` System.out.println("Hi")
            invokeInstanceMethod("println", System.out, Arrays.asList(String.class), Arrays.asList("Hi"));
            ``
         
        
        :param java.lang.String or str methodName: The name of the method to execute.
        :param java.lang.Object ownerInstance: The object instance of which the method will be
                executed.
        :param java.util.List[java.lang.Class[typing.Any]] parameterTypes: The parameter **types** that the method takes.
        :param java.util.List[java.lang.Object] args: The parameter values that should be passed to the method.
                This value can be null or zero length if there are no parameters
                to pass
        :return: The return value as returned from executing the method.
        :rtype: java.lang.Object
        :raises java.lang.RuntimeException: if there is a problem accessing the field
                using reflection.  A RuntimeException is used so that calling
                tests can avoid using a try/catch block, but will still fail
                when an error is encountered.
        """

    @staticmethod
    @typing.overload
    def invokeInstanceMethod(methodName: typing.Union[java.lang.String, str], ownerInstance: java.lang.Object, parameterType: java.lang.Class[typing.Any], arg: java.lang.Object) -> java.lang.Object:
        """
        Uses reflection to execute the method denoted by the given method
        name.  If any value is returned from the method execution, then it 
        will be returned from this method.  Otherwise, ``null`` is returned.
         
        
        Note: if the method is static, then the ``ownerInstance`` field 
        can be the class of the object that contains the method.
         
         
        If the method you are calling takes no parameters, then call 
        :meth:`invokeInstanceMethod(String, Object) <.invokeInstanceMethod>` instead.
         
         
        This method is just a convenience for calling 
        :meth:`invokeInstanceMethod(String, Object, Class[], Object[]) <.invokeInstanceMethod>` when the method only
        takes a single parameter, so that you don't have the ugliness of creating arrays as the
        parameters for this method.
         
         
        As an example:
         
            // The call below is equivalent to calling: `` System.out.println("Hi")
            invokeInstanceMethod("println", System.out, String.class, "Hi");
            ``
         
        
        :param java.lang.String or str methodName: The name of the method to execute.
        :param java.lang.Object ownerInstance: The object instance of which the method will be
                executed.
        :param java.lang.Class[typing.Any] parameterType: The parameter types that the method takes.
        :param java.lang.Object arg: The parameter value that should be passed to the method.
        :return: The return value as returned from executing the method.
        :rtype: java.lang.Object
        :raises java.lang.RuntimeException: if there is a problem accessing the field
                using reflection.  A RuntimeException is used so that calling
                tests can avoid using a try/catch block, but will still fail
                when an error is encountered.
        """

    @staticmethod
    @typing.overload
    def invokeInstanceMethod(methodName: typing.Union[java.lang.String, str], ownerInstance: java.lang.Object, *args: java.lang.Object) -> java.lang.Object:
        """
        Uses reflection to execute the method denoted by the given method
        name.  If any value is returned from the method execution, then it 
        will be returned from this method.  Otherwise, ``null`` is returned.
         
        
        Note: if the method is static, then the ``ownerInstance`` field 
        can be the class of the object that contains the method.
         
         
        **Warning: The exact class of each ``arg`` will be used as the class type
        of the parameter for the method being called.  If the method you are calling takes 
        parameters that do not match exactly the class of the args you wish to use, then 
        call :meth:`invokeInstanceMethod(String, Object, List, List) <.invokeInstanceMethod>` instead so that you 
        can specify the parameter types explicitly.
        **
         
         
        If the method you are calling takes no parameters, then call 
        :meth:`invokeInstanceMethod(String, Object) <.invokeInstanceMethod>` instead.
         
         
        This method is just a convenience for calling 
        :meth:`invokeInstanceMethod(String, Object, Class[], Object[]) <.invokeInstanceMethod>` when the method only
        takes a single parameter, so that you don't have the ugliness of creating arrays as the
        parameters for this method.
         
         
        As an example:
         
            // The call below is equivalent to calling: `` System.out.println("Hi")
            invokeInstanceMethod("println", System.out, "Hi");
         
            // This call is equivalent to the one above
            invokeInstanceMethod("println", System.out, Arrays.asList(String.class), Arrays.asList("Hi"));
             
            ``
         
        
        :param java.lang.String or str methodName: The name of the method to execute.
        :param java.lang.Object ownerInstance: The object instance of which the method will be
                executed.
        :param jpype.JArray[java.lang.Object] args: The parameter value that should be passed to the method.
        :return: The return value as returned from executing the method.
        :rtype: java.lang.Object
        :raises java.lang.RuntimeException: if there is a problem accessing the field
                using reflection.  A RuntimeException is used so that calling
                tests can avoid using a try/catch block, but will still fail
                when an error is encountered.
        """

    @staticmethod
    @typing.overload
    def invokeInstanceMethod(methodName: typing.Union[java.lang.String, str], ownerInstance: java.lang.Object) -> java.lang.Object:
        """
        This method is just a "pass through" method for 
        :meth:`invokeInstanceMethod(String, Object, Class[], Object[]) <.invokeInstanceMethod>` so 
        that callers do not need to pass null to that method when the 
        underlying instance method does not have any parameters.
        
        :param java.lang.String or str methodName: The name of the method to execute.
        :param java.lang.Object ownerInstance: The object instance of which the method will be
                executed.
        :return: The return value as returned from executing the method.
        :rtype: java.lang.Object
        :raises java.lang.RuntimeException: if there is a problem accessing the field
                using reflection.  A RuntimeException is used so that calling
                tests can avoid using a try/catch block, but will still fail
                when an error is encountered.
        
        .. seealso::
        
            | :obj:`Method.invoke(java.lang.Object, java.lang.Object[])`
        
            | :obj:`.invokeInstanceMethod(String, Object, Class[], Object[])`
        """

    @staticmethod
    def locateFieldByTypeOnClass(classType: java.lang.Class[typing.Any], containingClass: java.lang.Class[typing.Any]) -> java.lang.reflect.Field:
        """
        Get the first field specification contained within containingClass which has the type classType.
        This method is only really useful if it is known that only a single field of 
        classType exists within the containingClass hierarchy.
        
        :param java.lang.Class[typing.Any] classType: the class
        :param java.lang.Class[typing.Any] containingClass: the class that contains a field of the given type
        :return: field which corresponds to type classType or null
        :rtype: java.lang.reflect.Field
        """

    @staticmethod
    def setInstanceField(fieldName: typing.Union[java.lang.String, str], ownerInstance: java.lang.Object, value: java.lang.Object):
        """
        Sets the instance field by the given name on the given object 
        instance.  
         
        
        Note: if the field is static, then the ``ownerInstance`` field 
        can be the class of the object that contains the variable.
        
        :param java.lang.String or str fieldName: The name of the field to retrieve.
        :param java.lang.Object ownerInstance: The object instance from which to get the 
                variable instance.
        :param java.lang.Object value: The value to use when setting the given field
        :raises java.lang.RuntimeException: if there is a problem accessing the field
                using reflection.  A RuntimeException is used so that calling
                tests can avoid using a try/catch block, but will still fail
                when an error is encountered.
        
        .. seealso::
        
            | :obj:`Field.set(Object, Object)`
        """


class ConcurrentTestExceptionHandler(java.lang.Thread.UncaughtExceptionHandler):
    """
    A class which handles exceptions that occur off of the main test thread.  Exceptions can be
    reported to this class, which will later be checked by :obj:`AbstractGenericTest`.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def clear():
        """
        Clears all exceptions being tracked by this class
        """

    @staticmethod
    def disable():
        """
        Disables this class's tracking of exceptions.  Clients use this method to have this class
        ignore expected exceptions.   This is a bit course-grained, as it does not allow clients to
        ignore specific expected exceptions.
        """

    @staticmethod
    def enable():
        """
        Enables this class after a call to :meth:`disable() <.disable>` has been made
        """

    @staticmethod
    def getExceptions() -> java.util.List[TestExceptionTracker]:
        """
        Returns all exceptions tracked by this class
        
        :return: all exceptions tracked by this class
        :rtype: java.util.List[TestExceptionTracker]
        """

    @staticmethod
    def handle(thread: java.lang.Thread, t: java.lang.Throwable):
        """
        Tells this class to process the given throwable
        
        :param java.lang.Thread thread: the thread that encountered the throwable
        :param java.lang.Throwable t: the throwable
        """

    @staticmethod
    def hasException() -> bool:
        """
        Returns true if this class has been given any exceptions to handle since last being cleared
        
        :return: true if this class has been given any exceptions to handle since last being cleared
        :rtype: bool
        """

    @staticmethod
    def isEnabled() -> bool:
        """
        Returns true if this class is enabled.  When disabled this class does not track exceptions.
        
        :return: true if enabled
        :rtype: bool
        """

    @staticmethod
    def registerHandler():
        """
        Installs this exception handler as the default uncaught exception handler.  See
        :meth:`Thread.setDefaultUncaughtExceptionHandler(UncaughtExceptionHandler) <Thread.setDefaultUncaughtExceptionHandler>`
        """



__all__ = ["AbstractGuiTest", "TestThread", "TestReportingException", "AbstractGenericTest", "ConcurrentTestExceptionStatement", "AbstractGTest", "TestExceptionTracker", "TestUtils", "ConcurrentTestExceptionHandler"]
