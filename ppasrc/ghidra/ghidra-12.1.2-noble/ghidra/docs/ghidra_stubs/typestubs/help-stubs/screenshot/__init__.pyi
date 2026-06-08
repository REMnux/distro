from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.widgets.fieldpanel.field
import docking.widgets.table
import ghidra.app.plugin.core.comments
import ghidra.framework.plugintool
import ghidra.program.model.address
import ghidra.program.model.listing
import ghidra.test
import ghidra.util.bean
import java.awt # type: ignore
import java.awt.image # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


T = typing.TypeVar("T")


class TutorialScreenShotGenerator(AbstractScreenShotGenerator):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    @deprecated("NOTE:  Please do not remove this until we have decided how to create a showImage() method\n        that is compatible with screenshots NOT in Help (ahem, Tutorial!!!).")
    def showImage(self) -> None:
        """
        
        
        
        .. deprecated::
        
        NOTE:  Please do not remove this until we have decided how to create a showImage() method
                that is compatible with screenshots NOT in Help (ahem, Tutorial!!!).
        """


class ImageDialogProvider(docking.DialogComponentProvider):

    @typing.type_check_only
    class ShapePainter(ghidra.util.bean.GGlassPanePainter):

        class_: typing.ClassVar[java.lang.Class]

        def setColor(self, color: java.awt.Color) -> None:
            ...


    class_: typing.ClassVar[java.lang.Class]


class AbstractScreenShotGenerator(ghidra.test.AbstractGhidraHeadedIntegrationTest):

    class_: typing.ClassVar[java.lang.Class]
    tool: ghidra.framework.plugintool.PluginTool
    env: ghidra.test.TestEnv
    program: ghidra.program.model.listing.Program
    image: java.awt.Image

    def __init__(self) -> None:
        ...

    def addSelection(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]) -> None:
        ...

    def addr(self, value: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        ...

    @deprecated("use addr(long) instead")
    def address(self, value: typing.Union[jpype.JLong, int]) -> ghidra.program.model.address.Address:
        """
        
        
        :param jpype.JLong or int value: the address's long value
        :return: the new address
        :rtype: ghidra.program.model.address.Address
        
        .. deprecated::
        
        use :meth:`addr(long) <.addr>` instead
        """

    def captureActionIcon(self, actionName: typing.Union[java.lang.String, str]) -> None:
        ...

    def captureComponent(self, component: java.awt.Component) -> java.awt.Image:
        ...

    def captureComponents(self, comps: java.util.List[java.awt.Component]) -> None:
        ...

    @typing.overload
    def captureDialog(self) -> None:
        ...

    @typing.overload
    def captureDialog(self, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def captureDialog(self, title: typing.Union[java.lang.String, str]) -> None:
        ...

    @typing.overload
    def captureDialog(self, clazz: java.lang.Class[docking.DialogComponentProvider]) -> None:
        ...

    @typing.overload
    def captureDialog(self, provider: docking.DialogComponentProvider) -> None:
        ...

    @typing.overload
    def captureDialog(self, clazz: java.lang.Class[docking.DialogComponentProvider], width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def captureDialog(self, dialog: java.awt.Dialog) -> None:
        ...

    @typing.overload
    def captureDialog(self, dialog: java.awt.Dialog, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        ...

    def captureIcon(self, icon: javax.swing.Icon) -> None:
        ...

    def captureIsolatedComponent(self, component: javax.swing.JComponent, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def captureIsolatedProvider(self, clazz: java.lang.Class[docking.ComponentProvider], width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def captureIsolatedProvider(self, provider: docking.ComponentProvider, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        ...

    def captureIsolatedProviderWindow(self, clazz: java.lang.Class[docking.ComponentProvider], width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        """
        The same as :meth:`GhidraScreenShotGenerator.captureIsolatedProvider(Class, int, int) <GhidraScreenShotGenerator.captureIsolatedProvider>` except
        this method will also capture the containing window.
        
        :param java.lang.Class[docking.ComponentProvider] clazz: the provider class
        :param jpype.JInt or int width: the width of the capture
        :param jpype.JInt or int height: the height of the capture
        """

    def captureListingField(self, address: typing.Union[jpype.JLong, int], fieldName: typing.Union[java.lang.String, str], padding: typing.Union[jpype.JInt, int]) -> None:
        ...

    def captureListingRange(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int], width: typing.Union[jpype.JInt, int]) -> None:
        ...

    def captureMenu(self) -> None:
        ...

    def captureMenuBarMenu(self, menuName: typing.Union[java.lang.String, str], *subMenuNames: typing.Union[java.lang.String, str]) -> None:
        ...

    def captureMenuBarMenuHierachy(self, menuName: typing.Union[java.lang.String, str], *subMenuNames: typing.Union[java.lang.String, str]) -> None:
        ...

    @typing.overload
    def captureProvider(self, clazz: java.lang.Class[docking.ComponentProvider]) -> None:
        ...

    @typing.overload
    def captureProvider(self, provider: docking.ComponentProvider) -> None:
        ...

    @typing.overload
    def captureProvider(self, name: typing.Union[java.lang.String, str]) -> None:
        ...

    @typing.overload
    def captureProviderWindow(self, name: typing.Union[java.lang.String, str]) -> None:
        """
        Captures the window, including decorations. This will use a :obj:`Robot` to create a screen
        capture, which has the effect of getting all items within the window bounds. This method is
        needed if you wish to capture child windows, like popups/hovers.
        
         
        
        Other capture methods will not use the screen capture mechanism, but rather will directly
        render the given component. In this case, subordinate windows will not be captured. For
        example, see :meth:`captureProvider(Class) <.captureProvider>`.
        
        :param java.lang.String or str name: the provider's name
        """

    @typing.overload
    def captureProviderWindow(self, clazz: java.lang.Class[docking.ComponentProvider]) -> None:
        """
        Captures the window, including decorations. This will use a :obj:`Robot` to create a screen
        capture, which has the effect of getting all items within the window bounds. This method is
        needed if you wish to capture child windows, like popups/hovers.
        
         
        
        Other capture methods will not use the screen capture mechanism, but rather will directly
        render the given component. In this case, subordinate windows will not be captured. For
        example, see :meth:`captureProvider(Class) <.captureProvider>`.
        
        :param java.lang.Class[docking.ComponentProvider] clazz: the provider's class
        """

    @typing.overload
    def captureProviderWindow(self, provider: docking.ComponentProvider) -> None:
        """
        Captures the window, including decorations. This will use a :obj:`Robot` to create a screen
        capture, which has the effect of getting all items within the window bounds. This method is
        needed if you wish to capture child windows, like popups/hovers.
        
         
        
        Other capture methods will not use the screen capture mechanism, but rather will directly
        render the given component. In this case, subordinate windows will not be captured. For
        example, see :meth:`captureProvider(Class) <.captureProvider>`.
        
        :param docking.ComponentProvider provider: the provider
        """

    @typing.overload
    def captureProviderWindow(self, name: typing.Union[java.lang.String, str], width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        """
        Captures the window, including decorations. This will use a :obj:`Robot` to create a screen
        capture, which has the effect of getting all items within the window bounds. This method is
        needed if you wish to capture child windows, like popups/hovers.
        
         
        
        Other capture methods will not use the screen capture mechanism, but rather will directly
        render the given component. In this case, subordinate windows will not be captured. For
        example, see :meth:`captureProvider(Class) <.captureProvider>`.
        
        :param java.lang.String or str name: the provider's name
        :param jpype.JInt or int width: the desired width
        :param jpype.JInt or int height: the desired height
        """

    @typing.overload
    def captureProviderWindow(self, provider: docking.ComponentProvider, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        """
        Captures the window, including decorations. This will use a :obj:`Robot` to create a screen
        capture, which has the effect of getting all items within the window bounds. This method is
        needed if you wish to capture child windows, like popups/hovers.
        
         
        
        Other capture methods will not use the screen capture mechanism, but rather will directly
        render the given component. In this case, subordinate windows will not be captured. For
        example, see :meth:`captureProvider(Class) <.captureProvider>`.
        
        :param docking.ComponentProvider provider: the provider's name
        :param jpype.JInt or int width: the desired width
        :param jpype.JInt or int height: the desired height
        """

    def captureProviderWithScreenShot(self, provider: docking.ComponentProvider) -> None:
        """
        Captures the provider by using a screen shot and not by painting the provider directly (as
        does :meth:`captureProvider(ComponentProvider) <.captureProvider>`). Use this method if you need to capture the
        provider along with any popup windows.
        
        :param docking.ComponentProvider provider: the provider
        """

    def captureToolWindow(self, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def captureWindow(self) -> None:
        ...

    @typing.overload
    def captureWindow(self, window: java.awt.Window) -> None:
        ...

    @typing.overload
    def captureWindow(self, window: java.awt.Window, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        ...

    def closeNonProgramArchives(self) -> None:
        ...

    def closeProvider(self, clazz: java.lang.Class[docking.ComponentProvider]) -> None:
        ...

    def createBookmark(self, address: typing.Union[jpype.JLong, int]) -> None:
        ...

    def createEmptyImage(self, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> java.awt.image.BufferedImage:
        ...

    def crop(self, bounds: java.awt.Rectangle) -> java.awt.Image:
        ...

    def doubleClickCursor(self) -> None:
        ...

    @typing.overload
    def drawArrow(self, c: java.awt.Color, start: java.awt.Point, end: java.awt.Point) -> None:
        ...

    @typing.overload
    def drawArrow(self, c: java.awt.Color, thickness: typing.Union[jpype.JInt, int], start: java.awt.Point, end: java.awt.Point, arrowSize: typing.Union[jpype.JInt, int]) -> None:
        ...

    def drawBorder(self, c: java.awt.Color) -> None:
        ...

    def drawLine(self, c: java.awt.Color, thickness: typing.Union[jpype.JInt, int], start: java.awt.Point, end: java.awt.Point) -> None:
        ...

    def drawOval(self, c: java.awt.Color, rect: java.awt.Rectangle, thickness: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def drawRectangle(self, c: java.awt.Color, r: java.awt.Rectangle, padding: typing.Union[jpype.JInt, int], thickness: typing.Union[jpype.JInt, int]) -> java.awt.Rectangle:
        ...

    @typing.overload
    def drawRectangle(self, c: java.awt.Color, rect: java.awt.Rectangle, thickness: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def drawRectangleAround(self, component: javax.swing.JComponent, color: java.awt.Color, padding: typing.Union[jpype.JInt, int]) -> java.awt.Rectangle:
        ...

    @typing.overload
    def drawRectangleAround(self, component: javax.swing.JComponent, root: javax.swing.JComponent, color: java.awt.Color, padding: typing.Union[jpype.JInt, int]) -> java.awt.Rectangle:
        """
        Draws a rectangle around the given component. The root parameter is used to calculate screen
        coordinates. This allows you to capture a sub-component of a UI, drawing rectangles around
        children of said sub-component.
        
         
        
        If you are unsure of what to pass for ``root``, the call
        :meth:`drawRectangleAround(JComponent, Color, int) <.drawRectangleAround>` instead.
        
        :param javax.swing.JComponent component: the component to be en-rectangled
        :param javax.swing.JComponent root: the outermost container widget being displayed; null implies a top-level parent
        :param java.awt.Color color: the rectangle color
        :param jpype.JInt or int padding: the space between the rectangle and the component; more space makes the
                    component more visible
        :return: the bounds of the drawn rectangle
        :rtype: java.awt.Rectangle
        """

    def drawRectangleWithDropShadowAround(self, component: javax.swing.JComponent, color: java.awt.Color, padding: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def drawText(self, text: typing.Union[java.lang.String, str], color: java.awt.Color, start: java.awt.Point, size: typing.Union[jpype.JFloat, float]) -> None:
        ...

    @typing.overload
    def drawText(self, text: typing.Union[java.lang.String, str], color: java.awt.Color, start: java.awt.Point, font: java.awt.Font) -> None:
        ...

    def error(self, e: java.lang.Exception) -> None:
        ...

    def exit(self) -> None:
        ...

    def fillRectangle(self, c: java.awt.Color, rect: java.awt.Rectangle) -> None:
        ...

    def findProviderToolBarButton(self, provider: docking.ComponentProvider, actionName: typing.Union[java.lang.String, str]) -> javax.swing.JButton:
        ...

    def findRowByPartialText(self, table: javax.swing.JTable, searchString: typing.Union[java.lang.String, str]) -> int:
        ...

    def generateImage(self, c: java.awt.Component) -> None:
        ...

    def getBounds(self, component: javax.swing.JComponent) -> java.awt.Rectangle:
        ...

    def getCursorBounds(self) -> java.awt.Rectangle:
        ...

    @typing.overload
    def getDialog(self) -> docking.DialogComponentProvider:
        ...

    @typing.overload
    def getDialog(self, clazz: java.lang.Class[docking.DialogComponentProvider]) -> docking.DialogComponentProvider:
        ...

    @typing.overload
    def getDockableComponent(self, provider: docking.ComponentProvider) -> docking.DockableComponent:
        ...

    @typing.overload
    def getDockableComponent(self, clazz: java.lang.Class[docking.ComponentProvider]) -> docking.DockableComponent:
        ...

    def getField(self, point: java.awt.Point) -> docking.widgets.fieldpanel.field.Field:
        ...

    def getPopupMenu(self) -> javax.swing.JPopupMenu:
        ...

    @typing.overload
    def getProvider(self, name: typing.Union[java.lang.String, str]) -> docking.ComponentProvider:
        ...

    @typing.overload
    def getProvider(self, clazz: java.lang.Class[T]) -> T:
        ...

    def go(self, address: typing.Union[jpype.JLong, int]) -> None:
        ...

    @typing.overload
    def goToListing(self, address: typing.Union[jpype.JLong, int]) -> None:
        ...

    @typing.overload
    def goToListing(self, address: typing.Union[jpype.JLong, int], scrollToMiddle: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    @typing.overload
    def goToListing(self, address: typing.Union[jpype.JLong, int], fieldName: typing.Union[java.lang.String, str], scrollToMiddle: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    def hideTableColumn(self, table: docking.widgets.table.GTable, columnName: typing.Union[java.lang.String, str]) -> None:
        ...

    def leftClickCursor(self) -> None:
        ...

    @typing.overload
    def loadPlugin(self, clazz: java.lang.Class[ghidra.framework.plugintool.Plugin]) -> ghidra.framework.plugintool.Plugin:
        ...

    @typing.overload
    def loadPlugin(self, className: typing.Union[java.lang.String, str]) -> ghidra.framework.plugintool.Plugin:
        ...

    @typing.overload
    def loadProgram(self) -> None:
        ...

    @typing.overload
    def loadProgram(self, programName: typing.Union[java.lang.String, str]) -> ghidra.program.model.listing.Program:
        ...

    @typing.overload
    def makeSelection(self, addrSet: ghidra.program.model.address.AddressSet) -> None:
        ...

    @typing.overload
    def makeSelection(self, start: typing.Union[jpype.JLong, int], end: typing.Union[jpype.JLong, int]) -> None:
        ...

    def middleClickCursor(self) -> None:
        ...

    def moveProvider(self, movee: docking.ComponentProvider, relativeTo: docking.ComponentProvider, position: docking.WindowPosition) -> None:
        ...

    @typing.overload
    def moveProviderToFront(self, provider: docking.ComponentProvider, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def moveProviderToFront(self, provider: docking.ComponentProvider) -> None:
        ...

    @typing.overload
    def moveProviderToItsOwnWindow(self, provider: docking.ComponentProvider) -> java.awt.Window:
        ...

    @typing.overload
    def moveProviderToItsOwnWindow(self, provider: docking.ComponentProvider, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> java.awt.Window:
        ...

    def moveWindowUp(self, window: java.awt.Window, yOffset: typing.Union[jpype.JInt, int]) -> None:
        ...

    def padImage(self, c: java.awt.Color, top: typing.Union[jpype.JInt, int], left: typing.Union[jpype.JInt, int], right: typing.Union[jpype.JInt, int], bottom: typing.Union[jpype.JInt, int]) -> java.awt.Image:
        ...

    @typing.overload
    def performAction(self, actionName: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], wait: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    @typing.overload
    def performAction(self, actionName: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], contextProvider: docking.ComponentProvider, wait: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    def performDialogAction(self, actionName: typing.Union[java.lang.String, str], wait: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    def performMemorySearch(self, searchString: typing.Union[java.lang.String, str]) -> None:
        ...

    def placeImagesSideBySide(self, left: java.awt.Image, right: java.awt.Image) -> java.awt.Image:
        ...

    @typing.overload
    def positionCursor(self, address: typing.Union[jpype.JLong, int]) -> None:
        ...

    @typing.overload
    def positionCursor(self, address: typing.Union[jpype.JLong, int], fieldName: typing.Union[java.lang.String, str]) -> None:
        ...

    def positionListingCenter(self, address: typing.Union[jpype.JLong, int]) -> None:
        ...

    def positionListingTop(self, address: typing.Union[jpype.JLong, int]) -> None:
        ...

    def prepareCommentsDialog(self, dialog: ghidra.app.plugin.core.comments.CommentsDialog, annotationText: typing.Union[java.lang.String, str]) -> None:
        ...

    def prepareTool(self) -> None:
        ...

    def pressButtonOnDialog(self, buttonText: typing.Union[java.lang.String, str]) -> None:
        ...

    def pressOkOnDialog(self) -> None:
        ...

    def removeField(self, fieldName: typing.Union[java.lang.String, str]) -> None:
        ...

    def removeFlowArrows(self) -> None:
        ...

    def rightClickCursor(self) -> None:
        ...

    def scrollToRow(self, table: javax.swing.JTable, row: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def selectRow(self, table: javax.swing.JTable, rowIndex: typing.Union[jpype.JInt, int]) -> None:
        ...

    @typing.overload
    def selectRow(self, table: javax.swing.JTable, searchString: typing.Union[java.lang.String, str]) -> None:
        ...

    def setDividerPercentage(self, provider1: java.lang.Class[docking.ComponentProvider], provider2: java.lang.Class[docking.ComponentProvider], percentage: typing.Union[jpype.JFloat, float]) -> None:
        ...

    def setListingFieldWidth(self, fieldName: typing.Union[java.lang.String, str], width: typing.Union[jpype.JInt, int]) -> None:
        ...

    def setSelected(self, button: javax.swing.JToggleButton, select: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    def setSelectedAnayzer(self, analysisPanel: java.lang.Object, analyzerName: typing.Union[java.lang.String, str]) -> None:
        ...

    def setToolSize(self, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        ...

    def setUp(self) -> None:
        ...

    def setUser(self, userName: typing.Union[java.lang.String, str]) -> None:
        ...

    def setWindowSize(self, window: java.awt.Window, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> None:
        ...

    def showAnalysisOptions(self, selectedAnalyzerName: typing.Union[java.lang.String, str]) -> None:
        ...

    def showColumnSettings(self, table: docking.widgets.table.GTable, colName: typing.Union[java.lang.String, str]) -> None:
        ...

    def showCommentDialog(self, text: typing.Union[java.lang.String, str]) -> None:
        ...

    def showMenuBarMenu(self, menuName: typing.Union[java.lang.String, str], *submenuNames: typing.Union[java.lang.String, str]) -> java.util.List[java.awt.Component]:
        ...

    def showOptions(self, optionsCategoryName: typing.Union[java.lang.String, str]) -> None:
        ...

    def showProgramOptions(self, optionsCategoryName: typing.Union[java.lang.String, str]) -> None:
        ...

    def showProvider(self, clazz: java.lang.Class[T]) -> T:
        ...

    def showTab(self, title: typing.Union[java.lang.String, str]) -> java.awt.Component:
        ...

    def showTableColumn(self, table: docking.widgets.table.GTable, columnName: typing.Union[java.lang.String, str]) -> None:
        ...

    def takeSnippet(self, bounds: java.awt.Rectangle) -> java.awt.Image:
        """
        Crops a part of the current image, keeping what is inside the given bounds. This method
        creates a shape such that the top and bottom of the cropped image have a jagged line, looking
        somewhat like a sideways lightening bolt.
        
        :param java.awt.Rectangle bounds: the bounds to keep
        :return: the snippet
        :rtype: java.awt.Image
        """

    def tearDown(self) -> None:
        ...

    def topOfListing(self, address: typing.Union[jpype.JLong, int]) -> None:
        ...

    @property
    def dialog(self) -> docking.DialogComponentProvider:
        ...

    @property
    def field(self) -> docking.widgets.fieldpanel.field.Field:
        ...

    @property
    def dockableComponent(self) -> docking.DockableComponent:
        ...

    @property
    def provider(self) -> docking.ComponentProvider:
        ...

    @property
    def bounds(self) -> java.awt.Rectangle:
        ...

    @property
    def popupMenu(self) -> javax.swing.JPopupMenu:
        ...

    @property
    def cursorBounds(self) -> java.awt.Rectangle:
        ...


class GhidraScreenShotGenerator(AbstractScreenShotGenerator):
    """
    Extend this class to create screen shot images for help. The name of the class determines the
    topic directory where the captured image will be stored. So if the class name is
    XyzShreenShots, the resulting captured image will appear in help topic directly "Xyz", regardless
    of which module has that topic.  The test name will determine the name of the image file
    that is generated. So if the test name is testHappyBirthday, the filename will be
    HappyBirthday.png.
    """

    class_: typing.ClassVar[java.lang.Class]

    def finished(self, helpTopic: jpype.protocol.SupportsPath, oldImageName: typing.Union[java.lang.String, str]) -> None:
        """
        Call when you are finished generating a new image.  This method will either show the
        newly created image or write it to disk, depending upon the value of
        :obj:`.SAVE_CREATED_IMAGE_FILE`, which is a system property.
        
        :param jpype.protocol.SupportsPath helpTopic: The help topic that contains the image
        :param java.lang.String or str oldImageName: The name of the image
        """

    def loadDefaultTool(self) -> None:
        ...

    def performFrontEndAction(self, actionName: typing.Union[java.lang.String, str], owner: typing.Union[java.lang.String, str], wait: typing.Union[jpype.JBoolean, bool]) -> None:
        ...

    @typing.overload
    def saveOrDisplayImage(self) -> None:
        """
        Generally, you shouldn't use this.  This is only visible for those who do not directly
        extend this class.
        """

    @typing.overload
    def saveOrDisplayImage(self, name: typing.Union[java.lang.String, str]) -> None:
        ...

    @deprecated("use instead finished(File, String).")
    def saveToHelp(self, helpTopic: typing.Union[java.lang.String, str], imageName: typing.Union[java.lang.String, str]) -> None:
        """
        
        
        
        .. deprecated::
        
        use instead :meth:`finished(File, String) <.finished>`.
        :param java.lang.String or str helpTopic: The help topic that contains the image
        :param java.lang.String or str imageName: The name of the image
        """

    @deprecated("use instead finished(File, String).")
    def showImage(self, helpTopic: typing.Union[java.lang.String, str], oldImageName: typing.Union[java.lang.String, str]) -> None:
        """
        
        
        
        .. deprecated::
        
        use instead :meth:`finished(File, String) <.finished>`.
        :param java.lang.String or str helpTopic: The help topic that contains the image
        :param java.lang.String or str oldImageName: The name of the image
        """


class HelpMissingScreenShotReportGenerator(java.lang.Object):

    @typing.type_check_only
    class HelpTestFile(java.lang.Comparable[HelpMissingScreenShotReportGenerator.HelpTestFile]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class HelpTestCase(java.lang.Comparable[HelpMissingScreenShotReportGenerator.HelpTestCase]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]) -> None:
        ...


class HelpScreenShotReportGenerator(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]) -> None:
        ...



__all__ = ["TutorialScreenShotGenerator", "ImageDialogProvider", "AbstractScreenShotGenerator", "GhidraScreenShotGenerator", "HelpMissingScreenShotReportGenerator", "HelpScreenShotReportGenerator"]
