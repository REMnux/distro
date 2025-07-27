from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.table
import ghidra.framework.main.logviewer.event
import ghidra.framework.main.logviewer.model
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.plaf.basic # type: ignore
import javax.swing.table # type: ignore


class FVSliderUI(javax.swing.plaf.basic.BasicSliderUI):
    """
    Custom UI for a slider that dynamically adjusts the thumb height based on the size of the
    given :obj:`JScrollPane` and {JTable}.
     
    Note: This is used instead of a {link BasicScrollBarUI} instance because of the complexity
    of trying to adjust the thumb size of a :obj:`JScrollBar` that is not attached to a 
    :obj:`JScrollPane` instance.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, slider: javax.swing.JSlider, scrollPane: javax.swing.JScrollPane, table: javax.swing.JTable, reader: ghidra.framework.main.logviewer.model.ChunkReader, model: ghidra.framework.main.logviewer.model.ChunkModel):
        """
        Constructor.
        
        :param javax.swing.JSlider slider: 
        :param javax.swing.JScrollPane scrollPane: 
        :param javax.swing.JTable table: 
        :param ghidra.framework.main.logviewer.model.ChunkReader reader: 
        :param ghidra.framework.main.logviewer.model.ChunkModel model:
        """


class ViewportUtility(java.util.Observer):
    """
    Utility class for managing the viewport in the :obj:`FVTable`. This viewport must be 
    adjusted manually whenever :obj:`Chunk` objects are added to or removed from to the view, 
    or whenever the :obj:`FVSlider` is moved.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: ghidra.framework.main.logviewer.event.FVEventListener):
        ...

    def getHeight(self) -> int:
        """
        Returns the height (in pixels) of the viewport.
        
        :return: 
        :rtype: int
        """

    def getNumRowsInViewport(self) -> int:
        """
        Returns the number of rows that are visible in the viewport.
        
        :return: 
        :rtype: int
        """

    def getViewportPositionAsRow(self) -> int:
        """
        Returns the table row associated with the top of the viewport.
        
        :return: 
        :rtype: int
        """

    def isInViewport(self, row: typing.Union[jpype.JInt, int]) -> bool:
        """
        Returns true if the given row is in the viewport.
        
        :param jpype.JInt or int row: 
        :return: 
        :rtype: bool
        """

    def moveViewportDown(self, rows: typing.Union[jpype.JInt, int], selection: typing.Union[jpype.JBoolean, bool]):
        """
        Moves the viewport down the number of rows specified. If moving down puts he view below 
        the bounds of the first-visible chunk, load the next chunk.
        
        :param jpype.JInt or int rows: 
        :param jpype.JBoolean or bool selection:
        """

    def moveViewportToBottom(self):
        """
        Snaps the viewport to the bottom of the table.
        """

    def moveViewportToTop(self):
        """
        Snaps the viewport to the top of the table.
        """

    def moveViewportUp(self, rows: typing.Union[jpype.JInt, int], selection: typing.Union[jpype.JBoolean, bool]):
        """
        Moves the viewport up the number of rows specified. If moving up puts he view above 
        the bounds of the first-visible chunk, load a previous chunk.
        
        :param jpype.JInt or int rows: 
        :param jpype.JBoolean or bool selection:
        """

    def scrollViewportTo(self, row: typing.Union[jpype.JInt, int]):
        """
        Moves the viewport (top) to the given row in the current view.
        
        :param jpype.JInt or int row:
        """

    def setModel(self, model: ghidra.framework.main.logviewer.model.ChunkModel):
        """
        
        
        :param ghidra.framework.main.logviewer.model.ChunkModel model:
        """

    def setReader(self, reader: ghidra.framework.main.logviewer.model.ChunkReader):
        """
        
        
        :param ghidra.framework.main.logviewer.model.ChunkReader reader:
        """

    def setTable(self, table: FVTable):
        """
        
        
        :param FVTable table:
        """

    def setViewport(self, viewport: javax.swing.JViewport):
        """
        
        
        :param javax.swing.JViewport viewport:
        """

    @property
    def viewportPositionAsRow(self) -> jpype.JInt:
        ...

    @property
    def inViewport(self) -> jpype.JBoolean:
        ...

    @property
    def numRowsInViewport(self) -> jpype.JInt:
        ...

    @property
    def height(self) -> jpype.JInt:
        ...


class FVTable(docking.widgets.table.GTable, java.awt.event.MouseMotionListener, java.awt.event.MouseListener):
    """
    The table that backs the :obj:`FileViewer` window. It is responsible for displaying
    :obj:`Chunk` instances.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.framework.main.logviewer.model.ChunkReader, viewportUtility: ViewportUtility, model: ghidra.framework.main.logviewer.model.ChunkModel, eventListener: ghidra.framework.main.logviewer.event.FVEventListener):
        """
        Ctor.
        
        :param ghidra.framework.main.logviewer.model.ChunkReader reader: 
        :param ViewportUtility viewportUtility: 
        :param ghidra.framework.main.logviewer.model.ChunkModel model: 
        :param ghidra.framework.main.logviewer.event.FVEventListener eventListener:
        """

    def addRow(self, row: typing.Union[java.lang.String, str]):
        """
        Adds the given row to the table.
        
        :param java.lang.String or str row:
        """

    def addRows(self, rows: java.util.List[java.lang.String]):
        """
        Adds the list of rows to the table.
        
        :param java.util.List[java.lang.String] rows:
        """

    def clear(self):
        """
        Removes all rows from the table model.
        """

    def decrementAndAddSelection(self, rows: typing.Union[jpype.JInt, int]):
        """
        Decrements the selection by the number of rows given, and adds the new rows to the 
        selection.
        
        :param jpype.JInt or int rows:
        """

    def decrementSelection(self, rows: typing.Union[jpype.JInt, int]):
        """
        Moves the table selection up by the number of rows specified, ensuring that selection
        does not go beyond the beginning of the file.
        
        :param jpype.JInt or int rows:
        """

    def incrementAndAddSelection(self, rows: typing.Union[jpype.JInt, int]):
        """
        Increments the selection by the given number of rows, but doesn't affect any previously
        selected rows. This is typically called when selecting while dragging.
        
        :param jpype.JInt or int rows:
        """

    def incrementSelection(self, rows: typing.Union[jpype.JInt, int]):
        """
        Moves the table selection down by the number of rows specified, ensuring that selection
        does not go beyond the bounds of the file.
        
        :param jpype.JInt or int rows:
        """

    def prepareRenderer(self, renderer: javax.swing.table.TableCellRenderer, row: typing.Union[jpype.JInt, int], column: typing.Union[jpype.JInt, int]) -> java.awt.Component:
        """
        Adjusts the column widths to be at least as wide as the widest cell.  This is required
        for horizontal scrolling to work properly.
        """

    def restoreSelection(self):
        """
        Set any previously selected table rows to a selected state. This should be called any 
        time a chunk is read into the table. 
         
        Note: This is critically important when the user has selected a row, then scrolled such that 
        the selected row is in a chunk that has been swapped out and is no longer in the table. When
        that chunk is scrolled back into view, this will restore the selection.
         
        Note2: If there is a range of selected values and the table is somewhere in the middle of
        that range, just select the entire table.
        """

    def setMouseDragging(self, isMouseDragging: typing.Union[jpype.JBoolean, bool]):
        ...

    def setShiftDown(self, isDown: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the status of the shift key.
        
        :param jpype.JBoolean or bool isDown:
        """

    def valueChanged(self, e: javax.swing.event.ListSelectionEvent):
        """
        Invoked when a new row has been selected in the table. Update our chunk model to 
        reflect as much.
        
        :param javax.swing.event.ListSelectionEvent e:
        """


class FVToolBar(javax.swing.JToolBar):
    """
    Toolbar that contains widgets for controlling the :obj:`FileViewer`.
    """

    @typing.type_check_only
    class ScrollLockAction(javax.swing.AbstractAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class FileOpenAction(javax.swing.AbstractAction):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: ghidra.framework.main.logviewer.event.FVEventListener):
        """
        Constructor.
        
        :param ghidra.framework.main.logviewer.event.FVEventListener eventListener: the event listener that will be notified of action events
        """

    def isScrollLockOn(self) -> bool:
        ...

    def setScrollLockOn(self, lock: typing.Union[jpype.JBoolean, bool]):
        ...

    @property
    def scrollLockOn(self) -> jpype.JBoolean:
        ...

    @scrollLockOn.setter
    def scrollLockOn(self, value: jpype.JBoolean):
        ...


class FileViewer(javax.swing.JPanel, java.util.Observer):
    """
    UI for viewing the contents of very large files efficiently. Pieces of a file are read in using
    the :obj:`ChunkReader`, which are then displayed line-by-line in :obj:`FVTable`.  As users
    scroll up/down, new sections of the file are swapped in as appropriate.
     
    
    Notes:
     
    1. The viewer consists of a simple JTable and a custom JSlider. The table displays lines of
    text described by:obj:`Chunk` objects. The number of chunks visible at any given time
    is restricted by the:obj:`ChunkModel.MAX_VISIBLE_CHUNKS` property.
    2. Because only part of the file is loaded into the viewable table at any given time, the
    built-in scrollbar associated with the scroll pane cannot be used. We want the scroll bar
    maximum size to reflect the total size of the file, not just what's in view at the time. So
    we use our own slider implementation (:obj:`FVSlider`) and manage the size/position
    ourselves. If you're asking why a JSlider is used instead of a JScrollPane, it's because the
    former is more easily configuration for what we need.
    3. Communication between modules (the table, the slider, the viewport utility, etc...) is done
    almost exclusively via events, using the custom:obj:`FVEvent` framework.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, reader: ghidra.framework.main.logviewer.model.ChunkReader, model: ghidra.framework.main.logviewer.model.ChunkModel, eventListener: ghidra.framework.main.logviewer.event.FVEventListener):
        """
        Constructor.
        
        :param ghidra.framework.main.logviewer.model.ChunkReader reader: the log file reader
        :param ghidra.framework.main.logviewer.model.ChunkModel model: the reader's data model
        :param ghidra.framework.main.logviewer.event.FVEventListener eventListener: the event listener; the hub through which this API communicates
        :raises IOException: if there is an issue reading the log file
        """


class FVTableModel(javax.swing.table.AbstractTableModel):
    """
    The model that backs the :obj:`FVTable` table. This model defines 4 columns: date,
    time, log level, and the message.
    """

    class_: typing.ClassVar[java.lang.Class]
    DATE_COL: typing.Final = 0
    TIME_COL: typing.Final = 1
    LEVEL_COL: typing.Final = 2
    MESSAGE_COL: typing.Final = 3

    def __init__(self):
        ...

    @typing.overload
    def addRow(self, row: typing.Union[java.lang.String, str], notify: typing.Union[jpype.JBoolean, bool]):
        """
        Adds a row to the model.
        
        :param java.lang.String or str row: the data to add
        :param jpype.JBoolean or bool notify: if true, a notification will be sent to subscribers
        """

    @typing.overload
    def addRow(self, row: typing.Union[java.lang.String, str], index: typing.Union[jpype.JInt, int], notify: typing.Union[jpype.JBoolean, bool]):
        """
        Adds a row to the model
        
        :param java.lang.String or str row: the data to add
        :param jpype.JInt or int index: the position within the model to add this to
        :param jpype.JBoolean or bool notify: if true, a notification will be sent to subscribers
        """

    def addRowsToBottom(self, rows: java.util.List[java.lang.String]):
        """
        Adds a list of rows to the model and fires off a notification.
        
        :param java.util.List[java.lang.String] rows:
        """

    def addRowsToTop(self, rows: java.util.List[java.lang.String]):
        """
        Adds a list of rows to the model and fires off a notification.
        
        :param java.util.List[java.lang.String] rows:
        """

    def clear(self):
        """
        Clears all lines from the model and fires off a notification.
        """

    def removeRowsFromBottom(self, count: typing.Union[jpype.JInt, int]):
        """
        Removes a set of rows from the bottom of the view.
        
        :param jpype.JInt or int count: the number of rows to remove
        """

    def removeRowsFromTop(self, count: typing.Union[jpype.JInt, int]):
        """
        Removes a set of rows from the top of the view.
        
        :param jpype.JInt or int count: the number of rows to remove
        """


class ReloadDialog(javax.swing.JDialog):
    """
    Simple warning dialog for letting the user know when the input file has been updated. This 
    includes an option allowing the user to opt-out of seeing subsequent pop-ups.
     
    Note: The Ghidra :obj:`OptionsPanel <docking.options.editor.OptionsPanel>`
    is not sufficient for this as it doesn't allow for custom objects to be
    displayed (the opt-out checkbox).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, eventListener: ghidra.framework.main.logviewer.event.FVEventListener):
        """
        Constructor.
        """

    def setVisible(self, visible: typing.Union[jpype.JBoolean, bool]):
        """
        Need to override the base implementation so we can short-circuit this and only show
        the dialog if the user has not previously selected the opt-out checkbox.
        """


class FVSlider(javax.swing.JSlider, javax.swing.event.ChangeListener, java.awt.event.MouseMotionListener, java.awt.event.MouseListener):
    """
    Custom slider that acts as the scroll bar for the FVTable. This slider listens for
    changes to the viewport and updates its position accordingly.
     
    Q. Why not just use the standard :obj:`JScrollBar <javax.swing.JScrollBar>` that comes with the :obj:`JScrollPane`?
     
    A. It's because we are viewing only a portion of the total file at any given time.
        If we used the standard scroll mechanism, it would size itself and its viewport
        according to that subset of the total file, while we want it to reflect the file
        in its entirety.
     
    Q. Why extend a :obj:`JSlider` for this custom scroll bar instead of a :obj:`JScrollBar`?
     
    A. The :obj:`JSlider` is much easier to customize, specifically when trying to adjust
        the size of the slider thumb. Functionally they are both acceptable for our
        purposes, but the ease of using the slider wins out.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, scrollPane: javax.swing.JScrollPane, table: FVTable, viewportUtility: ViewportUtility, model: ghidra.framework.main.logviewer.model.ChunkModel, reader: ghidra.framework.main.logviewer.model.ChunkReader, eventListener: ghidra.framework.main.logviewer.event.FVEventListener):
        """
        Constructor. Builds the UI elements and establishes event listeners.
        
        :param javax.swing.JScrollPane scrollPane: 
        :param FVTable table: 
        :param ViewportUtility viewportUtility: 
        :param ghidra.framework.main.logviewer.model.ChunkModel model: 
        :param ghidra.framework.main.logviewer.model.ChunkReader reader: 
        :param ghidra.framework.main.logviewer.event.FVEventListener eventListener:
        """

    def getFilePosition(self, sliderPos: typing.Union[jpype.JInt, int]) -> int:
        """
        Returns the file position (long) for the given slider position (int). This is calculated by
        computing the position of the slider as a percentage of its maximum, and applying the same
        to the file position (relative to the total file size).
        
        :param jpype.JInt or int sliderPos: 
        :return: 
        :rtype: int
        """

    def mouseDragged(self, e: java.awt.event.MouseEvent):
        """
        MOUSE EVENTS
         
        We need to set the mouseDown attribute so we only initiate a viewport
        update if the slider is moving in response to user action on the slider.
        """

    def setMaximum(self, fileSize: typing.Union[jpype.JLong, int]):
        """
        Sets the maximum slider position given the size of the file. If the file position is
        greater than the maximum size of an integer, we just set it to that maximum size.
        
        :param jpype.JLong or int fileSize:
        """

    def setValue(self, filePos: typing.Union[jpype.JLong, int]):
        """
        Sets the value of the slider based on the given file position.
        
        :param jpype.JLong or int filePos:
        """

    def stateChanged(self, e: javax.swing.event.ChangeEvent):
        """
        Invoked when the slider value has changed. When this happens we need to update the 
        viewport to match, but ONLY if this event is triggered as a result of the user 
        manually moving the slider (and not as a result of the slider being moved programmatically
        in response to a viewport change).
        """

    def syncWithViewport(self):
        """
        Updates the slider so it is in sync with the current position of the viewport. 
         
        Note that this is only done if the mouse is NOT down; if it is, it means the user is 
        moving the thumb and we should do nothing.
        """

    @property
    def filePosition(self) -> jpype.JLong:
        ...


class FileWatcher(java.lang.Object):
    """
    The FileWatcher *watches* a single file and fires a change notification whenever the file 
    is modified. A couple notes:
     
    1. To keep from processing change events every time the file is modified, which may be
        too frequent and cause processing issues, we use a simple polling mechanism.  
        
    2. Changes in the file are identified by inspecting the :meth:`File.lastModified() <File.lastModified>`
        timestamp. 
     
    3. The :obj:`WatchService` mechanism is not being used here since we cannot specify a 
        polling rate.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, file: jpype.protocol.SupportsPath, eventListener: ghidra.framework.main.logviewer.event.FVEventListener):
        """
        Constructor. Creates a new :obj:`Executor` that will inspect the file at regular 
        intervals.  Users must call :meth:`start() <.start>` to begin polling.
        
        :param jpype.protocol.SupportsPath file: the file to be watched
        """

    def start(self):
        """
        Starts polling, or resumes polling if previously stopped.
        """

    def stop(self):
        """
        Suspends the timer so it will no longer poll. This does not perform a shutdown, so the
        future may be scheduled again.
        """


class LogLevelTableCellRenderer(docking.widgets.table.GTableCellRenderer):
    """
    Renderer for the :obj:`FVTable` that will set the background color based on
    the text contents. This is intended to be used only for the log level 
    column.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...



__all__ = ["FVSliderUI", "ViewportUtility", "FVTable", "FVToolBar", "FileViewer", "FVTableModel", "ReloadDialog", "FVSlider", "FileWatcher", "LogLevelTableCellRenderer"]
