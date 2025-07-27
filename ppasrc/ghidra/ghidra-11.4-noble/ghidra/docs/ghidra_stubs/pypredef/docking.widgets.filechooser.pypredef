from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking
import docking.dnd
import docking.widgets
import docking.widgets.list
import docking.widgets.table
import ghidra.util.filechooser
import ghidra.util.worker
import java.awt # type: ignore
import java.awt.event # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.table # type: ignore


T = typing.TypeVar("T")


@typing.type_check_only
class FileChooserActionManager(java.lang.Object):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class GFileChooserOptionsDialog(docking.ReusableDialogComponentProvider):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FileEditor(javax.swing.AbstractCellEditor, javax.swing.table.TableCellEditor):
    ...
    class_: typing.ClassVar[java.lang.Class]


class GhidraFileChooserPanel(javax.swing.JPanel, docking.dnd.Droppable):
    """
    Panel for entering a file name that includes a title border, a text field
    for entering a filename, and a button for bringing up a file chooser dialog.
    """

    class_: typing.ClassVar[java.lang.Class]
    INPUT_MODE: typing.Final = 0
    """
    This mode denotes that only existing files will
    be chosen for the purpose of reading.
    """

    OUTPUT_MODE: typing.Final = 1
    """
    This mode denotes that existing files (or new files)
    will be chosen for the purpose of writing.
    If an existing file is selected the user will
    be prompted to confirm overwrite.
    """


    def __init__(self, title: typing.Union[java.lang.String, str], propertyName: typing.Union[java.lang.String, str], defaultFileName: typing.Union[java.lang.String, str], createBorder: typing.Union[jpype.JBoolean, bool], mode: typing.Union[jpype.JInt, int]):
        """
        Constructs a new GhidraFileChooserPanel
        
        :param java.lang.String or str title: the title for this panel
        :param java.lang.String or str propertyName: the property name to save state
        :param java.lang.String or str defaultFileName: the default file name.
        :param jpype.JBoolean or bool createBorder: flag to create the border or not.
        :param jpype.JInt or int mode: whether :obj:`.INPUT_MODE` or :obj:`.OUTPUT_MODE`
        """

    def addDocumentListener(self, dl: javax.swing.event.DocumentListener):
        """
        Adds a document listener to the text field.
        
        :param javax.swing.event.DocumentListener dl: the document listener to add.
        """

    def dispose(self):
        ...

    def getCurrentDirectory(self) -> str:
        ...

    def getFileName(self) -> str:
        """
        Returns the filename currently in the text field.
        
        :return: the filename currently in the text field
        :rtype: str
        """

    def setFileFilter(self, filter: ghidra.util.filechooser.GhidraFileFilter):
        """
        Sets the file filter.
        
        :param ghidra.util.filechooser.GhidraFileFilter filter: the new file filter
        """

    def setFileName(self, path: typing.Union[java.lang.String, str]):
        """
        Sets the textfield with the given filename.
        
        :param java.lang.String or str path: the name of the file to put in the text field.
        """

    def setFileSelectionMode(self, mode: GhidraFileChooserMode):
        """
        Sets the ``GhidraFileChooser`` to allow the user to just
        select files, just select
        directories, or select both files and directories.  The default is
        ``GhidraFileChooserMode.FILES_ONLY``.
        
        :param GhidraFileChooserMode mode: the type of files to be displayed
        :raises IllegalArgumentException: if ``mode`` is an
                        illegal Dialog mode
        """

    def setListener(self, listener: GhidraFileChooserPanelListener):
        """
        Sets the listener.
        
        :param GhidraFileChooserPanelListener listener: the new listener
        """

    @property
    def fileName(self) -> java.lang.String:
        ...

    @fileName.setter
    def fileName(self, value: java.lang.String):
        ...

    @property
    def currentDirectory(self) -> java.lang.String:
        ...


@typing.type_check_only
class FileListCellRenderer(docking.widgets.list.GListCellRenderer[java.io.File]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, chooser: GhidraFileChooser):
        ...


@typing.type_check_only
class DirectoryTable(docking.widgets.table.GTable, GhidraFileChooserDirectoryModelIf):

    @typing.type_check_only
    class FileSizeRenderer(docking.widgets.table.GTableCellRenderer):
        """
        Table cell renderer to display file sizes in more friendly terms
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class DirectoryList(docking.widgets.list.GList[java.io.File], GhidraFileChooserDirectoryModelIf):
    ...
    class_: typing.ClassVar[java.lang.Class]


@typing.type_check_only
class FileComparator(java.util.Comparator[java.io.File]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class GhidraFileChooserMode(java.lang.Enum[GhidraFileChooserMode]):
    """
    Modes available for selecting files in the file chooser
    """

    class_: typing.ClassVar[java.lang.Class]
    FILES_ONLY: typing.Final[GhidraFileChooserMode]
    """
    Only files may be chosen
    """

    DIRECTORIES_ONLY: typing.Final[GhidraFileChooserMode]
    """
    Only directories may be chosen
    """

    FILES_AND_DIRECTORIES: typing.Final[GhidraFileChooserMode]
    """
    Files and directories may be chosen
    """


    def supportsDirectories(self) -> bool:
        ...

    def supportsFiles(self) -> bool:
        ...

    @staticmethod
    def valueOf(name: typing.Union[java.lang.String, str]) -> GhidraFileChooserMode:
        ...

    @staticmethod
    def values() -> jpype.JArray[GhidraFileChooserMode]:
        ...


@typing.type_check_only
class FileTableCellRenderer(docking.widgets.table.GTableCellRenderer):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, chooser: GhidraFileChooser):
        ...


class GhidraFile(java.io.File):
    """
    An extension of File that does not translate to the
    native operating system's file separator.
    For example, on Windows:
     
    
    ``File f = new File("c:/temp/foo.txt");``
    
    ``String path = f.getAbsolutePath();``
    
    In this case, path equals "c:\temp\foo.txt".
    However using GhidraFile, path would still equal "c:/temp/foo.txt"
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, parent: typing.Union[java.lang.String, str], child: typing.Union[java.lang.String, str], separator: typing.Union[jpype.JChar, int, str]):
        """
        Construct a new GhidraFile.
        
        :param java.lang.String or str parent: the parent directory; eg, "c:\temp"
        :param java.lang.String or str child: the child file name; eg, "foo.txt"
        :param jpype.JChar or int or str separator: the separator character; eg, '/' or '\'
        """

    @typing.overload
    def __init__(self, path: typing.Union[java.lang.String, str], separator: typing.Union[jpype.JChar, int, str]):
        """
        Construct a new GhidraFile.
        
        :param java.lang.String or str path: the path to the file; eg, "c:\temp\foo.txt" or "temp\foo.txt"
        :param jpype.JChar or int or str separator: the separator character; eg, '/' or '\'
        """

    @typing.overload
    def __init__(self, parent: jpype.protocol.SupportsPath, name: typing.Union[java.lang.String, str], separator: typing.Union[jpype.JChar, int, str]):
        """
        Construct a new GhidraFile.
        
        :param jpype.protocol.SupportsPath parent: the parent file path
        :param java.lang.String or str name: the name of the file
        :param jpype.JChar or int or str separator: the separator character; eg, '/' or '\'
        """


class GhidraFileChooserDirectoryModelIf(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def edit(self):
        ...

    def getFile(self, row: typing.Union[jpype.JInt, int]) -> java.io.File:
        ...

    def getSelectedFile(self) -> java.io.File:
        ...

    def getSelectedRows(self) -> jpype.JArray[jpype.JInt]:
        ...

    def setSelectedFile(self, file: jpype.protocol.SupportsPath):
        ...

    @property
    def selectedFile(self) -> java.io.File:
        ...

    @selectedFile.setter
    def selectedFile(self, value: java.io.File):
        ...

    @property
    def file(self) -> java.io.File:
        ...

    @property
    def selectedRows(self) -> jpype.JArray[jpype.JInt]:
        ...


class FileDropDownSelectionDataModel(docking.widgets.DropDownTextFieldDataModel[java.io.File]):
    """
    A model that allows the :obj:`DropDownSelectionTextField` to work with File objects.
    """

    @typing.type_check_only
    class FileComparator(java.util.Comparator[java.io.File]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FileSearchComparator(java.util.Comparator[java.lang.Object]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FileDropDownRenderer(docking.widgets.list.GListCellRenderer[java.io.File]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, chooser: GhidraFileChooser):
        ...


@typing.type_check_only
class DirectoryListModel(javax.swing.AbstractListModel[java.io.File]):

    class_: typing.ClassVar[java.lang.Class]

    def getAllFiles(self) -> java.util.List[java.io.File]:
        ...

    def set(self, index: typing.Union[jpype.JInt, int], file: jpype.protocol.SupportsPath) -> java.io.File:
        ...

    @property
    def allFiles(self) -> java.util.List[java.io.File]:
        ...


@typing.type_check_only
class DirectoryTableModel(docking.widgets.table.AbstractSortedTableModel[java.io.File]):
    ...
    class_: typing.ClassVar[java.lang.Class]


class GhidraFileChooserPanelListener(java.lang.Object):
    """
    A listener for notifying when the file in the file chooser panel have changed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def fileChanged(self, file: jpype.protocol.SupportsPath):
        """
        Notification the file change.
        
        :param jpype.protocol.SupportsPath file: the new file
        """

    def fileDropped(self, file: jpype.protocol.SupportsPath):
        """
        Notification that a new file was dropped on the panel.
        
        :param jpype.protocol.SupportsPath file: the new file that was dropped
        """


class FileChooserToggleButton(javax.swing.JToggleButton):

    @typing.type_check_only
    class ButtonMouseListener(java.awt.event.MouseAdapter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, text: typing.Union[java.lang.String, str]):
        ...

    @typing.overload
    def __init__(self, action: javax.swing.Action):
        ...


class LocalFileChooserModel(ghidra.util.filechooser.GhidraFileChooserModel):
    """
    A default implementation of the file chooser model that browses the local file system.
    """

    @typing.type_check_only
    class FileSystemRootInfo(java.lang.Object):
        """
        Handles querying / caching information about file system root locations.
         
        
        Only a single instance of this class is needed and can be shared statically.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


@typing.type_check_only
class RecentGhidraFile(GhidraFile):
    """
    Marker file to signal that this object is a entry in the user's 'recently used' list
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: typing.Union[java.lang.String, str], separator: typing.Union[jpype.JChar, int, str]):
        ...


class GhidraFileChooser(docking.ReusableDialogComponentProvider, java.io.FileFilter):
    """
    An implementation of a file chooser dialog.
    This class is designed to emulate the JFileChooser,
    but it removes the network locking issue.
    When a network drive is down, the JFileChooser can
    take several minutes to come up.
    
    Why use this file chooser over JFileChooser??
    Let me enumerate the reasons...
     
    1. JFileChooser cannot show hidden/system files, but we can!
    2. JFileChooser does not properly consume key strokes (global actions in docking windows)
    3. This class is threaded, so loading delays do not lock the GUI
    4. This class provides shortcut buttons similar to those of the Windows native chooser
    """

    @typing.type_check_only
    class SelectionListener(docking.widgets.DropDownSelectionChoiceListener[java.io.File], typing.Generic[T]):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FileChooserJob(ghidra.util.worker.Job):

        class_: typing.ClassVar[java.lang.Class]

        def run(self):
            ...

        def runSwing(self):
            ...


    @typing.type_check_only
    class SetSelectedFileJob(GhidraFileChooser.FileChooserJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SetSelectedFileAndAcceptSelection(GhidraFileChooser.FileChooserJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ClearSelectedFilesJob(GhidraFileChooser.FileChooserJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UpdateDirectoryContentsJob(GhidraFileChooser.FileChooserJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UpdateMyComputerJob(GhidraFileChooser.FileChooserJob):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, myComputerFile: jpype.protocol.SupportsPath, forceUpdate: typing.Union[jpype.JBoolean, bool], addToHistory: typing.Union[jpype.JBoolean, bool]):
            ...


    @typing.type_check_only
    class UpdateRecentJob(GhidraFileChooser.FileChooserJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class SetSelectedFilesAndStartEditJob(GhidraFileChooser.FileChooserJob):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class UnselectableButtonGroup(javax.swing.ButtonGroup):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class FileList(java.lang.Object):
        """
        A list that allows us to always access the first cell without having to check the lists
        size.  The list also allows us to clear and set a value in one method call.  We are
        essentially using this list to hold selected files, where in certain modes, there will only
        be a single file selection.
        
         
        The methods on the class are synchronized to ensure thread visibility.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...

        def getFile(self) -> java.io.File:
            ...

        def getFiles(self) -> java.util.List[java.io.File]:
            ...

        def setFile(self, file: jpype.protocol.SupportsPath):
            ...

        def setFiles(self, newFiles: java.util.List[java.io.File]):
            ...

        def size(self) -> int:
            ...

        @property
        def file(self) -> java.io.File:
            ...

        @file.setter
        def file(self, value: java.io.File):
            ...

        @property
        def files(self) -> java.util.List[java.io.File]:
            ...

        @files.setter
        def files(self, value: java.util.List[java.io.File]):
            ...


    @typing.type_check_only
    class HistoryEntry(java.lang.Object):
        """
        Container class to manage history entries for a directory and any selected file
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    FILES_ONLY: typing.Final = 0
    """
    Instruction to display only files.
    """

    DIRECTORIES_ONLY: typing.Final = 1
    """
    Instruction to display only directories.
    """

    FILES_AND_DIRECTORIES: typing.Final = 2
    """
    Instruction to display both files and directories.
    """


    def __init__(self, parent: java.awt.Component):
        """
        Constructs a new ghidra file chooser.
        
        :param java.awt.Component parent: the parent component
        """

    def addFileFilter(self, f: ghidra.util.filechooser.GhidraFileFilter):
        """
        Adds the specified file filter.
        
        :param ghidra.util.filechooser.GhidraFileFilter f: the new file filter
        """

    def getCurrentDirectory(self) -> java.io.File:
        """
        Returns the current directory.
        
        :return: the current directory
        :rtype: java.io.File
        
        .. seealso::
        
            | :obj:`.setCurrentDirectory`
        """

    @typing.overload
    def getSelectedFile(self) -> java.io.File:
        """
        Returns the selected file. This can be set either by the  programmer via
        :meth:`setSelectedFile(File) <.setSelectedFile>` or by a user action, such as either typing the
        filename into the UI or selecting the file from a list in the UI.
        
        :return: the selected file; null if cancelled or no file was selected
        :rtype: java.io.File
        """

    @typing.overload
    def getSelectedFile(self, show: typing.Union[jpype.JBoolean, bool]) -> java.io.File:
        """
        Returns the selected file. This can be set either by the programmer
        via :meth:`setSelectedFile(File) <.setSelectedFile>` or by a user action, such as either typing the filename
        into the UI or selecting the file from a list in the UI.
         
        
        Note: this method can be called after the chooser has been shown, in which case the
        value returned has been validated by the chooser.  Also, the method may be called
        while the chooser is showing (like from a test thread).  In this case, the selected file
        will not have been validated by the chooser.
        
        :param jpype.JBoolean or bool show: if true then the dialog is displayed
        :return: the selected file; null if cancelled or no file was selected
        :rtype: java.io.File
        """

    def getSelectedFiles(self) -> java.util.List[java.io.File]:
        """
        Returns the selected files.  This will show the file chooser
        
        :return: the selected files; an empty array if cancelled or no file was selected
        :rtype: java.util.List[java.io.File]
        """

    def isMultiSelectionEnabled(self) -> bool:
        """
        Returns true if multiple files can be selected.
        
        :return: true if multiple files can be selected
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.setMultiSelectionEnabled`
        """

    def rescanCurrentDirectory(self):
        """
        Causes the file chooser to refresh its contents
        with the content of the currently displayed directory.
        """

    def setApproveButtonText(self, buttonText: typing.Union[java.lang.String, str]):
        """
        Sets the text used in the ``OK`` button
        
        :param java.lang.String or str buttonText: the text
        """

    def setApproveButtonToolTipText(self, tooltipText: typing.Union[java.lang.String, str]):
        """
        Sets the tooltip text used in the ``OK`` button
        
        :param java.lang.String or str tooltipText: the tooltip text
        """

    def setCurrentDirectory(self, directory: jpype.protocol.SupportsPath):
        """
        Sets the current directory. Passing in ``null`` sets the
        file chooser to point to the user's default directory.
        This default depends on the operating system. It is
        typically the "My Documents" folder on Windows, and the user's
        home directory on Unix.
         
        
        If the file passed in as ``currentDirectory`` is not a
        directory, the parent of the file will be used as the currentDirectory.
        If the parent is not traversable, then it will walk up the parent tree
        until it finds a traversable directory, or hits the root of the
        file system.
        
        :param jpype.protocol.SupportsPath directory: the current directory to point to
        
        .. seealso::
        
            | :obj:`.getCurrentDirectory`
        """

    def setFileFilter(self, filter: ghidra.util.filechooser.GhidraFileFilter):
        """
        Sets the current file filter.
        
        :param ghidra.util.filechooser.GhidraFileFilter filter: the file filter to make current
        """

    @typing.overload
    @deprecated("use instead setFileSelectionMode(GhidraFileChooserMode)")
    def setFileSelectionMode(self, mode: typing.Union[jpype.JInt, int]):
        """
        Sets the ``GhidraFileChooser`` to allow the user to just
        select files, just select
        directories, or select both files and directories.  The default is
        :obj:`JFileChooser.FILES_ONLY`.
        
        :param jpype.JInt or int mode: the type of files to be displayed:
         
        * :obj:`GhidraFileChooser.FILES_ONLY`
        * :obj:`GhidraFileChooser.DIRECTORIES_ONLY`
        * :obj:`GhidraFileChooser.FILES_AND_DIRECTORIES`
        
        :raises IllegalArgumentException: if ``mode`` is an
                    illegal Dialog mode
        
        .. deprecated::
        
        use instead :meth:`setFileSelectionMode(GhidraFileChooserMode) <.setFileSelectionMode>`
        """

    @typing.overload
    def setFileSelectionMode(self, mode: GhidraFileChooserMode):
        """
        Sets this file chooser to allow the user to just select files, just select
        directories, or select both files and directories.  The default is
        :obj:`GhidraFileChooserMode.FILES_ONLY`.
        
        :param GhidraFileChooserMode mode: the type of files to be displayed
        """

    def setLastDirectoryPreference(self, newKey: typing.Union[java.lang.String, str]):
        """
        Sets the preference key for this chooser to use when saving the last directory that was used
        to successfully choose a file.
        
        :param java.lang.String or str newKey: the key
        """

    def setMultiSelectionEnabled(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Sets the file chooser to allow multiple file selections.
        
        :param jpype.JBoolean or bool b: true if multiple files may be selected
        
        .. seealso::
        
            | :obj:`.isMultiSelectionEnabled`
        """

    def setSelectedFile(self, file: jpype.protocol.SupportsPath):
        """
        Sets the selected file. If the file's parent directory is not the current directory,
        changes the current directory to be the file's parent directory.
         
        
        If the given file is a directory, then it's parent directory will be made the current
        directory and the directory represented by the file will be selected within the parent
        directory.
         
        
        If the given file does not exist, then the following will happen:
         
        * If the parent directory of the file exists, then the parent directory will be made
        the current directory and the name of the file will be put into the filename
        textfield; otherwise,
        * If the parent file does not exist, then the selection is cleared.
        
         
        
        If the given file is null, then the selected file state is cleared.
        
        :param jpype.protocol.SupportsPath file: the selected file
        
        .. seealso::
        
            | :obj:`.getSelectedFile`
        """

    def setSelectedFileFilter(self, filter: ghidra.util.filechooser.GhidraFileFilter):
        """
        Set the selected filter to the given filter
        
        :param ghidra.util.filechooser.GhidraFileFilter filter: the filter to initially set
        """

    def setShowDetails(self, showDetails: typing.Union[jpype.JBoolean, bool]):
        """
        When **true** is passed the chooser will use a detailed table view to show the files;
        false will show a simplified list of files.
        
        :param jpype.JBoolean or bool showDetails: true to show details
        """

    def show(self):
        ...

    def wasCancelled(self) -> bool:
        """
        Returns true if the user clicked the "cancel" button on the file chooser.
        
        :return: true if the user clicked the "cancel" button on the file chooser
        :rtype: bool
        """

    @property
    def selectedFiles(self) -> java.util.List[java.io.File]:
        ...

    @property
    def selectedFile(self) -> java.io.File:
        ...

    @selectedFile.setter
    def selectedFile(self, value: java.io.File):
        ...

    @property
    def currentDirectory(self) -> java.io.File:
        ...

    @currentDirectory.setter
    def currentDirectory(self, value: java.io.File):
        ...

    @property
    def multiSelectionEnabled(self) -> jpype.JBoolean:
        ...

    @multiSelectionEnabled.setter
    def multiSelectionEnabled(self, value: jpype.JBoolean):
        ...



__all__ = ["FileChooserActionManager", "GFileChooserOptionsDialog", "FileEditor", "GhidraFileChooserPanel", "FileListCellRenderer", "DirectoryTable", "DirectoryList", "FileComparator", "GhidraFileChooserMode", "FileTableCellRenderer", "GhidraFile", "GhidraFileChooserDirectoryModelIf", "FileDropDownSelectionDataModel", "DirectoryListModel", "DirectoryTableModel", "GhidraFileChooserPanelListener", "FileChooserToggleButton", "LocalFileChooserModel", "RecentGhidraFile", "GhidraFileChooser"]
