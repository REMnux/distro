from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.util
import docking.widgets.search
import generic.jar
import ghidra.util
import ghidra.util.task
import help
import java.beans # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.util # type: ignore
import javax.help # type: ignore
import javax.help.event # type: ignore
import javax.swing # type: ignore


class HelpManager(help.HelpService):
    """
    Class that uses JavaHelp browser to show context sensitive help.
    
     
    Note: this manager will validate all registered help when in development mode.  In order
    to catch items that have not registered help at all, we rely on those items to register a
    default :obj:`HelpLocation` that will get flagged as invalid.  Examples of this usage are
    the :obj:`DockingActionIf` and the :obj:`ComponentProvider` base classes.
    """

    class_: typing.ClassVar[java.lang.Class]
    SHOW_AID_KEY: typing.Final = "SHOW.HELP.NAVIGATION.AID"

    def addHelpSet(self, url: java.net.URL, classLoader: GHelpClassLoader) -> None:
        """
        Add the help set for the given URL.
        
        :param java.net.URL url: url for the HelpSet (.hs) file
        :param GHelpClassLoader classLoader: the help classloader that knows how to find help modules in the classpath
        :raises HelpSetException: if the help set could not be created from the given URL.
        """

    def getInvalidHelpLocations(self, monitor: ghidra.util.task.TaskMonitor) -> java.util.Map[java.lang.Object, ghidra.util.HelpLocation]:
        ...

    def getMasterHelpSet(self) -> help.GHelpSet:
        """
        Returns the master help set (the one into which all other help sets are merged).
        
        :return: the help set
        :rtype: help.GHelpSet
        """

    @property
    def invalidHelpLocations(self) -> java.util.Map[java.lang.Object, ghidra.util.HelpLocation]:
        ...

    @property
    def masterHelpSet(self) -> help.GHelpSet:
        ...


class DockingHelpSet(help.GHelpSet):
    """
    An extension of the :obj:`GHelpSet` that allows ``Docking`` classes to be installed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, loader: java.lang.ClassLoader, helpset: java.net.URL) -> None:
        ...


class NavigationAidToggleAction(javax.swing.AbstractAction):

    @typing.type_check_only
    class SelfPaintingIcon(javax.swing.Icon):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self) -> None:
        ...


@typing.type_check_only
class CalloutRequest(java.lang.Object):
    """
    A class that will trigger a UI aid to show users to where in the given html page the view has 
    been navigated.   As users follow links, the new page is loaded, but it is not always easy to see
    where on the page the original link is pointing.   This will paint a UI marker where at the 
    destination of the clicked link.  Perhaps the most important job of this class is to reposition
    the view once the html loading has finished.
     
    
    This class is complicated due to the asynchronous nature of html document loading and rendering.
    The document is loaded in a background thread. After the page is loaded, some elements on the 
    page, such as images, may also be loaded asynchronously.  As these elements get loaded, the 
    geometry of the page may change.  This means that the destination bounds of a link may change as 
    the page is being loaded and rendered.  To compensate for these changes, we need a way to delay
    showing the UI marker until the page is fully rendered.  Here we use a :obj:`SwingUpdateManager`
    to delay the UI marker until no new changes are being made.  At that point, the bounds of the
    anchor should be finalized.
    """

    @typing.type_check_only
    class PageLoadingListener(java.beans.PropertyChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class StarShape(java.awt.geom.Path2D.Float):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class LocationHintPainter(docking.util.AnimationPainter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def dispose(self) -> None:
        ...

    def runLater(self) -> None:
        ...


class HelpActionManager(java.lang.Object):
    """
    Register help for a specific component.
    """

    class_: typing.ClassVar[java.lang.Class]

    def setHelpLocation(self, comp: javax.swing.JComponent, helpLocation: ghidra.util.HelpLocation) -> None:
        """
        Enable help for a component.
        
        :param javax.swing.JComponent comp: component that has help associated with it
        :param ghidra.util.HelpLocation helpLocation: help content location
        """


class DockingHelpBroker(help.GHelpBroker):
    """
    An extension of the :obj:`GHelpBroker` that allows ``Docking`` classes to be installed.
     
    
    Additions include:
     
    * A find feature
    * A UI navigation aid
    * An action to refresh the current page
    """

    @typing.type_check_only
    class HelpIDChangedListener(javax.help.event.HelpModelListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, hs: javax.help.HelpSet) -> None:
        ...


@typing.type_check_only
class HelpViewSearcher(java.lang.Object):
    """
    Enables the Find Dialog for searching through the current page of a help document.
    """

    @typing.type_check_only
    class FindDialogAction(javax.swing.AbstractAction):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class HtmlTextSearcher(docking.widgets.search.TextComponentSearcher):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, editorPane: javax.swing.JEditorPane) -> None:
            ...


    @typing.type_check_only
    class HtmlSearchResults(docking.widgets.search.TextComponentSearchResults):

        @typing.type_check_only
        class PageLoadedListener(java.beans.PropertyChangeListener):
            ...
            class_: typing.ClassVar[java.lang.Class]


        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]


class TestHelpService(HelpManager):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def install(masterHelpSetUrl: java.net.URL) -> None:
        ...


class GHelpClassLoader(java.lang.ClassLoader):
    """
    A :obj:`ClassLoader` for loading help data.  This is only need when running in Eclipse.  We
    do not include help data in the source tree for any module, in order to save build time.  By
    doing this, we need a way to allow the Java Help system to find this data.  We have
    Overridden :meth:`findResource(String) <.findResource>` to look in our module directories for their
    respective help.
     
    
    This class is not needed in an installation since the help is bundled into jar files that
    live in the classpath and thus the default class loader will find them.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, moduleDirectory: generic.jar.ResourceFile) -> None:
        """
        Constructs this class loader with the given module, which may be null.  When the module
        is null, this class will only looks for items on the classpath, under a 'help' directory.
        
        :param generic.jar.ResourceFile moduleDirectory: the module directory to search; may be null
        """



__all__ = ["HelpManager", "DockingHelpSet", "NavigationAidToggleAction", "CalloutRequest", "HelpActionManager", "DockingHelpBroker", "HelpViewSearcher", "TestHelpService", "GHelpClassLoader"]
