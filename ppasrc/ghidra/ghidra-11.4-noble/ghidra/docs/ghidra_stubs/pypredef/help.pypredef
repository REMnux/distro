from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import generic.jar
import ghidra.util
import help.validator
import help.validator.location
import help.validator.model
import java.awt # type: ignore
import java.beans # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import java.nio.file # type: ignore
import java.util # type: ignore
import javax.help # type: ignore
import javax.help.plaf.basic # type: ignore
import javax.swing # type: ignore
import javax.swing.event # type: ignore
import javax.swing.text # type: ignore
import javax.swing.text.html # type: ignore
import org.xml.sax.helpers # type: ignore
import resources


T = typing.TypeVar("T")


class HelpRightArrowIcon(javax.swing.Icon):
    """
    A basic arrow that points to the right, with padding on the sides and above.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, color: java.awt.Color):
        ...


class HelpBuildUtils(java.lang.Object):

    class Stringizer(java.lang.Object, typing.Generic[T]):

        class_: typing.ClassVar[java.lang.Class]

        def stringize(self, obj: T) -> str:
            ...


    class HelpFilesFilter(java.io.FileFilter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, *extensions: typing.Union[java.lang.String, str]):
            ...


    class_: typing.ClassVar[java.lang.Class]
    debug: typing.ClassVar[jpype.JBoolean]

    @staticmethod
    def cleanupHelpFileLinks(helpFile: jpype.protocol.SupportsPath):
        ...

    @staticmethod
    def createReferencePath(fileURI: java.net.URI) -> java.nio.file.Path:
        ...

    @staticmethod
    def debug(text: typing.Union[java.lang.String, str]):
        ...

    @staticmethod
    def findApplicationUrl(relativePath: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Searches the application classpath (for a module file) and directory structure (for a release
        file), depending on whether in release mode or development mode, to find the URL for the 
        given relative path.
        
        :param java.lang.String or str relativePath: the path
        :return: the URL or null if not found
        :rtype: java.net.URL
        """

    @staticmethod
    def findModuleFile(relativePath: typing.Union[java.lang.String, str]) -> generic.jar.ResourceFile:
        """
        Finds the actual module file for the given relative path when in development mode.  For 
        example, given: 
         
            help/shared/DefaultStyle.css
         
        This method will find: 
         
            {repo}/Ghidra/Framework/Help/src/main/resources/help/shared/DefaultStyle.css
         
        
        :param java.lang.String or str relativePath: the path
        :return: the file
        :rtype: generic.jar.ResourceFile
        """

    @staticmethod
    def getFile(srcFile: jpype.protocol.SupportsPath, relativePath: typing.Union[java.lang.String, str]) -> java.nio.file.Path:
        """
        Returns a path object using the given source file path as the source of the given relative 
        path.  The returned path represents a local file on the file system.
        
        :param jpype.protocol.SupportsPath srcFile: the source file path
        :param java.lang.String or str relativePath: the relative path
        :return: a path or null if the resolved path is not a local file
        :rtype: java.nio.file.Path
        """

    @staticmethod
    def getHelpTopicDir(file: jpype.protocol.SupportsPath) -> java.nio.file.Path:
        """
        Returns a file object that is the help topic directory for the given file.
           
         
        This method is useful for finding the help topic directory when the given file doesn't 
        live directly under a help topic.
        
        :param jpype.protocol.SupportsPath file: the file for which to find a topic
        :return: the path to the help topic directory
        :rtype: java.nio.file.Path
        """

    @staticmethod
    def getRoot(roots: collections.abc.Sequence, file: jpype.protocol.SupportsPath) -> java.nio.file.Path:
        ...

    @staticmethod
    def getRuntimeIcon(ref: typing.Union[java.lang.String, str]) -> resources.IconProvider:
        ...

    @staticmethod
    def getSharedHelpDirectory() -> java.nio.file.Path:
        ...

    @staticmethod
    @typing.overload
    def isRemote(uriString: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given String represents a remote resource
        
        :param java.lang.String or str uriString: the URI to test
        :return: true if the given String represents a remote resource
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isRemote(path: jpype.protocol.SupportsPath) -> bool:
        """
        Returns true if the given Path represents a remote resource
        
        :param jpype.protocol.SupportsPath path: the path
        :return: true if the given Path represents a remote resource
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def isRemote(uri: java.net.URI) -> bool:
        """
        Returns true if the given URI represents a remote resource
        
        :param java.net.URI uri: the URI
        :return: true if the given URI represents a remote resource
        :rtype: bool
        """

    @staticmethod
    def locateImageReference(sourceFile: jpype.protocol.SupportsPath, ref: typing.Union[java.lang.String, str]) -> ImageLocation:
        """
        Turn an HTML IMG reference into a location object that has resolved path info.  This will 
        locate files based upon relative references, specialized help system references (i.e., 
        help/topics/...),  and absolute URLs.
        
        :param jpype.protocol.SupportsPath sourceFile: the source file path of the image reference
        :param java.lang.String or str ref: the reference text
        :return: an absolute path; null if the URI is remote
        :rtype: ImageLocation
        :raises URISyntaxException: if there is an exception creating a URL/URI for the image location
        """

    @staticmethod
    def locateReference(sourceFile: jpype.protocol.SupportsPath, ref: typing.Union[java.lang.String, str]) -> java.nio.file.Path:
        """
        Turn an HTML HREF reference into an absolute path.  This will locate files based upon 
        relative references, specialized help system references (i.e., help/topics/...),  and 
        absolute URLs.
        
        :param jpype.protocol.SupportsPath sourceFile: the reference's source file
        :param java.lang.String or str ref: the reference text
        :return: an absolute path; null if the URI is remote
        :rtype: java.nio.file.Path
        :raises URISyntaxException: if there is an exception creating a URL/URI for the image location
        """

    @staticmethod
    def relativize(parent: jpype.protocol.SupportsPath, child: jpype.protocol.SupportsPath) -> java.nio.file.Path:
        ...

    @staticmethod
    def relativizeWithHelpTopics(p: jpype.protocol.SupportsPath) -> java.nio.file.Path:
        ...

    @staticmethod
    def toDefaultFS(path: jpype.protocol.SupportsPath) -> java.nio.file.Path:
        ...

    @staticmethod
    def toFS(targetFS: jpype.protocol.SupportsPath, path: jpype.protocol.SupportsPath) -> java.nio.file.Path:
        ...

    @staticmethod
    def toLocation(file: jpype.protocol.SupportsPath) -> help.validator.location.HelpModuleLocation:
        ...


class JavaHelpFilesBuilder(java.lang.Object):
    """
    This class:
     
    * Creates a XXX_map.xml file (topic IDs to help files)
    * Creates a XXX_TOC.xml file from a source toc.xml file
    * Finds unused images
    """

    @typing.type_check_only
    class LogFileWriter(java.io.PrintWriter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, outputDir: jpype.protocol.SupportsPath, moduleName: typing.Union[java.lang.String, str], linkDatabase: help.validator.LinkDatabase):
        ...

    def generateHelpFiles(self, help: help.validator.location.HelpModuleCollection):
        ...


class GHelpSet(javax.help.HelpSet):
    """
    Ghidra help set that creates a GhidraHelpBroker, installs some custom HTML handling code via
    the GHelpHTMLEditorKit, and most importantly, changes how the JavaHelp system works with 
    regard to integrating Help Sets.
     
    
    The HelpSet class uses a javax.help.Map object to locate HTML files by javax.help.map.ID objects.
    This class has overridden that basic usage of the Map object to allow ID lookups to take 
    place across GHelpSet objects.  We need to do this due to how we merge help set content 
    across modules.  More specifically, in order to merge, we have to make all ``<tocitem>`` xml tags
    the same, including the target HTML file they may reference.  Well, when a module uses a 
    ``<tocitem>`` tag that references an HTML file **not inside of it's module**, then JavaHelp 
    considers this an error and does not correctly merge the HelpSets that share the reference.
    Further, it does not properly locate the shared HTML file reference.  This class allows lookups
    across modules by overridden the lookup functionality done by the map object.  More specifically,
    we override :meth:`getCombinedMap() <.getCombinedMap>` and :meth:`getLocalMap() <.getLocalMap>` to use a custom delegate map
    object that knows how to do this "cross-module" help lookup.
    
    
    .. seealso::
    
        | :obj:`GHelpHTMLEditorKit`
    """

    @typing.type_check_only
    class GHelpMap(javax.help.Map):
        """
        A special class to allow us to handle help ID lookups across help sets
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, loader: java.lang.ClassLoader, helpset: java.net.URL):
        ...


class HelpService(java.lang.Object):
    """
    ``HelpService`` defines a service for displaying Help content by an ID or URL.
    """

    class_: typing.ClassVar[java.lang.Class]
    DUMMY_HELP_SET_NAME: typing.Final = "Dummy_HelpSet.hs"

    def clearHelp(self, helpObject: java.lang.Object):
        """
        Removes this object from the help system.  This method is useful, for example,
        when a single Java :obj:`Component` will have different help locations
        assigned over its lifecycle.
        
        :param java.lang.Object helpObject: the object for which to clear help
        """

    def excludeFromHelp(self, helpObject: java.lang.Object):
        """
        Signals to the help system to ignore the given object when searching for and validating
        help.  Once this method has been called, no help can be registered for the given object.
        
        :param java.lang.Object helpObject: the object to exclude from the help system.
        """

    def getHelpLocation(self, object: java.lang.Object) -> ghidra.util.HelpLocation:
        """
        Returns the registered (via :meth:`registerHelp(Object, HelpLocation) <.registerHelp>` help
        location for the given object; null if there is no registered
        help.
        
        :param java.lang.Object object: The object for which to find a registered HelpLocation.
        :return: the registered HelpLocation
        :rtype: ghidra.util.HelpLocation
        
        .. seealso::
        
            | :obj:`.registerHelp(Object, HelpLocation)`
        """

    def helpExists(self) -> bool:
        """
        Returns true if the help system has been initialized properly; false if help does not
        exist or is not working.
        
        :return: true if the help system has found the applications help content and has finished
                initializing
        :rtype: bool
        """

    def isExcludedFromHelp(self, helpObject: java.lang.Object) -> bool:
        """
        Returns true if the given object is meant to be ignored by the help system
        
        :param java.lang.Object helpObject: the object to check
        :return: true if ignored
        :rtype: bool
        
        .. seealso::
        
            | :obj:`.excludeFromHelp(Object)`
        """

    def registerHelp(self, helpObject: java.lang.Object, helpLocation: ghidra.util.HelpLocation):
        """
        Register help for a specific object.
         
         
        Do not call this method will a ``null`` help location.  Instead, to signal that
        an item has no help, call :meth:`excludeFromHelp(Object) <.excludeFromHelp>`.
        
        :param java.lang.Object helpObject: the object to associate the specified help location with
        :param ghidra.util.HelpLocation helpLocation: help content location
        """

    def reload(self):
        """
        Called when a major system even happens, such as changing the system theme.
        """

    @typing.overload
    def showHelp(self, helpObject: java.lang.Object, infoOnly: typing.Union[jpype.JBoolean, bool], parent: java.awt.Component):
        """
        Display the Help content identified by the help object.
        
        :param java.lang.Object helpObject: the object to which help was previously registered
        :param jpype.JBoolean or bool infoOnly: display :obj:`HelpLocation` information only, not the help UI
        :param java.awt.Component parent: requesting component
        
        .. seealso::
        
            | :obj:`.registerHelp(Object, HelpLocation)`
        """

    @typing.overload
    def showHelp(self, url: java.net.URL):
        """
        Display the help page for the given URL.  This is a specialty method for displaying
        help when a specific file is desired, like an introduction page.  Showing help for
        objects within the system is accomplished by calling
        :meth:`showHelp(Object, boolean, Component) <.showHelp>`.
        
        :param java.net.URL url: the URL to display
        
        .. seealso::
        
            | :obj:`.showHelp(Object, boolean, Component)`
        """

    @typing.overload
    def showHelp(self, location: ghidra.util.HelpLocation):
        """
        Display the help page for the given help location.
        
        :param ghidra.util.HelpLocation location: the location to display.
        
        .. seealso::
        
            | :obj:`.showHelp(Object, boolean, Component)`
        """

    @property
    def excludedFromHelp(self) -> jpype.JBoolean:
        ...

    @property
    def helpLocation(self) -> ghidra.util.HelpLocation:
        ...


class Help(java.lang.Object):
    """
    Creates the HelpManager for the application. This is just a glorified global variable for
    the application.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getHelpService() -> HelpService:
        """
        Get the help service
        
        :return: a non-null help service
        :rtype: HelpService
        """

    @staticmethod
    def installHelpService(service: HelpService):
        ...


class ImageLocation(java.lang.Object):
    """
    A class that represents the original location of an IMG tag along with its location 
    resolution within the help system.
     
     
    Some images are represented by 'in memory' or 'runtime' values that do not have a valid
    url.
    """

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createInvalidRuntimeLocation(sourceFile: jpype.protocol.SupportsPath, imageSrc: typing.Union[java.lang.String, str]) -> ImageLocation:
        ...

    @staticmethod
    def createLocalLocation(sourceFile: jpype.protocol.SupportsPath, imageSrc: typing.Union[java.lang.String, str], resolvedUri: java.net.URI, resolvedPath: jpype.protocol.SupportsPath) -> ImageLocation:
        ...

    @staticmethod
    def createRemoteLocation(sourceFile: jpype.protocol.SupportsPath, imageSrc: typing.Union[java.lang.String, str], resolvedUri: java.net.URI) -> ImageLocation:
        ...

    @staticmethod
    def createRuntimeLocation(sourceFile: jpype.protocol.SupportsPath, imageSrc: typing.Union[java.lang.String, str], resolvedUri: java.net.URI, resolvedPath: jpype.protocol.SupportsPath) -> ImageLocation:
        ...

    def getImageSrc(self) -> str:
        ...

    def getResolvedPath(self) -> java.nio.file.Path:
        ...

    def getResolvedUri(self) -> java.net.URI:
        ...

    def getSourceFile(self) -> java.nio.file.Path:
        ...

    def isInvalidRuntimeImage(self) -> bool:
        ...

    def isRemote(self) -> bool:
        ...

    def isRuntime(self) -> bool:
        ...

    @property
    def invalidRuntimeImage(self) -> jpype.JBoolean:
        ...

    @property
    def resolvedPath(self) -> java.nio.file.Path:
        ...

    @property
    def resolvedUri(self) -> java.net.URI:
        ...

    @property
    def runtime(self) -> jpype.JBoolean:
        ...

    @property
    def imageSrc(self) -> java.lang.String:
        ...

    @property
    def remote(self) -> jpype.JBoolean:
        ...

    @property
    def sourceFile(self) -> java.nio.file.Path:
        ...


class TOCConverter(java.lang.Object):
    """
    Converts the Ghidra "source" TOC file to a JavaHelp TOC file. The Ghidra
    source TOC file contains the table of context index name and its
    corresponding url. However, JavaHelp expects the target value to be map ID in
    the map file.
    """

    @typing.type_check_only
    class TOCItem(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TOCHandler(org.xml.sax.helpers.DefaultHandler):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...


class GHelpBroker(javax.help.DefaultHelpBroker):
    """
    Ghidra help broker that displays the help set; sets the application icon on the help frame and
    attempts to maintain the user window size.
    """

    @typing.type_check_only
    class PageLocationUpdater(java.beans.PropertyChangeListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, hs: javax.help.HelpSet):
        """
        Construct a new GhidraHelpBroker.
        
        :param javax.help.HelpSet hs: java help set associated with this help broker
        """

    def reload(self):
        ...


class CustomSearchView(javax.help.SearchView):

    @typing.type_check_only
    class CustomHelpSearchNavigator(javax.help.JHelpSearchNavigator):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, view: javax.help.NavigatorView, model: javax.help.HelpModel):
            ...


    @typing.type_check_only
    class CustomSearchNavigatorUI(javax.help.plaf.basic.BasicSearchNavigatorUI):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, navigator: javax.help.JHelpSearchNavigator):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, hs: javax.help.HelpSet, name: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], locale: java.util.Locale, params: java.util.Hashtable):
        ...


class GHelpBuilder(java.lang.Object):
    """
    A class to build help for an entire 'G' application.  This class will take in a list of
    module paths and build the help for each module.  To build single modules, call this class
    with only one module path.
     
    
    Note: Help links must not be absolute.  They can be relative, including ``. and ..``
    syntax.  Further, they can use the special help system syntax, which is:
     
    * **help/topics/**topicName/Filename.html for referencing help topic files
    * **help/**shared/image.png for referencing image files at paths rooted under
    the module's root help dir
    """

    @typing.type_check_only
    class PrintErrorRunnable(java.lang.Runnable):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class Results(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...


class GHelpHTMLEditorKit(javax.swing.text.html.HTMLEditorKit):
    """
    A class that allows Ghidra to intercept JavaHelp navigation events in order to resolve them
    to Ghidra's help system.  Without this class, contribution plugins have no way of
    referencing help documents within Ghidra's default help location.
     
    
    This class is currently installed by the :obj:`GHelpSet`.
    
    
    .. seealso::
    
        | :obj:`GHelpSet`
    """

    @typing.type_check_only
    class ResolverHyperlinkListener(javax.swing.event.HyperlinkListener):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GHelpHTMLFactory(javax.swing.text.html.HTMLEditorKit.HTMLFactory):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class GHelpImageView(javax.swing.text.html.ImageView):
        """
        Overridden to allow us to find images that are defined as constants in places like
        :obj:`Icons`
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, elem: javax.swing.text.Element):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def zoomIn():
        ...

    @staticmethod
    def zoomOut():
        ...


class PathKey(java.lang.Object):
    """
    A class that wraps a Path and allows map lookup for paths from different file systems
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, p: jpype.protocol.SupportsPath):
        ...

    @typing.overload
    def __init__(self, path: typing.Union[java.lang.String, str]):
        ...


class CustomFavoritesView(javax.help.FavoritesView):
    """
    This class allows us to change the renderer of the favorites tree.
    """

    @typing.type_check_only
    class CustomHelpFavoritesNavigator(javax.help.JHelpFavoritesNavigator):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CustomFavoritesNavigatorUI(javax.help.plaf.basic.BasicFavoritesNavigatorUI):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CustomFavoritesCellRenderer(javax.help.plaf.basic.BasicFavoritesCellRenderer):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, helpModel: javax.help.HelpModel):
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, hs: javax.help.HelpSet, name: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], params: java.util.Hashtable):
        ...

    @typing.overload
    def __init__(self, hs: javax.help.HelpSet, name: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], locale: java.util.Locale, params: java.util.Hashtable):
        ...


class JavaHelpSetBuilder(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, moduleName: typing.Union[java.lang.String, str], helpMapFile: jpype.protocol.SupportsPath, helpTOCFile: jpype.protocol.SupportsPath, indexerOutputDirectory: jpype.protocol.SupportsPath, helpSetFile2: jpype.protocol.SupportsPath):
        ...

    def writeHelpSetFile(self):
        ...


class CustomTOCView(javax.help.TOCView):
    """
    A custom Table of Contents view that we specify in our JavaHelp xml documents.  This view 
    lets us install custom renderers and custom tree items for use by those renderers.  These
    renderers let us display custom text defined by the TOC_Source.xml files.  We also add some
    utility like: tooltips in development mode, node selection when pressing F1.
    """

    class CustomDefaultTOCFactory(javax.help.TOCView.DefaultTOCFactory):
        """
        Our custom factory that knows how to look for extra XML attributes and how to 
        create our custom tree items
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class CustomTOCNavigatorUI(javax.help.plaf.basic.BasicTOCNavigatorUI):
        """
        Our hook to install our custom cell renderer.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, b: javax.help.JHelpTOCNavigator):
            ...

        def getHelpModel(self) -> javax.help.HelpModel:
            ...

        @property
        def helpModel(self) -> javax.help.HelpModel:
            ...


    @typing.type_check_only
    class CustomCellRenderer(javax.help.plaf.basic.BasicTOCCellRenderer):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, map: javax.help.Map, view: javax.help.TOCView):
            ...


    class CustomTreeItemDecorator(javax.help.TOCItem):
        """
        A custom tree item that allows us to store and retrieve custom attributes that we parsed
        from the TOC xml document.
        """

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, wrappedItem: javax.help.TOCItem):
            ...

        def getDisplayText(self) -> str:
            ...

        def getTocID(self) -> str:
            ...

        @property
        def displayText(self) -> java.lang.String:
            ...

        @property
        def tocID(self) -> java.lang.String:
            ...


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, hs: javax.help.HelpSet, name: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], params: java.util.Hashtable):
        ...

    @typing.overload
    def __init__(self, hs: javax.help.HelpSet, name: typing.Union[java.lang.String, str], label: typing.Union[java.lang.String, str], locale: java.util.Locale, params: java.util.Hashtable):
        ...

    def getHelpModel(self) -> javax.help.HelpModel:
        ...

    @property
    def helpModel(self) -> javax.help.HelpModel:
        ...


class HelpDescriptor(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getHelpInfo(self) -> str:
        """
        Returns a descriptive String about the help object that this descriptor represents.
        
        :return: the help info
        :rtype: str
        """

    def getHelpObject(self) -> java.lang.Object:
        """
        Returns the object for which help locations are defined.  This may be the implementor of
        this interface or some other delegate object.
        
        :return: the help object
        :rtype: java.lang.Object
        """

    @property
    def helpObject(self) -> java.lang.Object:
        ...

    @property
    def helpInfo(self) -> java.lang.String:
        ...


class TOCItemProvider(java.lang.Object):
    """
    An interface that allows us to perform dependency injection in the testing environment
    """

    class_: typing.ClassVar[java.lang.Class]

    def getExternalTocItemsById(self) -> java.util.Map[java.lang.String, help.validator.model.TOCItemExternal]:
        """
        Returns all external TOC items referenced by this provider
        
        :return: the items
        :rtype: java.util.Map[java.lang.String, help.validator.model.TOCItemExternal]
        """

    def getTocDefinitionsByID(self) -> java.util.Map[java.lang.String, help.validator.model.TOCItemDefinition]:
        """
        Returns all TOC items defined by this provider
        
        :return: the items
        :rtype: java.util.Map[java.lang.String, help.validator.model.TOCItemDefinition]
        """

    @property
    def externalTocItemsById(self) -> java.util.Map[java.lang.String, help.validator.model.TOCItemExternal]:
        ...

    @property
    def tocDefinitionsByID(self) -> java.util.Map[java.lang.String, help.validator.model.TOCItemDefinition]:
        ...


class OverlayHelpTree(java.lang.Object):
    """
    A class that will take in a group of help directories and create a tree of
    help Table of Contents (TOC) items.  Ideally, this tree can be used to create a single
    TOC document, or individual TOC documents, one for each help directory (this allows
    for better modularity).
     
    
    We call this class an **overlay** tree to drive home the idea that each
    help directory's TOC data is put into the tree, with any duplicate paths overlayed
    on top of those from other help directories.
    """

    @typing.type_check_only
    class OverlayNode(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self, parentNode: OverlayHelpTree.OverlayNode, rootItem: help.validator.model.TOCItem):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, tocItemProvider: TOCItemProvider, linkDatabase: help.validator.LinkDatabase):
        ...

    def printTreeForID(self, outputFile: jpype.protocol.SupportsPath, sourceFileID: typing.Union[java.lang.String, str]):
        ...



__all__ = ["HelpRightArrowIcon", "HelpBuildUtils", "JavaHelpFilesBuilder", "GHelpSet", "HelpService", "Help", "ImageLocation", "TOCConverter", "GHelpBroker", "CustomSearchView", "GHelpBuilder", "GHelpHTMLEditorKit", "PathKey", "CustomFavoritesView", "JavaHelpSetBuilder", "CustomTOCView", "HelpDescriptor", "TOCItemProvider", "OverlayHelpTree"]
