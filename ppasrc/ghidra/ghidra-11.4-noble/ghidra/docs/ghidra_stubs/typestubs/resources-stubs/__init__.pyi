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
import java.net # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore


class MultiIcon(javax.swing.Icon):
    """
    Icon class for displaying overlapping icons.  Icons are drawn in the order they
    are added.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, baseIcon: javax.swing.Icon):
        """
        Constructs a new MultiIcon with an initial base icon that will always be drawn first.
        
        :param javax.swing.Icon baseIcon: the base icon that will always be drawn first.
        """

    @typing.overload
    def __init__(self, baseIcon: javax.swing.Icon, disabled: typing.Union[jpype.JBoolean, bool]):
        """
        Constructs a new MultiIcon with an initial base icon that will always be drawn first.
        
        :param javax.swing.Icon baseIcon: the base icon that will always be drawn first.
        """

    @typing.overload
    def __init__(self, baseIcon: javax.swing.Icon, *icons: javax.swing.Icon):
        """
        Construct a new MultiIcon with the provided base image and subsequent images
        
        :param javax.swing.Icon baseIcon: base image always drawn first
        :param jpype.JArray[javax.swing.Icon] icons: images drawn atop the base
        """

    @typing.overload
    def __init__(self, baseIcon: javax.swing.Icon, disabled: typing.Union[jpype.JBoolean, bool], width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        """
        Construct a new MultiIcon with a predetermined size
        
        :param javax.swing.Icon baseIcon: Primary icon that is always drawn first
        :param jpype.JBoolean or bool disabled: flag to draw this icon in a disabled state
        :param jpype.JInt or int width: horizontal dimension of this icon
        :param jpype.JInt or int height: vertical dimension of this icon
        """

    def addIcon(self, icon: javax.swing.Icon):
        """
        Adds an icon that is to be drawn on top of the base icon and any other icons that
        have been added.
        
        :param javax.swing.Icon icon: the icon to be added.
        """

    def getDescription(self) -> str:
        ...

    def getIcons(self) -> jpype.JArray[javax.swing.Icon]:
        """
        Return array of Icons that were added to this MultIcon.
        """

    @property
    def description(self) -> java.lang.String:
        ...

    @property
    def icons(self) -> jpype.JArray[javax.swing.Icon]:
        ...


class IconProvider(java.lang.Object):
    """
    A class that knows how to provide an icon and the URL for that icon.  If :meth:`getUrl() <.getUrl>`
    returns a non-null value, then that is the URL used to originally load the icon in this class.
     
     
    If :meth:`getUrl() <.getUrl>` returns null, then :meth:`getOrCreateUrl() <.getOrCreateUrl>` can be used to create a
    value URL by writing out the image for this class's icon.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, icon: javax.swing.Icon, url: java.net.URL):
        ...

    def getImage(self) -> java.awt.Image:
        ...

    def getOrCreateUrl(self) -> java.net.URL:
        """
        Returns the value of :meth:`getUrl() <.getUrl>` if it is non-null.  Otherwise, this class will
        attempt to create a temporary file containing the image of this class in order to return
        a URL for that temp file.  If a temporary file could not be created, then the URL 
        returned from this class will point to the 
        :meth:`default icon <ResourceManager.getDefaultIcon>`.
        
        :return: the URL
        :rtype: java.net.URL
        """

    def getUrl(self) -> java.net.URL:
        ...

    def isInvalid(self) -> bool:
        ...

    @property
    def image(self) -> java.awt.Image:
        ...

    @property
    def invalid(self) -> jpype.JBoolean:
        ...

    @property
    def orCreateUrl(self) -> java.net.URL:
        ...

    @property
    def url(self) -> java.net.URL:
        ...


class Icons(java.lang.Object):
    """
    A class to get generic icons for standard actions.  All methods in this class return an 
    icon that is 16x16 unless the method name ends in another size.'
    """

    class_: typing.ClassVar[java.lang.Class]
    EMPTY_ICON: typing.Final[javax.swing.Icon]
    HELP_ICON: typing.Final[javax.swing.Icon]
    ADD_ICON: typing.Final[javax.swing.Icon]
    COPY_ICON: typing.Final[javax.swing.Icon]
    CUT_ICON: typing.Final[javax.swing.Icon]
    PASTE_ICON: typing.Final[javax.swing.Icon]
    COLLAPSE_ALL_ICON: typing.Final[javax.swing.Icon]
    EXPAND_ALL_ICON: typing.Final[javax.swing.Icon]
    CONFIGURE_FILTER_ICON: typing.Final[javax.swing.Icon]
    CLEAR_ICON: typing.Final[javax.swing.Icon]
    DELETE_ICON: typing.Final[javax.swing.Icon]
    ERROR_ICON: typing.Final[javax.swing.Icon]
    HOME_ICON: typing.Final[javax.swing.Icon]
    NAVIGATE_ON_INCOMING_EVENT_ICON: typing.Final[javax.swing.Icon]
    NAVIGATE_ON_OUTGOING_EVENT_ICON: typing.Final[javax.swing.Icon]
    NOT_ALLOWED_ICON: typing.Final[javax.swing.Icon]
    OPEN_FOLDER_ICON: typing.Final[javax.swing.Icon]
    CLOSED_FOLDER_ICON: typing.Final[javax.swing.Icon]
    REFRESH_ICON: typing.Final[javax.swing.Icon]
    SORT_ASCENDING_ICON: typing.Final[javax.swing.Icon]
    SORT_DESCENDING_ICON: typing.Final[javax.swing.Icon]
    STOP_ICON: typing.Final[javax.swing.Icon]
    STRONG_WARNING_ICON: typing.Final[javax.swing.Icon]
    WARNING_ICON: typing.Final[javax.swing.Icon]
    INFO_ICON: typing.Final[javax.swing.Icon]
    LEFT_ICON: typing.Final[javax.swing.Icon]
    RIGHT_ICON: typing.Final[javax.swing.Icon]
    UP_ICON: typing.Final[javax.swing.Icon]
    DOWN_ICON: typing.Final[javax.swing.Icon]
    LEFT_ALTERNATE_ICON: typing.Final[javax.swing.Icon]
    """
    An version of the LEFT_ICON with a different color
    """

    RIGHT_ALTERNATE_ICON: typing.Final[javax.swing.Icon]
    """
    An version of the RIGHT_ICON with a different color
    """

    SAVE_ICON: typing.Final[javax.swing.Icon]
    SAVE_AS_ICON: typing.Final[javax.swing.Icon]
    MAKE_SELECTION_ICON: typing.Final[javax.swing.Icon]
    ARROW_DOWN_RIGHT_ICON: typing.Final[javax.swing.Icon]
    ARROW_UP_LEFT_ICON: typing.Final[javax.swing.Icon]

    @staticmethod
    @typing.overload
    def get(iconPath: typing.Union[java.lang.String, str]) -> javax.swing.ImageIcon:
        """
        Gets the icon for the given icon path. The given path should be relative to the classpath.
        If an icon by that name can't be found, the default "bomb" icon is returned instead.
         
        
        For example, an icon named foo.png would typically be stored in the module at 
        "{modulePath}/src/main/resources/image/foo.png".  To reference that icon, use the path
        "images/foo.png", since "{modulePath}/src/main/resources" is in the classpath.
        
        :param java.lang.String or str iconPath: the icon path (relative to the classpath)
        :return: The icon referenced by that path.
        :rtype: javax.swing.ImageIcon
        """

    @staticmethod
    @typing.overload
    def get(iconPath: typing.Union[java.lang.String, str], width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> javax.swing.ImageIcon:
        """
        Gets the icon for the given icon path and scale it to the specified width and height.
        The given path should be relative to the classpath.
        If an icon by that name can't be found, the default "bomb" icon is returned instead.
         
        
        For example, an icon named foo.png would typically be stored in the module at 
        "{modulePath}/src/main/resources/image/foo.png".  To reference that icon, use the path
        "images/foo.png", since "{modulePath}/src/main/resources" is in the classpath.
        
        :param java.lang.String or str iconPath: the icon path (relative to the classpath)
        :param jpype.JInt or int width: the desired width after scaling
        :param jpype.JInt or int height: the desired height after scaling
        :return: The icon referenced by that path.
        :rtype: javax.swing.ImageIcon
        """

    @staticmethod
    def getIconForIconsReference(snippet: typing.Union[java.lang.String, str]) -> IconProvider:
        """
        Returns an :obj:`IconProvider` for the given string value, which is usually the 'src' 
        attribute of an IMG tag
        
        :param java.lang.String or str snippet: the snippet
        :return: the icon provider
        :rtype: IconProvider
        """

    @staticmethod
    def isIconsReference(snippet: typing.Union[java.lang.String, str]) -> bool:
        """
        Returns true if the given string is a Java code snippet that references this class
        
        :param java.lang.String or str snippet: the string to check
        :return: true if the given string is a Java code snippet that references this class
        :rtype: bool
        """


class MultiIconBuilder(java.lang.Object):
    """
    A builder to allow for easier creation of an icon that is composed of a base icon, with 
    other icons overlaid.  The :meth:`build() <.build>` method returns an :obj:`ImageIcon`, as this
    allows Java's buttons to automatically create disabled icons correctly.
     
     
    Note: this class is a work-in-progress.  Add more methods for locating overlays as needed.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, baseIcon: javax.swing.Icon):
        ...

    def addCenteredIcon(self, icon: javax.swing.Icon) -> MultiIconBuilder:
        ...

    @typing.overload
    def addIcon(self, icon: javax.swing.Icon, w: typing.Union[jpype.JInt, int], h: typing.Union[jpype.JInt, int], quandrant: QUADRANT) -> MultiIconBuilder:
        """
        Adds the specified icon as an overlay to the base icon, possibly scaled according
        to the specified width and height, in the specified quadrant corner.
        
        :param javax.swing.Icon icon: the icon to overlay
        :param jpype.JInt or int w: width of the overlaid icon
        :param jpype.JInt or int h: height of the overlaid icon
        :param QUADRANT quandrant: corner to place the overlay on
        :return: this builder (for chaining)
        :rtype: MultiIconBuilder
        """

    @typing.overload
    def addIcon(self, icon: javax.swing.Icon, w: typing.Union[jpype.JInt, int], h: typing.Union[jpype.JInt, int], x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]) -> MultiIconBuilder:
        """
        Adds the specified icon as an overlay to the base icon at the given offsets and scaled
        to the specified width and height.
        
        :param javax.swing.Icon icon: the icon to overlay
        :param jpype.JInt or int w: width of the overlaid icon
        :param jpype.JInt or int h: height of the overlaid icon
        :param jpype.JInt or int x: the horizontal offset of the overlay with respect to the base icon
        :param jpype.JInt or int y: the vertical offset of the overlay with respect to the base icon
        :return: this builder (for chaining)
        :rtype: MultiIconBuilder
        """

    @typing.overload
    def addLowerLeftIcon(self, icon: javax.swing.Icon) -> MultiIconBuilder:
        """
        Adds the given icon as an overlay to the base icon, to the lower-left
        
        :param javax.swing.Icon icon: the icon
        :return: this builder
        :rtype: MultiIconBuilder
        """

    @typing.overload
    def addLowerLeftIcon(self, icon: javax.swing.Icon, w: typing.Union[jpype.JInt, int], h: typing.Union[jpype.JInt, int]) -> MultiIconBuilder:
        """
        Adds the given icon as an overlay to the base icon, to the lower-left,
        scaled to the given width and height
        
        :param javax.swing.Icon icon: the icon
        :param jpype.JInt or int w: the desired width
        :param jpype.JInt or int h: the desired height
        :return: this builder
        :rtype: MultiIconBuilder
        """

    @typing.overload
    def addLowerRightIcon(self, icon: javax.swing.Icon) -> MultiIconBuilder:
        """
        Adds the given icon as an overlay to the base icon, to the lower-right
        
        :param javax.swing.Icon icon: the icon
        :return: this builder
        :rtype: MultiIconBuilder
        """

    @typing.overload
    def addLowerRightIcon(self, icon: javax.swing.Icon, w: typing.Union[jpype.JInt, int], h: typing.Union[jpype.JInt, int]) -> MultiIconBuilder:
        """
        Adds the given icon as an overlay to the base icon, to the lower-right,
        scaled to the given width and height
        
        :param javax.swing.Icon icon: the icon
        :param jpype.JInt or int w: the desired width
        :param jpype.JInt or int h: the desired height
        :return: this builder
        :rtype: MultiIconBuilder
        """

    def addText(self, text: typing.Union[java.lang.String, str], font: java.awt.Font, color: java.awt.Color, quandrant: QUADRANT) -> MultiIconBuilder:
        """
        Add text overlaid on the base icon, aligned to the specified quadrant.
        
        :param java.lang.String or str text: Text string to write onto the icon.  Probably can only fit a letter or two
        :param java.awt.Font font: The font to use to render the text.  You know the size of the base icon, so
        you should be able to figure out the size of the font to use for the text
        :param java.awt.Color color: The color to use when rendering the text
        :param QUADRANT quandrant: The :obj:`QUADRANT` to align the text to different parts of the icon
        :return: this builder (for chaining)
        :rtype: MultiIconBuilder
        """

    def build(self) -> javax.swing.ImageIcon:
        ...

    def setDescription(self, description: typing.Union[java.lang.String, str]) -> MultiIconBuilder:
        """
        Sets a description for the icon being built.  This is useful for debugging.
        
        :param java.lang.String or str description: the description
        :return: this builder
        :rtype: MultiIconBuilder
        """


class ResourceManager(java.lang.Object):
    """
    General resource management class that provides a convenient
    way of accessing external resources used in Ghidra.
     
    
     
    .. _safe:
    
    
    There is a known problem with Java's :obj:`MediaTracker` that can cause deadlocks.  The various
    methods of this class that create :obj:`ImageIcon`s will do so by loading image bytes directly,
    as opposed to using the flawed constructor :meth:`ImageIcon.ImageIcon(Image) <ImageIcon.ImageIcon>`.
    """

    class_: typing.ClassVar[java.lang.Class]
    BOMB: typing.Final = "images/core.png"
    BIG_BOMB: typing.Final = "images/core24.png"
    EXTERNAL_ICON_PREFIX: typing.Final = "[EXTERNAL]"

    def __init__(self):
        ...

    @staticmethod
    def findIcon(path: typing.Union[java.lang.String, str]) -> javax.swing.ImageIcon:
        """
        Attempts to load an icon from the given path. Returns the icon or null if no icon was
        found from the given path. This differs from :meth:`loadImage(String) <.loadImage>` in that
        loadImage will return the default Icon if one can't be found. Further, loadImage will cache
        even the default value, while findIcon only caches resolved icons.
        
        :param java.lang.String or str path: the icon to load, e.g., "images/home.gif"
        :return: the ImageIcon if it exists or null
        :rtype: javax.swing.ImageIcon
        """

    @staticmethod
    def getDefaultIcon() -> javax.swing.ImageIcon:
        ...

    @staticmethod
    @typing.overload
    def getDisabledIcon(icon: javax.swing.Icon) -> javax.swing.ImageIcon:
        """
        Get the disabled rendering of the given icon.
        
        :param javax.swing.Icon icon: The icon to disable.
        :return: disabled icon
        :rtype: javax.swing.ImageIcon
        """

    @staticmethod
    @typing.overload
    def getDisabledIcon(icon: javax.swing.ImageIcon) -> javax.swing.ImageIcon:
        """
        Get the disabled rendering of the given imageIcon.
        
        :param javax.swing.ImageIcon icon: The icon to disable.
        :return: disabled icon
        :rtype: javax.swing.ImageIcon
        """

    @staticmethod
    @typing.overload
    def getDisabledIcon(icon: javax.swing.Icon, brightnessPercent: typing.Union[jpype.JInt, int]) -> javax.swing.ImageIcon:
        """
        Returns a disabled icon while allowing the caller to control the brightness of the icon
        returned
        
        :param javax.swing.Icon icon: The icon to disable.
        :param jpype.JInt or int brightnessPercent: The level of brightness (0-100, where 100 is the brightest).
        :return: a disabled version of the original icon.
        :rtype: javax.swing.ImageIcon
        """

    @staticmethod
    def getIconName(icon: javax.swing.Icon) -> str:
        """
        Get the name of this icon.  The value is usually going to be the URL from which the icon 
        was loaded
        
        :param javax.swing.Icon icon: the icon for which the name is desired
        :return: the name
        :rtype: str
        """

    @staticmethod
    def getImageIcon(icon: javax.swing.Icon) -> javax.swing.ImageIcon:
        """
        Returns an :obj:`ImageIcon` for the given icon.  If the value is already an ImageIcon, then
        that object is returned; otherwise, an ImageIcon will be created the `safe <safe_>`_
        way.
        
        :param javax.swing.Icon icon: The icon to convert
        :return: the new icon
        :rtype: javax.swing.ImageIcon
        """

    @staticmethod
    def getImageIconFromImage(imageName: typing.Union[java.lang.String, str], image: java.awt.Image) -> javax.swing.ImageIcon:
        """
        Creates an image icon from the given image.  This method will create an ``ImageIcon``
        the `"safe" <safe>`_ way by avoiding the constructor 
        :meth:`ImageIcon.ImageIcon(Image) <ImageIcon.ImageIcon>`, which can
        trigger problems with Java's :obj:`MediaTracker`.
        
        :param java.lang.String or str imageName: A textual description of the image; may be null
        :param java.awt.Image image: The image to use for creating an ImageIcon.
        :return: the new icon
        :rtype: javax.swing.ImageIcon
        """

    @staticmethod
    def getLoadedIcons() -> java.util.Set[javax.swing.Icon]:
        """
        Returns a list of all loaded icons.
        
        :return: a list of all loaded icons
        :rtype: java.util.Set[javax.swing.Icon]
        """

    @staticmethod
    def getResource(filename: typing.Union[java.lang.String, str]) -> java.net.URL:
        """
        Finds a resource with a given name. This method returns null if no
        resource with this name is found. The rules for searching resources
        associated with a given class are implemented by the defining class
        loader of the class.
        
        :param java.lang.String or str filename: "partially" qualified resource filename to get, e.g.,
                "images/go-home.png" would look for the file named 'home.gif' in
                the 'images' subdirectory of the 'resources' package,
                following the search rules defined by your CLASSPATH and
                return an InputStream if found; null if it cannot load the resource.
        :return: the URL
        :rtype: java.net.URL
        """

    @staticmethod
    def getResourceAsStream(filename: typing.Union[java.lang.String, str]) -> java.io.InputStream:
        """
        Finds a resource with a given name. This method returns null if no resource
        with this name is found. The rules for searching resources associated with a
        given class are implemented by the defining class loader of the class.
        
        :param java.lang.String or str filename: "partially" qualified resource filename to get, e.g., "images/home.gif" 
                would look for the file named 'home.gif' in the 'images' subdirectory of 
                the 'resources' package, following the search rules defined by your 
                CLASSPATH and return an InputStream if found; null if it cannot load the resource.
        :return: the input stream
        :rtype: java.io.InputStream
        """

    @staticmethod
    def getResourceFile(filename: typing.Union[java.lang.String, str]) -> java.io.File:
        """
        Locates a File resource by the given name
        
        :param java.lang.String or str filename: the filename
        :return: the File for the given resource; null if there is no such file
        :rtype: java.io.File
        """

    @staticmethod
    def getResourceNames(dirName: typing.Union[java.lang.String, str], extension: typing.Union[java.lang.String, str]) -> java.util.Set[java.lang.String]:
        """
        Search the classpath for files in the <classpath entry>/``dirName`` 
        location that have the given extension.  In ``null`` is passed for the 
        extension, then all files found in the given dir names will be returned.  In this 
        way, ``null`` is a wildcard.
        
         
        The names returned from this method are relative and are meant to be used in a 
        later callback to this class for methods such as :meth:`loadImage(String) <.loadImage>` or
        :meth:`getResource(String) <.getResource>`.
        
        :param java.lang.String or str dirName: the name of the directory under which to search
        :param java.lang.String or str extension: the extension that matching files must possess
        :return: set of filenames in the given directory that end with the given extension
        :rtype: java.util.Set[java.lang.String]
        """

    @staticmethod
    def getResources(dirName: typing.Union[java.lang.String, str], extension: typing.Union[java.lang.String, str]) -> java.util.Set[java.net.URL]:
        """
        Search the classpath for files in the <classpath entry>/``dirName`` 
        location that have the given extension.  In ``null`` is passed for the 
        extension, then all files found in the given dir names will be returned.  In this 
        way, ``null`` is a wildcard.
        
         
        This method differs from :meth:`getResource(String) <.getResource>` in that this method finds 
        multiple matches.
        
        :param java.lang.String or str dirName: the name of the sub-directory under which to search
        :param java.lang.String or str extension: the extension that matching files must possess
        :return: set of URLs in the given directory that end with the given extension
        :rtype: java.util.Set[java.net.URL]
        """

    @staticmethod
    @typing.overload
    def getScaledIcon(icon: javax.swing.Icon, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int], hints: typing.Union[jpype.JInt, int]) -> javax.swing.ImageIcon:
        """
        Creates a scaled ImageIcon from the given icon.
        
        :param javax.swing.Icon icon: the icon to scale
        :param jpype.JInt or int width: the width of the new icon
        :param jpype.JInt or int height: the height of the new icon
        :param jpype.JInt or int hints: scaling hints (see :meth:`BufferedImage.getScaledInstance(int, int, int) <BufferedImage.getScaledInstance>`
        :return: A new, scaled ImageIcon
        :rtype: javax.swing.ImageIcon
        """

    @staticmethod
    @typing.overload
    def getScaledIcon(icon: javax.swing.ImageIcon, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> javax.swing.ImageIcon:
        """
        Creates a scaled ImageIcon from the given icon with scaling of 
        :obj:`Image.SCALE_AREA_AVERAGING`
        
        :param javax.swing.ImageIcon icon: the icon to scale
        :param jpype.JInt or int width: the width of the new icon
        :param jpype.JInt or int height: the height of the new icon
        :return: A new, scaled ImageIcon
        :rtype: javax.swing.ImageIcon
        """

    @staticmethod
    @typing.overload
    def getScaledIcon(icon: javax.swing.Icon, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> javax.swing.Icon:
        """
        Creates a scaled Icon from the given icon with scaling of 
        :obj:`Image.SCALE_AREA_AVERAGING`. If an EmptyIcon is passed, a new EmptyIcon is returned
        with the new dimensions.
        
        :param javax.swing.Icon icon: the icon to scale
        :param jpype.JInt or int width: the width of the new icon
        :param jpype.JInt or int height: the height of the new icon
        :return: A new, scaled ImageIcon
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def getToolImages() -> java.util.Set[java.lang.String]:
        ...

    @staticmethod
    def loadIcon(iconPath: typing.Union[java.lang.String, str]) -> javax.swing.Icon:
        """
        Load the icon specified by iconPath. The iconPath can be either a path to a resource on
        the classpath or a relative or absolute path to an icon on the file system. If the iconPath
        is a path to a classpath resource, then it will be searched directly or also with an "images/"
        prepended to the path. For example, if there exists an icon "home.gif" on the classpath that
        was stored in the standard "images" resource directory, then it exists on the classpath 
        as "images/home.gif". That icon will be found if the iconPath is either "images/home.gif" or
        just as "home.gif".
        
        :param java.lang.String or str iconPath: name of file to load, e.g., "images/home.gif"
        :return: an Icon from the given iconPath or null, if no such icon can be found
        :rtype: javax.swing.Icon
        """

    @staticmethod
    @typing.overload
    def loadImage(imageName: typing.Union[java.lang.String, str], imageBytes: jpype.JArray[jpype.JByte]) -> javax.swing.ImageIcon:
        """
        Load the image using the specified bytes. The image icon will
        be cached using the image name. The bytes must have been
        read from an image file containing a supported image format,
        such as GIF, JPEG, or (as of 1.3) PNG.
        
        :param java.lang.String or str imageName: the name of the image
        :param jpype.JArray[jpype.JByte] imageBytes: the bytes of the image
        :return: the image icon stored in the bytes
        :rtype: javax.swing.ImageIcon
        """

    @staticmethod
    @typing.overload
    def loadImage(filename: typing.Union[java.lang.String, str], width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> javax.swing.ImageIcon:
        """
        Load and scale the image specified by filename; returns null if problems occur trying to load
        the file.
        
        :param java.lang.String or str filename: name of file to load, e.g., "images/home.gif"
        :param jpype.JInt or int width: - the width to scale the image to
        :param jpype.JInt or int height: - the height to scale the image to
        :return: the scaled image.
        :rtype: javax.swing.ImageIcon
        """

    @staticmethod
    @typing.overload
    def loadImage(iconPath: typing.Union[java.lang.String, str]) -> javax.swing.ImageIcon:
        """
        Load the image specified by filename; returns the default bomb icon
        if problems occur trying to load the file.
        
        :param java.lang.String or str iconPath: name of file to load, e.g., "images/home.gif"
        :return: the image icon stored in the bytes
        :rtype: javax.swing.ImageIcon
        """

    @staticmethod
    def loadImages(*filenames: typing.Union[java.lang.String, str]) -> java.util.List[javax.swing.ImageIcon]:
        """
        Load the images specified by filenames; substitutes the default bomb icon
        if problems occur trying to load an individual file.
        
        :param jpype.JArray[java.lang.String] filenames: vararg list of string filenames (ie. "images/home.gif")
        :return: list of ImageIcons with each image, problem / missing images replaced with
        the default icon.
        :rtype: java.util.List[javax.swing.ImageIcon]
        """

    @staticmethod
    def reloadImage(filename: typing.Union[java.lang.String, str]) -> javax.swing.ImageIcon:
        """
        A convenience method to force the image denoted by ``filename`` to be read 
        from disk and to not use the cached version
        
        :param java.lang.String or str filename: name of file to load, e.g., "images/home.gif"
        :return: the image icon stored in the bytes
        :rtype: javax.swing.ImageIcon
        
        .. seealso::
        
            | :obj:`.loadImage(String)`
        """


class QUADRANT(java.lang.Enum[QUADRANT]):
    """
    Enum specifying the quadrant of an overlay, either upper left, upper right, lower left, lower right.
    """

    class_: typing.ClassVar[java.lang.Class]
    UL: typing.Final[QUADRANT]
    UR: typing.Final[QUADRANT]
    LL: typing.Final[QUADRANT]
    LR: typing.Final[QUADRANT]

    @staticmethod
    @typing.overload
    def valueOf(name: typing.Union[java.lang.String, str]) -> QUADRANT:
        ...

    @staticmethod
    @typing.overload
    def valueOf(s: typing.Union[java.lang.String, str], defaultValue: QUADRANT) -> QUADRANT:
        """
        String to enum.
        
        :param java.lang.String or str s: string of either "UL", "UR", "LL", "LR"
        :param QUADRANT defaultValue: value to return if string is invalid
        :return: QUADRANT enum
        :rtype: QUADRANT
        """

    @staticmethod
    def values() -> jpype.JArray[QUADRANT]:
        ...



__all__ = ["MultiIcon", "IconProvider", "Icons", "MultiIconBuilder", "ResourceManager", "QUADRANT"]
