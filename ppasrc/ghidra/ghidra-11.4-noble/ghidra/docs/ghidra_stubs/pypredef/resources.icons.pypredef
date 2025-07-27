from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt # type: ignore
import java.lang # type: ignore
import java.net # type: ignore
import javax.swing # type: ignore


class EmptyIcon(javax.swing.Icon):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        ...

    def getIconHeight(self) -> int:
        ...

    def getIconWidth(self) -> int:
        ...

    def paintIcon(self, c: java.awt.Component, g: java.awt.Graphics, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        ...

    @property
    def iconHeight(self) -> jpype.JInt:
        ...

    @property
    def iconWidth(self) -> jpype.JInt:
        ...


@deprecated("This class has been replaced by DisabledImageIcon since it \n extends ImageIconWrapper which has also been deprecated.")
class DisabledImageIconWrapper(ImageIconWrapper):
    """
    Creates a disabled version of an icon
    
    
    .. deprecated::
    
    This class has been replaced by :obj:`DisabledImageIcon` since it 
    extends :obj:`ImageIconWrapper` which has also been deprecated.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, baseIcon: javax.swing.Icon):
        """
        Construct wrapped disabled ImageIcon based upon specified baseIcon. 
        A 50% brightness will be applied.
        
        :param javax.swing.Icon baseIcon: enabled icon to be rendered as disabled
        """

    @typing.overload
    def __init__(self, baseIcon: javax.swing.Icon, brightnessPercent: typing.Union[jpype.JInt, int]):
        """
        Construct wrapped disabled ImageIcon based upon specified baseIcon
        using the specified brightness level
        
        :param javax.swing.Icon baseIcon: 
        :param jpype.JInt or int brightnessPercent: a brightness level specified using a 
        value in the range of 0 thru 100.
        """


@deprecated("This class has been replaced by a series of classes that extend\n LazyImageIcon: UrlImageIcon, DerivedImageIcon, BytesImageIcon,\n DisabledImageIcon, and ScaledImageIcon. Pick the one that matches \n the constructor that was being used to create an ImageIconWrapper")
class ImageIconWrapper(javax.swing.ImageIcon, FileBasedIcon):
    """
    ``ImageIconWrapper`` provides the ability to instantiate 
    an ImageIcon with delayed loading.  In addition to delayed loading
    it has the added benefit of allowing the use of static initialization
    of ImageIcons without starting the Swing thread which can cause
    problems when running headless.
    
    
    .. deprecated::
    
    This class has been replaced by a series of classes that extend
    :obj:`LazyImageIcon`: :obj:`UrlImageIcon`, :obj:`DerivedImageIcon`, :obj:`BytesImageIcon`,
    :obj:`DisabledImageIcon`, and :obj:`ScaledImageIcon`. Pick the one that matches 
    the constructor that was being used to create an ImageIconWrapper
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, imageBytes: jpype.JArray[jpype.JByte], imageName: typing.Union[java.lang.String, str]):
        """
        Construct wrapped ImageIcon based upon specified image byte array
        (see :meth:`Toolkit.createImage(byte[]) <Toolkit.createImage>`)
        
        :param jpype.JArray[jpype.JByte] imageBytes: image bytes
        :param java.lang.String or str imageName: image reference name
        """

    @typing.overload
    def __init__(self, image: java.awt.Image, imageName: typing.Union[java.lang.String, str]):
        """
        Construct wrapped ImageIcon based upon specified image
        
        :param java.awt.Image image: icon image
        :param java.lang.String or str imageName: image reference name
        """

    @typing.overload
    def __init__(self, icon: javax.swing.Icon):
        """
        Construct wrapped ImageIcon based upon specified icon
        which may require transformation into ImageIcon
        
        :param javax.swing.Icon icon: the icon
        """

    @typing.overload
    def __init__(self, url: java.net.URL):
        """
        Construct wrapped ImageIcon based upon specified resource URL
        
        :param java.net.URL url: icon image resource URL
        """

    def getImageName(self) -> str:
        """
        Get icon reference name
        
        :return: icon name
        :rtype: str
        """

    @property
    def imageName(self) -> java.lang.String:
        ...


class DerivedImageIcon(LazyImageIcon):
    """
    :obj:`LazyImageIcon` that is created from an :obj:`Icon` or an :obj:`Image`
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, icon: javax.swing.Icon):
        """
        Constructor for deriving from an icon
        
        :param javax.swing.Icon icon: the source icon
        """

    @typing.overload
    def __init__(self, name: typing.Union[java.lang.String, str], image: java.awt.Image):
        """
        Constructor for deriving from an image
        
        :param java.lang.String or str name: the name of the image
        :param java.awt.Image image: the source image
        """

    def getSourceIcon(self) -> javax.swing.Icon:
        ...

    @property
    def sourceIcon(self) -> javax.swing.Icon:
        ...


class ReflectedIcon(DerivedImageIcon):
    """
    :obj:`LazyImageIcon` that creates a reflected version of an icon. This creates a version of the
    icon which has had either its x values reflected (left to right) or its y values reflected
    (upside down)
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, baseIcon: javax.swing.Icon, leftToRight: typing.Union[jpype.JBoolean, bool]):
        """
        Construct a icon that is reflected either left to right or upside down.
        
        :param javax.swing.Icon baseIcon: base icon
        :param jpype.JBoolean or bool leftToRight: true flips x values, false flips y values
        """


class UrlImageIcon(LazyImageIcon):
    """
    :obj:`LazyImageIcon` that is created from a URL to an icon file.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: typing.Union[java.lang.String, str], url: java.net.URL):
        """
        Constructor
        
        :param java.lang.String or str path: the path String used to create the URL
        :param java.net.URL url: the :obj:`URL` to an icon resource file
        """

    def getOriginalPath(self) -> str:
        """
        Returns the original path that was used to generate the URL (e.g. images/foo.png)
        
        :return: the original path that was used to generate the URL (e.g. images/foo.png)
        :rtype: str
        """

    def getUrl(self) -> java.net.URL:
        """
        Returns the URL that was used to create this icon
        
        :return: the URL that was used to create this icon
        :rtype: java.net.URL
        """

    @property
    def originalPath(self) -> java.lang.String:
        ...

    @property
    def url(self) -> java.net.URL:
        ...


class TranslateIcon(javax.swing.Icon):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, icon: javax.swing.Icon, translateX: typing.Union[jpype.JInt, int], translateY: typing.Union[jpype.JInt, int]):
        """
        Where the translate values are offset from the icon's upper corner
        
        :param javax.swing.Icon icon: the icon
        :param jpype.JInt or int translateX: the x translation
        :param jpype.JInt or int translateY: the y translation
        """

    def getBaseIcon(self) -> javax.swing.Icon:
        """
        Returns the icon that is being translated
        
        :return: the icon that is being translated
        :rtype: javax.swing.Icon
        """

    def getX(self) -> int:
        """
        Returns the amount the icon is being translated on the x axis;
        
        :return: the amount the icon is being translated on the x axis;
        :rtype: int
        """

    def getY(self) -> int:
        """
        Returns the amount the icon is being translated on the y axis;
        
        :return: the amount the icon is being translated on the y axis;
        :rtype: int
        """

    @property
    def baseIcon(self) -> javax.swing.Icon:
        ...

    @property
    def x(self) -> jpype.JInt:
        ...

    @property
    def y(self) -> jpype.JInt:
        ...


class CenterTranslateIcon(TranslateIcon):
    """
    An icon that will update it's x,y offset to be centered over another, presumably larger
    icon.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, icon: javax.swing.Icon, centerOverSize: typing.Union[jpype.JInt, int]):
        """
        Constructor
        
        :param javax.swing.Icon icon: the icon to center
        :param jpype.JInt or int centerOverSize: the size of the area over which this icon is be centered.  
                
        
                Note:  this constructor assumes the area is a square. If not, add another
                constructor to this class that takes a width and height for the area
        """


class OvalBackgroundColorIcon(javax.swing.Icon):
    """
    Paints an oval of the given size, based upon the Component passed to 
    :meth:`paintIcon(Component, Graphics, int, int) <.paintIcon>`.  If the component is null, then no 
    painting will take place.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        ...

    def getIconHeight(self) -> int:
        ...

    def getIconWidth(self) -> int:
        ...

    def paintIcon(self, c: java.awt.Component, g: java.awt.Graphics, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        ...

    @property
    def iconHeight(self) -> jpype.JInt:
        ...

    @property
    def iconWidth(self) -> jpype.JInt:
        ...


class ColorIcon(javax.swing.Icon):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, color: java.awt.Color, outlineColor: java.awt.Color, size: typing.Union[jpype.JInt, int]):
        ...

    @typing.overload
    def __init__(self, color: java.awt.Color, outlineColor: java.awt.Color, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        ...


class IconWrapper(javax.swing.Icon):
    """
    ``IconWrapper`` provides a simple icon wrapper which 
    delays icon construction until its first use.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...


class OvalColorIcon(javax.swing.Icon):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, color: java.awt.Color, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        ...

    def getIconHeight(self) -> int:
        ...

    def getIconWidth(self) -> int:
        ...

    def paintIcon(self, c: java.awt.Component, g: java.awt.Graphics, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        ...

    @property
    def iconHeight(self) -> jpype.JInt:
        ...

    @property
    def iconWidth(self) -> jpype.JInt:
        ...


class FileBasedIcon(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getFilename(self) -> str:
        """
        Get the name of the image which in most cases will be the associated data file path.
        
        :return: icon name/path
        :rtype: str
        """

    @property
    def filename(self) -> java.lang.String:
        ...


class RotateIcon(javax.swing.Icon):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, icon: javax.swing.Icon, degrees: typing.Union[jpype.JInt, int]):
        ...

    def getRotation(self) -> int:
        """
        Returns the rotation amount.
        
        :return: the rotation amount
        :rtype: int
        """

    def getSourceIcon(self) -> javax.swing.Icon:
        """
        The source icon being rotated.
        
        :return: the source icon being rotate
        :rtype: javax.swing.Icon
        """

    @property
    def rotation(self) -> jpype.JInt:
        ...

    @property
    def sourceIcon(self) -> javax.swing.Icon:
        ...


class ScaledImageIcon(DerivedImageIcon):
    """
    :obj:`LazyImageIcon` that creates a scaled version of an icon
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, baseIcon: javax.swing.Icon, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        """
        Construct wrapped scaled ImageIcon based upon specified
        baseIcon and desired size.  The rendering hints of 
        :obj:`Image.SCALE_AREA_AVERAGING` will be applied.
        
        :param javax.swing.Icon baseIcon: base icon
        :param jpype.JInt or int width: new icon width
        :param jpype.JInt or int height: new icon height
        """

    @typing.overload
    def __init__(self, baseIcon: javax.swing.Icon, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int], hints: typing.Union[jpype.JInt, int]):
        """
        Construct wrapped scaled ImageIcon based upon specified
        baseIcon and desired size
        
        :param javax.swing.Icon baseIcon: base icon
        :param jpype.JInt or int width: new icon width
        :param jpype.JInt or int height: new icon height
        :param jpype.JInt or int hints: :obj:`RenderingHints` used by :obj:`Graphics2D`
        """


class LazyImageIcon(javax.swing.ImageIcon, FileBasedIcon):
    """
    ``LazyImageIcon`` provides the ability to instantiate 
    an ImageIcon with delayed loading.  In addition to delayed loading
    it has the added benefit of allowing the use of static initialization
    of ImageIcons without starting the Swing thread which can cause
    problems when running headless.
    """

    class_: typing.ClassVar[java.lang.Class]


class ColorIcon3D(javax.swing.Icon):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, color: java.awt.Color):
        ...

    @typing.overload
    def __init__(self, color: java.awt.Color, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        ...

    def getColor(self) -> java.awt.Color:
        ...

    def getIconHeight(self) -> int:
        ...

    def getIconWidth(self) -> int:
        ...

    def paintIcon(self, c: java.awt.Component, g: java.awt.Graphics, x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        ...

    @property
    def iconHeight(self) -> jpype.JInt:
        ...

    @property
    def iconWidth(self) -> jpype.JInt:
        ...

    @property
    def color(self) -> java.awt.Color:
        ...


class DisabledImageIcon(DerivedImageIcon):
    """
    :obj:`LazyImageIcon` that creates a disabled version of an icon
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, baseIcon: javax.swing.Icon):
        """
        Construct wrapped disabled ImageIcon based upon specified baseIcon. 
        A 50% brightness will be applied.
        
        :param javax.swing.Icon baseIcon: enabled icon to be rendered as disabled
        """

    @typing.overload
    def __init__(self, baseIcon: javax.swing.Icon, brightnessPercent: typing.Union[jpype.JInt, int]):
        """
        Construct wrapped disabled ImageIcon based upon specified baseIcon
        using the specified brightness level
        
        :param javax.swing.Icon baseIcon: the icon to create a disabled version of
        :param jpype.JInt or int brightnessPercent: a brightness level specified using a 
        value in the range of 0 thru 100.
        """


class BytesImageIcon(LazyImageIcon):
    """
    :obj:`LazyImageIcon` that is created from a byte array
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, name: typing.Union[java.lang.String, str], imageBytes: jpype.JArray[jpype.JByte]):
        ...


class UnresolvedIcon(DerivedImageIcon):
    """
    Icon class for when we can't find an icon for a path
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, path: typing.Union[java.lang.String, str], icon: javax.swing.ImageIcon):
        ...


@deprecated("This class has been replaced by ScaledImageIcon since it \n extends ImageIconWrapper which has also been deprecated.")
class ScaledImageIconWrapper(ImageIconWrapper):
    """
    Creates a scaled version of an icon
    
    
    .. deprecated::
    
    This class has been replaced by :obj:`ScaledImageIcon` since it 
    extends :obj:`ImageIconWrapper` which has also been deprecated.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, baseIcon: javax.swing.Icon, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]):
        """
        Construct wrapped scaled ImageIcon based upon specified
        baseIcon and desired size.  The rendering hints of 
        :obj:`Image.SCALE_AREA_AVERAGING` will be applied.
        
        :param javax.swing.Icon baseIcon: base icon
        :param jpype.JInt or int width: new icon width
        :param jpype.JInt or int height: new icon height
        """

    @typing.overload
    def __init__(self, baseIcon: javax.swing.Icon, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int], hints: typing.Union[jpype.JInt, int]):
        """
        Construct wrapped scaled ImageIcon based upon specified
        baseIcon and desired size
        
        :param javax.swing.Icon baseIcon: base icon
        :param jpype.JInt or int width: new icon width
        :param jpype.JInt or int height: new icon height
        :param jpype.JInt or int hints: :obj:`RenderingHints` used by :obj:`Graphics2D`
        """



__all__ = ["EmptyIcon", "DisabledImageIconWrapper", "ImageIconWrapper", "DerivedImageIcon", "ReflectedIcon", "UrlImageIcon", "TranslateIcon", "CenterTranslateIcon", "OvalBackgroundColorIcon", "ColorIcon", "IconWrapper", "OvalColorIcon", "FileBasedIcon", "RotateIcon", "ScaledImageIcon", "LazyImageIcon", "ColorIcon3D", "DisabledImageIcon", "BytesImageIcon", "UnresolvedIcon", "ScaledImageIconWrapper"]
