from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt # type: ignore
import java.awt.image # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class Callout(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def createCallout(self, calloutInfo: CalloutComponentInfo) -> java.awt.Image:
        ...

    def createCalloutOnImage(self, image: java.awt.Image, calloutInfo: CalloutComponentInfo) -> java.awt.Image:
        ...


class ToolIconURL(java.lang.Comparable[ToolIconURL]):
    """
    Container class for an icon and its location. If the location is
    not valid, then a default "bomb" icon is used as the icon.
    """

    @typing.type_check_only
    class ToolIconImageConsumer(java.awt.image.ImageConsumer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]
    LARGE_ICON_SIZE: typing.Final = 24
    """
    The large icon size (height and width)
    """

    MEDIUM_ICON_SIZE: typing.Final = 22
    """
    The medium icon size (height and width)
    """

    SMALL_ICON_SIZE: typing.Final = 16
    """
    The small icon size (height and width)
    """


    @typing.overload
    def __init__(self, location: typing.Union[java.lang.String, str]):
        """
        Constructor
        
        :param java.lang.String or str location: filename for the icon (relative or absolute)
        """

    @typing.overload
    def __init__(self, location: typing.Union[java.lang.String, str], bytes: jpype.JArray[jpype.JByte]):
        ...

    def getIcon(self) -> javax.swing.ImageIcon:
        """
        Return the icon as :obj:`.LARGE_ICON_SIZE` pixel size.
        
        :return: the icon
        :rtype: javax.swing.ImageIcon
        """

    def getIconBytes(self) -> jpype.JArray[jpype.JByte]:
        """
        Returns the icon bytes
        
        :return: the bytes
        :rtype: jpype.JArray[jpype.JByte]
        """

    def getLocation(self) -> str:
        """
        Return the location of this icon
        
        :return: the location of this icon
        :rtype: str
        """

    def getSmallIcon(self) -> javax.swing.ImageIcon:
        """
        Return the icon as :obj:`.SMALL_ICON_SIZE` pixel size.
        
        :return: the icon
        :rtype: javax.swing.ImageIcon
        """

    def isAnimated(self) -> bool:
        """
        Returns true if the Icon is an animated image.
         
        
        **WARNING: ** This call may block the Swing thread for up to :obj:`.MAX_IMAGE_LOAD_TIME`
        milliseconds the first time it is called!
        
        :return: true if animated
        :rtype: bool
        """

    @property
    def icon(self) -> javax.swing.ImageIcon:
        ...

    @property
    def animated(self) -> jpype.JBoolean:
        ...

    @property
    def smallIcon(self) -> javax.swing.ImageIcon:
        ...

    @property
    def location(self) -> java.lang.String:
        ...

    @property
    def iconBytes(self) -> jpype.JArray[jpype.JByte]:
        ...


class DropShadow(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def createDropShadow(self, image: java.awt.image.BufferedImage, shadowSize: typing.Union[jpype.JInt, int]) -> java.awt.Image:
        ...

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...


class CalloutComponentInfo(java.lang.Object):
    """
    An object that describes a component to be 'called-out'.  A callout is a way to 
    emphasize a widget (usually this is only needed for small GUI elements, like an action or
    icon).
     
     
    The given component info is used to render a magnified image of the given component 
    onto another image.  For this to work, the rendering engine will need to know how to 
    translate the component's location to that of the image space onto which the callout 
    will be drawn.  This is the purpose of requiring the 'destination component'.  That 
    component provides the bounds that will be used to move the component's relative position
    (which is relative to the components parent).
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, destinationComponent: java.awt.Component, component: java.awt.Component):
        ...

    @typing.overload
    def __init__(self, destinationComponent: java.awt.Component, component: java.awt.Component, locationOnScreen: java.awt.Point, relativeLocation: java.awt.Point, size: java.awt.Dimension):
        ...

    def convertPointToParent(self, location: java.awt.Point) -> java.awt.Point:
        ...

    def setMagnification(self, magnification: typing.Union[jpype.JDouble, float]):
        ...



__all__ = ["Callout", "ToolIconURL", "DropShadow", "CalloutComponentInfo"]
