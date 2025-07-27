from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import docking.widgets.label
import java.awt # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class ImagePanel(javax.swing.JPanel):
    """
    Creates a panel that displays an :obj:`Image`. Users may pan the image as desired and zoom the
    image according to specific zoom levels.
    """

    @typing.type_check_only
    class PanAndZoomComponent(docking.widgets.label.GIconLabel):

        class_: typing.ClassVar[java.lang.Class]
        TRANSLATION_RESET_PROPERTY: typing.Final = "translation-reset"

        def __init__(self, image: javax.swing.Icon, horizontalAlignment: typing.Union[jpype.JInt, int]):
            ...

        def getTranslation(self) -> java.awt.Point:
            ...

        def isTranslated(self) -> bool:
            ...

        def resetTranslation(self):
            ...

        def translate(self, dX: typing.Union[jpype.JInt, int], dY: typing.Union[jpype.JInt, int]):
            ...

        @property
        def translation(self) -> java.awt.Point:
            ...

        @property
        def translated(self) -> jpype.JBoolean:
            ...


    class_: typing.ClassVar[java.lang.Class]
    ZOOM_LEVELS: typing.Final[jpype.JArray[jpype.JFloat]]
    DEFAULT_ZOOM_FACTOR: typing.Final = 1.0
    IMAGE_PROPERTY: typing.Final = "image"
    """
    Property name that indicates the image displayed by this panel has changed
    """

    ZOOM_PROPERTY: typing.Final = "zoom"
    """
    Property name that indicates the zoom level of the image has changed
    """

    DEFAULT_ZOOM_PROPERTY: typing.Final = "default_zoom"
    """
    Property name that indicates the default zoom level of the image has changed
    """

    TRANSLATION_PROPERTY: typing.Final = "translation"
    """
    Property name that indicates the image has been translated
    """


    @typing.overload
    def __init__(self):
        """
        Create an empty NavigableImagePanel
        """

    @typing.overload
    def __init__(self, image: java.awt.Image):
        """
        Create an NavigableImagePanel with the specified image
        
        :param java.awt.Image image: the image
        """

    def canZoomIn(self) -> bool:
        """
        Determine if the image can zoom in further based on current magnification levels
        
        :return: True if magnification steps are available, false otherwise
        :rtype: bool
        """

    def canZoomOut(self) -> bool:
        """
        Determine if the image can zoom out further based on current magnification levels
        
        :return: True if (de-)magnification steps are available, false otherwise
        :rtype: bool
        """

    def getDefaultZoomFactor(self) -> float:
        """
        Get the default zoom factory
        
        :return: the zoom factor
        :rtype: float
        """

    def getImage(self) -> java.awt.Image:
        """
        Get the currently-displayed image
        
        :return: the current image
        :rtype: java.awt.Image
        """

    def getImageBackgroundColor(self) -> java.awt.Color:
        """
        Get the current background color of this panel
        
        :return: the background color
        :rtype: java.awt.Color
        """

    @deprecated("unused")
    def getText(self) -> str:
        """
        Unused
        
        :return: unused
        :rtype: str
        
        .. deprecated::
        
        unused
        """

    def getTranslation(self) -> java.awt.Point:
        """
        Get the X-Y distance the image has moved
        
        :return: the X-Y distances the image has moved
        :rtype: java.awt.Point
        """

    def getZoomFactor(self) -> float:
        """
        Get the current zoom factor the image is being drawn to
        
        :return: the image magnification factor
        :rtype: float
        """

    def isImageTranslationEnabled(self) -> bool:
        ...

    def isImageZoomEnabled(self) -> bool:
        ...

    def isTranslated(self) -> bool:
        """
        Determine if the image has been moved from its original location
        
        :return: True if the image has moved, false otherwise
        :rtype: bool
        """

    def resetImageTranslation(self):
        """
        Move the image back to the center. Zoom factor is unmodified.
        """

    def resetZoom(self):
        ...

    def setDefaultZoomFactor(self, zoom: typing.Union[jpype.JFloat, float]):
        """
        Set the default zoom level, adhering to the same set of constrains as :meth:`setZoomFactor(float) <.setZoomFactor>`
        
        :param jpype.JFloat or float zoom: the zoom
        
        .. seealso::
        
            | :obj:`.setZoomFactor(float)`
        
            | :obj:`.resetZoom()`
        """

    def setImage(self, image: java.awt.Image):
        """
        Set the image this panel should display
        
        :param java.awt.Image image: the new image to display
        """

    def setImageBackgroundColor(self, color: java.awt.Color):
        """
        Set the background color of the panel. If the specified color is null, the
        default color for panel backgrounds is used.
        
        :param java.awt.Color color: the new background color
        """

    def setImageTranslationEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    def setImageZoomEnabled(self, enabled: typing.Union[jpype.JBoolean, bool]):
        ...

    @deprecated("unused")
    def setText(self, text: typing.Union[java.lang.String, str]):
        """
        Unused
        
        :param java.lang.String or str text: unused
        
        .. deprecated::
        
        unused
        """

    def setZoomFactor(self, zoom: typing.Union[jpype.JFloat, float]):
        """
        Set the magnification factor of the image. The zoom parameter is aligned to the
        nearest pre-configured magnification factor, rounding down for zoom factors less than
        1.0, and up for factors greater than 1.0. Zoom factors outside the pre-configured range
        are limited to the nearest range extent.
        
        :param jpype.JFloat or float zoom: the zoom
        """

    @typing.overload
    def zoomIn(self):
        """
        Enlarge the image about the image center
        """

    @typing.overload
    def zoomIn(self, center: java.awt.Point):
        """
        Enlarge the image about the given point
        
        :param java.awt.Point center: location to enlarge the image around
        """

    @typing.overload
    def zoomOut(self):
        """
        Shrink the image about the image center
        """

    @typing.overload
    def zoomOut(self, center: java.awt.Point):
        """
        Shrink the image about the given point
        
        :param java.awt.Point center: location to shrink the image around
        """

    @property
    def image(self) -> java.awt.Image:
        ...

    @image.setter
    def image(self, value: java.awt.Image):
        ...

    @property
    def defaultZoomFactor(self) -> jpype.JFloat:
        ...

    @defaultZoomFactor.setter
    def defaultZoomFactor(self, value: jpype.JFloat):
        ...

    @property
    def translation(self) -> java.awt.Point:
        ...

    @property
    def imageBackgroundColor(self) -> java.awt.Color:
        ...

    @imageBackgroundColor.setter
    def imageBackgroundColor(self, value: java.awt.Color):
        ...

    @property
    def imageZoomEnabled(self) -> jpype.JBoolean:
        ...

    @imageZoomEnabled.setter
    def imageZoomEnabled(self, value: jpype.JBoolean):
        ...

    @property
    def translated(self) -> jpype.JBoolean:
        ...

    @property
    def imageTranslationEnabled(self) -> jpype.JBoolean:
        ...

    @imageTranslationEnabled.setter
    def imageTranslationEnabled(self, value: jpype.JBoolean):
        ...

    @property
    def text(self) -> java.lang.String:
        ...

    @text.setter
    def text(self, value: java.lang.String):
        ...

    @property
    def zoomFactor(self) -> jpype.JFloat:
        ...

    @zoomFactor.setter
    def zoomFactor(self, value: jpype.JFloat):
        ...



__all__ = ["ImagePanel"]
