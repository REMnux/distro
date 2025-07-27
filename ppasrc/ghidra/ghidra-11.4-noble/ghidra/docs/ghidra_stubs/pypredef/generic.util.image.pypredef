from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt # type: ignore
import java.awt.image # type: ignore
import java.io # type: ignore
import java.lang # type: ignore
import javax.swing # type: ignore


class ImageUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def changeColor(image: java.awt.Image, oldColor: java.awt.Color, newColor: java.awt.Color) -> java.awt.Image:
        """
        Creates a new image that is the same as the given image but has the given colored 
        pixels replaced with the given new color
        
        :param java.awt.Image image: the image to change
        :param java.awt.Color oldColor: the color to replace
        :param java.awt.Color newColor: the color to use
        :return: the new image
        :rtype: java.awt.Image
        """

    @staticmethod
    def createDisabledImage(image: java.awt.Image, brightnessPercent: typing.Union[jpype.JInt, int]) -> java.awt.Image:
        """
        Creates a disabled version of the given image.  The disabled version will be grayed
        and have the varying gray levels blended together.
        
        :param java.awt.Image image: the image to disable
        :param jpype.JInt or int brightnessPercent: the amount of brightness to apply; 0-100
        :return: the new image
        :rtype: java.awt.Image
        """

    @staticmethod
    def createEmptyImage(width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int]) -> java.awt.image.BufferedImage:
        """
        Creates a new image of the given size.  This image is suitable for drawing operations.
        
        :param jpype.JInt or int width: the width of the new image
        :param jpype.JInt or int height: the height of the new image
        :return: a new image of the given size.  This image is suitable for drawing operations.
        :rtype: java.awt.image.BufferedImage
        """

    @staticmethod
    def createImage(c: java.awt.Component) -> java.awt.Image:
        """
        Creates an image of the given component
        
        :param java.awt.Component c: the component
        :return: the image
        :rtype: java.awt.Image
        """

    @staticmethod
    def createScaledImage(image: java.awt.Image, width: typing.Union[jpype.JInt, int], height: typing.Union[jpype.JInt, int], hints: typing.Union[jpype.JInt, int]) -> java.awt.Image:
        """
        Creates a scaled image based upon the given image.
        NOTE: Avoid invocation by a static initializer.
        
        :param java.awt.Image image: the image to scale
        :param jpype.JInt or int width: the new width
        :param jpype.JInt or int height: the new height
        :param jpype.JInt or int hints: :obj:`RenderingHints` used by :obj:`Graphics2D`
        :return: a scaled version of the given image
        :rtype: java.awt.Image
        """

    @staticmethod
    def crop(i: java.awt.Image, bounds: java.awt.Rectangle) -> java.awt.Image:
        """
        Crops the given image, keeping the given bounds
        
        :param java.awt.Image i: the image to crop
        :param java.awt.Rectangle bounds: the new bounds
        :return: a new image based on the given image, cropped to the given bounds.
        :rtype: java.awt.Image
        """

    @staticmethod
    def getBufferedImage(image: java.awt.Image) -> java.awt.image.BufferedImage:
        """
        Copies this image into a buffered image.  If this image is already a buffered image, then
        it will be returned.
        
        :param java.awt.Image image: the image
        :return: the buffered image
        :rtype: java.awt.image.BufferedImage
        """

    @staticmethod
    @typing.overload
    def makeTransparent(icon: javax.swing.Icon) -> javax.swing.Icon:
        """
        Make the specified icon semi-transparent using the default transparency alpha
        
        :param javax.swing.Icon icon: The icon to make semi-transparent
        :return: a new icon, based on the original, made semi-transparent
        :rtype: javax.swing.Icon
        
        .. seealso::
        
            | :obj:`ImageUtils.DEFAULT_TRANSPARENCY_ALPHA`
        """

    @staticmethod
    @typing.overload
    def makeTransparent(icon: javax.swing.Icon, alpha: typing.Union[jpype.JFloat, float]) -> javax.swing.Icon:
        """
        Make the specified icon semi-transparent using the specified transparency alpha
        
        :param javax.swing.Icon icon: the icon to make semi-transparent
        :param jpype.JFloat or float alpha: the alpha value to use in making the icon transparent
        :return: a new icon, based on the original, made semi-transparent
        :rtype: javax.swing.Icon
        """

    @staticmethod
    def padImage(i: java.awt.Image, c: java.awt.Color, top: typing.Union[jpype.JInt, int], left: typing.Union[jpype.JInt, int], right: typing.Union[jpype.JInt, int], bottom: typing.Union[jpype.JInt, int]) -> java.awt.Image:
        """
        Pads the given image with space in the amount given.
        
        :param java.awt.Image i: the image to pad
        :param java.awt.Color c: the color to use for the padding background
        :param jpype.JInt or int top: the top padding
        :param jpype.JInt or int left: the left padding
        :param jpype.JInt or int right: the right padding
        :param jpype.JInt or int bottom: the bottom padding
        :return: a new image with the given image centered inside of padding
        :rtype: java.awt.Image
        """

    @staticmethod
    def placeImagesSideBySide(left: java.awt.Image, right: java.awt.Image) -> java.awt.Image:
        """
        Places the two given images side-by-side into a new image.
        
        :param java.awt.Image left: the left image
        :param java.awt.Image right: the right image
        :return: a new image with the two given images side-by-side into a new image.
        :rtype: java.awt.Image
        """

    @staticmethod
    def readFile(imageFile: jpype.protocol.SupportsPath) -> java.awt.image.BufferedImage:
        """
        Load an image from a file
        
        :param jpype.protocol.SupportsPath imageFile: image source-data file
        :return: the image, decoded from bytes in specified file
        :rtype: java.awt.image.BufferedImage
        :raises IOException: if there is an exception
        """

    @staticmethod
    def toRenderedImage(image: java.awt.Image) -> java.awt.image.RenderedImage:
        """
        Turns the given image into a :obj:`RenderedImage`
        
        :param java.awt.Image image: the image
        :return: the rendered image
        :rtype: java.awt.image.RenderedImage
        """

    @staticmethod
    def waitForImage(imageName: typing.Union[java.lang.String, str], image: java.awt.Image) -> bool:
        """
        Waits a reasonable amount of time for the given image to load
        
        :param java.lang.String or str imageName: the name of the image
        :param java.awt.Image image: the image for which to wait
        :return: true if the wait was successful
        :rtype: bool
        """

    @staticmethod
    @typing.overload
    def writeFile(i: java.awt.Image, imageFile: jpype.protocol.SupportsPath):
        """
        Write the specified image to file in PNG format
        
        :param java.awt.Image i: the image to save
        :param jpype.protocol.SupportsPath imageFile: the file to save the image to
        :raises IOException: if there is an exception
        """

    @staticmethod
    @typing.overload
    def writeFile(i: java.awt.image.RenderedImage, imageFile: jpype.protocol.SupportsPath):
        """
        Write the specified image to file in PNG format
        
        :param java.awt.image.RenderedImage i: the image to save
        :param jpype.protocol.SupportsPath imageFile: the file to save the image to
        :raises IOException: if there is an exception
        """

    @staticmethod
    def writeIconToPNG(icon: javax.swing.Icon, filename: typing.Union[java.lang.String, str]):
        """
        Writes the given icon out to the file denoted by ``filename`` ** in the PNG format**.
        
        :param javax.swing.Icon icon: the icon to write
        :param java.lang.String or str filename: the filename denoting the write destination
        :raises IOException: see :meth:`ImageIO.write(RenderedImage, String, File) <ImageIO.write>`
        """



__all__ = ["ImageUtils"]
