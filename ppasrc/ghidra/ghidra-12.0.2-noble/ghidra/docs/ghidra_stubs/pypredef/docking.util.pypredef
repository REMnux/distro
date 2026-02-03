from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import ghidra.util.bean
import java.awt # type: ignore
import java.lang # type: ignore
import java.time # type: ignore
import java.util # type: ignore
import javax.swing # type: ignore
import org.jdesktop.animation.timing # type: ignore
import utility.function


class AnimatedIcon(javax.swing.Icon):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, icons: java.util.List[javax.swing.Icon], frameDelay: typing.Union[jpype.JInt, int], framesToSkip: typing.Union[jpype.JInt, int]):
        ...


class AnimationRunner(java.lang.Object):
    """
    A class that does basic setup work for creating an :obj:`Animator`.  The animator will run a 
    timer in a background thread, calling the client periodically until the animation progress is
    finished.  The actual visual animation is handled by the client's :obj:`AnimationPainter`.
    This class is provided for convenience.  Clients can create their own :obj:`Animator` as needed. 
     
    
    A :meth:`painter <.setPainter>` must be supplied before calling :meth:`start() <.start>`.
    A simple example usage: 
     
    GTable table = ...;
    AnimationPainter painter = new AnimationPainter() {
        public void paint(GGlassPane glassPane, Graphics graphics, double value) {
              
            // repaint some contents to the glass pane's graphics using the current value as to 
            // know where we are in the progress of animating
        }
    };
    AnimationRunner animation = new AnimationRunner(table);
    animation.setPainter(painter);
    animation.start();
      
    ...
      
    // code to stop animation, such as when a request for a new animation is received
    if (animation != null) {
        animation.stop();
    }
      
     
     
    
    Clients who wish to perform more configuration can call :meth:`createAnimator() <.createAnimator>` to perform the
    basic setup, calling :meth:`start() <.start>` when finished with any follow-up configuration.
     
    
    See :obj:`Animator` for details on the animation process.
    """

    @typing.type_check_only
    class UserDefinedPainter(ghidra.util.bean.GGlassPanePainter):
        """
        A painter that will call the user-supplied painter with the current value.
        """

        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, component: javax.swing.JComponent):
        ...

    def createAnimator(self) -> org.jdesktop.animation.timing.Animator:
        """
        Creates the animator used to perform animation.  Clients will call :meth:`Animator.start() <Animator.start>`
        to begin animation.  Many attributes of the animator can be configured before starting.
        
        :return: the animator
        :rtype: org.jdesktop.animation.timing.Animator
        :raises IllegalStateException: if require values have not been set on this class, such as 
        :meth:`setValues(Double...) <.setValues>` or :meth:`setPainter(AnimationPainter) <.setPainter>`.
        """

    def setCurrentValue(self, value: typing.Union[java.lang.Double, float]):
        """
        This is a method used by the animator.  Clients should not call this method.
        
        :param java.lang.Double or float value: the current value created by the animator
        """

    def setDoneCallback(self, c: utility.function.Callback):
        """
        Sets a callback to be called when the animation is finished.
        
        :param utility.function.Callback c: the callback
        """

    def setDuration(self, duration: java.time.Duration):
        """
        Sets the animation duration.  The default is 1 second.
        
        :param java.time.Duration duration: the duration
        """

    def setPainter(self, animationPainter: AnimationPainter):
        """
        Sets the painter required for the animator to work.
        
        :param AnimationPainter animationPainter: the painter.
        """

    def setRemovePainterWhenFinished(self, b: typing.Union[jpype.JBoolean, bool]):
        """
        Signals to remove the painter from the glass pane when the animation is finished.  Clients
        can specify ``false`` which will allow the painting to continue after the animation has
        finished.
        
        :param jpype.JBoolean or bool b: true to remove the painter.  The default value is true.
        """

    def setValues(self, *values: typing.Union[java.lang.Double, float]):
        """
        Sets the values passed to the animator created by this class.  These values will be split 
        into a range of values, broken up by the duration of the animator. The default values are 0 
        and 1.   
         
        
        See :meth:`PropertySetter.createAnimator(int, Object, String, Object...) <PropertySetter.createAnimator>`.
        
        :param jpype.JArray[java.lang.Double] values: the values
        """

    def start(self):
        """
        Starts the animation process, creating the animator as needed.  This method can be called
        repeatedly without calling stop first.
        """

    def stop(self):
        """
        Stops all animation and removes the painter from the glass pane. :meth:`start() <.start>` can be 
        called again after calling this method.
        """


class TextShaper(java.lang.Object):
    """
    A class that will layout text into lines based on the given display size.   This class requires
    the graphics context in order to correctly size the text.
    """

    @typing.type_check_only
    class TextShaperLine(java.lang.Object):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class TextLayoutLine(TextShaper.TextShaperLine):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BlankLine(TextShaper.TextShaperLine):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, text: typing.Union[java.lang.String, str], displaySize: java.awt.Dimension, g2d: java.awt.Graphics2D):
        """
        Creates a text shaper with the given text, display size and graphics context.
        
        :param java.lang.String or str text: the text
        :param java.awt.Dimension displaySize: the size
        :param java.awt.Graphics2D g2d: the graphics
        """

    def drawText(self, g: java.awt.Graphics2D):
        """
        Renders the wrapped text into the graphics used to create this class.
        
        :param java.awt.Graphics2D g: the graphics into which the text should be painted.
        """

    def getLines(self) -> java.util.List[TextShaper.TextShaperLine]:
        ...

    def getTextSize(self) -> java.awt.Dimension:
        """
        Returns the bounds of the wrapped text of this class
        
        :return: the bounds of the wrapped text of this class
        :rtype: java.awt.Dimension
        """

    def isClipped(self) -> bool:
        """
        Returns true if the text is too large to fit in the original display size
        
        :return: true if the text is too large to fit in the original display size
        :rtype: bool
        """

    @property
    def textSize(self) -> java.awt.Dimension:
        ...

    @property
    def lines(self) -> java.util.List[TextShaper.TextShaperLine]:
        ...

    @property
    def clipped(self) -> jpype.JBoolean:
        ...


class SwingAnimationCallback(java.lang.Object):
    """
    A simple interface that allows implementing clients to get called back from the animation
    framework.  The callbacks can be used to perform swing work.
    """

    class_: typing.ClassVar[java.lang.Class]

    def done(self):
        """
        Called when the entire animation cycle is done.  This allows clients to perform any
        finalization work.
        """

    def getDuration(self) -> int:
        """
        Returns the duration of this callback.  The default is ``1000 ms``.  Subclasses
        can override this as needed.
        
        :return: the duration
        :rtype: int
        """

    def progress(self, percentComplete: typing.Union[jpype.JDouble, float]):
        """
        Called over the course of an animation cycle.
        
        :param jpype.JDouble or float percentComplete: a value (from 0 to 1.0) that indicates the percentage of the 
                                animation cycle that has completed.
        """

    @property
    def duration(self) -> jpype.JInt:
        ...


class GraphicsUtils(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    @typing.overload
    def drawString(c: javax.swing.JComponent, g: java.awt.Graphics, text: typing.Union[java.lang.String, str], x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    @typing.overload
    def drawString(c: javax.swing.JComponent, g2d: java.awt.Graphics2D, text: typing.Union[java.lang.String, str], x: typing.Union[jpype.JInt, int], y: typing.Union[jpype.JInt, int]):
        ...

    @staticmethod
    def getGraphics2D(g: java.awt.Graphics) -> java.awt.Graphics2D:
        ...

    @staticmethod
    def stringWidth(c: javax.swing.JComponent, fm: java.awt.FontMetrics, string: typing.Union[java.lang.String, str]) -> int:
        ...


class AnimationUtils(java.lang.Object):

    class SwingAnimationCallbackDriver(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def setPercentComplete(self, percent: typing.Union[jpype.JDouble, float]):
            ...


    class FocusDriver(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def setPercentComplete(self, percent: typing.Union[jpype.JDouble, float]):
            ...


    @typing.type_check_only
    class FocusPainter(ghidra.util.bean.GGlassPanePainter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class PointToComponentDriver(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def setPercentComplete(self, percent: typing.Union[jpype.JDouble, float]):
            ...


    @typing.type_check_only
    class PointToComponentPainter(ghidra.util.bean.GGlassPanePainter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class BasicAnimationDriver(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def setPercentComplete(self, percent: typing.Union[jpype.JDouble, float]):
            ...


    class BasicAnimationPainter(ghidra.util.bean.GGlassPanePainter):

        class_: typing.ClassVar[java.lang.Class]

        def __init__(self):
            ...


    @typing.type_check_only
    class UserDefinedPainter(AnimationUtils.BasicAnimationPainter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class ComponentToComponentDriver(AnimationUtils.BasicAnimationDriver):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ComponentToComponentPainter(AnimationUtils.BasicAnimationPainter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class RotateDriver(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def setPercentComplete(self, percentComplete: typing.Union[jpype.JDouble, float]):
            ...


    @typing.type_check_only
    class RotatePainter(ghidra.util.bean.GGlassPanePainter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class ShakeDriver(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def setEmphasis(self, emphasis: typing.Union[jpype.JDouble, float]):
            ...


    class PulseDriver(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def setEmphasis(self, emphasis: typing.Union[jpype.JDouble, float]):
            ...


    @typing.type_check_only
    class PulsePainter(ghidra.util.bean.GGlassPanePainter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class ShakePainter(ghidra.util.bean.GGlassPanePainter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class PulseAndShakePainter(AnimationUtils.PulsePainter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class DragonImageDriver(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]

        def setPercentComplete(self, percentComplete: typing.Union[jpype.JDouble, float]):
            ...


    @typing.type_check_only
    class DragonImagePainter(ghidra.util.bean.GGlassPanePainter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @staticmethod
    def createPaintingAnimator(component: java.awt.Component, painter: AnimationPainter) -> org.jdesktop.animation.timing.Animator:
        ...

    @staticmethod
    def executeSwingAnimationCallback(callback: SwingAnimationCallback) -> org.jdesktop.animation.timing.Animator:
        ...

    @staticmethod
    def focusComponent(component: java.awt.Component) -> org.jdesktop.animation.timing.Animator:
        """
        Focuses the current component by graying out all other components but the given one and
        bringing that component to the middle of the screen.
        
        :param java.awt.Component component: The component to focus
        :return: the new animator
        :rtype: org.jdesktop.animation.timing.Animator
        """

    @staticmethod
    def getGlassPane(c: java.awt.Component) -> ghidra.util.bean.GGlassPane:
        """
        Returns the :obj:`GGlassPane` for the given component
        
        :param java.awt.Component c: the component
        :return: the glass pane
        :rtype: ghidra.util.bean.GGlassPane
        """

    @staticmethod
    def isAnimationEnabled() -> bool:
        """
        Returns true if animation is enabled; false if animation has been disable, such as by
        a user option
        
        :return: true if enabled
        :rtype: bool
        """

    @staticmethod
    def pulseAndShakeComponent(component: java.awt.Component) -> org.jdesktop.animation.timing.Animator:
        ...

    @staticmethod
    @typing.overload
    def pulseComponent(component: java.awt.Component) -> org.jdesktop.animation.timing.Animator:
        ...

    @staticmethod
    @typing.overload
    def pulseComponent(component: java.awt.Component, pulseCount: typing.Union[jpype.JInt, int]) -> org.jdesktop.animation.timing.Animator:
        ...

    @staticmethod
    def rotateComponent(component: java.awt.Component) -> org.jdesktop.animation.timing.Animator:
        ...

    @staticmethod
    def setAnimationEnabled(enabled: typing.Union[jpype.JBoolean, bool]):
        """
        Enables animation **for all tools in the Ghidra universe**.
        
        :param jpype.JBoolean or bool enabled: true if animations should be used
        """

    @staticmethod
    def shakeComponent(component: java.awt.Component) -> org.jdesktop.animation.timing.Animator:
        ...

    @staticmethod
    def showTheDragonOverComponent(component: java.awt.Component) -> org.jdesktop.animation.timing.Animator:
        ...

    @staticmethod
    def transitionFromComponentToComponent(fromComponent: java.awt.Component, toComponent: java.awt.Component) -> org.jdesktop.animation.timing.Animator:
        ...

    @staticmethod
    def transitionUserFocusToComponent(activeComponent: java.awt.Component, toFocusComponent: java.awt.Component) -> org.jdesktop.animation.timing.Animator:
        ...


class GGlassPaneMessage(java.lang.Object):
    """
    A class that allows clients to paint a message over top of a given component.
     
    
    This class will honor newline characters and will word wrap as needed.  If the message being 
    displayed will not fit within the bounds of the given component, then the text will be clipped.
    """

    @typing.type_check_only
    class AbstractTextPainer(AnimationPainter):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CenterTextPainter(GGlassPaneMessage.AbstractTextPainer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class BottomTextPainter(GGlassPaneMessage.AbstractTextPainer):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, component: javax.swing.JComponent):
        ...

    def hide(self):
        """
        Hides any message being displayed.  This can be called even if the message has been hidden.
        """

    def setHideDelay(self, duration: java.time.Duration):
        """
        Sets the amount of time the message will remain on screen after the animation has completed.
        To hide the message sooner, call :meth:`hide() <.hide>`.
        
        :param java.time.Duration duration: the duration
        """

    def showBottomMessage(self, newMessage: typing.Union[java.lang.String, str]):
        """
        Shows a message at the bottom of the component used by this class.
        
        :param java.lang.String or str newMessage: the message
        """

    def showCenteredMessage(self, newMessage: typing.Union[java.lang.String, str]):
        """
        Shows the given message centered over the component used by this class.
        
        :param java.lang.String or str newMessage: the message
        """

    def showMessage(self, newMessage: typing.Union[java.lang.String, str], painter: AnimationPainter):
        ...


class AnimationPainter(java.lang.Object):
    """
    An interface used with :obj:`AnimationUtils` to allow clients to use the timing 
    framework while performing their own painting.
    """

    class_: typing.ClassVar[java.lang.Class]

    def paint(self, glassPane: ghidra.util.bean.GGlassPane, graphics: java.awt.Graphics, value: typing.Union[jpype.JDouble, float]):
        """
        Called back each time the animation system generates a timing event.
        
        :param ghidra.util.bean.GGlassPane glassPane: the glass pane upon which painting takes place
        :param java.awt.Graphics graphics: the graphics used to paint
        :param jpype.JDouble or float value: a value from the range supplied to the animator when it was created
        """



__all__ = ["AnimatedIcon", "AnimationRunner", "TextShaper", "SwingAnimationCallback", "GraphicsUtils", "AnimationUtils", "GGlassPaneMessage", "AnimationPainter"]
