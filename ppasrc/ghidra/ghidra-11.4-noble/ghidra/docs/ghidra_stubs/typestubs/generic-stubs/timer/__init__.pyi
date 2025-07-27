from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import java.awt.event # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


T = typing.TypeVar("T")


class GhidraSwinglessTimer(GhidraTimer):
    """
    The GhidraSwinglessTimer is similar to the javax.swing.Timer class.  The big difference is
    that it does NOT use the swing thread for its callbacks.  Similar to the swing timer, only 
    one timer thread is ever used no matter how many GhidraSwinglessTimers are instantiated.
     
    It fires one or more ``TimerCallback``s at specified
    intervals. 
    Setting up a timer
    involves creating a ``GhidraSwinglessTimer`` object,
    registering one or more TimerCallbacks on it,
    and starting the timer using
    the ``start`` method.
    """

    @typing.type_check_only
    class MyTimerTask(java.util.TimerTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    @typing.type_check_only
    class CleanupTimerTask(java.util.TimerTask):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        """
        Creates a new repeating timer with a initial delay of 100ms and a continual delay of 100ms.
        """

    @typing.overload
    def __init__(self, delay: typing.Union[jpype.JInt, int], callback: TimerCallback):
        """
        Creates a new repeating timer with a initial and continual delay with the given delay.
        
        :param jpype.JInt or int delay: the delay to use for the first and subsequent timer callbacks.
        :param TimerCallback callback: the callback the be called with the timer fires.
        """

    @typing.overload
    def __init__(self, initialDelay: typing.Union[jpype.JInt, int], delay: typing.Union[jpype.JInt, int], callback: TimerCallback):
        """
        Creates a new repeating timer with an initial and continual delay.
        
        :param jpype.JInt or int initialDelay: the delay to use for the first timer callbacks.
        :param jpype.JInt or int delay: the delay to use for subsequent timer callbacks.
        :param TimerCallback callback: the callback the be called with the timer fires.
        """

    def getDelay(self) -> int:
        """
        Returns the delay for all callbacks after the first callback.
        
        :return: the delay for all callbacks after the first callback.
        :rtype: int
        """

    def getInitialDelay(self) -> int:
        """
        Returns the delay for the first callback.
        
        :return: the delay for the first callback.
        :rtype: int
        """

    def isRepeats(self) -> bool:
        """
        Returns true if this timer is set to repeating.
        
        :return: true if this timer is set to repeating.
        :rtype: bool
        """

    def isRunning(self) -> bool:
        """
        Returns true if the timer is running.
        """

    @staticmethod
    def main(args: jpype.JArray[java.lang.String]):
        ...

    def setDelay(self, delay: typing.Union[jpype.JInt, int]):
        """
        Sets the delay for all callbacks after the first callback
        """

    def setInitialDelay(self, initialDelay: typing.Union[jpype.JInt, int]):
        """
        Sets the delay for the first callbacks.
        """

    def setRepeats(self, repeats: typing.Union[jpype.JBoolean, bool]):
        """
        Sets whether this timer repeats.
        
        :param jpype.JBoolean or bool repeats: if true, the timer will repeat, if false the timer will only fire once.
        """

    def setTimerCallback(self, callback: TimerCallback):
        """
        Sets the callback to be called when the timer fires.
        """

    def start(self):
        """
        Starts the timer.
        """

    def stop(self):
        """
        Stops the timer.
        """

    @property
    def running(self) -> jpype.JBoolean:
        ...

    @property
    def repeats(self) -> jpype.JBoolean:
        ...

    @repeats.setter
    def repeats(self, value: jpype.JBoolean):
        ...

    @property
    def delay(self) -> jpype.JInt:
        ...

    @delay.setter
    def delay(self, value: jpype.JInt):
        ...

    @property
    def initialDelay(self) -> jpype.JInt:
        ...

    @initialDelay.setter
    def initialDelay(self, value: jpype.JInt):
        ...


class GhidraTimerFactory(java.lang.Object):
    """
    Creates a new :obj:`GhidraTimer` appropriate for a headed or headless environment.
     
    
    If running a headed environment, the callback will happen on the Swing thread.  Otherwise, the
    callback will happen on the non-Swing :obj:`Timer` thread.
     
    
    See also :obj:`GTimer`
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    @staticmethod
    def getGhidraTimer(initialDelay: typing.Union[jpype.JInt, int], delay: typing.Union[jpype.JInt, int], callback: TimerCallback) -> GhidraTimer:
        ...


class GhidraTimer(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def getDelay(self) -> int:
        ...

    def getInitialDelay(self) -> int:
        ...

    def isRepeats(self) -> bool:
        ...

    def isRunning(self) -> bool:
        ...

    def setDelay(self, delay: typing.Union[jpype.JInt, int]):
        ...

    def setInitialDelay(self, initialDelay: typing.Union[jpype.JInt, int]):
        ...

    def setRepeats(self, repeats: typing.Union[jpype.JBoolean, bool]):
        ...

    def setTimerCallback(self, callback: TimerCallback):
        ...

    def start(self):
        ...

    def stop(self):
        ...

    @property
    def running(self) -> jpype.JBoolean:
        ...

    @property
    def repeats(self) -> jpype.JBoolean:
        ...

    @repeats.setter
    def repeats(self, value: jpype.JBoolean):
        ...

    @property
    def delay(self) -> jpype.JInt:
        ...

    @delay.setter
    def delay(self, value: jpype.JInt):
        ...

    @property
    def initialDelay(self) -> jpype.JInt:
        ...

    @initialDelay.setter
    def initialDelay(self, value: jpype.JInt):
        ...


class GhidraSwingTimer(GhidraTimer, java.awt.event.ActionListener):

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self):
        ...

    @typing.overload
    def __init__(self, delay: typing.Union[jpype.JInt, int], callback: TimerCallback):
        ...

    @typing.overload
    def __init__(self, initialDelay: typing.Union[jpype.JInt, int], delay: typing.Union[jpype.JInt, int], callback: TimerCallback):
        ...


class ExpiringSwingTimer(GhidraSwingTimer):
    """
    This class allows clients to run swing action at some point in the future, when the given
    condition is met, allowing for the task to timeout.  While this class implements the
    :obj:`GhidraTimer` interface, it is really meant to be used to execute a code snippet one
    time at some point in the future.
     
     
    Both the call to check for readiness and the actual client code will be run on the Swing
    thread.
    """

    @typing.type_check_only
    class ExpiringTimerCallback(TimerCallback):
        ...
        class_: typing.ClassVar[java.lang.Class]


    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, delay: typing.Union[jpype.JInt, int], expireMs: typing.Union[jpype.JInt, int], isReady: java.util.function.BooleanSupplier, runnable: java.lang.Runnable):
        """
        Constructor
         
         
        Note: this class sets the parent's initial delay to 0.  This is to allow the client
        code to be executed without delay when the ready condition is true.
        
        :param jpype.JInt or int delay: the delay between calls to check ``isReady``
        :param java.util.function.BooleanSupplier isReady: true if the code should be run
        :param jpype.JInt or int expireMs: the amount of time past which the code will not be run
        :param java.lang.Runnable runnable: the code to run
        """

    def didRun(self) -> bool:
        """
        Returns true if the client runnable was run
        
        :return: true if the client runnable was run
        :rtype: bool
        """

    @staticmethod
    def get(supplier: java.util.function.Supplier[T], expireMs: typing.Union[jpype.JInt, int], consumer: java.util.function.Consumer[T]) -> ExpiringSwingTimer:
        """
        Calls the given consumer with the non-null value returned from the given supplier.  The
        returned timer will be running.
         
         
        Once the timer has performed the work, any calls to start the returned timer will
        not perform any work.  You can check :meth:`didRun() <.didRun>` to see if the work has been completed.
        
        :param T: the type used by the supplier and consumer:param java.util.function.Supplier[T] supplier: the supplier of the desired value
        :param jpype.JInt or int expireMs: the amount of time past which the code will not be run
        :param java.util.function.Consumer[T] consumer: the consumer to be called with the supplier's value
        :return: the timer object that is running, which will execute the given code when ready
        :rtype: ExpiringSwingTimer
        """

    def isExpired(self) -> bool:
        """
        Returns true the initial expiration period has passed
        
        :return: true if expired
        :rtype: bool
        """

    @staticmethod
    def runWhen(isReady: java.util.function.BooleanSupplier, expireMs: typing.Union[jpype.JInt, int], runnable: java.lang.Runnable) -> ExpiringSwingTimer:
        """
        Runs the given client runnable when the given condition returns true.  The returned timer
        will be running.
         
         
        Once the timer has performed the work, any calls to start the returned timer will
        not perform any work.  You can check :meth:`didRun() <.didRun>` to see if the work has been completed.
        
        :param java.util.function.BooleanSupplier isReady: true if the code should be run
        :param jpype.JInt or int expireMs: the amount of time past which the code will not be run
        :param java.lang.Runnable runnable: the code to run
        :return: the timer object that is running, which will execute the given code when ready
        :rtype: ExpiringSwingTimer
        """

    @property
    def expired(self) -> jpype.JBoolean:
        ...


class TimerCallback(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def timerFired(self):
        ...



__all__ = ["GhidraSwinglessTimer", "GhidraTimerFactory", "GhidraTimer", "GhidraSwingTimer", "ExpiringSwingTimer", "TimerCallback"]
