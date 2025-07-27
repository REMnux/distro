from __future__ import annotations
import collections.abc
import datetime
import typing
from warnings import deprecated # type: ignore

import jpype # type: ignore
import jpype.protocol # type: ignore

import edu.uci.ics.jung.visualization # type: ignore
import ghidra.graph.graphs
import ghidra.graph.viewer
import ghidra.graph.viewer.layout
import ghidra.util.task
import java.awt # type: ignore
import java.awt.geom # type: ignore
import java.lang # type: ignore
import java.util # type: ignore
import java.util.function # type: ignore


E = typing.TypeVar("E")
V = typing.TypeVar("V")


class MoveViewToLayoutSpacePointAnimatorFunctionGraphJob(MoveViewAnimatorFunctionGraphJob[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], layoutSpacePoint: java.awt.geom.Point2D, useAnimation: typing.Union[jpype.JBoolean, bool]):
        ...


class FitGraphToViewJob(GraphJob, typing.Generic[V, E]):
    """
    A job to scale one or more viewers such that the contained graph will fit entirely inside the
    viewing area.
    """

    class_: typing.ClassVar[java.lang.Class]

    @typing.overload
    def __init__(self, *viewers: edu.uci.ics.jung.visualization.VisualizationServer[V, E]):
        ...

    @typing.overload
    def __init__(self, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], onlyResizeWhenTooBig: typing.Union[jpype.JBoolean, bool]):
        ...


class AbstractAnimator(java.lang.Object):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def hasFinished(self) -> bool:
        ...

    def isRunning(self) -> bool:
        ...

    def setBusyListener(self, listener: ghidra.util.task.BusyListener):
        ...

    def start(self):
        ...

    def stop(self):
        """
        Stops this animator **and all scheduled animators!**
        """

    @property
    def running(self) -> jpype.JBoolean:
        ...


class TwinkleVertexAnimator(AbstractAnimator, typing.Generic[V, E]):
    """
    A class to animate a vertex in order to draw attention to it.
     
    Note: this class is not a :obj:`AbstractAnimatorJob` so that it can run concurrently 
    with jobs in the graph (jobs run one-at-a-time).
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V, useAnimation: typing.Union[jpype.JBoolean, bool]):
        ...

    def getVertex(self) -> V:
        ...

    def setCurrentEmphasis(self, currentEmphasis: typing.Union[jpype.JDouble, float]):
        ...

    @property
    def vertex(self) -> V:
        ...


class AbstractGraphVisibilityTransitionJob(AbstractAnimatorJob, typing.Generic[V, E]):
    """
    A job that provides an animator and callbacks for transitioning the visibility of 
    graph vertices.  The opacity value will change from 0 to 1 over the course of the job. 
    Subclasses can decide how to use the opacity value as it changes.   For example, a 
    subclass can fade in or out the vertices provided to the job.
    """

    class_: typing.ClassVar[java.lang.Class]

    def setPercentComplete(self, percentComplete: typing.Union[jpype.JDouble, float]):
        """
        Callback from our animator.
        """


class MoveVertexToCenterAnimatorFunctionGraphJob(MoveViewAnimatorFunctionGraphJob[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V, useAnimation: typing.Union[jpype.JBoolean, bool]):
        ...


class GraphJob(java.lang.Object):
    """
    A graph job is an item of work that needs to be performed.
    
    
    .. seealso::
    
        | :obj:`GraphJobRunner`
    """

    class_: typing.ClassVar[java.lang.Class]

    def canShortcut(self) -> bool:
        """
        Returns true if the job can be told to stop running, but to still perform any final 
        work before being done.
        
        :return: true if the job can be shortcut
        :rtype: bool
        """

    def dispose(self):
        """
        Call to immediately stop this job, ignoring any exceptions or state issues that arise.
        """

    def execute(self, listener: GraphJobListener):
        """
        Tells this job to do its work.  This call will be on the Swing thread.  It is required
        that the given listener be called on the Swing thread when the job is finished.
        
        :param GraphJobListener listener: the listener this job is expected to call when its work is finished
        """

    def isFinished(self) -> bool:
        """
        Returns true if this job has finished its work
        
        :return: true if this job has finished its work
        :rtype: bool
        """

    def shortcut(self):
        """
        Tells this job to stop running, but to still perform any final work before being done.
         
         
        Note: if your job is multi-threaded, then you must make sure to end your thread and
        work before returning from this method.  If that cannot be done in a timely manner, then
        your :meth:`canShortcut() <.canShortcut>` should return false.
        """

    @property
    def finished(self) -> jpype.JBoolean:
        ...


class AbstractGraphTransitionJob(AbstractGraphVisibilityTransitionJob[V, E], typing.Generic[V, E]):
    """
    A job to transition vertices in a graph for location and visibility.  The parent class 
    handled the opacity callback.  The progress of the job is used by this class to move 
    vertices from the start location to the final destination, where the progress is the
    percentage of the total move to display.
    """

    @typing.type_check_only
    class TransitionPoints(java.lang.Object):

        class_: typing.ClassVar[java.lang.Class]
        startPoint: java.awt.geom.Point2D
        destinationPoint: java.awt.geom.Point2D

        def __init__(self, startPoint: java.awt.geom.Point2D, destinationPoint: java.awt.geom.Point2D):
            ...


    @typing.type_check_only
    class ArticulationTransitionPoints(AbstractGraphTransitionJob.TransitionPoints):

        class_: typing.ClassVar[java.lang.Class]
        pointToUpdate: java.awt.geom.Point2D

        def __init__(self, currentEdgePoint: java.awt.geom.Point2D, destinationPoint: java.awt.geom.Point2D):
            ...


    class_: typing.ClassVar[java.lang.Class]

    def calculateDefaultLayoutLocations(self, verticesToIgnore: java.util.Set[V]) -> ghidra.graph.viewer.layout.LayoutPositions[V, E]:
        """
        Calculates default vertex locations for the current graph by using the current layout, 
        excluding those vertices in the given *ignore* set.  The graph, 
        layout and vertices will be unaltered.
        
        :param java.util.Set[V] verticesToIgnore: The set of vertices which should be excluded from the layout process
        :return: The mapping of all arranged vertices to their respective locations
        :rtype: ghidra.graph.viewer.layout.LayoutPositions[V, E]
        """

    def setPercentComplete(self, percentComplete: typing.Union[jpype.JDouble, float]):
        """
        Callback from our animator.
        """


class RelayoutFunctionGraphJob(AbstractGraphTransitionJob[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, viewer: ghidra.graph.viewer.GraphViewer[V, E], useAnimation: typing.Union[jpype.JBoolean, bool]):
        ...


class MoveViewAnimatorFunctionGraphJob(AbstractAnimatorJob, typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], useAnimation: typing.Union[jpype.JBoolean, bool]):
        ...

    def setOffset(self, offsetFromOriginalPoint: java.awt.geom.Point2D):
        ...


class GraphJobListener(java.lang.Object):
    """
    A listener to :obj:`GraphJob` state
    """

    class_: typing.ClassVar[java.lang.Class]

    def jobFinished(self, job: GraphJob):
        ...


class FilterVerticesJob(AbstractGraphVisibilityTransitionJob[V, E], typing.Generic[V, E]):
    """
    Uses the given filter to fade out vertices that do not pass.  Vertices that pass the filter
    will be included in the graph.  Not only will passing vertices be included, but so too 
    will any vertices reachable from those vertices.
     
     
    This job will update the graph so that any previously filtered vertices will be put
    back into the graph.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, viewer: ghidra.graph.viewer.GraphViewer[V, E], graph: ghidra.graph.graphs.FilteringVisualGraph[V, E], filter: java.util.function.Predicate[V], remove: typing.Union[jpype.JBoolean, bool]):
        """
        Constructor
        
        :param ghidra.graph.viewer.GraphViewer[V, E] viewer: the viewer upon which to operate
        :param ghidra.graph.graphs.FilteringVisualGraph[V, E] graph: the graph to filter
        :param java.util.function.Predicate[V] filter: the predicate used to determine what passes the filter
        :param jpype.JBoolean or bool remove: true signals to remove the vertices from the view; false signals to leave
                    them visible, but faded to show that they failed the filter
        """


class MoveVertexToCenterTopAnimatorFunctionGraphJob(MoveViewAnimatorFunctionGraphJob[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], vertex: V, useAnimation: typing.Union[jpype.JBoolean, bool]):
        ...


class GraphJobRunner(GraphJobListener):
    """
    A class to run :obj:`GraphJob`s.  This class will queue jobs and will run them
    in the Swing thread.  Job implementations may be multi-threaded, as they choose, by managing
    threads themselves.    This is different than a typical job runner, which is usually
    itself threaded.
     
    
    A job is considered finished when :meth:`jobFinished(GraphJob) <.jobFinished>`
    is called on this class.  After this callback, the next job will be run.  
     
    
    :meth:`setFinalJob(GraphJob) <.setFinalJob>` sets a job to be run last, after all jobs in the queue
    have finished.
     
     
    When a job is added via :meth:`schedule(GraphJob) <.schedule>`, any currently running job will 
    be told to finish immediately, if it's :meth:`GraphJob.canShortcut() <GraphJob.canShortcut>` returns true.  If it 
    cannot be shortcut, then it will be allowed to finish.  Further, this logic will be applied
    to each job in the queue.  So, if there are multiple jobs in the queue, which all return
    true for :meth:`GraphJob.canShortcut() <GraphJob.canShortcut>`, then they will each be shortcut (allowing them 
    to complete) before running the newly scheduled job.
     
     
    This class is thread-safe in that you can :meth:`schedule(GraphJob) <.schedule>` jobs from any
    thread.
     
     
    Synchronization Policy:  the methods that mutate fields of this class or read them 
    must be synchronized.
    """

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self):
        ...

    def dispose(self):
        """
        Clears any pending jobs, stops the currently running job ungracefully and updates this
        class so that any new jobs added will be ignored.
        """

    def finishAllJobs(self):
        """
        Causes all jobs to be finished as quickly as possible, calling :meth:`GraphJob.shortcut() <GraphJob.shortcut>`
        on each job.   
         
         
        Note: some jobs are not shortcut-able and will finish on their own time.  Any jobs 
        queued behind a non-shortcut-able job will **not** be shortcut.
        
        
        .. seealso::
        
            | :obj:`.dispose()`
        """

    def isBusy(self) -> bool:
        ...

    def schedule(self, job: GraphJob):
        ...

    def setFinalJob(self, job: GraphJob):
        """
        Sets a job to run after all currently running and queued jobs.  If a final job was already
        set, then that job will be replaced with the given job.
        
        :param GraphJob job: the job to run
        """

    @property
    def busy(self) -> jpype.JBoolean:
        ...


class AbstractAnimatorJob(GraphJob):

    class_: typing.ClassVar[java.lang.Class]
    TOO_BIG_TO_ANIMATE: typing.Final = 125
    """
    A somewhat arbitrary vertex count past which not to animate actions that are intensive.
    """


    def __init__(self):
        ...

    def setBusyListener(self, listener: ghidra.util.task.BusyListener):
        ...


class EdgeHoverAnimator(AbstractAnimator, typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, primaryViewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], satelliteViewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], useAnimation: typing.Union[jpype.JBoolean, bool]):
        ...

    def setNextPaint(self, nextPaint: typing.Union[jpype.JInt, int]):
        ...


class MoveViewToViewSpacePointAnimatorFunctionGraphJob(MoveViewAnimatorFunctionGraphJob[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, viewer: edu.uci.ics.jung.visualization.VisualizationServer[V, E], viewSpacePoint: java.awt.geom.Point2D, useAnimation: typing.Union[jpype.JBoolean, bool]):
        ...


class EnsureAreaVisibleAnimatorFunctionGraphJob(MoveViewAnimatorFunctionGraphJob[V, E], typing.Generic[V, E]):

    class_: typing.ClassVar[java.lang.Class]

    def __init__(self, primaryViewer: edu.uci.ics.jung.visualization.VisualizationViewer[V, E], satelliteViewer: ghidra.graph.viewer.SatelliteGraphViewer[V, E], vertex: V, visibleArea: java.awt.Rectangle, useAnimation: typing.Union[jpype.JBoolean, bool]):
        ...



__all__ = ["MoveViewToLayoutSpacePointAnimatorFunctionGraphJob", "FitGraphToViewJob", "AbstractAnimator", "TwinkleVertexAnimator", "AbstractGraphVisibilityTransitionJob", "MoveVertexToCenterAnimatorFunctionGraphJob", "GraphJob", "AbstractGraphTransitionJob", "RelayoutFunctionGraphJob", "MoveViewAnimatorFunctionGraphJob", "GraphJobListener", "FilterVerticesJob", "MoveVertexToCenterTopAnimatorFunctionGraphJob", "GraphJobRunner", "AbstractAnimatorJob", "EdgeHoverAnimator", "MoveViewToViewSpacePointAnimatorFunctionGraphJob", "EnsureAreaVisibleAnimatorFunctionGraphJob"]
