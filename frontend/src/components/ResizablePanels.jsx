import { useState, useRef, useCallback, useEffect } from 'react';
import clsx from 'clsx';

/**
 * Resizable panel container with draggable dividers
 *
 * Usage:
 * <ResizablePanels
 *   panels={[
 *     { id: 'left', minWidth: 200, defaultWidth: 320, content: <LeftPanel /> },
 *     { id: 'center', minWidth: 300, content: <CenterPanel /> },
 *     { id: 'right', minWidth: 300, defaultWidth: 520, content: <RightPanel /> },
 *   ]}
 * />
 */
export default function ResizablePanels({ panels, className }) {
  // Initialize widths from defaults or distribute evenly
  const [widths, setWidths] = useState(() => {
    const initial = {};
    panels.forEach((panel, idx) => {
      if (panel.defaultWidth) {
        initial[panel.id] = panel.defaultWidth;
      }
    });
    return initial;
  });

  const containerRef = useRef(null);
  const draggingRef = useRef(null);
  const startXRef = useRef(0);
  const startWidthsRef = useRef({});

  const handleMouseDown = useCallback((e, dividerIndex) => {
    e.preventDefault();
    draggingRef.current = dividerIndex;
    startXRef.current = e.clientX;

    // Store current widths
    const container = containerRef.current;
    if (!container) return;

    const panelElements = container.querySelectorAll('[data-panel]');
    const currentWidths = {};
    panelElements.forEach((el, idx) => {
      currentWidths[panels[idx].id] = el.getBoundingClientRect().width;
    });
    startWidthsRef.current = currentWidths;

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }, [panels]);

  const handleMouseMove = useCallback((e) => {
    if (draggingRef.current === null) return;

    const delta = e.clientX - startXRef.current;
    const leftPanelId = panels[draggingRef.current].id;
    const rightPanelId = panels[draggingRef.current + 1].id;
    const leftMinWidth = panels[draggingRef.current].minWidth || 100;
    const rightMinWidth = panels[draggingRef.current + 1].minWidth || 100;

    const leftStart = startWidthsRef.current[leftPanelId] || 300;
    const rightStart = startWidthsRef.current[rightPanelId] || 300;

    let newLeftWidth = leftStart + delta;
    let newRightWidth = rightStart - delta;

    // Enforce minimum widths
    if (newLeftWidth < leftMinWidth) {
      newLeftWidth = leftMinWidth;
      newRightWidth = leftStart + rightStart - leftMinWidth;
    }
    if (newRightWidth < rightMinWidth) {
      newRightWidth = rightMinWidth;
      newLeftWidth = leftStart + rightStart - rightMinWidth;
    }

    setWidths(prev => ({
      ...prev,
      [leftPanelId]: newLeftWidth,
      [rightPanelId]: newRightWidth,
    }));
  }, [panels]);

  const handleMouseUp = useCallback(() => {
    draggingRef.current = null;
    document.removeEventListener('mousemove', handleMouseMove);
    document.removeEventListener('mouseup', handleMouseUp);
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  }, [handleMouseMove]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, [handleMouseMove, handleMouseUp]);

  return (
    <div ref={containerRef} className={clsx('flex h-full', className)}>
      {panels.map((panel, idx) => (
        <div key={panel.id} className="flex">
          {/* Panel */}
          <div
            data-panel={panel.id}
            className="flex flex-col overflow-hidden"
            style={{
              width: widths[panel.id] ? `${widths[panel.id]}px` : undefined,
              flex: widths[panel.id] ? 'none' : '1 1 0%',
              minWidth: panel.minWidth || 100,
            }}
          >
            {panel.content}
          </div>

          {/* Divider (not after last panel) */}
          {idx < panels.length - 1 && (
            <div
              className="relative flex-shrink-0 w-1 bg-border hover:bg-accent/50 cursor-col-resize group transition-colors"
              onMouseDown={(e) => handleMouseDown(e, idx)}
            >
              {/* Drag handle indicator */}
              <div className="absolute inset-y-0 -left-1 -right-1 group-hover:bg-accent/20" />
              <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-1 h-8 rounded-full bg-secondary opacity-0 group-hover:opacity-100 transition-opacity" />
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

/**
 * Simple two-panel horizontal resizable layout
 */
export function ResizableHorizontal({ left, right, defaultLeftWidth = 320, minLeft = 200, minRight = 300 }) {
  const [leftWidth, setLeftWidth] = useState(defaultLeftWidth);
  const containerRef = useRef(null);
  const draggingRef = useRef(false);
  const startXRef = useRef(0);
  const startWidthRef = useRef(0);

  const handleMouseDown = useCallback((e) => {
    e.preventDefault();
    draggingRef.current = true;
    startXRef.current = e.clientX;
    startWidthRef.current = leftWidth;

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }, [leftWidth]);

  const handleMouseMove = useCallback((e) => {
    if (!draggingRef.current) return;

    const container = containerRef.current;
    if (!container) return;

    const containerWidth = container.getBoundingClientRect().width;
    const delta = e.clientX - startXRef.current;
    let newWidth = startWidthRef.current + delta;

    // Enforce constraints
    newWidth = Math.max(minLeft, newWidth);
    newWidth = Math.min(containerWidth - minRight - 4, newWidth); // 4 for divider

    setLeftWidth(newWidth);
  }, [minLeft, minRight]);

  const handleMouseUp = useCallback(() => {
    draggingRef.current = false;
    document.removeEventListener('mousemove', handleMouseMove);
    document.removeEventListener('mouseup', handleMouseUp);
    document.body.style.cursor = '';
    document.body.style.userSelect = '';
  }, [handleMouseMove]);

  useEffect(() => {
    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, [handleMouseMove, handleMouseUp]);

  return (
    <div ref={containerRef} className="flex h-full">
      {/* Left panel */}
      <div style={{ width: leftWidth, minWidth: minLeft }} className="flex-shrink-0 overflow-hidden">
        {left}
      </div>

      {/* Divider */}
      <div
        className="w-1 bg-border hover:bg-accent/50 cursor-col-resize flex-shrink-0 transition-colors"
        onMouseDown={handleMouseDown}
      />

      {/* Right panel */}
      <div style={{ minWidth: minRight }} className="flex-1 overflow-hidden">
        {right}
      </div>
    </div>
  );
}
