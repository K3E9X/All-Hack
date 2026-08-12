import { Component } from 'react';

/**
 * Without this, a single render exception unmounts the whole app and leaves a
 * blank page with nothing in the UI to explain it — an operator mid-engagement
 * sees the tool vanish. One bad number from the API should cost one page, not
 * the session.
 *
 * Keyed on the route in App so navigating away clears the error instead of
 * trapping the user on a dead screen.
 */
export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Keep the stack reachable in the console; there is no telemetry sink here.
    console.error('render error:', error, info?.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="page">
        <div className="card">
          <div className="card__head"><span className="card__title">This screen failed to render</span></div>
          <div className="card__body">
            <p className="home-intro">
              The rest of the app still works — the engagement and any running scans are unaffected.
            </p>
            <pre className="mono" style={{ whiteSpace: 'pre-wrap', fontSize: 12, marginTop: 8 }}>
              {String(this.state.error?.message || this.state.error)}
            </pre>
            <div className="form-actions" style={{ marginTop: 8 }}>
              <button className="btn btn--solid" onClick={() => this.setState({ error: null })}>Retry</button>
            </div>
          </div>
        </div>
      </div>
    );
  }
}
