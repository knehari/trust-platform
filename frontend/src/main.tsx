import { Component, type ErrorInfo, type ReactNode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import './style.css';
import './ui.css';

/** Shows what failed instead of a blank page, and offers a reload. */
class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  componentDidCatch(error: Error, info: ErrorInfo) { console.error('Console crashed', error, info.componentStack); }
  render() {
    if (!this.state.error) return this.props.children;
    return <div className="ui-crash" role="alert">
      <h1>The console hit an unexpected error</h1>
      <p>Nothing was changed on the server. Reload the page; if it happens again, send this message to the team.</p>
      <pre>{String(this.state.error.stack ?? this.state.error.message)}</pre>
      <button type="button" className="ui-button ui-button-primary" onClick={() => window.location.reload()}>Reload</button>
    </div>;
  }
}

createRoot(document.getElementById('root')!).render(<ErrorBoundary><App /></ErrorBoundary>);
