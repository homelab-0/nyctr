import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { AuthProvider } from './auth';
import './styles.css';

class AppErrorBoundary extends React.Component<{ children: React.ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    if (this.state.failed)
      return (
        <main className="boot-screen">
          <div className="empty">
            <h1>Something interrupted this view</h1>
            <p>
              Your saved requests and reviews remain on the server. Reload the workspace to try
              again.
            </p>
            <button className="button primary" onClick={() => window.location.reload()}>
              Reload workspace
            </button>
          </div>
        </main>
      );
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <AppErrorBoundary>
      <AuthProvider>
        <App />
      </AuthProvider>
    </AppErrorBoundary>
  </React.StrictMode>,
);
