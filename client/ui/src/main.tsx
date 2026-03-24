import React from 'react';
import ReactDOM from 'react-dom/client';
import { HashRouter } from 'react-router-dom';

import App from './App';
import './index.css';

// Initialize theme from storage before render
const stored = localStorage.getItem('pf-theme');
if (stored) {
  try {
    const { state } = JSON.parse(stored);
    document.documentElement.classList.toggle('dark', state?.isDark ?? true);
  } catch {
    document.documentElement.classList.add('dark');
  }
} else {
  document.documentElement.classList.add('dark');
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <HashRouter>
      <App />
    </HashRouter>
  </React.StrictMode>
);
