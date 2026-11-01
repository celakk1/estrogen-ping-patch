import React from 'react';
import { createRoot } from 'react-dom/client';
import { IconoirProvider } from 'iconoir-react';
import App from './App';
import './styles.css';

createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <IconoirProvider
      iconProps={{
        className: 'app-icon',
        width: 16,
        height: 16,
        'aria-hidden': true,
        focusable: false,
      }}
    >
      <App />
    </IconoirProvider>
  </React.StrictMode>,
);
