import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';
import './styles.css';
import { createMatrixRuntime } from './matrix';

let runtime: Awaited<ReturnType<typeof createMatrixRuntime>> | undefined;

export async function mountApplication(): Promise<void> {
  // Callback handling commits or rejects OAuth before React can mount any UI.
  runtime = await createMatrixRuntime();
  void runtime; // retain lifecycle ownership for the mounted application.
  createRoot(document.getElementById('root')!).render(<StrictMode><App runtime={runtime} /></StrictMode>);
}
