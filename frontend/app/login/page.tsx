'use client';

import { useSearchParams } from 'next/navigation';
import { Suspense } from 'react';
import { Database, AlertCircle } from '@/components/icons';

function LoginContent() {
  const searchParams = useSearchParams();
  const error = searchParams.get('error');

  const errorMessages: Record<string, string> = {
    access_denied: 'Access was denied. Please try again.',
    state: 'Invalid OAuth state. Please try again.',
    exchange: 'Failed to complete authentication. Please try again.',
    profile: 'Failed to fetch user profile. Please try again.',
    unauthorized: 'You are not authorized to access this application.',
  };

  const errorMessage = error ? errorMessages[error] || 'An error occurred. Please try again.' : null;

  return (
    <div className="min-h-screen flex items-center justify-center bg-theme-bg">
      <div className="text-center p-10 bg-theme-bg-secondary/50 border border-theme-border-dim rounded-2xl max-w-md w-full mx-4">
        <div className="w-16 h-16 rounded-2xl bg-purple-600/20 border border-purple-500/30 flex items-center justify-center mx-auto mb-6">
          <Database className="w-8 h-8 text-purple-400" />
        </div>

        <h1 className="text-2xl font-semibold text-theme-text mb-2">CXDB</h1>
        <p className="text-theme-text-dim mb-8">AI Context Store - Authenticated Access</p>

        {errorMessage && (
          <div className="flex items-center gap-2 justify-center text-red-400 text-sm mb-6 p-3 bg-red-600/10 border border-red-500/20 rounded-lg">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{errorMessage}</span>
          </div>
        )}

        <a
              href="/auth/login"
              className="inline-flex items-center justify-center gap-3 px-6 py-3 bg-purple-600 hover:bg-purple-500 text-white font-medium rounded-lg transition-colors"
            >
              <Database className="w-[18px] h-[18px]" />
              Sign in
        </a>

        <p className="text-xs text-theme-text-faint mt-8">
          Access restricted to authorized users only.
        </p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={
      <div className="min-h-screen flex items-center justify-center bg-theme-bg">
        <div className="text-theme-text-dim">Loading...</div>
      </div>
    }>
      <LoginContent />
    </Suspense>
  );
}
