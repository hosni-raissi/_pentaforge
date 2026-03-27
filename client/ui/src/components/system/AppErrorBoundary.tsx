import React from "react";

type Props = {
  children: React.ReactNode;
};

type State = {
  hasError: boolean;
  message: string;
};

export class AppErrorBoundary extends React.Component<Props, State> {
  public state: State = {
    hasError: false,
    message: "",
  };

  public static getDerivedStateFromError(error: unknown): State {
    const message = error instanceof Error ? error.message : String(error);
    return {
      hasError: true,
      message,
    };
  }

  public componentDidCatch(error: unknown): void {
    console.error("App crashed:", error);
  }

  private readonly resetAppState = () => {
    try {
      localStorage.removeItem("pf-config");
      localStorage.removeItem("pf-projects");
      localStorage.removeItem("pf-theme");
    } catch (error) {
      console.error("Failed to clear persisted UI state:", error);
    }
    window.location.reload();
  };

  public render() {
    if (!this.state.hasError) {
      return this.props.children;
    }

    return (
      <div className="flex min-h-screen items-center justify-center bg-surface-0 p-6 text-text-primary">
        <div className="w-full max-w-xl rounded-xl border border-border bg-surface-1 p-5">
          <h1 className="text-base font-semibold">UI Runtime Error</h1>
          <p className="mt-2 text-sm text-text-secondary">
            The app hit an unexpected error while rendering.
          </p>
          <pre className="mt-3 overflow-auto rounded-md border border-border bg-surface-0 p-3 text-xs text-text-secondary">
            {this.state.message || "Unknown error"}
          </pre>
          <button
            type="button"
            className="mt-4 rounded-md bg-pf-600 px-3 py-2 text-sm font-medium text-white hover:bg-pf-700"
            onClick={this.resetAppState}
          >
            Clear Local UI State And Reload
          </button>
        </div>
      </div>
    );
  }
}
