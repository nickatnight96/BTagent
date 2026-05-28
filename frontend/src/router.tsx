import { lazy, Suspense, type ComponentType } from "react";
import { createBrowserRouter } from "react-router-dom";
import { Layout } from "@/components/layout/Layout";
import { LoginPage } from "@/components/auth/LoginPage";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { Skeleton } from "@/components/ds/skeleton";

// #146 perf: code-split the route pages. The app shell (Layout, Sidebar,
// LoginPage, ProtectedRoute) stays in the eager entry bundle since it is
// always needed on first paint, but each page below is pulled into its own
// async chunk so the initial download no longer carries every screen.
//
// react-router's `lazy` route option only supports its own data-router
// module contract, so we use plain `React.lazy` + a `<Suspense>` wrapper.
// Named exports are mapped to the default export `React.lazy` expects.
const InvestigationList = lazy(() =>
  import("@/components/investigations/InvestigationList").then((m) => ({
    default: m.InvestigationList,
  })),
);
const InvestigationWorkspace = lazy(() =>
  import("@/components/workspace/InvestigationWorkspace").then((m) => ({
    default: m.InvestigationWorkspace,
  })),
);
const IOCNotebook = lazy(() =>
  import("@/components/iocs/IOCNotebook").then((m) => ({ default: m.IOCNotebook })),
);
const MitreMatrix = lazy(() =>
  import("@/components/mitre/MitreMatrix").then((m) => ({ default: m.MitreMatrix })),
);
const KnowledgePage = lazy(() =>
  import("@/components/knowledge/KnowledgePage").then((m) => ({ default: m.KnowledgePage })),
);
const HuntTriagePage = lazy(() =>
  import("@/components/hunt/HuntTriagePage").then((m) => ({ default: m.HuntTriagePage })),
);
const HuntPackagePage = lazy(() =>
  import("@/components/hunts/HuntPackagePage").then((m) => ({ default: m.HuntPackagePage })),
);
const CorrelationPage = lazy(() =>
  import("@/components/correlation/CorrelationPage").then((m) => ({
    default: m.CorrelationPage,
  })),
);
const PlaybookList = lazy(() =>
  import("@/components/playbooks/PlaybookList").then((m) => ({ default: m.PlaybookList })),
);
const PlaybookBuilder = lazy(() =>
  import("@/components/playbooks/PlaybookBuilder").then((m) => ({ default: m.PlaybookBuilder })),
);
const PlaybookExecutionView = lazy(() =>
  import("@/components/playbooks/PlaybookExecutionView").then((m) => ({
    default: m.PlaybookExecutionView,
  })),
);
const AuditLedgerPage = lazy(() =>
  import("@/components/audit/AuditLedgerPage").then((m) => ({ default: m.AuditLedgerPage })),
);
const TLPPolicyPage = lazy(() =>
  import("@/components/policies/TLPPolicyPage").then((m) => ({ default: m.TLPPolicyPage })),
);

/** Fallback shown while a route chunk is being fetched. */
function RouteFallback() {
  return (
    <div className="flex-1 space-y-4 p-6">
      <Skeleton className="h-8 w-64" />
      <Skeleton className="h-4 w-full max-w-2xl" />
      <Skeleton className="h-4 w-full max-w-xl" />
      <Skeleton className="h-64 w-full" />
    </div>
  );
}

/** Wrap a lazily-loaded page in a Suspense boundary with the shared fallback. */
function lazyRoute(Component: ComponentType) {
  return (
    <Suspense fallback={<RouteFallback />}>
      <Component />
    </Suspense>
  );
}

export const router = createBrowserRouter([
  {
    path: "/login",
    element: <LoginPage />,
  },
  {
    path: "/",
    element: (
      <ProtectedRoute>
        <Layout />
      </ProtectedRoute>
    ),
    children: [
      {
        index: true,
        element: lazyRoute(InvestigationList),
      },
      {
        path: "investigations/:id",
        element: lazyRoute(InvestigationWorkspace),
      },
      {
        path: "iocs",
        element: lazyRoute(IOCNotebook),
      },
      {
        path: "mitre",
        element: lazyRoute(MitreMatrix),
      },
      {
        path: "knowledge",
        element: lazyRoute(KnowledgePage),
      },
      {
        path: "hunt",
        element: lazyRoute(HuntTriagePage),
      },
      {
        path: "hunts",
        element: lazyRoute(HuntPackagePage),
      },
      {
        path: "correlate",
        element: lazyRoute(CorrelationPage),
      },
      {
        path: "playbooks",
        element: lazyRoute(PlaybookList),
      },
      {
        path: "playbooks/builder",
        element: lazyRoute(PlaybookBuilder),
      },
      {
        path: "playbooks/builder/:id",
        element: lazyRoute(PlaybookBuilder),
      },
      {
        path: "playbooks/:id/execute",
        element: lazyRoute(PlaybookExecutionView),
      },
      {
        path: "audit",
        element: lazyRoute(AuditLedgerPage),
      },
      {
        path: "policies",
        element: lazyRoute(TLPPolicyPage),
      },
    ],
  },
]);
