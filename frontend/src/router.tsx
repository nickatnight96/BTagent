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
const HuntPlanPage = lazy(() =>
  import("@/components/hunts/HuntPlanPage").then((m) => ({ default: m.HuntPlanPage })),
);
const AgenticRiskPage = lazy(() =>
  import("@/components/agentic/AgenticRiskPage").then((m) => ({ default: m.AgenticRiskPage })),
);
const CorrelationPage = lazy(() =>
  import("@/components/correlation/CorrelationPage").then((m) => ({
    default: m.CorrelationPage,
  })),
);
const AlertTriagePage = lazy(() =>
  import("@/components/triage/AlertTriagePage").then((m) => ({
    default: m.AlertTriagePage,
  })),
);
const ResponsePlanPage = lazy(() =>
  import("@/components/response/ResponsePlanPage").then((m) => ({
    default: m.ResponsePlanPage,
  })),
);
const BulkMitigationPage = lazy(() =>
  import("@/components/mitigation/BulkMitigationPage").then((m) => ({
    default: m.BulkMitigationPage,
  })),
);
const WorkflowList = lazy(() =>
  import("@/components/workflows/WorkflowList").then((m) => ({ default: m.WorkflowList })),
);
const WorkflowDetail = lazy(() =>
  import("@/components/workflows/WorkflowDetail").then((m) => ({ default: m.WorkflowDetail })),
);
const WorkflowCanvas = lazy(() =>
  import("@/components/workflows/WorkflowCanvas").then((m) => ({ default: m.WorkflowCanvas })),
);
const WorkflowEditor = lazy(() =>
  import("@/components/workflows/WorkflowEditor").then((m) => ({ default: m.WorkflowEditor })),
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
const MfaSettingsPage = lazy(() =>
  import("@/components/auth/MfaSettingsPage").then((m) => ({ default: m.MfaSettingsPage })),
);
const IntegrationsPage = lazy(() =>
  import("@/components/connectors/IntegrationsPage").then((m) => ({
    default: m.IntegrationsPage,
  })),
);
const SSOIdentitiesPage = lazy(() =>
  import("@/components/auth/SSOIdentitiesPage").then((m) => ({ default: m.SSOIdentitiesPage })),
);
const BehavioralHuntsPage = lazy(() =>
  import("@/components/behavioral/BehavioralHuntsPage").then((m) => ({
    default: m.BehavioralHuntsPage,
  })),
);
const CloudHuntsPage = lazy(() =>
  import("@/components/cloud/CloudHuntsPage").then((m) => ({
    default: m.CloudHuntsPage,
  })),
);
const PatternInsightsPage = lazy(() =>
  import("@/components/pattern/PatternInsightsPage").then((m) => ({
    default: m.PatternInsightsPage,
  })),
);
const IdentityHuntsPage = lazy(() =>
  import("@/components/identity/IdentityHuntsPage").then((m) => ({
    default: m.IdentityHuntsPage,
  })),
);
const DetectionValidationPage = lazy(() =>
  import("@/components/validation/DetectionValidationPage").then((m) => ({
    default: m.DetectionValidationPage,
  })),
);
const DetectionProposalsPage = lazy(() =>
  import("@/components/detection/DetectionProposalsPage").then((m) => ({
    default: m.DetectionProposalsPage,
  })),
);
const ReportsPage = lazy(() =>
  import("@/components/reports/ReportsPage").then((m) => ({ default: m.ReportsPage })),
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
        path: "hunt-plan",
        element: lazyRoute(HuntPlanPage),
      },
      {
        path: "agentic-risk",
        element: lazyRoute(AgenticRiskPage),
      },
      {
        path: "correlate",
        element: lazyRoute(CorrelationPage),
      },
      {
        path: "triage",
        element: lazyRoute(AlertTriagePage),
      },
      {
        path: "response-plan",
        element: lazyRoute(ResponsePlanPage),
      },
      {
        path: "mitigation",
        element: lazyRoute(BulkMitigationPage),
      },
      {
        path: "workflows",
        element: lazyRoute(WorkflowList),
      },
      {
        path: "workflows/:id",
        element: lazyRoute(WorkflowDetail),
      },
      {
        path: "workflows/:id/versions/:version/canvas",
        element: lazyRoute(WorkflowCanvas),
      },
      {
        path: "workflows/:id/versions/:version/edit",
        element: lazyRoute(WorkflowEditor),
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
      {
        path: "security",
        element: lazyRoute(MfaSettingsPage),
      },
      {
        path: "integrations",
        element: lazyRoute(IntegrationsPage),
      },
      {
        path: "sso-identities",
        element: lazyRoute(SSOIdentitiesPage),
      },
      {
        path: "behavioral",
        element: lazyRoute(BehavioralHuntsPage),
      },
      {
        path: "cloud-hunts",
        element: lazyRoute(CloudHuntsPage),
      },
      {
        path: "pattern-insights",
        element: lazyRoute(PatternInsightsPage),
      },
      {
        path: "identity-hunts",
        element: lazyRoute(IdentityHuntsPage),
      },
      {
        path: "detection-validation",
        element: lazyRoute(DetectionValidationPage),
      },
      {
        path: "detection-proposals",
        element: lazyRoute(DetectionProposalsPage),
      },
      {
        path: "reports",
        element: lazyRoute(ReportsPage),
      },
    ],
  },
]);
