import { createBrowserRouter } from "react-router-dom";
import { Layout } from "@/components/layout/Layout";
import { LoginPage } from "@/components/auth/LoginPage";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { InvestigationList } from "@/components/investigations/InvestigationList";
import { InvestigationWorkspace } from "@/components/workspace/InvestigationWorkspace";
import { IOCNotebook } from "@/components/iocs/IOCNotebook";
import { MitreMatrix } from "@/components/mitre/MitreMatrix";
import { KnowledgePage } from "@/components/knowledge/KnowledgePage";
import { PlaybookList } from "@/components/playbooks/PlaybookList";
import { HuntPackagePage } from "@/components/hunts/HuntPackagePage";
import { AuditLedgerPage } from "@/components/audit/AuditLedgerPage";
import { PlaybookBuilder } from "@/components/playbooks/PlaybookBuilder";
import { PlaybookExecutionView } from "@/components/playbooks/PlaybookExecutionView";

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
        element: <InvestigationList />,
      },
      {
        path: "investigations/:id",
        element: <InvestigationWorkspace />,
      },
      {
        path: "iocs",
        element: <IOCNotebook />,
      },
      {
        path: "hunts",
        element: <HuntPackagePage />,
      },
      {
        path: "audit",
        element: <AuditLedgerPage />,
      },
      {
        path: "mitre",
        element: <MitreMatrix />,
      },
      {
        path: "knowledge",
        element: <KnowledgePage />,
      },
      {
        path: "playbooks",
        element: <PlaybookList />,
      },
      {
        path: "playbooks/builder",
        element: <PlaybookBuilder />,
      },
      {
        path: "playbooks/builder/:id",
        element: <PlaybookBuilder />,
      },
      {
        path: "playbooks/:id/execute",
        element: <PlaybookExecutionView />,
      },
    ],
  },
]);
