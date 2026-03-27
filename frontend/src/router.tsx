import { createBrowserRouter } from "react-router-dom";
import { Layout } from "@/components/layout/Layout";
import { LoginPage } from "@/components/auth/LoginPage";
import { ProtectedRoute } from "@/components/auth/ProtectedRoute";
import { InvestigationList } from "@/components/investigations/InvestigationList";
import { InvestigationWorkspace } from "@/components/workspace/InvestigationWorkspace";
import { IOCNotebook } from "@/components/iocs/IOCNotebook";
import { MitreMatrix } from "@/components/mitre/MitreMatrix";

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
        path: "mitre",
        element: <MitreMatrix />,
      },
    ],
  },
]);
