import { create } from "zustand";

type ActivePanel =
  | "chat"
  | "timeline"
  | "iocs"
  | "evidence"
  | "events"
  // #117: the cloud IAM containment-proposal review lives in the investigation
  // workspace, so it is one of the case tabs rather than a top-level route.
  | "containment";

interface UIState {
  sidebarOpen: boolean;
  theme: "dark";
  activePanel: ActivePanel;

  toggleSidebar: () => void;
  setSidebarOpen: (open: boolean) => void;
  setActivePanel: (panel: ActivePanel) => void;
}

export const useUIStore = create<UIState>((set) => ({
  sidebarOpen: true,
  theme: "dark" as const,
  activePanel: "chat",

  toggleSidebar: () => {
    set((state) => ({ sidebarOpen: !state.sidebarOpen }));
  },

  setSidebarOpen: (open: boolean) => {
    set({ sidebarOpen: open });
  },

  setActivePanel: (panel: ActivePanel) => {
    set({ activePanel: panel });
  },
}));
