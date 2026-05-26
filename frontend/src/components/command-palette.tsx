import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  AlertCircle,
  FileText,
  GitBranch,
  Home,
  Moon,
  Search,
  Sun,
  Target,
} from "lucide-react";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ds/command";
import { useThemeStore } from "@/stores/themeStore";

/**
 * Global Cmd-K command palette. Mounted once near the application root
 * (in main.tsx). Opens on Cmd-K (mac) / Ctrl-K (everyone else) and
 * scrolls a flat list of jump-to-view + theme actions.
 *
 * Future: dynamic results (investigations, IOCs, workflows, playbooks)
 * sourced from the existing REST endpoints.
 */
export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const navigate = useNavigate();
  const setTheme = useThemeStore((s) => s.setTheme);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const go = (path: string) => () => {
    setOpen(false);
    navigate(path);
  };

  const theme = (t: "light" | "dark" | "system") => () => {
    setOpen(false);
    setTheme(t);
  };

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput placeholder="Search investigations, IOCs, workflows..." />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>

        <CommandGroup heading="Navigate">
          <CommandItem onSelect={go("/")}>
            <Home className="h-4 w-4" />
            <span>Dashboard</span>
          </CommandItem>
          <CommandItem onSelect={go("/investigations")}>
            <AlertCircle className="h-4 w-4" />
            <span>Investigations</span>
          </CommandItem>
          <CommandItem onSelect={go("/iocs")}>
            <Search className="h-4 w-4" />
            <span>IOCs</span>
          </CommandItem>
          <CommandItem onSelect={go("/hunts")}>
            <Target className="h-4 w-4" />
            <span>Hunt Package</span>
          </CommandItem>
          <CommandItem onSelect={go("/playbooks")}>
            <GitBranch className="h-4 w-4" />
            <span>Playbooks</span>
          </CommandItem>
          <CommandItem onSelect={go("/mitre")}>
            <Target className="h-4 w-4" />
            <span>MITRE Coverage</span>
          </CommandItem>
          <CommandItem onSelect={go("/reports")}>
            <FileText className="h-4 w-4" />
            <span>Reports</span>
          </CommandItem>
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Theme">
          <CommandItem onSelect={theme("light")}>
            <Sun className="h-4 w-4" />
            <span>Light</span>
            <CommandShortcut>L</CommandShortcut>
          </CommandItem>
          <CommandItem onSelect={theme("dark")}>
            <Moon className="h-4 w-4" />
            <span>Dark</span>
            <CommandShortcut>D</CommandShortcut>
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
