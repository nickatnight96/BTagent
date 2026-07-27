import { useEffect, useState } from "react";
import { Building2, Loader2, Save } from "lucide-react";
import { toast } from "sonner";
import {
  emptyOrgProfile,
  getOrgProfile,
  updateOrgProfile,
  type OrgProfile,
} from "@/api/orgProfile";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { Textarea } from "@/components/ds/textarea";
import { Label } from "@/components/ds/label";

// --- serialize / parse helpers ------------------------------------------- //
// The profile stores free-form JSON (tech_stack: dict, ir_team.shifts:
// list[dict]); the editor renders those as compact line-oriented text and
// round-trips them so a save preserves the structure the backend expects.

function parseCompliance(text: string): string[] {
  return text
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
}

function serializeTechStack(techStack: Record<string, unknown>): string {
  return Object.entries(techStack)
    .map(([category, value]) => {
      const items = Array.isArray(value) ? value.join(", ") : String(value);
      return `${category}: ${items}`;
    })
    .join("\n");
}

function parseTechStack(text: string): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const idx = trimmed.indexOf(":");
    if (idx === -1) continue;
    const category = trimmed.slice(0, idx).trim();
    if (!category) continue;
    out[category] = trimmed
      .slice(idx + 1)
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }
  return out;
}

function serializeShifts(shifts: Array<Record<string, unknown>>): string {
  return shifts
    .map((shift) => {
      const name = String(shift.name ?? "");
      const timezone = String(shift.timezone ?? "");
      const hours = String(shift.hours ?? "");
      return `${name} | ${timezone} | ${hours}`;
    })
    .join("\n");
}

function parseShifts(text: string): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const [name = "", timezone = "", hours = ""] = trimmed.split("|").map((s) => s.trim());
    if (!name && !timezone && !hours) continue;
    out.push({ name, timezone, hours });
  }
  return out;
}

/**
 * Organisation-profile editor (#418 / GH #393). The profile is injected into
 * agent prompts, so admins tune industry, compliance frameworks, tech stack
 * and IR-team shifts here; a save PUTs the WHOLE profile (fields this editor
 * doesn't surface — critical assets, escalation paths, on-call — are preserved
 * from the loaded profile). Non-admins get a read-only view. A failed fetch
 * hides the panel so it never blocks the Config Center from rendering.
 */
export function OrgProfilePanel() {
  const role = useAuthStore((s) => s.user?.role);
  const isAdmin = role === UserRole.ADMIN;

  const [profile, setProfile] = useState<OrgProfile | null>(null);
  const [industry, setIndustry] = useState("");
  const [complianceText, setComplianceText] = useState("");
  const [techStackText, setTechStackText] = useState("");
  const [shiftsText, setShiftsText] = useState("");
  const [busy, setBusy] = useState(false);

  const hydrate = (p: OrgProfile) => {
    setProfile(p);
    setIndustry(p.industry ?? "");
    setComplianceText((p.compliance ?? []).join(", "));
    setTechStackText(serializeTechStack(p.tech_stack ?? {}));
    setShiftsText(serializeShifts(p.ir_team?.shifts ?? []));
  };

  useEffect(() => {
    let cancelled = false;
    getOrgProfile()
      .then((resp) => {
        if (!cancelled) hydrate(resp.profile ?? emptyOrgProfile());
      })
      .catch(() => {
        if (!cancelled) setProfile(null);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (profile === null) return null;

  const handleSave = async () => {
    setBusy(true);
    try {
      const next: OrgProfile = {
        ...profile,
        industry: industry.trim(),
        compliance: parseCompliance(complianceText),
        tech_stack: parseTechStack(techStackText),
        ir_team: {
          ...profile.ir_team,
          shifts: parseShifts(shiftsText),
        },
      };
      const resp = await updateOrgProfile(next);
      hydrate(resp.profile ?? next);
      toast.success("Organization profile saved");
    } catch {
      toast.error("Could not save the organization profile");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section data-testid="org-profile-panel">
      <div className="flex items-center gap-2 mb-3">
        <Building2 className="w-4 h-4 text-primary" aria-hidden="true" />
        <h2 className="text-sm font-semibold">Organization profile</h2>
        <span className="text-xs text-muted-foreground flex-1">
          {isAdmin
            ? "injected into agent prompts; admin-editable"
            : "read-only (admin-managed)"}
        </span>
        {busy && (
          <Loader2
            className="w-3.5 h-3.5 animate-spin text-muted-foreground"
            aria-label="Saving"
          />
        )}
      </div>

      {isAdmin ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 max-w-3xl">
          <div className="space-y-1.5">
            <Label htmlFor="org-profile-industry">Industry</Label>
            <Input
              id="org-profile-industry"
              value={industry}
              onChange={(e) => setIndustry(e.target.value)}
              placeholder="financial_services"
              data-testid="org-profile-industry"
              className="h-9"
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="org-profile-compliance">Compliance frameworks</Label>
            <Input
              id="org-profile-compliance"
              value={complianceText}
              onChange={(e) => setComplianceText(e.target.value)}
              placeholder="PCI-DSS, SOX, HIPAA"
              data-testid="org-profile-compliance"
              className="h-9"
            />
            <p className="text-[11px] text-muted-foreground">Comma-separated.</p>
          </div>
          <div className="space-y-1.5 md:col-span-2">
            <Label htmlFor="org-profile-tech-stack">Tech stack</Label>
            <Textarea
              id="org-profile-tech-stack"
              value={techStackText}
              onChange={(e) => setTechStackText(e.target.value)}
              placeholder={"siem: Splunk, Sentinel\nedr: CrowdStrike"}
              data-testid="org-profile-tech-stack"
              rows={3}
              className="font-mono text-xs"
            />
            <p className="text-[11px] text-muted-foreground">
              One category per line as <code>category: item1, item2</code>.
            </p>
          </div>
          <div className="space-y-1.5 md:col-span-2">
            <Label htmlFor="org-profile-shifts">IR team shifts</Label>
            <Textarea
              id="org-profile-shifts"
              value={shiftsText}
              onChange={(e) => setShiftsText(e.target.value)}
              placeholder={"Day | America/New_York | 08:00-16:00\nNight | UTC | 20:00-04:00"}
              data-testid="org-profile-shifts"
              rows={3}
              className="font-mono text-xs"
            />
            <p className="text-[11px] text-muted-foreground">
              One shift per line as <code>name | timezone | hours</code>.
            </p>
          </div>
          <div className="md:col-span-2">
            <Button
              size="sm"
              onClick={() => void handleSave()}
              disabled={busy}
              data-testid="org-profile-save"
            >
              <Save className="w-4 h-4 mr-1.5" aria-hidden="true" />
              Save profile
            </Button>
          </div>
        </div>
      ) : (
        <dl
          className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs max-w-3xl"
          data-testid="org-profile-readonly"
        >
          <div>
            <dt className="text-muted-foreground">Industry</dt>
            <dd data-testid="org-profile-view-industry">{profile.industry || "—"}</dd>
          </div>
          <div>
            <dt className="text-muted-foreground">Compliance frameworks</dt>
            <dd data-testid="org-profile-view-compliance">
              {profile.compliance.length ? profile.compliance.join(", ") : "—"}
            </dd>
          </div>
          <div className="md:col-span-2">
            <dt className="text-muted-foreground">Tech stack</dt>
            <dd
              className="whitespace-pre-wrap font-mono"
              data-testid="org-profile-view-tech-stack"
            >
              {Object.keys(profile.tech_stack).length
                ? serializeTechStack(profile.tech_stack)
                : "—"}
            </dd>
          </div>
          <div className="md:col-span-2">
            <dt className="text-muted-foreground">IR team shifts</dt>
            <dd className="whitespace-pre-wrap font-mono" data-testid="org-profile-view-shifts">
              {profile.ir_team.shifts.length ? serializeShifts(profile.ir_team.shifts) : "—"}
            </dd>
          </div>
        </dl>
      )}
    </section>
  );
}
