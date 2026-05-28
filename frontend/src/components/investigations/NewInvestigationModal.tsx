import { useState, useCallback, type FormEvent } from "react";
import { Loader2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ds/dialog";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { Label } from "@/components/ds/label";
import { Textarea } from "@/components/ds/textarea";
import { NativeSelect } from "@/components/ds/native-select";
import { Severity, TLP } from "@/types/config";
import { createInvestigation } from "@/api/investigations";
import { useInvestigationStore } from "@/stores/investigationStore";

interface NewInvestigationModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

const severityOptions = [
  { value: Severity.CRITICAL, label: "Critical" },
  { value: Severity.HIGH, label: "High" },
  { value: Severity.MEDIUM, label: "Medium" },
  { value: Severity.LOW, label: "Low" },
  { value: Severity.INFO, label: "Info" },
];

const tlpOptions = [
  { value: TLP.RED, label: "TLP:RED" },
  { value: TLP.AMBER, label: "TLP:AMBER" },
  { value: TLP.AMBER_STRICT, label: "TLP:AMBER+STRICT" },
  { value: TLP.GREEN, label: "TLP:GREEN" },
  { value: TLP.CLEAR, label: "TLP:CLEAR" },
];

const templateOptions = [
  { value: "", label: "No template" },
  { value: "phishing", label: "Phishing Investigation" },
  { value: "malware", label: "Malware Analysis" },
  { value: "insider_threat", label: "Insider Threat" },
  { value: "data_exfil", label: "Data Exfiltration" },
  { value: "ransomware", label: "Ransomware Response" },
  { value: "lateral_movement", label: "Lateral Movement" },
];

export function NewInvestigationModal({
  open,
  onOpenChange,
}: NewInvestigationModalProps) {
  const { upsertInvestigation } = useInvestigationStore();

  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState(Severity.MEDIUM);
  const [tlp, setTlp] = useState(TLP.AMBER);
  const [template, setTemplate] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const resetForm = useCallback(() => {
    setTitle("");
    setDescription("");
    setSeverity(Severity.MEDIUM);
    setTlp(TLP.AMBER);
    setTemplate("");
    setError(null);
  }, []);

  const handleSubmit = useCallback(
    async (e: FormEvent) => {
      e.preventDefault();

      if (!title.trim()) {
        setError("Title is required");
        return;
      }

      setIsSubmitting(true);
      setError(null);

      try {
        // Backend expects ``tlp_level: lowercase`` (matching the
        // shared ``TLP`` enum in ``btagent_shared.types.config``); the
        // frontend ``TLP`` enum stores uppercase strings for display
        // in the form, so coerce to lowercase before posting.
        const investigation = await createInvestigation({
          title: title.trim(),
          description: description.trim(),
          severity,
          tlp_level: (tlp as string).toLowerCase() as TLP,
          template: template || undefined,
        });

        upsertInvestigation(investigation);
        resetForm();
        onOpenChange(false);
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Failed to create investigation";
        setError(message);
      } finally {
        setIsSubmitting(false);
      }
    },
    [
      title,
      description,
      severity,
      tlp,
      template,
      upsertInvestigation,
      resetForm,
      onOpenChange,
    ]
  );

  return (
    <Dialog
      open={open}
      onOpenChange={(isOpen) => {
        if (!isOpen) resetForm();
        onOpenChange(isOpen);
      }}
    >
      <DialogContent data-testid="new-investigation-dialog">
        <DialogHeader>
          <DialogTitle>New Investigation</DialogTitle>
          <DialogDescription>
            Create a new security investigation. The AI agent will begin analysis
            once created.
          </DialogDescription>
        </DialogHeader>

        <form
          onSubmit={handleSubmit}
          className="space-y-4"
          data-testid="new-investigation-form"
        >
          <div className="space-y-1.5">
            <Label htmlFor="new-investigation-title">Title</Label>
            <Input
              id="new-investigation-title"
              placeholder="e.g., Suspicious login from 185.220.101.x"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              autoFocus
              data-testid="new-investigation-title-input"
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="new-investigation-description">Description</Label>
            <Textarea
              id="new-investigation-description"
              placeholder="Describe the incident or alert details..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              data-testid="new-investigation-description-input"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="new-investigation-severity">Severity</Label>
              <NativeSelect
                id="new-investigation-severity"
                value={severity}
                onChange={(e) => setSeverity(e.target.value as Severity)}
                data-testid="new-investigation-severity-input"
              >
                {severityOptions.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </NativeSelect>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="new-investigation-tlp">TLP</Label>
              <NativeSelect
                id="new-investigation-tlp"
                value={tlp}
                onChange={(e) => setTlp(e.target.value as TLP)}
                data-testid="new-investigation-tlp-input"
              >
                {tlpOptions.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </NativeSelect>
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="new-investigation-template">Template</Label>
            <NativeSelect
              id="new-investigation-template"
              value={template}
              onChange={(e) => setTemplate(e.target.value)}
              data-testid="new-investigation-template-input"
            >
              {templateOptions.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </NativeSelect>
          </div>

          {error && (
            <div
              className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
              role="alert"
              data-testid="new-investigation-error"
            >
              {error}
            </div>
          )}

          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              onClick={() => onOpenChange(false)}
              data-testid="new-investigation-cancel-button"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={isSubmitting}
              data-testid="new-investigation-submit-button"
            >
              {isSubmitting && (
                <Loader2 className="w-4 h-4 mr-2 animate-spin" />
              )}
              Create Investigation
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
