import { useState, useCallback, type FormEvent } from "react";
import { Dialog, DialogContent, DialogFooter } from "@/components/ui/Dialog";
import { Button } from "@/components/ui/Button";
import { Input, Textarea, Select } from "@/components/ui/Input";
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
        const investigation = await createInvestigation({
          title: title.trim(),
          description: description.trim(),
          severity,
          tlp,
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
    [title, description, severity, tlp, template, upsertInvestigation, resetForm, onOpenChange],
  );

  return (
    <Dialog
      open={open}
      onOpenChange={(isOpen) => {
        if (!isOpen) resetForm();
        onOpenChange(isOpen);
      }}
    >
      <DialogContent
        title="New Investigation"
        description="Create a new security investigation. The AI agent will begin analysis once created."
      >
        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            label="Title"
            placeholder="e.g., Suspicious login from 185.220.101.x"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            autoFocus
          />

          <Textarea
            label="Description"
            placeholder="Describe the incident or alert details..."
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            rows={3}
          />

          <div className="grid grid-cols-2 gap-4">
            <Select
              label="Severity"
              options={severityOptions}
              value={severity}
              onChange={(e) => setSeverity(e.target.value as Severity)}
            />

            <Select
              label="TLP"
              options={tlpOptions}
              value={tlp}
              onChange={(e) => setTlp(e.target.value as TLP)}
            />
          </div>

          <Select
            label="Template"
            options={templateOptions}
            value={template}
            onChange={(e) => setTemplate(e.target.value)}
          />

          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-md p-3 text-sm text-red-400">
              {error}
            </div>
          )}

          <DialogFooter>
            <Button
              type="button"
              variant="ghost"
              onClick={() => onOpenChange(false)}
            >
              Cancel
            </Button>
            <Button type="submit" isLoading={isSubmitting}>
              Create Investigation
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
