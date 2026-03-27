import { type ReactNode } from "react";
import * as RadixDialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { clsx } from "clsx";
import { twMerge } from "tailwind-merge";

interface DialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  children: ReactNode;
}

function Dialog({ open, onOpenChange, children }: DialogProps) {
  return (
    <RadixDialog.Root open={open} onOpenChange={onOpenChange}>
      {children}
    </RadixDialog.Root>
  );
}

function DialogTrigger({ children }: { children: ReactNode }) {
  return <RadixDialog.Trigger asChild>{children}</RadixDialog.Trigger>;
}

interface DialogContentProps {
  children: ReactNode;
  title: string;
  description?: string;
  className?: string;
}

function DialogContent({
  children,
  title,
  description,
  className,
}: DialogContentProps) {
  return (
    <RadixDialog.Portal>
      <RadixDialog.Overlay className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 animate-in fade-in duration-200" />
      <RadixDialog.Content
        className={twMerge(
          clsx(
            "fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50",
            "bg-slate-900 border border-slate-700/50 rounded-xl shadow-2xl shadow-black/40",
            "w-full max-w-lg max-h-[85vh] overflow-y-auto",
            "p-6 animate-slide-in",
            "focus:outline-none",
            className,
          ),
        )}
        onEscapeKeyDown={(e) => {
          // Allow escape to close
          e.stopPropagation();
        }}
      >
        <div className="flex items-start justify-between mb-4">
          <div>
            <RadixDialog.Title className="text-lg font-semibold text-slate-100">
              {title}
            </RadixDialog.Title>
            {description && (
              <RadixDialog.Description className="text-sm text-slate-400 mt-1">
                {description}
              </RadixDialog.Description>
            )}
          </div>
          <RadixDialog.Close className="text-slate-400 hover:text-slate-200 p-1 rounded-md hover:bg-slate-800 transition-colors">
            <X className="h-5 w-5" />
          </RadixDialog.Close>
        </div>
        {children}
      </RadixDialog.Content>
    </RadixDialog.Portal>
  );
}

function DialogFooter({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      className={twMerge(
        clsx("flex items-center justify-end gap-3 mt-6 pt-4 border-t border-slate-700/50", className),
      )}
    >
      {children}
    </div>
  );
}

export { Dialog, DialogTrigger, DialogContent, DialogFooter };
export type { DialogProps, DialogContentProps };
