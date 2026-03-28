import { useMemo, useState, useCallback } from "react";
import { Copy, Check, FileCode } from "lucide-react";
import { usePlaybookStore } from "@/stores/playbookStore";
import { nodesToYAML } from "@/utils/playbook-graph";

export function PlaybookYAMLEditor() {
  const { builderNodes, builderEdges } = usePlaybookStore();
  const [copied, setCopied] = useState(false);

  const yamlContent = useMemo(() => {
    if (builderNodes.length === 0) {
      return "# Add nodes to the canvas to generate YAML";
    }
    return nodesToYAML(builderNodes, builderEdges);
  }, [builderNodes, builderEdges]);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(yamlContent);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback for older browsers
      const textArea = document.createElement("textarea");
      textArea.value = yamlContent;
      document.body.appendChild(textArea);
      textArea.select();
      document.execCommand("copy");
      document.body.removeChild(textArea);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  }, [yamlContent]);

  return (
    <div className="flex flex-col h-full bg-slate-900 border-l border-slate-700/50">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-slate-700/50 shrink-0">
        <div className="flex items-center gap-2">
          <FileCode className="w-4 h-4 text-slate-400" />
          <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
            YAML Preview
          </span>
        </div>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-2 py-1 text-xs font-medium text-slate-400 bg-slate-800 border border-slate-700 rounded hover:bg-slate-700 hover:text-slate-200 transition-colors"
        >
          {copied ? (
            <>
              <Check className="w-3 h-3 text-green-400" />
              <span className="text-green-400">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3 h-3" />
              Copy
            </>
          )}
        </button>
      </div>

      {/* YAML content */}
      <div className="flex-1 overflow-auto p-3">
        <pre className="text-xs font-mono text-slate-300 leading-relaxed whitespace-pre-wrap">
          {yamlContent.split("\n").map((line, i) => (
            <div key={i} className="flex">
              <span className="inline-block w-8 text-right pr-3 text-slate-600 select-none shrink-0">
                {i + 1}
              </span>
              <span>
                {highlightYamlLine(line)}
              </span>
            </div>
          ))}
        </pre>
      </div>
    </div>
  );
}

/** Simple YAML syntax highlighting via spans. */
function highlightYamlLine(line: string): React.ReactNode {
  // Comments
  if (line.trim().startsWith("#")) {
    return <span className="text-slate-500 italic">{line}</span>;
  }

  // Key: value pairs
  const colonIdx = line.indexOf(":");
  if (colonIdx > 0) {
    const key = line.substring(0, colonIdx);
    const rest = line.substring(colonIdx);

    // Check if value is a string in quotes
    const valueStr = rest.substring(1).trim();
    const isQuoted = valueStr.startsWith('"') || valueStr.startsWith("'");
    const isNumber = /^\d+$/.test(valueStr);
    const isBoolOrNull = ["true", "false", "null", "{}"].includes(valueStr);

    return (
      <>
        <span className="text-blue-400">{key}</span>
        <span className="text-slate-500">:</span>
        {valueStr && (
          <span
            className={
              isQuoted
                ? "text-green-400"
                : isNumber
                  ? "text-amber-400"
                  : isBoolOrNull
                    ? "text-purple-400"
                    : "text-slate-200"
            }
          >
            {rest.substring(1)}
          </span>
        )}
      </>
    );
  }

  // List items
  if (line.trim().startsWith("- ")) {
    const indent = line.substring(0, line.indexOf("-"));
    const content = line.substring(line.indexOf("-") + 2);
    return (
      <>
        <span>{indent}</span>
        <span className="text-slate-500">- </span>
        <span className="text-slate-200">{content}</span>
      </>
    );
  }

  return <span>{line}</span>;
}
