import { useCallback } from "react";
import {
  X,
  ExternalLink,
  Zap,
  Clock,
  Shield,
  Globe,
  Server,
  AlertTriangle,
  CheckCircle2,
  Circle,
  Loader2,
  XCircle,
  Link2,
} from "lucide-react";
import { useIOCStore } from "@/stores/iocStore";
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
import type { EnrichmentStatus, MitreTag } from "@/types/ioc";

interface IOCDetailPanelProps {
  onClose: () => void;
}

function EnrichmentStatusIcon({ status }: { status: EnrichmentStatus }) {
  switch (status) {
    case "enriched":
      return <CheckCircle2 className="w-4 h-4 text-green-400" />;
    case "enriching":
      return <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />;
    case "failed":
      return <XCircle className="w-4 h-4 text-red-400" />;
    default:
      return <Circle className="w-4 h-4 text-slate-500" />;
  }
}

function StatusLabel({ status }: { status: EnrichmentStatus }) {
  const labels: Record<EnrichmentStatus, string> = {
    enriched: "Enriched",
    enriching: "Enriching...",
    failed: "Failed",
    pending: "Pending",
  };
  const colors: Record<EnrichmentStatus, string> = {
    enriched: "text-green-400",
    enriching: "text-blue-400",
    failed: "text-red-400",
    pending: "text-slate-500",
  };
  return (
    <span className={`text-xs font-medium ${colors[status]}`}>
      {labels[status]}
    </span>
  );
}

function ConfidenceBar({ confidence }: { confidence: number }) {
  const color =
    confidence < 0.3
      ? "bg-red-500"
      : confidence < 0.7
        ? "bg-amber-500"
        : "bg-green-500";
  const bgColor =
    confidence < 0.3
      ? "bg-red-500/20"
      : confidence < 0.7
        ? "bg-amber-500/20"
        : "bg-green-500/20";

  return (
    <div className="flex items-center gap-2">
      <div className={`flex-1 h-2 rounded-full ${bgColor}`}>
        <div
          className={`h-full rounded-full ${color} transition-all`}
          style={{ width: `${Math.round(confidence * 100)}%` }}
        />
      </div>
      <span className="text-xs text-slate-400 tabular-nums">
        {Math.round(confidence * 100)}%
      </span>
    </div>
  );
}

function SectionHeader({ children }: { children: React.ReactNode }) {
  return (
    <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
      {children}
    </h3>
  );
}

function MitreTagBadge({ tag }: { tag: MitreTag }) {
  return (
    <a
      href={`https://attack.mitre.org/techniques/${tag.technique_id.replace(".", "/")}/`}
      target="_blank"
      rel="noopener noreferrer"
      className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-xs font-medium bg-purple-500/15 text-purple-400 border border-purple-500/20 hover:bg-purple-500/25 hover:border-purple-500/30 transition-colors cursor-pointer"
      title={`${tag.technique_id}: ${tag.technique_name} (${tag.tactic})`}
      aria-label={`View MITRE technique ${tag.technique_id} ${tag.technique_name} on attack.mitre.org`}
      data-testid={`ioc-detail-mitre-tag-${tag.technique_id}-link`}
    >
      {tag.technique_id}
      <span className="text-purple-500/70">{tag.technique_name}</span>
    </a>
  );
}

export function IOCDetailPanel({ onClose }: IOCDetailPanelProps) {
  const { selectedIOC, isEnriching, enrichIOC } = useIOCStore();

  const handleEnrich = useCallback(() => {
    if (selectedIOC) {
      void enrichIOC(selectedIOC.id);
    }
  }, [selectedIOC, enrichIOC]);

  if (!selectedIOC) return null;

  const { enrichment_data } = selectedIOC;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/40 backdrop-blur-sm z-40"
        onClick={onClose}
        aria-hidden="true"
        data-testid="ioc-detail-backdrop"
      />

      {/* Slide-over panel */}
      <div
        className="fixed right-0 top-0 bottom-0 w-full max-w-lg bg-slate-950 border-l border-slate-700/50 z-50 overflow-y-auto shadow-2xl shadow-black/40 animate-slide-in-right"
        role="dialog"
        aria-labelledby="ioc-detail-title"
        data-testid="ioc-detail"
      >
        {/* Header */}
        <div className="sticky top-0 z-10 bg-slate-950/95 backdrop-blur-sm border-b border-slate-700/50 p-4">
          <div className="flex items-start justify-between">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <Badge className="text-[10px] shrink-0">
                  {(selectedIOC.type ?? "unknown").toUpperCase()}
                </Badge>
                <EnrichmentStatusIcon status={selectedIOC.enrichment_status ?? "pending"} />
                <StatusLabel status={selectedIOC.enrichment_status ?? "pending"} />
              </div>
              <p
                id="ioc-detail-title"
                className="font-mono text-sm text-slate-200 break-all"
                data-testid="ioc-detail-value"
              >
                {selectedIOC.value}
              </p>
            </div>
            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-200 p-1 rounded-md hover:bg-slate-800 transition-colors shrink-0 ml-3"
              aria-label="Close IOC detail panel"
              data-testid="ioc-detail-close-button"
            >
              <X className="h-5 w-5" aria-hidden="true" />
            </button>
          </div>

          <div className="flex items-center gap-3 mt-3">
            <Button
              size="sm"
              onClick={handleEnrich}
              isLoading={isEnriching}
              disabled={(selectedIOC.enrichment_status ?? "pending") === "enriching"}
              data-testid="ioc-detail-enrich-button"
            >
              <Zap className="w-3.5 h-3.5" aria-hidden="true" />
              Enrich Now
            </Button>
          </div>
        </div>

        <div className="p-4 space-y-6">
          {/* Summary */}
          <div>
            <SectionHeader>Summary</SectionHeader>
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-slate-900 rounded-lg p-3 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase tracking-wide">
                  Source
                </span>
                <p className="text-sm text-slate-200 mt-0.5">
                  {selectedIOC.source}
                </p>
              </div>
              <div className="bg-slate-900 rounded-lg p-3 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase tracking-wide">
                  TLP
                </span>
                <p className="text-sm text-slate-200 mt-0.5">
                  {selectedIOC.tlp ?? selectedIOC.tlp_level ?? "N/A"}
                </p>
              </div>
              <div className="bg-slate-900 rounded-lg p-3 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase tracking-wide">
                  Confidence
                </span>
                <div className="mt-1">
                  <ConfidenceBar confidence={selectedIOC.confidence} />
                </div>
              </div>
              <div className="bg-slate-900 rounded-lg p-3 border border-slate-800">
                <span className="text-[10px] text-slate-500 uppercase tracking-wide">
                  First Seen
                </span>
                <p className="text-sm text-slate-200 mt-0.5">
                  {new Date(selectedIOC.first_seen).toLocaleDateString(
                    undefined,
                    { month: "short", day: "numeric", year: "numeric" },
                  )}
                </p>
              </div>
            </div>
          </div>

          {/* MITRE Technique Tags */}
          {(selectedIOC.mitre_tags ?? []).length > 0 && (
            <div>
              <SectionHeader>MITRE ATT&CK Techniques</SectionHeader>
              <div className="flex flex-wrap gap-2">
                {(selectedIOC.mitre_tags ?? []).map((tag) => (
                  <MitreTagBadge key={tag.technique_id} tag={tag} />
                ))}
              </div>
            </div>
          )}

          {/* CTI Enrichment Data */}
          {enrichment_data && (
            <div>
              <SectionHeader>CTI Enrichment</SectionHeader>
              <div className="space-y-3">
                {/* VirusTotal */}
                {enrichment_data.virus_total && (
                  <div className="bg-slate-900 rounded-lg p-4 border border-slate-800" data-testid="ioc-detail-virustotal">
                    <div className="flex items-center gap-2 mb-3">
                      <Shield className="w-4 h-4 text-blue-400" aria-hidden="true" />
                      <span className="text-sm font-medium text-slate-200">
                        VirusTotal
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div>
                        <span className="text-slate-500">Detections</span>
                        <p className="text-slate-200 font-medium">
                          <span
                            className={
                              enrichment_data.virus_total.positives > 5
                                ? "text-red-400"
                                : enrichment_data.virus_total.positives > 0
                                  ? "text-amber-400"
                                  : "text-green-400"
                            }
                          >
                            {enrichment_data.virus_total.positives}
                          </span>
                          /{enrichment_data.virus_total.total}
                        </p>
                      </div>
                      <div>
                        <span className="text-slate-500">Reputation</span>
                        <p className="text-slate-200 font-medium">
                          {enrichment_data.virus_total.reputation}
                        </p>
                      </div>
                      <div className="col-span-2">
                        <span className="text-slate-500">Last Analysis</span>
                        <p className="text-slate-200">
                          {new Date(
                            enrichment_data.virus_total.last_analysis_date,
                          ).toLocaleString()}
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* Shodan */}
                {enrichment_data.shodan && (
                  <div className="bg-slate-900 rounded-lg p-4 border border-slate-800" data-testid="ioc-detail-shodan">
                    <div className="flex items-center gap-2 mb-3">
                      <Server className="w-4 h-4 text-orange-400" aria-hidden="true" />
                      <span className="text-sm font-medium text-slate-200">
                        Shodan
                      </span>
                    </div>
                    <div className="space-y-2 text-xs">
                      <div>
                        <span className="text-slate-500">Open Ports</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {(enrichment_data.shodan.ports ?? []).map((port) => (
                            <span
                              key={port}
                              className="px-1.5 py-0.5 bg-slate-800 rounded text-slate-300 font-mono"
                            >
                              {port}
                            </span>
                          ))}
                        </div>
                      </div>
                      {(enrichment_data.shodan.vulns ?? []).length > 0 && (
                        <div>
                          <span className="text-slate-500">
                            Vulnerabilities
                          </span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {(enrichment_data.shodan.vulns ?? []).map((vuln) => (
                              <span
                                key={vuln}
                                className="px-1.5 py-0.5 bg-red-500/15 rounded text-red-400 font-mono text-[10px]"
                              >
                                {vuln}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                      <div className="grid grid-cols-2 gap-2">
                        <div>
                          <span className="text-slate-500">ISP</span>
                          <p className="text-slate-200">
                            {enrichment_data.shodan.isp ?? "N/A"}
                          </p>
                        </div>
                        <div>
                          <span className="text-slate-500">Location</span>
                          <p className="text-slate-200">
                            {enrichment_data.shodan.city ?? "Unknown"},{" "}
                            {enrichment_data.shodan.country ?? "Unknown"}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* GreyNoise */}
                {enrichment_data.grey_noise && (
                  <div className="bg-slate-900 rounded-lg p-4 border border-slate-800" data-testid="ioc-detail-greynoise">
                    <div className="flex items-center gap-2 mb-3">
                      <Globe className="w-4 h-4 text-teal-400" aria-hidden="true" />
                      <span className="text-sm font-medium text-slate-200">
                        GreyNoise
                      </span>
                    </div>
                    <div className="grid grid-cols-3 gap-3 text-xs">
                      <div>
                        <span className="text-slate-500">Classification</span>
                        <p
                          className={`font-medium ${
                            enrichment_data.grey_noise.classification ===
                            "malicious"
                              ? "text-red-400"
                              : enrichment_data.grey_noise.classification ===
                                  "benign"
                                ? "text-green-400"
                                : "text-slate-300"
                          }`}
                        >
                          {enrichment_data.grey_noise.classification}
                        </p>
                      </div>
                      <div>
                        <span className="text-slate-500">Noise</span>
                        <p className="text-slate-200">
                          {enrichment_data.grey_noise.noise ? "Yes" : "No"}
                        </p>
                      </div>
                      <div>
                        <span className="text-slate-500">RIOT</span>
                        <p className="text-slate-200">
                          {enrichment_data.grey_noise.riot ? "Yes" : "No"}
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* AbuseIPDB */}
                {enrichment_data.abuse_ipdb && (
                  <div className="bg-slate-900 rounded-lg p-4 border border-slate-800" data-testid="ioc-detail-abuseipdb">
                    <div className="flex items-center gap-2 mb-3">
                      <AlertTriangle className="w-4 h-4 text-red-400" aria-hidden="true" />
                      <span className="text-sm font-medium text-slate-200">
                        AbuseIPDB
                      </span>
                    </div>
                    <div className="grid grid-cols-2 gap-3 text-xs">
                      <div>
                        <span className="text-slate-500">Abuse Score</span>
                        <p
                          className={`text-lg font-bold ${
                            enrichment_data.abuse_ipdb
                              .abuse_confidence_score > 75
                              ? "text-red-400"
                              : enrichment_data.abuse_ipdb
                                    .abuse_confidence_score > 30
                                ? "text-amber-400"
                                : "text-green-400"
                          }`}
                        >
                          {enrichment_data.abuse_ipdb.abuse_confidence_score}%
                        </p>
                      </div>
                      <div>
                        <span className="text-slate-500">Total Reports</span>
                        <p className="text-lg font-bold text-slate-200">
                          {enrichment_data.abuse_ipdb.total_reports}
                        </p>
                      </div>
                      <div>
                        <span className="text-slate-500">ISP</span>
                        <p className="text-slate-200">
                          {enrichment_data.abuse_ipdb.isp}
                        </p>
                      </div>
                      <div>
                        <span className="text-slate-500">Usage</span>
                        <p className="text-slate-200">
                          {enrichment_data.abuse_ipdb.usage_type}
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {/* MISP */}
                {enrichment_data.misp && (
                  <div className="bg-slate-900 rounded-lg p-4 border border-slate-800" data-testid="ioc-detail-misp">
                    <div className="flex items-center gap-2 mb-3">
                      <Shield className="w-4 h-4 text-indigo-400" aria-hidden="true" />
                      <span className="text-sm font-medium text-slate-200">
                        MISP
                      </span>
                      <Badge className="text-[10px]">
                        {enrichment_data.misp.event_count ?? 0} events
                      </Badge>
                    </div>
                    {(enrichment_data.misp.events ?? []).length > 0 && (
                      <div className="space-y-2">
                        {(enrichment_data.misp.events ?? []).slice(0, 5).map((evt) => (
                          <div
                            key={evt.id}
                            className="flex items-start gap-2 py-1.5 border-b border-slate-800 last:border-0 text-xs"
                          >
                            <span className="text-slate-500 shrink-0">
                              {evt.date}
                            </span>
                            <span className="text-slate-300">{evt.info}</span>
                          </div>
                        ))}
                      </div>
                    )}
                    {(enrichment_data.misp.tags ?? []).length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-2">
                        {(enrichment_data.misp.tags ?? []).map((tag) => (
                          <span
                            key={tag}
                            className="px-1.5 py-0.5 bg-indigo-500/15 rounded text-indigo-400 text-[10px]"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Enrichment Timeline */}
          {(enrichment_data?.raw_results ?? []).length > 0 && (
              <div>
                <SectionHeader>Enrichment Timeline</SectionHeader>
                <div className="space-y-2">
                  {(enrichment_data?.raw_results ?? []).map((result, idx) => (
                    <div
                      key={idx}
                      className="flex items-center gap-3 text-xs py-2 border-b border-slate-800/50 last:border-0"
                    >
                      <EnrichmentStatusIcon status={result.status} />
                      <div className="flex-1">
                        <span className="text-slate-200 font-medium">
                          {result.source}
                        </span>
                        {result.error && (
                          <p className="text-red-400 text-[10px] mt-0.5">
                            {result.error}
                          </p>
                        )}
                      </div>
                      <div className="flex items-center gap-1 text-slate-500">
                        <Clock className="w-3 h-3" aria-hidden="true" />
                        {new Date(result.timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

          {/* Related IOCs */}
          {(selectedIOC.related_ioc_ids ?? []).length > 0 && (
            <div>
              <SectionHeader>
                Related IOCs ({(selectedIOC.related_ioc_ids ?? []).length})
              </SectionHeader>
              <div className="space-y-2" data-testid="ioc-detail-related-list">
                {(selectedIOC.related_ioc_ids ?? []).map((relatedId) => (
                  <button
                    key={relatedId}
                    onClick={() => {
                      const { selectIOC } = useIOCStore.getState();
                      selectIOC(relatedId);
                    }}
                    className="flex items-center gap-2 w-full text-left px-3 py-2 bg-slate-900 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors"
                    aria-label={`Open related IOC ${relatedId}`}
                    data-testid={`ioc-detail-related-item-${relatedId}`}
                  >
                    <Link2 className="w-3.5 h-3.5 text-slate-500 shrink-0" aria-hidden="true" />
                    <span className="font-mono text-xs text-slate-300 truncate">
                      {relatedId}
                    </span>
                    <ExternalLink className="w-3 h-3 text-slate-600 shrink-0 ml-auto" aria-hidden="true" />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Investigation link */}
          {selectedIOC.investigation_id && (
            <div>
              <SectionHeader>Investigation</SectionHeader>
              <a
                href={`/investigations/${selectedIOC.investigation_id}`}
                className="flex items-center gap-2 px-3 py-2.5 bg-slate-900 rounded-lg border border-slate-800 hover:border-slate-700 transition-colors"
                aria-label={`Open investigation ${selectedIOC.investigation_title ?? selectedIOC.investigation_id}`}
                data-testid="ioc-detail-investigation-link"
              >
                <span className="text-xs text-slate-300">
                  {selectedIOC.investigation_title ??
                    selectedIOC.investigation_id}
                </span>
                <ExternalLink className="w-3 h-3 text-slate-500 ml-auto" aria-hidden="true" />
              </a>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
