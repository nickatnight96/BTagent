"""Integration nodes -- one Node (or a small set of Nodes) per vendor.

Sprint 1 shipped the GreyNoise reference Node. Sprint 2 ports the rest
of the BTagent connector surface: Splunk, CrowdStrike, Sentinel, Elastic,
VirusTotal, Shodan, AbuseIPDB, MISP. All 9 honour
``BTAGENT_MOCK_CONNECTORS=true`` and raise ``NotImplementedError`` on the
production path until Sprint 3+ wires the live HTTP clients through the
credential vault.
"""

from btagent_engine.integrations.abuseipdb import (
    AbuseIPDBCheckInput,
    AbuseIPDBCheckNode,
    AbuseIPDBCheckOutput,
)
from btagent_engine.integrations.crowdstrike import (
    CrowdStrikeIsolateHostInput,
    CrowdStrikeIsolateHostNode,
    CrowdStrikeIsolateHostOutput,
    CrowdStrikeListDetectionsInput,
    CrowdStrikeListDetectionsNode,
    CrowdStrikeListDetectionsOutput,
)
from btagent_engine.integrations.elastic import (
    ElasticSearchInput,
    ElasticSearchNode,
    ElasticSearchOutput,
)
from btagent_engine.integrations.greynoise import (
    GreyNoiseLookupIPInput,
    GreyNoiseLookupIPNode,
    GreyNoiseLookupIPOutput,
)
from btagent_engine.integrations.misp import (
    MISPGetEventInput,
    MISPGetEventNode,
    MISPGetEventOutput,
    MISPSearchAttributeInput,
    MISPSearchAttributeNode,
    MISPSearchAttributeOutput,
)
from btagent_engine.integrations.sentinel import (
    SentinelKQLQueryInput,
    SentinelKQLQueryNode,
    SentinelKQLQueryOutput,
)
from btagent_engine.integrations.shodan import (
    ShodanHostLookupInput,
    ShodanHostLookupNode,
    ShodanHostLookupOutput,
)
from btagent_engine.integrations.splunk import (
    SplunkSearchInput,
    SplunkSearchNode,
    SplunkSearchOutput,
)
from btagent_engine.integrations.virustotal import (
    VirusTotalDomainLookupInput,
    VirusTotalDomainLookupNode,
    VirusTotalDomainLookupOutput,
    VirusTotalHashLookupInput,
    VirusTotalHashLookupNode,
    VirusTotalHashLookupOutput,
    VirusTotalIPLookupInput,
    VirusTotalIPLookupNode,
    VirusTotalIPLookupOutput,
)

__all__ = [
    "AbuseIPDBCheckInput",
    "AbuseIPDBCheckNode",
    "AbuseIPDBCheckOutput",
    "CrowdStrikeIsolateHostInput",
    "CrowdStrikeIsolateHostNode",
    "CrowdStrikeIsolateHostOutput",
    "CrowdStrikeListDetectionsInput",
    "CrowdStrikeListDetectionsNode",
    "CrowdStrikeListDetectionsOutput",
    "ElasticSearchInput",
    "ElasticSearchNode",
    "ElasticSearchOutput",
    "GreyNoiseLookupIPInput",
    "GreyNoiseLookupIPNode",
    "GreyNoiseLookupIPOutput",
    "MISPGetEventInput",
    "MISPGetEventNode",
    "MISPGetEventOutput",
    "MISPSearchAttributeInput",
    "MISPSearchAttributeNode",
    "MISPSearchAttributeOutput",
    "SentinelKQLQueryInput",
    "SentinelKQLQueryNode",
    "SentinelKQLQueryOutput",
    "ShodanHostLookupInput",
    "ShodanHostLookupNode",
    "ShodanHostLookupOutput",
    "SplunkSearchInput",
    "SplunkSearchNode",
    "SplunkSearchOutput",
    "VirusTotalDomainLookupInput",
    "VirusTotalDomainLookupNode",
    "VirusTotalDomainLookupOutput",
    "VirusTotalHashLookupInput",
    "VirusTotalHashLookupNode",
    "VirusTotalHashLookupOutput",
    "VirusTotalIPLookupInput",
    "VirusTotalIPLookupNode",
    "VirusTotalIPLookupOutput",
]
