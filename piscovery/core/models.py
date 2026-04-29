from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RenderType(Enum):
    SSR = "Server-Side Rendered"
    CSR = "Client-Side Rendered"
    STATIC = "Static"
    UNKNOWN = "Unknown"


@dataclass
class Config:
    target: str
    port_scan: bool = True
    llm_model: str = "gpt-4o"
    llm_api_key: str = ""
    llm_base_url: str = "https://api.openai.com/v1"
    headers: dict = field(default_factory=dict)
    max_depth: int = 3
    max_pages: int = 50
    concurrency: int = 5
    timeout: int = 30
    llm_timeout: int = 120
    output_file: str = ""
    target_url: str = ""
    nmap_args: str = ""
    render_wait: int = 0
    scan_budget: int = 1800
    path_depth_limit: int = 12
    query_variants_limit: int = 3
    block_heavy_resources: bool = True
    click_discovery: bool = False
    max_clicks_per_page: int = 6
    max_response_bytes: int = 5 * 1024 * 1024
    max_endpoint_analyses: int = 20
    endpoint_body_limit: int = 4096
    endpoint_body_total_cap: int = 2 * 1024 * 1024
    verbose: bool = False


@dataclass
class FormField:
    name: str = ""
    field_type: str = ""
    value: str = ""
    placeholder: str = ""
    required: bool = False


@dataclass
class FormInfo:
    action: str = ""
    method: str = "GET"
    fields: list = field(default_factory=list)
    enctype: str = ""


@dataclass
class XHREndpoint:
    url: str = ""
    method: str = "GET"
    resource_type: str = ""
    post_data: str = ""


@dataclass
class ResponseObservation:
    url: str = ""
    method: str = "GET"
    status_code: int = 0
    headers: dict = field(default_factory=dict)
    mime: str = ""
    body_preview: str = ""


@dataclass
class WebSocketObservation:
    url: str = ""
    sent_preview: str = ""
    received_preview: str = ""
    closed: bool = False
    close_code: int = 0


@dataclass
class EndpointInfo:
    url: str = ""
    raw_url_samples: list = field(default_factory=list)
    method: str = "GET"
    resource_type: str = ""
    post_data: str = ""
    status_code: int = 0
    response_headers: dict = field(default_factory=dict)
    response_body_preview: str = ""
    response_mime: str = ""
    observed_on_pages: list = field(default_factory=list)
    sample_count: int = 0
    interest_score: float = 0.0


@dataclass
class EndpointAnalysis:
    role: str = ""
    description: str = ""
    suggestions: list = field(default_factory=list)
    raw_response: str = ""


@dataclass
class EndpointReport:
    endpoint: Optional[EndpointInfo] = None
    analysis: Optional[EndpointAnalysis] = None


@dataclass
class PageInfo:
    url: str
    depth: int = 0
    status_code: int = 0
    title: str = ""
    render_type: RenderType = RenderType.UNKNOWN
    technologies: list = field(default_factory=list)
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)
    scripts: list = field(default_factory=list)
    parameters: dict = field(default_factory=dict)
    request_headers: dict = field(default_factory=dict)
    response_headers: dict = field(default_factory=dict)
    meta_tags: dict = field(default_factory=dict)
    cookies: list = field(default_factory=list)
    content_length: int = 0
    raw_html: str = ""
    rendered_html: str = ""
    xhr_endpoints: list = field(default_factory=list)
    responses: list = field(default_factory=list)
    ws_observations: list = field(default_factory=list)
    static_endpoint_hints: list = field(default_factory=list)
    manifest_url: str = ""


@dataclass
class AttackSuggestion:
    attack_type: str = ""
    target: str = ""
    reasoning: str = ""
    observation: str = ""


@dataclass
class LLMAnalysis:
    category: str = ""
    description: str = ""
    suggestions: list = field(default_factory=list)
    raw_response: str = ""


@dataclass
class PageReport:
    page: Optional[PageInfo] = None
    analysis: Optional[LLMAnalysis] = None
    triggered_endpoint_keys: list = field(default_factory=list)


@dataclass
class NmapResult:
    raw_output: str = ""
    open_ports: list = field(default_factory=list)
    services: dict = field(default_factory=dict)
    os_detection: str = ""


@dataclass
class ScanReport:
    target: str = ""
    target_url: str = ""
    render_type: RenderType = RenderType.UNKNOWN
    technologies: list = field(default_factory=list)
    nmap: Optional[NmapResult] = None
    sitemap_urls: list = field(default_factory=list)
    robots_info: dict = field(default_factory=dict)
    pages: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)
