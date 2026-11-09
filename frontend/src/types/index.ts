export type UserRole = 'Administrator' | 'Security Analyst' | 'Viewer';

export interface User {
  username: string;
  email: string;
  full_name: string;
  role: UserRole;
  created_at?: string;
  last_login?: string;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  role: UserRole;
  username: string;
  expires_in: number;
}

export interface SecurityLog {
  _id?: string;
  timestamp: string;
  server_id: string;
  server_name: string;
  source_ip: string;
  destination_ip?: string;
  event_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  username?: string | null;
  message: string;
  details?: Record<string, any>;
  integrity_hash: string;
  prev_hash?: string;
}

export interface LogListResponse {
  total: number;
  page: number;
  page_size: number;
  logs: SecurityLog[];
}

export interface SecurityAlert {
  _id?: string;
  alert_id: string;
  title: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'NEW' | 'INVESTIGATING' | 'RESOLVED' | 'FALSE_POSITIVE';
  rule_id: string;
  rule_name: string;
  source_ip?: string;
  target_user?: string;
  server_id?: string;
  timestamp: string;
  evidence_log_ids: string[];
  recommended_action: string;
  investigation_notes?: string;
  assigned_to?: string | null;
}

export interface AlertListResponse {
  total: number;
  page: number;
  page_size: number;
  alerts: SecurityAlert[];
}

export interface ServerAsset {
  _id?: string;
  server_id: string;
  hostname: string;
  ip_address: string;
  os_type: string;
  role: string;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  status: 'ACTIVE' | 'MAINTENANCE' | 'OFFLINE';
  description?: string;
  last_heartbeat?: string;
  log_count?: number;
}

export interface DetectionRule {
  _id?: string;
  rule_id: string;
  name: string;
  description: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  enabled: boolean;
  mitre_attack_id?: string;
  threshold: number;
  window_seconds: number;
  recommended_action: string;
  trigger_count?: number;
  last_triggered?: string | null;
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'IP' | 'User' | 'Server' | 'SecurityEvent' | 'Alert';
  properties: Record<string, any>;
}

export interface GraphEdge {
  source: string;
  target: string;
  type: string;
  properties?: Record<string, any>;
}

export interface GraphTopology {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface BlastRadiusResponse {
  focus: string;
  impacted_nodes: number;
  connected_servers: string[];
  connected_users: string[];
  connected_ips?: string[];
}

export interface AIAnalysisReport {
  alert_id: string;
  summary: string;
  threat_explanation: string;
  mitre_tactics: string[];
  attack_vector: string;
  blast_radius_assessment: string;
  recommended_mitigation: string[];
  confidence_score: number;
  model_used: string;
  is_fallback: boolean;
  analyzed_at: string;
}

export interface AIChatMessage {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

export interface AIChatResponse {
  response: string;
  model_used: string;
  is_fallback: boolean;
  suggestions: string[];
}

export interface DashboardAnalytics {
  kpis: {
    total_logs: number;
    total_alerts: number;
    critical_high_alerts: number;
    active_servers: number;
    by_severity: Record<string, number>;
    by_status: Record<string, number>;
  };
  top_ips: Array<{ ip: string; count: number }>;
  top_users: Array<{ user: string; count: number }>;
  top_servers: Array<{ server: string; count: number }>;
  event_distribution: Array<{ type: string; count: number }>;
  timeline: Array<{ time: string; events: number }>;
  recent_alerts: SecurityAlert[];
}
