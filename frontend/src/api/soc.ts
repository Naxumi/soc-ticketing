import { apiDownload, apiRequest } from "@/lib/api"

export type UserRole = "L1_ANALYST" | "L2_ANALYST" | "SOC_MANAGER"
export type AnalystRole = Extract<UserRole, "L1_ANALYST" | "L2_ANALYST">

export type Me = {
  id: string
  full_name: string
  username: string
  role: UserRole
  created_at: string
}

export type RegisterAnalystRequest = {
  full_name: string
  username: string
  password: string
  role: AnalystRole
}

export type RegisterAnalystResponse = {
  id: string
  full_name: string
  username: string
  role: UserRole
  created_at: string
}

export type ChangePasswordRequest = {
  old_password: string
  new_password: string
}

export type AdminUpdateAnalystRequest = {
  full_name?: string
  username?: string
  role?: AnalystRole
  password?: string
}

export type UserListItem = {
  id: string
  full_name: string
  username: string
  role: UserRole
  created_at: string
}

export type UserDetail = {
  id: string
  full_name: string
  username: string
  role: UserRole
  created_at: string
}

export type UserSessionItem = {
  id: string
  user_agent?: string | null
  ip_address?: string | null
  is_revoked: boolean
  expires_at: string
  created_at: string
}

export type UserTicketLogItem = {
  id: string
  ticket_id: string
  ticket_number: string
  source_ip: string
  threat_category?: string | null
  threat_type?: string | null
  severity?: string | null
  first_seen: string
  last_seen: string
  action: string
  note?: string | null
  created_at: string
}

export type UserDetailResponse = {
  user: UserDetail
  sessions: UserSessionItem[]
  ticket_logs: UserTicketLogItem[]
}

export type TokenResponse = {
  access_token: string
  access_token_expires_in: number
  refresh_token: string
  refresh_token_expires_in: number
}

export type TicketSeverity = "low" | "medium" | "high" | "critical"
export type TicketStatus =
  | "OPEN"
  | "IN_PROGRESS"
  | "ESCALATED"
  | "INVESTIGATING"
  | "FALSE_POSITIVE"
  | "RESOLVED"
  | "AGGREGATING"

export type TicketTab = "active" | "history"

export type TicketListItem = {
  id: string
  ticket_number?: string
  source_ip: string
  attack_rule_id: string
  threat_category?: string | null
  threat_type?: string | null
  severity?: TicketSeverity | null
  status: TicketStatus
  assignee_id?: string | null
  assignee_name?: string | null
  first_seen: string
  last_seen: string
  raw_log_count: number
  is_aggregating?: boolean
  window_expires_at?: string | null
  window_seconds?: number | null
}

export type ListTicketsResponse = {
  metadata: {
    total_data: number
    page: number
    total_pages: number
  }
  data: TicketListItem[]
}

export type TicketDetailResponse = {
  ticket: {
    id: string
    ticket_number?: string
    source_ip: string
    attack_rule_id: string
    threat_category?: string | null
    threat_type?: string | null
    severity?: TicketSeverity | null
    status: TicketStatus
    assignee_id?: string | null
    first_seen: string
    last_seen: string
    raw_log_count: number
    payload_first?: unknown
    payload_last?: unknown
    payload_sample?: unknown
    created_at: string
    updated_at: string
  }
  analysis?: {
    model_name: string
    summary?: string | null
    detailed_analysis?: string | null
    attack_vector?: string | null
    potential_impact?: string | null
    confidence_score?: number | null
    processing_time_ms?: number | null
    created_at: string
  } | null
  recommendations: Array<{ priority: number; action: string; reason?: string | null }>
  iocs: Array<{ ioc_type: string; ioc_value: string }>
  audit_logs: Array<{ action: string; note?: string | null; created_at: string; user_full_name?: string | null; user_role?: string | null }>
  raw_logs: Array<{
    wazuh_event_id?: string | null
    source_ip: string
    attack_rule_id: string
    event_timestamp: string
    raw_payload: unknown
    created_at: string
  }>
}

export type AnalyzeTicketResponse = {
  forwarded_to: string
  status_code: number
  engine_status?: string
  request_id?: string
  saved?: boolean
  response?: unknown
}

export type AnalyzeTicketRequest = {
  note?: string
  model_name?: string
  response_language?: "id" | "en"
}

export type AIModelsResponse = {
  models: string[]
}

export type UpdateTicketStatusRequest = {
  status: TicketStatus
  assignee_id?: string | null
  note: string
}

export type NotificationListItem = {
  id: string
  ticket_id?: string | null
  message: string
  is_read: boolean
  created_at: string
}

export type ListNotificationsResponse = {
  metadata: {
    total_data: number
    page: number
    total_pages: number
  }
  data: NotificationListItem[]
}

export type DashboardTimeWindow = {
  from: string
  to: string
  range: string
}

export type DashboardL1Focus = {
  unassigned_open: number
  open_high_critical: number
  my_in_progress: number
}

export type DashboardL2Focus = {
  escalated: number
  investigating: number
  unassigned_escalated_or_investigating: number
  my_investigating: number
}

export type DashboardFocusSection = {
  l1?: DashboardL1Focus | null
  l2?: DashboardL2Focus | null
}

export type DashboardTicketsSection = {
  backlog_by_status: Partial<Record<TicketStatus, number>>
  backlog_by_severity: Record<string, number>
  my_by_status: Partial<Record<TicketStatus, number>>
  created_in_window: number
  created_by_severity_in_window: Record<string, number>
  recent_in_window: TicketListItem[]
}

export type DashboardTeamAssigneeWorkload = {
  user_id: string
  full_name: string
  username: string
  role: UserRole
  active_by_status: Partial<Record<TicketStatus, number>>
  total_active: number
}

export type DashboardTeamSection = {
  unassigned_active: number
  assignees: DashboardTeamAssigneeWorkload[]
}

export type DashboardResponse = {
  window: DashboardTimeWindow
  role: UserRole
  unread_notifications: number
  tickets: DashboardTicketsSection
  focus?: DashboardFocusSection | null
  team?: DashboardTeamSection | null
  generated_at: string
  generated_at_unix: number
}

export const socApi = {
  login: (input: { username: string; password: string }) =>
    apiRequest<TokenResponse>("/api/v1/auth/login", {
      method: "POST",
      auth: false,
      body: JSON.stringify(input),
    }),

  logout: (refreshToken: string) =>
    apiRequest<null>("/api/v1/auth/logout", {
      method: "POST",
      auth: false,
      body: JSON.stringify({ refresh_token: refreshToken }),
    }),

  changePassword: (input: ChangePasswordRequest) =>
    apiRequest<null>("/api/v1/auth/change-password", {
      method: "POST",
      body: JSON.stringify(input),
    }),

  me: () => apiRequest<Me>("/api/v1/auth/me"),

  registerAnalyst: (input: RegisterAnalystRequest) =>
    apiRequest<RegisterAnalystResponse>("/api/v1/auth/register", {
      method: "POST",
      body: JSON.stringify(input),
    }),

  adminUpdateAnalyst: (id: string, input: AdminUpdateAnalystRequest) =>
    apiRequest<null>(`/api/v1/auth/users/${id}`, {
      method: "PATCH",
      body: JSON.stringify(input),
    }),

  listUsers: () => apiRequest<UserListItem[]>("/api/v1/users"),

  getUserDetail: (id: string) => apiRequest<UserDetailResponse>(`/api/v1/users/${id}`),

  revokeUserSessions: (id: string, input?: { session_id?: string }) =>
    apiRequest<null>(`/api/v1/users/${id}/sessions/revoke`, {
      method: "POST",
      body: input ? JSON.stringify(input) : undefined,
    }),

  deleteAnalyst: (id: string) =>
    apiRequest<null>(`/api/v1/users/${id}`, {
      method: "DELETE",
    }),

  listTickets: (q: {
    page: number
    limit: number
    status?: TicketStatus
    severity?: TicketSeverity
    assignee_id?: string
    tab?: TicketTab
  }) => {
    const params = new URLSearchParams({ page: String(q.page), limit: String(q.limit) })
    if (q.status) params.set("status", q.status)
    if (q.severity) params.set("severity", q.severity)
    if (q.assignee_id) params.set("assignee_id", q.assignee_id)
    if (q.tab) params.set("tab", q.tab)
    return apiRequest<ListTicketsResponse>(`/api/v1/tickets?${params.toString()}`)
  },

  ticketDetail: (id: string) => apiRequest<TicketDetailResponse>(`/api/v1/tickets/${id}`),

  updateTicketStatus: (id: string, input: UpdateTicketStatusRequest) =>
    apiRequest<null>(`/api/v1/tickets/${id}/status`, {
      method: "PATCH",
      body: JSON.stringify(input),
    }),

  analyzeTicket: (id: string, input: AnalyzeTicketRequest = {}) =>
    apiRequest<AnalyzeTicketResponse>(`/api/v1/tickets/${id}/analyze`, {
      method: "POST",
      body: JSON.stringify(input),
    }),

  listAiModels: () => apiRequest<AIModelsResponse>("/api/v1/ai/models"),

  listNotifications: (q: { page: number; limit: number; is_read?: boolean }) => {
    const params = new URLSearchParams({ page: String(q.page), limit: String(q.limit) })
    if (q.is_read !== undefined) params.set("is_read", String(q.is_read))
    return apiRequest<ListNotificationsResponse>(`/api/v1/notifications?${params.toString()}`)
  },

  markNotificationRead: (id: string) =>
    apiRequest<null>(`/api/v1/notifications/${id}/read`, {
      method: "PATCH",
    }),

  dashboard: (q: { range?: string; from?: string; to?: string; recent_limit?: number } = {}) => {
    const params = new URLSearchParams()
    if (q.range) params.set("range", q.range)
    if (q.from) params.set("from", q.from)
    if (q.to) params.set("to", q.to)
    if (typeof q.recent_limit === "number") params.set("recent_limit", String(q.recent_limit))
    const qs = params.toString()
    return apiRequest<DashboardResponse>(`/api/v1/dashboard${qs ? `?${qs}` : ""}`)
  },

  exportTicketsCSV: (q: {
    range?: string
    from?: string
    to?: string
    status?: TicketStatus
    severity?: TicketSeverity
    assignee_id?: string
    limit?: number
  } = {}) => {
    const params = new URLSearchParams()
    if (q.range) params.set("range", q.range)
    if (q.from) params.set("from", q.from)
    if (q.to) params.set("to", q.to)
    if (q.status) params.set("status", q.status)
    if (q.severity) params.set("severity", q.severity)
    if (q.assignee_id) params.set("assignee_id", q.assignee_id)
    if (typeof q.limit === "number") params.set("limit", String(q.limit))
    const qs = params.toString()
    return apiDownload(`/api/v1/reports/tickets.csv${qs ? `?${qs}` : ""}`, {
      headers: { Accept: "text/csv" },
    })
  },

  exportTicketsPDF: (q: {
    range?: string
    from?: string
    to?: string
    status?: TicketStatus
    severity?: TicketSeverity
    assignee_id?: string
    limit?: number
  } = {}) => {
    const params = new URLSearchParams()
    if (q.range) params.set("range", q.range)
    if (q.from) params.set("from", q.from)
    if (q.to) params.set("to", q.to)
    if (q.status) params.set("status", q.status)
    if (q.severity) params.set("severity", q.severity)
    if (q.assignee_id) params.set("assignee_id", q.assignee_id)
    if (typeof q.limit === "number") params.set("limit", String(q.limit))
    const qs = params.toString()
    return apiDownload(`/api/v1/reports/tickets.pdf${qs ? `?${qs}` : ""}`, {
      headers: { Accept: "application/pdf" },
    })
  },
}
