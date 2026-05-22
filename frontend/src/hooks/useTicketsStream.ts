import * as React from "react"
import { fetchEventSource } from "@microsoft/fetch-event-source"
import { useQueryClient } from "@tanstack/react-query"

import type {
  ListTicketsResponse,
  TicketListItem,
  TicketSeverity,
  TicketStatus,
  TicketTab,
  UserRole,
} from "@/api/soc"
import { API_BASE_URL } from "@/lib/api"
import { getAccessToken } from "@/lib/tokens"

type TicketStreamEventType =
  | "aggregating_created"
  | "aggregating_updated"
  | "aggregating_closed"
  | "ticket_created"

type TicketStreamEvent = {
  type: TicketStreamEventType
  ticket?: TicketListItem
  window_id?: string
  ticket_id?: string
}

type TicketQueryFilters = {
  page?: number
  limit?: number
  status?: TicketStatus | "all"
  severity?: TicketSeverity | "all"
  assignee?: "all" | "me"
  tab?: TicketTab
  role?: UserRole
  user_id?: string
}

type TicketsQueryKey = ["tickets", TicketQueryFilters]

const L1_ACTIVE_STATUSES: TicketStatus[] = ["OPEN", "IN_PROGRESS"]
const L1_HISTORY_STATUSES: TicketStatus[] = [
  "IN_PROGRESS",
  "ESCALATED",
  "INVESTIGATING",
  "FALSE_POSITIVE",
  "RESOLVED",
]
const L2_ACTIVE_STATUSES: TicketStatus[] = ["ESCALATED", "INVESTIGATING"]
const L2_HISTORY_STATUSES: TicketStatus[] = ["INVESTIGATING", "FALSE_POSITIVE", "RESOLVED"]

function allowedStatusesForRoleTab(role: UserRole | undefined, tab: TicketTab | undefined) {
  if (!role || !tab) return []
  if (role === "L1_ANALYST") {
    return tab === "active" ? L1_ACTIVE_STATUSES : L1_HISTORY_STATUSES
  }
  if (role === "L2_ANALYST") {
    return tab === "active" ? L2_ACTIVE_STATUSES : L2_HISTORY_STATUSES
  }
  return []
}

function shouldApplyToQuery(filters: TicketQueryFilters, item: TicketListItem) {
  if (filters.assignee === "me") {
    return false
  }
  if (item.status === "AGGREGATING" && filters.role === "L1_ANALYST" && filters.tab === "active") {
    return true
  }
  if ((filters.role === "L1_ANALYST" || filters.role === "L2_ANALYST") && filters.user_id) {
    if (item.assignee_id !== filters.user_id) {
      return false
    }
  }
  if (filters.status && filters.status !== "all" && item.status !== filters.status) {
    return false
  }
  if (!filters.status || filters.status === "all") {
    const allowed = allowedStatusesForRoleTab(filters.role, filters.tab)
    if (allowed.length > 0 && !allowed.includes(item.status)) {
      return false
    }
  }
  if (filters.severity && filters.severity !== "all" && item.severity !== filters.severity) {
    return false
  }
  return true
}

function upsertTicketItem(
  items: TicketListItem[],
  nextItem: TicketListItem,
  matchId: string | undefined
) {
  const idToMatch = matchId ?? nextItem.id
  const idx = items.findIndex((item) => item.id === idToMatch)
  if (idx === -1) {
    return [nextItem, ...items]
  }
  const copy = items.slice()
  copy[idx] = { ...copy[idx], ...nextItem }
  return copy
}

function removeWindowItem(items: TicketListItem[], windowId: string | undefined) {
  if (!windowId) return items
  return items.filter((item) => item.id !== windowId)
}

export function useTicketsStream(input: { enabled: boolean }) {
  const { enabled } = input
  const qc = useQueryClient()

  React.useEffect(() => {
    if (!enabled) return

    const access = getAccessToken()
    if (!access) return

    const ctrl = new AbortController()

    void fetchEventSource(new URL("/api/v1/tickets/stream", API_BASE_URL).toString(), {
      method: "GET",
      signal: ctrl.signal,
      openWhenHidden: true,
      headers: {
        Authorization: `Bearer ${access}`,
        Accept: "text/event-stream",
      },
      onmessage(ev) {
        if (ev.event !== "ticket") return
        let parsed: TicketStreamEvent
        try {
          parsed = JSON.parse(ev.data) as TicketStreamEvent
        } catch {
          return
        }

        const ticketItem = parsed.ticket
        const windowId = parsed.window_id ?? parsed.ticket?.id

        const queries = qc.getQueryCache().findAll({ queryKey: ["tickets"] })
        for (const query of queries) {
          const key = query.queryKey as TicketsQueryKey
          const filters = key[1] ?? {}

          qc.setQueryData<ListTicketsResponse>(key, (prev) => {
            if (!prev) return prev
            let nextData = prev.data

            if (parsed.type === "aggregating_closed") {
              nextData = removeWindowItem(nextData, parsed.window_id)
            }

            if (!ticketItem) {
              if (nextData === prev.data) return prev
              return { ...prev, data: nextData }
            }

            if (!shouldApplyToQuery(filters, ticketItem)) {
              if (nextData === prev.data) return prev
              return { ...prev, data: nextData }
            }

            switch (parsed.type) {
              case "aggregating_created":
              case "aggregating_updated":
                nextData = upsertTicketItem(nextData, ticketItem, windowId)
                break
              case "aggregating_closed":
              case "ticket_created":
                nextData = upsertTicketItem(nextData, ticketItem, ticketItem.id)
                break
              default:
                break
            }

            if (nextData === prev.data) return prev
            return { ...prev, data: nextData }
          })
        }
      },
    })

    return () => {
      ctrl.abort()
    }
  }, [enabled, qc])
}
