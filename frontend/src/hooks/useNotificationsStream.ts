import * as React from "react"
import { fetchEventSource } from "@microsoft/fetch-event-source"

import type { NotificationListItem } from "@/api/soc"
import { API_BASE_URL } from "@/lib/api"
import { getAccessToken } from "@/lib/tokens"

export function useNotificationsStream(input: {
  enabled: boolean
  onNotification: (n: NotificationListItem) => void
}) {
  const { enabled, onNotification } = input
  const onNotificationRef = React.useRef(onNotification)

  React.useEffect(() => {
    onNotificationRef.current = onNotification
  }, [onNotification])

  React.useEffect(() => {
    if (!enabled) return

    const access = getAccessToken()
    if (!access) return

    const ctrl = new AbortController()

    void fetchEventSource(new URL("/api/v1/notifications/stream", API_BASE_URL).toString(), {
      method: "GET",
      signal: ctrl.signal,
      openWhenHidden: true,
      headers: {
        Authorization: `Bearer ${access}`,
        Accept: "text/event-stream",
      },
      onmessage(ev) {
        if (ev.event !== "notification") return
        try {
          const parsed = JSON.parse(ev.data) as NotificationListItem
          onNotificationRef.current(parsed)
        } catch {
          // Ignore malformed event.
        }
      },
    })

    return () => {
      ctrl.abort()
    }
  }, [enabled])
}
