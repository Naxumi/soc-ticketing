import { clearTokens, getAccessToken, getRefreshToken, setTokens } from "@/lib/tokens"

export const API_BASE_URL =
  (import.meta.env.VITE_API_BASE_URL as string | undefined) ??
  "http://localhost:8080"

export type ApiErrorDetail = {
  code: string
  message: string
  details?: Record<string, string>
}

export type ApiEnvelope<T> = {
  success: boolean
  message?: string
  data?: T
  error?: ApiErrorDetail
  meta?: {
    page?: number
    limit?: number
    total_items?: number
    total_pages?: number
  }
}

export class ApiError extends Error {
  readonly status: number
  readonly code: string
  readonly details?: Record<string, string>

  constructor(input: { status: number; code: string; message: string; details?: Record<string, string> }) {
    super(input.message)
    this.name = "ApiError"
    this.status = input.status
    this.code = input.code
    this.details = input.details
  }
}

type TokenResponse = {
  access_token: string
  refresh_token: string
  access_token_expires_in: number
  refresh_token_expires_in: number
}

let refreshInFlight: Promise<void> | null = null

async function refreshTokens(): Promise<void> {
  const refreshToken = getRefreshToken()
  if (!refreshToken) {
    throw new ApiError({ status: 401, code: "UNAUTHORIZED", message: "Missing refresh token" })
  }

  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      const res = await fetch(new URL("/api/v1/auth/refresh", API_BASE_URL), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      })

      const body = (await res.json().catch(() => null)) as ApiEnvelope<TokenResponse> | null
      if (!res.ok || !body?.success || !body.data) {
        const err = body?.error
        clearTokens()
        throw new ApiError({
          status: res.status || 401,
          code: err?.code ?? "UNAUTHORIZED",
          message: err?.message ?? "Refresh failed",
          details: err?.details,
        })
      }

      setTokens({ accessToken: body.data.access_token, refreshToken: body.data.refresh_token })
    })().finally(() => {
      refreshInFlight = null
    })
  }

  return refreshInFlight
}

function toApiError(res: Response, body: ApiEnvelope<unknown> | null): ApiError {
  const err = body?.error
  return new ApiError({
    status: res.status,
    code: err?.code ?? "HTTP_ERROR",
    message: err?.message ?? res.statusText,
    details: err?.details,
  })
}

export async function apiRequest<T>(
  path: string,
  init: RequestInit & { auth?: boolean } = {}
): Promise<T> {
  const url = new URL(path, API_BASE_URL)
  const auth = init.auth ?? true

  const headers = new Headers(init.headers)
  headers.set("Accept", "application/json")

  if (init.body && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json")
  }

  if (auth) {
    const access = getAccessToken()
    if (access) {
      headers.set("Authorization", `Bearer ${access}`)
    }
  }

  const doFetch = async (): Promise<Response> =>
    fetch(url, {
      ...init,
      headers,
    })

  let res = await doFetch()

  if (res.status === 401 && auth) {
    // Attempt one refresh + retry.
    try {
      await refreshTokens()
    } catch {
      throw new ApiError({ status: 401, code: "UNAUTHORIZED", message: "Unauthorized" })
    }

    const access = getAccessToken()
    if (access) {
      headers.set("Authorization", `Bearer ${access}`)
    }
    res = await doFetch()
  }

  const body = (await res.json().catch(() => null)) as ApiEnvelope<T> | null
  if (!res.ok || !body) {
    throw toApiError(res, body as ApiEnvelope<unknown> | null)
  }
  if (!body.success) {
    throw toApiError(res, body as ApiEnvelope<unknown> | null)
  }

  return body.data as T
}

export async function apiDownload(
  path: string,
  init: RequestInit & { auth?: boolean } = {},
): Promise<Blob> {
  const url = new URL(path, API_BASE_URL)
  const auth = init.auth ?? true

  const headers = new Headers(init.headers)
  if (!headers.has("Accept")) {
    headers.set("Accept", "*/*")
  }

  if (auth) {
    const access = getAccessToken()
    if (access) {
      headers.set("Authorization", `Bearer ${access}`)
    }
  }

  const doFetch = async (): Promise<Response> =>
    fetch(url, {
      ...init,
      headers,
    })

  let res = await doFetch()

  if (res.status === 401 && auth) {
    try {
      await refreshTokens()
    } catch {
      throw new ApiError({ status: 401, code: "UNAUTHORIZED", message: "Unauthorized" })
    }

    const access = getAccessToken()
    if (access) {
      headers.set("Authorization", `Bearer ${access}`)
    }
    res = await doFetch()
  }

  if (!res.ok) {
    // Try to parse the standard envelope error, else fall back to HTTP status.
    const body = (await res.json().catch(() => null)) as ApiEnvelope<unknown> | null
    throw toApiError(res, body)
  }

  return res.blob()
}
