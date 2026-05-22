import * as React from "react"

import { socApi, type Me } from "@/api/soc"
import { ApiError } from "@/lib/api"
import { clearTokens, getAccessToken, getRefreshToken, setTokens } from "@/lib/tokens"

type AuthContextValue = {
  me: Me | null
  isBootstrapping: boolean
  login: (input: { username: string; password: string }) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = React.createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [me, setMe] = React.useState<Me | null>(null)
  const [isBootstrapping, setIsBootstrapping] = React.useState(true)

  const bootstrap = React.useCallback(async () => {
    const hasAnyToken = Boolean(getAccessToken() || getRefreshToken())
    if (!hasAnyToken) {
      setMe(null)
      setIsBootstrapping(false)
      return
    }

    try {
      const user = await socApi.me()
      setMe(user)
    } catch (err) {
      // If refresh fails, apiRequest clears tokens.
      if (err instanceof ApiError && err.status === 401) {
        clearTokens()
      }
      setMe(null)
    } finally {
      setIsBootstrapping(false)
    }
  }, [])

  React.useEffect(() => {
    void bootstrap()
  }, [bootstrap])

  const login = React.useCallback(async (input: { username: string; password: string }) => {
    const tokens = await socApi.login(input)
    setTokens({ accessToken: tokens.access_token, refreshToken: tokens.refresh_token })
    const user = await socApi.me()
    setMe(user)
  }, [])

  const logout = React.useCallback(async () => {
    const refresh = getRefreshToken()
    try {
      if (refresh) {
        await socApi.logout(refresh)
      }
    } catch {
      // Best-effort.
    } finally {
      clearTokens()
      setMe(null)
    }
  }, [])

  const value: AuthContextValue = {
    me,
    isBootstrapping,
    login,
    logout,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = React.useContext(AuthContext)
  if (!ctx) throw new Error("useAuth must be used within AuthProvider")
  return ctx
}
