import * as React from "react"
import { useNavigate } from "react-router-dom"
import { AlertCircle, Lock, User, Shield, CheckCircle } from "lucide-react"

import { ApiError } from "@/lib/api"
import { useAuth } from "@/auth/AuthContext"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export function LoginPage() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [username, setUsername] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [submitting, setSubmitting] = React.useState(false)
  const [error, setError] = React.useState<string | null>(null)
  const [focusedField, setFocusedField] = React.useState<string | null>(null)

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await login({ username, password })
      navigate("/tickets", { replace: true })
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message)
      } else {
        setError("Login failed")
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="min-h-svh flex flex-col lg:flex-row overflow-hidden bg-background">
      {/* Left Side - Brand & Features
          Light mode: bright blue-50 gradient
          Dark mode: deep navy gradient */}
      <div className="hidden lg:flex lg:w-1/2 bg-gradient-to-br from-brand-blue-50 via-brand-blue-100 to-white dark:from-brand-blue-800 dark:via-brand-blue-900 dark:to-brand-blue-800 relative overflow-hidden flex-col justify-between p-12">
        {/* Decorative background blobs */}
        <div className="absolute top-0 left-0 w-96 h-96 bg-brand-yellow-300/20 dark:bg-brand-blue-600/20 rounded-full blur-3xl -translate-x-1/2 -translate-y-1/2"></div>
        <div className="absolute bottom-0 right-0 w-96 h-96 bg-brand-blue-200/30 dark:bg-brand-yellow-500/10 rounded-full blur-3xl translate-x-1/2 translate-y-1/2"></div>
        <div className="absolute top-1/2 left-1/2 w-64 h-64 bg-brand-yellow-200/20 dark:bg-brand-yellow-500/5 rounded-full blur-2xl -translate-x-1/2 -translate-y-1/2"></div>

        {/* Content */}
        <div className="relative z-10">
          <div className="flex items-center gap-3 mb-8">
            <div className="p-3 bg-brand-yellow-500 rounded-lg shadow-lg shadow-brand-yellow-500/20">
              <Shield className="w-8 h-8 text-brand-blue-900" />
            </div>
            <div>
              <h1 className="text-3xl font-bold text-brand-blue-800 dark:text-white">SOC Ticketing System</h1>
              <p className="text-brand-blue-500 dark:text-brand-blue-300 text-sm">Vokasi UB • Security Operations</p>
            </div>
          </div>
          <p className="text-xl text-brand-blue-600 dark:text-brand-blue-200 mb-12 max-w-sm leading-relaxed">
            Advanced AI-powered security operations center for intelligent threat detection and analysis.
          </p>
        </div>

        {/* Features List */}
        <div className="relative z-10 space-y-4">
          <div className="flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-brand-yellow-600 dark:text-brand-yellow-500 flex-shrink-0 mt-1" />
            <div>
              <p className="text-brand-blue-800 dark:text-white font-medium">AI-Powered Analysis</p>
              <p className="text-brand-blue-500 dark:text-brand-blue-300 text-sm">Real-time threat intelligence</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-brand-yellow-600 dark:text-brand-yellow-500 flex-shrink-0 mt-1" />
            <div>
              <p className="text-brand-blue-800 dark:text-white font-medium">Intelligent Categorization</p>
              <p className="text-brand-blue-500 dark:text-brand-blue-300 text-sm">Automated threat classification</p>
            </div>
          </div>
          <div className="flex items-start gap-3">
            <CheckCircle className="w-5 h-5 text-brand-yellow-600 dark:text-brand-yellow-500 flex-shrink-0 mt-1" />
            <div>
              <p className="text-brand-blue-800 dark:text-white font-medium">Actionable Insights</p>
              <p className="text-brand-blue-500 dark:text-brand-blue-300 text-sm">Recommended remediation steps</p>
            </div>
          </div>
        </div>
      </div>

      {/* Right Side - Login Form */}
      <div className="w-full lg:w-1/2 flex items-center justify-center p-4 sm:p-8">
        <div className="w-full max-w-md">
          {/* Mobile header */}
          <div className="lg:hidden mb-8 text-center">
            <div className="flex justify-center mb-4">
              <div className="p-3 bg-brand-yellow-500 rounded-lg">
                <Shield className="w-8 h-8 text-brand-blue-900" />
              </div>
            </div>
            <h1 className="text-2xl font-bold text-foreground">SOC Ticketing System</h1>
            <p className="text-muted-foreground mt-2">Vokasi UB • Security Operations</p>
          </div>

          <Card className="border-0 shadow-xl">
            <CardHeader className="space-y-2">
              <CardTitle className="text-2xl">Welcome Back</CardTitle>
              <CardDescription>Sign in to your security operations account</CardDescription>
            </CardHeader>
            <CardContent>
              <form className="space-y-5" onSubmit={onSubmit}>
                {/* Username Field */}
                <div className="space-y-2">
                  <Label htmlFor="username" className="text-base font-medium">
                    Username
                  </Label>
                  <div className="relative">
                    <User className="absolute left-3 top-3 w-5 h-5 text-muted-foreground pointer-events-none" />
                    <Input
                      id="username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      onFocus={() => setFocusedField("username")}
                      onBlur={() => setFocusedField(null)}
                      autoComplete="username"
                      className={`pl-10 h-11 transition-all ${
                        focusedField === "username"
                          ? "ring-2 ring-brand-yellow-500/50 border-brand-yellow-500"
                          : ""
                      }`}
                      placeholder="Enter your username"
                      required
                    />
                  </div>
                </div>

                {/* Password Field */}
                <div className="space-y-2">
                  <Label htmlFor="password" className="text-base font-medium">
                    Password
                  </Label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-3 w-5 h-5 text-muted-foreground pointer-events-none" />
                    <Input
                      id="password"
                      type="password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      onFocus={() => setFocusedField("password")}
                      onBlur={() => setFocusedField(null)}
                      autoComplete="current-password"
                      className={`pl-10 h-11 transition-all ${
                        focusedField === "password"
                          ? "ring-2 ring-brand-yellow-500/50 border-brand-yellow-500"
                          : ""
                      }`}
                      placeholder="Enter your password"
                      required
                    />
                  </div>
                </div>

                {/* Error Message */}
                {error && (
                  <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3 flex items-start gap-2 animate-in fade-in slide-in-from-top-2">
                    <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
                    <p className="text-sm text-red-600">{error}</p>
                  </div>
                )}

                {/* Submit Button — brand-yellow-500 with dark text */}
                <Button
                  className="w-full h-11 text-base font-semibold bg-brand-yellow-500 text-brand-blue-900 hover:bg-brand-yellow-600 transition-all shadow-lg hover:shadow-xl active:scale-[0.98]"
                  type="submit"
                  disabled={submitting}
                >
                  {submitting ? (
                    <span className="flex items-center gap-2">
                      <div className="w-4 h-4 border-2 border-brand-blue-900 border-t-transparent rounded-full animate-spin" />
                      Signing in…
                    </span>
                  ) : (
                    "Sign in"
                  )}
                </Button>

                {/* Footer */}
                <div className="text-center text-sm text-muted-foreground pt-2">
                  <p>
                    Secure access for authorized personnel only.
                    <br />
                    <span className="text-xs">All activities are monitored and logged.</span>
                  </p>
                </div>
              </form>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
