import * as React from "react"
import { useMutation } from "@tanstack/react-query"
import { toast } from "sonner"
import { Loader2Icon, XIcon } from "lucide-react"

import { socApi } from "@/api/soc"
import { useAuth } from "@/auth/AuthContext"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

interface ChangePasswordModalProps {
  open: boolean
  onClose: () => void
}

export function ChangePasswordModal({ open, onClose }: ChangePasswordModalProps) {
  const { logout } = useAuth()
  const [oldPassword, setOldPassword] = React.useState("")
  const [newPassword, setNewPassword] = React.useState("")

  const changePwdMutation = useMutation({
    mutationFn: () =>
      socApi.changePassword({
        old_password: oldPassword,
        new_password: newPassword,
      }),
    onSuccess: async () => {
      toast.success("Password changed successfully. Please log in again.")
      onClose()
      await logout()
    },
    onError: (err: Error) => {
      toast.error(err.message || "Failed to change password")
    },
  })

  // Reset state when opened
  React.useEffect(() => {
    if (open) {
      setOldPassword("")
      setNewPassword("")
    }
  }, [open])

  if (!open) return null

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!oldPassword || !newPassword) {
      toast.error("Please fill in all fields")
      return
    }
    if (newPassword.length < 8) {
      toast.error("New password must be at least 8 characters")
      return
    }
    changePwdMutation.mutate()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4 backdrop-blur-sm">
      <div className="w-full max-w-md overflow-hidden rounded-xl bg-white shadow-2xl dark:bg-brand-blue-800">
        <div className="flex items-center justify-between border-b border-border p-4 dark:border-brand-blue-600/30">
          <h2 className="text-lg font-semibold text-brand-blue-800 dark:text-white">Change Password</h2>
          <Button variant="ghost" size="icon-sm" onClick={onClose} disabled={changePwdMutation.isPending}>
            <XIcon className="size-4" />
          </Button>
        </div>

        <form onSubmit={handleSubmit} className="p-4">
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="old-password">Current Password</Label>
              <Input
                id="old-password"
                type="password"
                placeholder="Enter current password"
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
                required
                disabled={changePwdMutation.isPending}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="new-password">New Password</Label>
              <Input
                id="new-password"
                type="password"
                placeholder="Enter new password (min. 8 characters)"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                minLength={8}
                disabled={changePwdMutation.isPending}
              />
            </div>
          </div>

          <div className="mt-6 flex justify-end gap-3">
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
              disabled={changePwdMutation.isPending}
            >
              Cancel
            </Button>
            <Button type="submit" disabled={changePwdMutation.isPending}>
              {changePwdMutation.isPending && <Loader2Icon className="mr-2 size-4 animate-spin" />}
              Save Changes
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}
