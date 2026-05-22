import { Link } from "react-router-dom"
import {
  ShieldIcon,
  BrainCircuitIcon,
  TicketIcon,
  BellRingIcon,
  ActivityIcon,
  UsersIcon,
  ChevronRightIcon,
  ZapIcon,
  LayersIcon,
  BarChart3Icon,
  ArrowRightIcon,
  CheckCircle2Icon,
  GlobeIcon,
  LockIcon,
  ServerIcon,
} from "lucide-react"
import { Button } from "@/components/ui/button"

/* ─── Reusable components ─── */

function FeatureCard({
  icon,
  title,
  description,
}: {
  icon: React.ReactNode
  title: string
  description: string
}) {
  return (
    <div className="group relative rounded-2xl border border-brand-blue-100 bg-white p-6 shadow-sm transition-all duration-300 hover:border-brand-yellow-500/40 hover:shadow-lg hover:-translate-y-1 dark:border-brand-blue-600/30 dark:bg-brand-blue-800/60">
      <div className="mb-4 flex size-12 items-center justify-center rounded-xl bg-brand-yellow-500/10 text-brand-yellow-600 transition-colors group-hover:bg-brand-yellow-500/20 dark:text-brand-yellow-500">
        {icon}
      </div>
      <h3 className="mb-2 text-lg font-semibold text-brand-blue-800 dark:text-white">
        {title}
      </h3>
      <p className="text-sm leading-relaxed text-brand-blue-500 dark:text-brand-blue-300">
        {description}
      </p>
    </div>
  )
}

function StepCard({
  number,
  title,
  description,
}: {
  number: string
  title: string
  description: string
}) {
  return (
    <div className="relative flex flex-col items-center text-center">
      <div className="mb-4 flex size-14 items-center justify-center rounded-full bg-brand-yellow-500 text-xl font-bold text-brand-blue-900 shadow-lg shadow-brand-yellow-500/20">
        {number}
      </div>
      <h3 className="mb-2 text-base font-semibold text-brand-blue-800 dark:text-white">
        {title}
      </h3>
      <p className="text-sm leading-relaxed text-brand-blue-500 dark:text-brand-blue-300">
        {description}
      </p>
    </div>
  )
}

function StatItem({ value, label }: { value: string; label: string }) {
  return (
    <div className="text-center">
      <div className="text-3xl font-bold text-brand-yellow-500 sm:text-4xl">{value}</div>
      <div className="mt-1 text-sm text-brand-blue-400 dark:text-brand-blue-300">{label}</div>
    </div>
  )
}

/* ─── Main Landing Page ─── */

export function LandingPage() {
  return (
    <div className="min-h-svh bg-background text-foreground">
      {/* ═══════════ Navbar ═══════════ */}
      <nav className="sticky top-0 z-50 border-b border-brand-blue-100/60 bg-white/80 backdrop-blur-lg dark:border-brand-blue-600/30 dark:bg-brand-blue-900/80">
        <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="flex size-9 items-center justify-center rounded-lg bg-brand-yellow-500">
              <ShieldIcon className="size-5 text-brand-blue-900" />
            </div>
            <div className="flex flex-col leading-tight">
              <span className="text-sm font-bold tracking-wider text-brand-blue-800 dark:text-white">
                SOC <span className="text-brand-yellow-600 dark:text-brand-yellow-500">Ticketing</span>
              </span>
              <span className="text-[10px] font-medium tracking-wide text-brand-blue-400 dark:text-brand-blue-300">
                VOKASI UB
              </span>
            </div>
          </Link>
          <div className="flex items-center gap-3">
            <Link to="/login">
              <Button variant="ghost" size="sm" className="text-brand-blue-600 hover:text-brand-blue-800 dark:text-brand-blue-200">
                Masuk
              </Button>
            </Link>
            <Link to="/login">
              <Button size="sm">
                Buka Dashboard
                <ChevronRightIcon className="ml-1 size-4" />
              </Button>
            </Link>
          </div>
        </div>
      </nav>

      {/* ═══════════ Hero ═══════════ */}
      <section className="relative overflow-hidden">
        {/* Decorative blobs */}
        <div className="pointer-events-none absolute -top-40 left-1/2 h-[500px] w-[700px] -translate-x-1/2 rounded-full bg-brand-yellow-300/15 blur-3xl dark:bg-brand-yellow-500/5" />
        <div className="pointer-events-none absolute -right-32 top-20 h-80 w-80 rounded-full bg-brand-blue-100/40 blur-3xl dark:bg-brand-blue-600/10" />

        <div className="relative mx-auto max-w-6xl px-4 pb-20 pt-16 sm:px-6 sm:pt-24 lg:pt-32">
          <div className="mx-auto max-w-3xl text-center">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-brand-yellow-500/30 bg-brand-yellow-500/10 px-4 py-1.5 text-xs font-semibold text-brand-yellow-700 dark:text-brand-yellow-400">
              <ZapIcon className="size-3.5" />
              AI-Powered Security Operations
            </div>

            <h1 className="text-4xl font-extrabold leading-tight tracking-tight text-brand-blue-900 sm:text-5xl lg:text-6xl dark:text-white">
              Security Operations Center{" "}
              <span className="bg-gradient-to-r from-brand-yellow-600 to-brand-yellow-400 bg-clip-text text-transparent">
                Ticketing System
              </span>
            </h1>

            <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-brand-blue-500 dark:text-brand-blue-300">
              Sistem tiket SOC berbasis AI untuk deteksi ancaman cerdas, kategorisasi otomatis,
              dan respons insiden yang lebih cepat. Dibangun untuk Program Studi Vokasi
              Universitas Brawijaya.
            </p>

            <div className="mt-10 flex flex-col items-center gap-4 sm:flex-row sm:justify-center">
              <Link to="/login">
                <Button size="lg" className="h-12 px-8 text-base shadow-lg shadow-brand-yellow-500/20">
                  Masuk ke Dashboard
                  <ArrowRightIcon className="ml-2 size-4" />
                </Button>
              </Link>
              <a href="#features">
                <Button variant="outline" size="lg" className="h-12 px-8 text-base">
                  Pelajari Fitur
                </Button>
              </a>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════ Stats Bar ═══════════ */}
      <section className="border-y border-brand-blue-100/60 bg-brand-blue-50/50 py-12 dark:border-brand-blue-600/20 dark:bg-brand-blue-800/30">
        <div className="mx-auto grid max-w-4xl grid-cols-2 gap-8 px-4 sm:grid-cols-4 sm:px-6">
          <StatItem value="24/7" label="Monitoring" />
          <StatItem value="<5s" label="Alert Response" />
          <StatItem value="AI" label="Threat Analysis" />
          <StatItem value="L1–L2" label="Tiered Analysts" />
        </div>
      </section>

      {/* ═══════════ Features ═══════════ */}
      <section id="features" className="py-20 sm:py-28">
        <div className="mx-auto max-w-6xl px-4 sm:px-6">
          <div className="mx-auto mb-16 max-w-2xl text-center">
            <h2 className="text-3xl font-bold text-brand-blue-900 sm:text-4xl dark:text-white">
              Fitur Utama
            </h2>
            <p className="mt-4 text-brand-blue-500 dark:text-brand-blue-300">
              Platform SOC yang lengkap untuk mengelola insiden keamanan dari deteksi hingga resolusi.
            </p>
          </div>

          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            <FeatureCard
              icon={<BrainCircuitIcon className="size-6" />}
              title="Analisis AI Otomatis"
              description="Analisis ancaman menggunakan model LLM (Groq) untuk menghasilkan ringkasan, vektor serangan, dampak potensial, dan rekomendasi aksi secara otomatis."
            />
            <FeatureCard
              icon={<TicketIcon className="size-6" />}
              title="Manajemen Tiket SOC"
              description="Alur kerja tiket lengkap dari OPEN → IN_PROGRESS → ESCALATED → INVESTIGATING → RESOLVED, dengan catatan audit dan assignment analis."
            />
            <FeatureCard
              icon={<BellRingIcon className="size-6" />}
              title="Notifikasi Real-time"
              description="Server-Sent Events (SSE) untuk notifikasi instan ketika tiket baru dibuat, status berubah, atau alert baru terdeteksi."
            />
            <FeatureCard
              icon={<ActivityIcon className="size-6" />}
              title="Aggregasi Alert Cerdas"
              description="Pengelompokan otomatis alert dari Wazuh berdasarkan source IP dan rule ID dalam jendela waktu, mengurangi noise secara signifikan."
            />
            <FeatureCard
              icon={<BarChart3Icon className="size-6" />}
              title="Dashboard & Reporting"
              description="Dashboard real-time dengan statistik backlog, workload tim, dan tren ancaman. Ekspor laporan ke CSV dan PDF."
            />
            <FeatureCard
              icon={<UsersIcon className="size-6" />}
              title="Manajemen Tim SOC"
              description="Kelola analis L1 dan L2 dengan role-based access control. SOC Manager dapat membuat, mengedit, dan menonaktifkan akun analis."
            />
          </div>
        </div>
      </section>

      {/* ═══════════ How It Works ═══════════ */}
      <section className="border-y border-brand-blue-100/60 bg-brand-blue-50/30 py-20 sm:py-28 dark:border-brand-blue-600/20 dark:bg-brand-blue-800/20">
        <div className="mx-auto max-w-6xl px-4 sm:px-6">
          <div className="mx-auto mb-16 max-w-2xl text-center">
            <h2 className="text-3xl font-bold text-brand-blue-900 sm:text-4xl dark:text-white">
              Cara Kerja
            </h2>
            <p className="mt-4 text-brand-blue-500 dark:text-brand-blue-300">
              Dari alert Wazuh hingga resolusi insiden dalam empat langkah sederhana.
            </p>
          </div>

          <div className="grid gap-12 sm:grid-cols-2 lg:grid-cols-4">
            <StepCard
              number="1"
              title="Wazuh Alert Masuk"
              description="Alert keamanan dari Wazuh SIEM dikirim melalui webhook API dan secara otomatis diagregasi."
            />
            <StepCard
              number="2"
              title="Tiket Dibuat"
              description="Setelah jendela agregasi selesai, sistem membuat tiket dengan raw logs dan metadata lengkap."
            />
            <StepCard
              number="3"
              title="AI Menganalisis"
              description="Analis memicu analisis AI yang menghasilkan ringkasan ancaman, IOC, dan rekomendasi aksi."
            />
            <StepCard
              number="4"
              title="Insiden Diselesaikan"
              description="Analis menangani tiket melalui alur kerja terstruktur hingga resolusi atau false positive."
            />
          </div>
        </div>
      </section>

      {/* ═══════════ Architecture / Integrations ═══════════ */}
      <section className="py-20 sm:py-28">
        <div className="mx-auto max-w-6xl px-4 sm:px-6">
          <div className="mx-auto mb-16 max-w-2xl text-center">
            <h2 className="text-3xl font-bold text-brand-blue-900 sm:text-4xl dark:text-white">
              Arsitektur & Integrasi
            </h2>
            <p className="mt-4 text-brand-blue-500 dark:text-brand-blue-300">
              Dibangun dengan stack modern dan terintegrasi dengan tool keamanan industri.
            </p>
          </div>

          <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
            {/* Tech cards */}
            {[
              {
                icon: <ServerIcon className="size-5" />,
                title: "Backend Go (Chi)",
                desc: "REST API performa tinggi dengan Go, Chi router, dan PostgreSQL.",
              },
              {
                icon: <LayersIcon className="size-5" />,
                title: "Frontend React + Vite",
                desc: "SPA modern dengan React 19, TailwindCSS v4, shadcn/ui, dan TypeScript.",
              },
              {
                icon: <ShieldIcon className="size-5" />,
                title: "Wazuh SIEM",
                desc: "Integrasi webhook untuk menerima alert keamanan secara real-time dari Wazuh.",
              },
              {
                icon: <BrainCircuitIcon className="size-5" />,
                title: "Groq LLM API",
                desc: "Analisis ancaman otomatis menggunakan model Llama 3.3 70B melalui Groq API.",
              },
              {
                icon: <LockIcon className="size-5" />,
                title: "JWT Authentication",
                desc: "Autentikasi aman dengan access/refresh token dan role-based access control.",
              },
              {
                icon: <GlobeIcon className="size-5" />,
                title: "SSE Real-time",
                desc: "Server-Sent Events untuk notifikasi dan update tiket secara real-time.",
              },
            ].map((item) => (
              <div
                key={item.title}
                className="flex items-start gap-4 rounded-xl border border-brand-blue-100 bg-white p-5 dark:border-brand-blue-600/30 dark:bg-brand-blue-800/40"
              >
                <div className="flex size-10 shrink-0 items-center justify-center rounded-lg bg-brand-blue-50 text-brand-blue-600 dark:bg-brand-blue-600/30 dark:text-brand-blue-300">
                  {item.icon}
                </div>
                <div>
                  <div className="font-semibold text-brand-blue-800 dark:text-white">{item.title}</div>
                  <div className="mt-1 text-sm text-brand-blue-500 dark:text-brand-blue-300">{item.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ═══════════ SOC Workflow ═══════════ */}
      <section className="border-y border-brand-blue-100/60 bg-brand-blue-50/30 py-20 sm:py-28 dark:border-brand-blue-600/20 dark:bg-brand-blue-800/20">
        <div className="mx-auto max-w-6xl px-4 sm:px-6">
          <div className="grid items-center gap-12 lg:grid-cols-2">
            <div>
              <h2 className="text-3xl font-bold text-brand-blue-900 sm:text-4xl dark:text-white">
                Alur Kerja Tiering SOC
              </h2>
              <p className="mt-4 text-brand-blue-500 dark:text-brand-blue-300">
                Sistem mendukung model tiering SOC standar industri dengan pembagian peran yang jelas.
              </p>

              <div className="mt-8 space-y-5">
                {[
                  {
                    role: "SOC Manager",
                    desc: "Mengelola tim, melihat dashboard global, ekspor laporan, dan mengatur akun analis.",
                  },
                  {
                    role: "L1 Analyst (Triage)",
                    desc: "Menerima tiket baru, melakukan triase awal, memicu analisis AI, dan eskalasi jika diperlukan.",
                  },
                  {
                    role: "L2 Analyst (Investigation)",
                    desc: "Menangani tiket yang dieskalasi, melakukan investigasi mendalam, dan menentukan resolusi akhir.",
                  },
                ].map((item) => (
                  <div key={item.role} className="flex items-start gap-3">
                    <CheckCircle2Icon className="mt-0.5 size-5 shrink-0 text-brand-yellow-600 dark:text-brand-yellow-500" />
                    <div>
                      <div className="font-semibold text-brand-blue-800 dark:text-white">{item.role}</div>
                      <div className="text-sm text-brand-blue-500 dark:text-brand-blue-300">{item.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Ticket lifecycle visual */}
            <div className="rounded-2xl border border-brand-blue-100 bg-white p-6 shadow-sm dark:border-brand-blue-600/30 dark:bg-brand-blue-800/50">
              <div className="mb-4 text-sm font-semibold text-brand-blue-800 dark:text-white">
                Siklus Hidup Tiket
              </div>
              <div className="flex flex-col gap-3">
                {[
                  { status: "AGGREGATING", color: "bg-gray-200 text-gray-700 dark:bg-gray-700 dark:text-gray-300" },
                  { status: "OPEN", color: "bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300" },
                  { status: "IN PROGRESS", color: "bg-brand-yellow-100 text-brand-yellow-700 dark:bg-brand-yellow-500/20 dark:text-brand-yellow-400" },
                  { status: "ESCALATED", color: "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400" },
                  { status: "INVESTIGATING", color: "bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400" },
                  { status: "RESOLVED", color: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400" },
                  { status: "FALSE POSITIVE", color: "bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400" },
                ].map((item, i, arr) => (
                  <div key={item.status} className="flex items-center gap-3">
                    <span className={`inline-flex min-w-[140px] items-center justify-center rounded-lg px-3 py-2 text-xs font-semibold ${item.color}`}>
                      {item.status}
                    </span>
                    {i < arr.length - 2 && (
                      <ChevronRightIcon className="size-4 text-brand-blue-300 dark:text-brand-blue-500" />
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ═══════════ CTA ═══════════ */}
      <section className="py-20 sm:py-28">
        <div className="mx-auto max-w-3xl px-4 text-center sm:px-6">
          <div className="rounded-3xl bg-gradient-to-br from-brand-blue-800 to-brand-blue-900 p-10 shadow-2xl sm:p-16">
            <ShieldIcon className="mx-auto mb-6 size-12 text-brand-yellow-500" />
            <h2 className="text-3xl font-bold text-white sm:text-4xl">
              Siap Memulai?
            </h2>
            <p className="mx-auto mt-4 max-w-lg text-brand-blue-200">
              Masuk ke dashboard untuk mulai mengelola insiden keamanan dengan bantuan AI.
            </p>
            <Link to="/login" className="mt-8 inline-block">
              <Button size="lg" className="h-12 px-10 text-base shadow-lg shadow-brand-yellow-500/30">
                Masuk ke Dashboard
                <ArrowRightIcon className="ml-2 size-4" />
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* ═══════════ Footer ═══════════ */}
      <footer className="border-t border-brand-blue-100/60 bg-brand-blue-50/50 py-10 dark:border-brand-blue-600/20 dark:bg-brand-blue-800/30">
        <div className="mx-auto max-w-6xl px-4 sm:px-6">
          <div className="flex flex-col items-center justify-between gap-6 sm:flex-row">
            <div className="flex items-center gap-2.5">
              <div className="flex size-8 items-center justify-center rounded-lg bg-brand-yellow-500">
                <ShieldIcon className="size-4 text-brand-blue-900" />
              </div>
              <div>
                <div className="text-sm font-bold text-brand-blue-800 dark:text-white">
                  SOC Ticketing System
                </div>
                <div className="text-xs text-brand-blue-400 dark:text-brand-blue-300">
                  Vokasi Universitas Brawijaya
                </div>
              </div>
            </div>

            <div className="text-center text-xs text-brand-blue-400 dark:text-brand-blue-300">
              Tugas Akhir — Program Studi Informatika, Fakultas Vokasi, Universitas Brawijaya
            </div>

            <div className="text-xs text-brand-blue-400 dark:text-brand-blue-300">
              &copy; {new Date().getFullYear()} Vokasi UB
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
