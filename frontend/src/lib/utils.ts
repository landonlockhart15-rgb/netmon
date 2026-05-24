import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

const TFMT: Intl.DateTimeFormatOptions = { hour: '2-digit', minute: '2-digit', second: '2-digit' }
const DFMT: Intl.DateTimeFormatOptions = { month: 'short', day: 'numeric', year: 'numeric' }
const DTFMT: Intl.DateTimeFormatOptions = { ...DFMT, ...TFMT }

export const fmtTime = (d: string | number | Date) => new Date(d).toLocaleTimeString('en-US', TFMT)
export const fmtDate = (d: string | number | Date) => new Date(d).toLocaleDateString('en-US', DFMT)
export const fmtDateTime = (d: string | number | Date) => new Date(d).toLocaleString('en-US', DTFMT)

export function formatRelativeTime(iso: string): string {
  const diff = (Date.now() - new Date(iso).getTime()) / 1000
  if (diff < 60) return 'just now'
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export function humanBytes(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`
  if (n < 1073741824) return `${(n / 1048576).toFixed(1)} MB`
  return `${(n / 1073741824).toFixed(2)} GB`
}

export function escapeHtml(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

export function clamp(v: number, min: number, max: number) {
  return Math.min(max, Math.max(min, v))
}
