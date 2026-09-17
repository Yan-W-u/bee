import { type SVGProps } from 'react'

export function OpenAIcon({ className, size = 24, ...props }: SVGProps<SVGSVGElement> & { size?: number }) {
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill="none" className={className} {...props}>
      <path d="M12 2C6.477 2 2 6.477 2 12s4.477 10 10 10 10-4.477 10-10S17.523 2 12 2z" fill="#10A37F" />
      <path d="M17.5 9.5l-1.5-2.5-1.5 2.5H13v5h1.5l1.5 2.5 1.5-2.5H19v-5h-1.5z" fill="#fff" />
      <path d="M7.5 14.5L6 12l1.5-2.5H9V7h1.5L12 4.5l1.5 2.5H15v2.5h1.5l1.5 2.5" fill="none" stroke="#fff" strokeWidth="1.2" />
    </svg>
  )
}

export function DeepSeekIcon({ className, size = 24, ...props }: SVGProps<SVGSVGElement> & { size?: number }) {
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill="none" className={className} {...props}>
      <rect width="24" height="24" rx="6" fill="#4F46E5" />
      <path d="M6 8h3l3 8 3-8h3" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="12" cy="12" r="1.5" fill="#fff" />
    </svg>
  )
}

export function AnthropicIcon({ className, size = 24, ...props }: SVGProps<SVGSVGElement> & { size?: number }) {
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill="none" className={className} {...props}>
      <rect width="24" height="24" rx="6" fill="#D97706" />
      <path d="M12 4l-5 16h3l1.2-4h5.6l1.2 4h3L16 4h-4z" fill="none" stroke="#fff" strokeWidth="1.5" strokeLinejoin="round" />
      <path d="M8.5 14h7" stroke="#fff" strokeWidth="1" />
    </svg>
  )
}

export function GoogleAIIcon({ className, size = 24, ...props }: SVGProps<SVGSVGElement> & { size?: number }) {
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill="none" className={className} {...props}>
      <rect width="24" height="24" rx="6" fill="#1A73E8" />
      <path d="M12 5a7 7 0 0 1 5.5 2.8l-2.5 2A3.5 3.5 0 0 0 12 8.5a3.5 3.5 0 0 0-3.2 2.2L5.5 8C7 6 9.3 5 12 5z" fill="#EA4335" />
      <path d="M8.8 13.3a3.5 3.5 0 0 1 0-2.6L5.5 8C3.5 11.5 5 16 8.5 17.5l3-2.5a3.5 3.5 0 0 1-2.7-1.7z" fill="#FBBC04" />
      <path d="M12 15.5a3.5 3.5 0 0 0 3.5-3.5H12v-2h6.5c.3 1 .3 2 0 3A7 7 0 0 1 12 19l-3.5-2.5 3 2.5z" fill="#34A853" />
      <path d="M12 15.5a3.5 3.5 0 0 1-3-1.5l-3.5 2.5A7 7 0 0 0 12 19l3.5-2.5-3 2.5z" fill="#4285F4" />
    </svg>
  )
}

export function OllamaIcon({ className, size = 24, ...props }: SVGProps<SVGSVGElement> & { size?: number }) {
  return (
    <svg viewBox="0 0 24 24" width={size} height={size} fill="none" className={className} {...props}>
      <rect width="24" height="24" rx="6" fill="#1E293B" stroke="#475569" strokeWidth="1" />
      <path d="M7 9h2v6H7zM11 7h2v8h-2zM15 9h2v6h-2z" fill="#64748B" />
      <circle cx="8" cy="8" r="1" fill="#F59E0B" />
      <circle cx="12" cy="6" r="1" fill="#F59E0B" />
      <circle cx="16" cy="8" r="1" fill="#F59E0B" />
    </svg>
  )
}