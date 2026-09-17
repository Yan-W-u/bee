import { type CSSProperties } from 'react'

interface BeeLogoProps {
  className?: string
  size?: number
  style?: CSSProperties
}

export function BeeLogo({ className, size = 32, style }: BeeLogoProps) {
  return (
    <img
      src="/bee-logo.png"
      alt="Bee Logo"
      className={className}
      style={{
        width: size,
        height: size,
        objectFit: 'contain',
        display: 'inline-block',
        ...style,
      }}
    />
  )
}
