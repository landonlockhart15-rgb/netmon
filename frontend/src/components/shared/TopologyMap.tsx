import { useState, useEffect, useRef, useMemo, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Router, Laptop, Smartphone, Cpu, Globe, Server, RefreshCw, Activity, HelpCircle, Zap, ShieldAlert, Clock, Play, Pause, SkipBack, SkipForward, UserPlus, Radio, GitCompare, WifiOff, ArrowRight, Layers } from 'lucide-react'
import { getTrafficDashboard, getNetworkInfo, getScans, getDevicesAtScan, type Device, type Scan } from '@/lib/api'
import { cn } from '@/lib/utils'

interface TopologyMapProps {
  devices: Device[]
  onSelect: (id: number) => void
}

interface Link {
  id: string
  from: string
  to: string
  active: boolean
  bytes: number
  packets: number
}

export default function TopologyMap({ devices, onSelect }: TopologyMapProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [dimensions, setDimensions] = useState({ width: 800, height: 500 })
  const [positionOverrides, setPositionOverrides] = useState<Record<string, { x: number; y: number }>>({})
  const [draggedNode, setDraggedNode] = useState<string | null>(null)
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)
  const [showInternet, setShowInternet] = useState(true)
  const [colorMode, setColorMode] = useState<'network' | 'security'>('network')
  // Temporal state: null = live, scan id = historical replay
  const [historicalScanId, setHistoricalScanId] = useState<number | null>(null)
  const [isPlaying, setIsPlaying] = useState(false)
  const [playbackSpeed] = useState(1500)

  // Snapshot Comparison (Diff) state
  const [isCompareMode, setIsCompareMode] = useState(false)
  const [comparePointAIndex, setComparePointAIndex] = useState<number>(0)
  const [comparePointBIndex, setComparePointBIndex] = useState<number>(0)

  // Fetch traffic dashboard for conversations
  const { data: dashboard } = useQuery({
    queryKey: ['traffic-dashboard'],
    queryFn: getTrafficDashboard,
    refetchInterval: 10_000,
  })

  // Fetch network info
  const { data: networkInfo } = useQuery({
    queryKey: ['network-info'],
    queryFn: getNetworkInfo,
  })

  // Fetch completed scan list for time machine slider
  const { data: scans } = useQuery({
    queryKey: ['scans'],
    queryFn: getScans,
    refetchInterval: 60_000,
    select: (data): Scan[] => data.filter(scan => scan.status === 'complete').reverse(),
  })

  const sliderScans = useMemo(() => (scans ? scans.slice(-20) : []), [scans])
  const liveIndex = sliderScans.length

  const currentIndex = useMemo(() => {
    if (historicalScanId === null) return liveIndex
    const idx = sliderScans.findIndex(s => s.id === historicalScanId)
    return idx === -1 ? liveIndex : idx
  }, [historicalScanId, sliderScans, liveIndex])

  const selectedScan = useMemo(() => {
    if (currentIndex < liveIndex) return sliderScans[currentIndex]
    return null
  }, [currentIndex, sliderScans, liveIndex])

  const previousScanId = useMemo(() => {
    if (currentIndex <= 0 || currentIndex > liveIndex) return null
    return sliderScans[currentIndex - 1]?.id ?? null
  }, [currentIndex, sliderScans, liveIndex])

  // Sync compare mode point indices when entering compare mode or when scans change
  useEffect(() => {
    if (sliderScans.length > 0 && comparePointBIndex === 0 && comparePointAIndex === 0) {
      setComparePointBIndex(liveIndex)
      setComparePointAIndex(Math.max(0, liveIndex - 1))
    }
  }, [sliderScans, liveIndex, comparePointAIndex, comparePointBIndex])

  const comparePointAScan = useMemo(() => {
    if (comparePointAIndex < liveIndex && sliderScans[comparePointAIndex]) {
      return sliderScans[comparePointAIndex]
    }
    return null
  }, [comparePointAIndex, sliderScans, liveIndex])

  const comparePointBScan = useMemo(() => {
    if (comparePointBIndex < liveIndex && sliderScans[comparePointBIndex]) {
      return sliderScans[comparePointBIndex]
    }
    return null
  }, [comparePointBIndex, sliderScans, liveIndex])

  const comparePointAId = comparePointAScan?.id ?? null
  const comparePointBId = comparePointBScan?.id ?? null

  // Fetch devices for Compare Point A (Baseline)
  const { data: rawPointADevices } = useQuery({
    queryKey: ['devices-at-scan', comparePointAId],
    queryFn: () => getDevicesAtScan(comparePointAId!),
    enabled: isCompareMode && comparePointAId !== null,
    select: (data) => (Array.isArray(data) ? data : []),
  })
  const pointADevices = useMemo(
    () => (comparePointAId !== null ? (rawPointADevices ?? []) : devices),
    [comparePointAId, rawPointADevices, devices]
  )

  // Fetch devices for Compare Point B (Target)
  const { data: rawPointBDevices } = useQuery({
    queryKey: ['devices-at-scan', comparePointBId],
    queryFn: () => getDevicesAtScan(comparePointBId!),
    enabled: isCompareMode && comparePointBId !== null,
    select: (data) => (Array.isArray(data) ? data : []),
  })
  const pointBDevices = useMemo(
    () => (comparePointBId !== null ? (rawPointBDevices ?? []) : devices),
    [comparePointBId, rawPointBDevices, devices]
  )

  // Compute detailed snapshot comparison diff between Point A and Point B
  const snapshotDiff = useMemo(() => {
    if (!isCompareMode) {
      return {
        newDeviceIds: new Set<number>(),
        disconnectedDevices: [] as Device[],
        changedDevices: new Map<number, { changes: string[]; detail: Record<string, { from: unknown; to: unknown }> }>(),
      }
    }

    const mapA = new Map<number, Device>()
    pointADevices.forEach(d => mapA.set(d.id, d))

    const mapB = new Map<number, Device>()
    pointBDevices.forEach(d => mapB.set(d.id, d))

    const newDeviceIds = new Set<number>()
    const disconnectedDevices: Device[] = []
    const changedDevices = new Map<number, { changes: string[]; detail: Record<string, { from: unknown; to: unknown }> }>()

    pointBDevices.forEach(dB => {
      const dA = mapA.get(dB.id)
      if (!dA) {
        newDeviceIds.add(dB.id)
      } else {
        const changes: string[] = []
        const detail: Record<string, { from: unknown; to: unknown }> = {}

        if (dA.ip && dB.ip && dA.ip !== dB.ip) {
          changes.push('IP Address')
          detail['IP Address'] = { from: dA.ip, to: dB.ip }
        }
        if (dA.hostname !== dB.hostname && (dA.hostname || dB.hostname)) {
          changes.push('Hostname')
          detail['Hostname'] = { from: dA.hostname || 'None', to: dB.hostname || 'None' }
        }
        const portsA = JSON.stringify([...(dA.open_ports || [])].sort())
        const portsB = JSON.stringify([...(dB.open_ports || [])].sort())
        if (portsA !== portsB) {
          changes.push('Open Ports')
          detail['Open Ports'] = { from: dA.open_ports?.join(', ') || 'None', to: dB.open_ports?.join(', ') || 'None' }
        }
        if (dA.trusted !== dB.trusted) {
          changes.push('Trust Role')
          detail['Trust Role'] = { from: dA.trusted ? 'Trusted' : 'Unknown', to: dB.trusted ? 'Trusted' : 'Unknown' }
        }

        if (changes.length > 0) {
          changedDevices.set(dB.id, { changes, detail })
        }
      }
    })

    pointADevices.forEach(dA => {
      if (!mapB.has(dA.id)) {
        disconnectedDevices.push(dA)
      }
    })

    return {
      newDeviceIds,
      disconnectedDevices,
      changedDevices,
    }
  }, [isCompareMode, pointADevices, pointBDevices])

  // Fetch previous scan devices to compute single-replay snapshot deltas
  const { data: previousDevices } = useQuery({
    queryKey: ['devices-at-scan', previousScanId],
    queryFn: () => getDevicesAtScan(previousScanId!),
    enabled: !isCompareMode && previousScanId !== null && historicalScanId !== null,
    select: (data) => (Array.isArray(data) ? data : []),
  })

  // Fetch historical devices when replaying a past scan in single replay mode
  const { data: historicalDevices } = useQuery({
    queryKey: ['devices-at-scan', historicalScanId],
    queryFn: () => getDevicesAtScan(historicalScanId!),
    enabled: !isCompareMode && historicalScanId !== null,
    select: (data) => (Array.isArray(data) ? data : []),
  })

  // The devices the map actually renders — live prop, historical snapshot, or compare mode combined set
  const displayDevices = useMemo(() => {
    if (isCompareMode) {
      return [...pointBDevices, ...snapshotDiff.disconnectedDevices]
    }
    return historicalScanId !== null ? (historicalDevices ?? []) : devices
  }, [isCompareMode, pointBDevices, snapshotDiff.disconnectedDevices, historicalScanId, historicalDevices, devices])

  // Identify devices newly added in current single snapshot relative to previous snapshot
  const newlyJoinedDeviceIds = useMemo(() => {
    if (isCompareMode) return snapshotDiff.newDeviceIds
    if (historicalScanId === null || !previousDevices || !previousDevices.length) return new Set<number>()
    const prevSet = new Set(previousDevices.map(d => d.id))
    const joined = new Set<number>()
    displayDevices.forEach(d => {
      if (!prevSet.has(d.id)) {
        joined.add(d.id)
      }
    })
    return joined
  }, [isCompareMode, snapshotDiff.newDeviceIds, historicalScanId, previousDevices, displayDevices])

  // Auto-play timer for synchronized time scrubber
  useEffect(() => {
    if (!isPlaying) return
    if (!sliderScans.length) return

    const interval = setInterval(() => {
      setHistoricalScanId(prevId => {
        const curIdx = prevId !== null ? sliderScans.findIndex(s => s.id === prevId) : liveIndex
        const nextIdx = curIdx + 1
        if (nextIdx >= liveIndex) {
          setIsPlaying(false)
          return null
        }
        return sliderScans[nextIdx].id
      })
    }, playbackSpeed)

    return () => clearInterval(interval)
  }, [isPlaying, sliderScans, liveIndex, playbackSpeed])

  const handleStepBack = () => {
    if (currentIndex > 0) {
      setHistoricalScanId(sliderScans[currentIndex - 1].id)
    }
  }

  const handleStepForward = () => {
    if (currentIndex < liveIndex - 1) {
      setHistoricalScanId(sliderScans[currentIndex + 1].id)
    } else if (currentIndex === liveIndex - 1) {
      setHistoricalScanId(null)
    }
  }

  const handleTogglePlay = () => {
    if (isPlaying) {
      setIsPlaying(false)
    } else {
      if (currentIndex >= liveIndex && sliderScans.length > 0) {
        setHistoricalScanId(sliderScans[0].id)
      }
      setIsPlaying(true)
    }
  }

  const gatewayIp = networkInfo?.gateway
  const conversations = dashboard?.conversations

  // Track dimensions
  useEffect(() => {
    if (!containerRef.current) return
    const updateSize = () => {
      setDimensions({
        width: containerRef.current?.clientWidth || 800,
        height: containerRef.current?.clientHeight || 500
      })
    }
    updateSize()
    window.addEventListener('resize', updateSize)
    return () => window.removeEventListener('resize', updateSize)
  }, [])

  // Helper: Is a device a gateway?
  const isGateway = useCallback((d: Device) => {
    if (d.ip === gatewayIp) return true
    if (d.ip.endsWith('.1') || d.ip.endsWith('.254')) return true
    const name = (d.hostname || d.label || '').toLowerCase()
    return name.includes('router') || name.includes('gateway') || name.includes('firewall')
  }, [gatewayIp])

  const gatewayDevice = useMemo(() => {
    return displayDevices.find(isGateway) || displayDevices[0]
  }, [displayDevices, isGateway])

  const defaultPositions = useMemo(() => {
    const { width, height } = dimensions
    const cx = width / 2
    const cy = height / 2
    const next: Record<string, { x: number; y: number }> = { internet: { x: cx, y: 70 } }
    const gatewayId = gatewayDevice ? `device-${gatewayDevice.id}` : 'gateway'
    next[gatewayId] = { x: cx, y: cy }
    const otherDevices = displayDevices.filter(d => d.id !== gatewayDevice?.id)
    otherDevices.forEach((device, index) => {
      const angle = (index / Math.max(1, otherDevices.length)) * 2 * Math.PI
      const radius = Math.min(cx * 0.65, cy * 0.65)
      next[`device-${device.id}`] = {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      }
    })
    return next
  }, [displayDevices, dimensions, gatewayDevice])

  const positions = useMemo(
    () => ({ ...defaultPositions, ...positionOverrides }),
    [defaultPositions, positionOverrides],
  )

  // Reset to default radial layout
  const resetLayout = () => {
    setPositionOverrides({})
  }

  const links = useMemo(() => {
    const list: Link[] = []
    const seen = new Set<string>()

    // 1. Add static physical link to Gateway for all devices (inactive by default)
    if (gatewayDevice) {
      const gId = `device-${gatewayDevice.id}`
      displayDevices.forEach(d => {
        if (d.id !== gatewayDevice.id) {
          const dId = `device-${d.id}`
          const linkId = `${dId}-${gId}`
          list.push({
            id: linkId,
            from: dId,
            to: gId,
            active: false,
            bytes: 0,
            packets: 0
          })
          seen.add(`${dId}-${gId}`)
          seen.add(`${gId}-${dId}`)
        }
      })
    }

    const findDeviceByIp = (ip: string) => displayDevices.find(d => d.ip === ip)

    // 2. Overlay connections from conversations
    if (Array.isArray(conversations)) {
      conversations.forEach(c => {
        if (!c.src_ip || !c.dst_ip) return
        const srcDevice = findDeviceByIp(c.src_ip)
        const dstDevice = findDeviceByIp(c.dst_ip)

        if (srcDevice && dstDevice) {
          // Local to local
          const id1 = `device-${srcDevice.id}`
          const id2 = `device-${dstDevice.id}`
          const linkKey = `${id1}-${id2}`
          const revKey = `${id2}-${id1}`

          if (!seen.has(linkKey) && !seen.has(revKey)) {
            let bytes = 0
            bytes += c.bytes ?? 0
            list.push({
              id: linkKey,
              from: id1,
              to: id2,
              active: true,
              bytes: bytes,
              packets: c.packets || 0
            })
            seen.add(linkKey)
          } else {
            const existing = list.find(l => l.id === linkKey || l.id === revKey)
            if (existing) {
              existing.active = true
              let bytes = 0
              bytes += c.bytes ?? 0
              existing.bytes += bytes
              existing.packets += c.packets || 0
            }
          }
        } else if (srcDevice && !dstDevice) {
          // Local to WAN
          if (!showInternet) return
          const dId = `device-${srcDevice.id}`
          const linkKey = `${dId}-internet`
          if (!seen.has(linkKey)) {
            let bytes = 0
            bytes += c.bytes ?? 0
            list.push({
              id: linkKey,
              from: dId,
              to: 'internet',
              active: true,
              bytes: bytes,
              packets: c.packets || 0
            })
            seen.add(linkKey)
          } else {
            const existing = list.find(l => l.id === linkKey)
            if (existing) {
              existing.active = true
              let bytes = 0
              bytes += c.bytes ?? 0
              existing.bytes += bytes
              existing.packets += c.packets || 0
            }
          }
        } else if (!srcDevice && dstDevice) {
          // WAN to Local
          if (!showInternet) return
          const dId = `device-${dstDevice.id}`
          const linkKey = `internet-${dId}`
          if (!seen.has(linkKey)) {
            let bytes = 0
            bytes += c.bytes ?? 0
            list.push({
              id: linkKey,
              from: 'internet',
              to: dId,
              active: true,
              bytes: bytes,
              packets: c.packets || 0
            })
            seen.add(linkKey)
          } else {
            const existing = list.find(l => l.id === linkKey)
            if (existing) {
              existing.active = true
              let bytes = 0
              bytes += c.bytes ?? 0
              existing.bytes += bytes
              existing.packets += c.packets || 0
            }
          }
        }
      })
    }

    return list
  }, [displayDevices, conversations, gatewayDevice, showInternet])

  // Drag handlers
  const handlePointerDown = (id: string, e: React.PointerEvent) => {
    e.currentTarget.setPointerCapture(e.pointerId)
    setDraggedNode(id)
  }

  const handlePointerMove = (e: React.PointerEvent) => {
    if (!draggedNode) return
    const rect = containerRef.current?.getBoundingClientRect()
    if (!rect) return
    const x = e.clientX - rect.left
    const y = e.clientY - rect.top
    
    const clampedX = Math.max(30, Math.min(rect.width - 30, x))
    const clampedY = Math.max(30, Math.min(rect.height - 30, y))

    setPositionOverrides(prev => ({
      ...prev,
      [draggedNode]: { x: clampedX, y: clampedY }
    }))
  }

  const handlePointerUp = (e: React.PointerEvent) => {
    try {
      e.currentTarget.releasePointerCapture(e.pointerId)
    } catch { /* pointer capture may already be released */ }
    setDraggedNode(null)
  }

  // Determine appropriate icon
  const getNodeIcon = (id: string, device?: Device) => {
    if (id === 'internet') return <Globe className="w-5 h-5" />
    if (!device) return <Cpu className="w-5 h-5" />
    if (isGateway(device)) return <Router className="w-5 h-5" />
    
    const host = (device.hostname || device.label || '').toLowerCase()
    const os = (device.os_guess || '').toLowerCase()
    if (host.includes('server') || os.includes('linux') || os.includes('ubuntu') || os.includes('debian')) {
      return <Server className="w-5 h-5" />
    }
    if (host.includes('phone') || os.includes('android') || os.includes('ios') || os.includes('iphone')) {
      return <Smartphone className="w-5 h-5" />
    }
    if (host.includes('pc') || host.includes('mac') || os.includes('windows') || os.includes('osx') || os.includes('darwin')) {
      return <Laptop className="w-5 h-5" />
    }
    return <Cpu className="w-5 h-5" />
  }

  const formatBytes = (bytes: number) => {
    if (bytes <= 0) return '0 B'
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(1024))
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`
  }

  // Hover properties
  const hoveredNodeInfo = useMemo(() => {
    if (!hoveredNode) return null
    if (hoveredNode === 'internet') {
      const convList = Array.isArray(conversations) ? conversations : []
      const wanTraffic = convList
        .filter(c => !displayDevices.some(d => d.ip === c.src_ip) || !displayDevices.some(d => d.ip === c.dst_ip))
        .reduce((acc, curr) => acc + curr.bytes, 0)
      return {
        id: 'internet',
        name: 'Internet (WAN)',
        ip: '0.0.0.0/0',
        details: 'External network interface gateway.',
        type: 'wan',
        traffic: formatBytes(wanTraffic),
        isNewlyJoined: false,
        isDisconnected: false,
        isNewInCompare: false,
        changedInfo: undefined,
      }
    }

    const deviceId = hoveredNode.replace('device-', '')
    const dev = displayDevices.find(d => d.id === Number(deviceId))
    if (!dev) return null

    const convList = Array.isArray(conversations) ? conversations : []
    const devTraffic = convList
      .filter(c => c.src_ip === dev.ip || c.dst_ip === dev.ip)
      .reduce((acc, curr) => acc + curr.bytes, 0)

    const isDisconnected = isCompareMode && snapshotDiff.disconnectedDevices.some(dd => dd.id === dev.id)
    const isNewInCompare = isCompareMode && snapshotDiff.newDeviceIds.has(dev.id)
    const changedInfo = isCompareMode ? snapshotDiff.changedDevices.get(dev.id) : undefined

    return {
      id: hoveredNode,
      name: dev.label || dev.hostname || 'Unknown Device',
      ip: dev.ip,
      mac: dev.mac || '—',
      vendor: dev.vendor || '—',
      os: dev.os_guess || '—',
      trusted: dev.trusted,
      ports: dev.open_ports?.length || 0,
      traffic: formatBytes(devTraffic),
      type: isGateway(dev) ? 'gateway' : 'client',
      vulnerability_count: dev.vulnerability_count || 0,
      max_cve_risk: dev.max_cve_risk || null,
      isNewlyJoined: !isCompareMode && newlyJoinedDeviceIds.has(dev.id),
      isDisconnected,
      isNewInCompare,
      changedInfo,
      raw: dev
    }
  }, [hoveredNode, displayDevices, conversations, isGateway, newlyJoinedDeviceIds, isCompareMode, snapshotDiff])

  // Speed and size based on connection metrics
  const getPulseProps = (bytes: number) => {
    if (bytes <= 0) return { dur: '4s', size: 3 }
    const kb = bytes / 1024
    if (kb < 5) return { dur: '4s', size: 3 }
    if (kb < 50) return { dur: '3s', size: 3.5 }
    if (kb < 500) return { dur: '2.2s', size: 4 }
    if (kb < 5000) return { dur: '1.6s', size: 4.5 }
    return { dur: '1.1s', size: 5 }
  }

  const isCapturing = dashboard?.capture?.capturing

  return (
    <div className="flex flex-col lg:flex-row gap-4">
      {/* Canvas */}
      <div 
        ref={containerRef}
        onPointerMove={handlePointerMove}
        className="relative flex-1 h-[520px] bg-[#12121e]/50 border border-white/5 rounded-xl overflow-hidden select-none nm-grid-bg"
      >
        <svg className="absolute inset-0 w-full h-full pointer-events-none">
          <defs>
            <linearGradient id="activeGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#8a5cf6" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.4" />
            </linearGradient>
          </defs>

          {/* Links */}
          {links.map(link => {
            const fromPos = positions[link.from]
            const toPos = positions[link.to]
            if (!fromPos || !toPos) return null

            const { dur, size } = getPulseProps(link.bytes)

            return (
              <g key={link.id}>
                <line
                  x1={fromPos.x}
                  y1={fromPos.y}
                  x2={toPos.x}
                  y2={toPos.y}
                  stroke={link.active ? 'url(#activeGradient)' : 'rgba(255,255,255,0.06)'}
                  strokeWidth={link.active ? 2.5 : 1.5}
                  strokeDasharray={link.active ? undefined : '4 4'}
                  className={cn(
                    "transition-all duration-300",
                    link.active && "topo-active-link filter drop-shadow-[0_0_4px_rgba(138,92,246,0.3)]"
                  )}
                />
                
                {link.active && (
                  <circle r={size} fill={link.to === 'internet' ? '#38bdf8' : '#8a5cf6'} className="topo-pulse-circle filter drop-shadow-[0_0_8px_currentColor]">
                    <animateMotion
                      dur={dur}
                      repeatCount="indefinite"
                      path={`M ${fromPos.x} ${fromPos.y} L ${toPos.x} ${toPos.y}`}
                    />
                  </circle>
                )}
              </g>
            )
          })}
        </svg>

        {/* Nodes */}
        {Object.entries(positions).map(([id, pos]) => {
          const isInternet = id === 'internet'
          const deviceId = id.replace('device-', '')
          const device = isInternet ? undefined : displayDevices.find(d => d.id === Number(deviceId))
          const isGway = device ? isGateway(device) : false

          const isSecurityMode = colorMode === 'security'
          const risk = device?.max_cve_risk?.toLowerCase()

          const isDisconnected = isCompareMode && device ? snapshotDiff.disconnectedDevices.some(dd => dd.id === device.id) : false
          const isNewInCompare = isCompareMode && device ? snapshotDiff.newDeviceIds.has(device.id) : false
          const changedInfo = isCompareMode && device ? snapshotDiff.changedDevices.get(device.id) : undefined
          const isNewlyJoinedSingle = !isCompareMode && device ? newlyJoinedDeviceIds.has(device.id) : false

          const glowClass = isInternet
            ? "shadow-cyan-500/20 text-cyan-400 border-cyan-500/30 hover:border-cyan-400"
            : isDisconnected
              ? "shadow-red-900/40 text-red-400 border-red-500/60 border-dashed bg-red-950/30 opacity-75"
              : isNewInCompare
                ? "shadow-emerald-500/40 text-emerald-300 border-emerald-400 animate-pulse bg-emerald-950/20"
                : changedInfo
                  ? "shadow-amber-500/40 text-amber-300 border-amber-400 bg-amber-950/20"
                  : isNewlyJoinedSingle
                    ? "shadow-emerald-500/40 text-emerald-300 border-emerald-400 animate-pulse bg-emerald-950/20"
                    : isSecurityMode
                      ? device
                        ? (risk === 'critical' || risk === 'high')
                          ? "shadow-red-500/25 text-red-400 border-red-500/40 hover:border-red-400 bg-red-950/10"
                          : risk === 'medium'
                            ? "shadow-orange-500/20 text-orange-400 border-orange-500/40 hover:border-orange-400 bg-orange-950/10"
                            : risk === 'low'
                              ? "shadow-yellow-500/15 text-yellow-400 border-yellow-500/30 hover:border-yellow-400 bg-yellow-950/5"
                              : "shadow-emerald-500/10 text-emerald-400 border-emerald-500/20 hover:border-emerald-400"
                        : "shadow-purple-500/20 text-purple-400 border-purple-500/30 hover:border-purple-400"
                      : isGway
                        ? "shadow-purple-500/20 text-purple-400 border-purple-500/30 hover:border-purple-400"
                        : device?.trusted
                          ? "shadow-emerald-500/10 text-emerald-400 border-emerald-500/20 hover:border-emerald-400"
                          : "shadow-amber-500/15 text-amber-400 border-amber-500/30 hover:border-amber-400"

          const isHovered = hoveredNode === id
          const isDragged = draggedNode === id

          return (
            <div
              key={id}
              id={`node-element-${id}`}
              style={{ left: pos.x, top: pos.y }}
              onPointerDown={e => handlePointerDown(id, e)}
              onPointerUp={handlePointerUp}
              onMouseEnter={() => setHoveredNode(id)}
              onMouseLeave={() => {
                if (hoveredNode === id) setHoveredNode(null)
              }}
              onClick={() => {
                if (device) onSelect(device.id)
              }}
              className={cn(
                "absolute -translate-x-1/2 -translate-y-1/2 flex flex-col items-center cursor-grab active:cursor-grabbing select-none group transition-transform duration-100",
                isHovered && "scale-110",
                isDragged && "scale-105"
              )}
            >
              <div className={cn(
                "relative w-11 h-11 rounded-full bg-[#16162a]/95 border flex items-center justify-center shadow-lg transition-all duration-300",
                glowClass,
                isHovered && "shadow-xl border-opacity-70 bg-[#22223a]/90"
              )}>
                {getNodeIcon(id, device)}
                {isDisconnected && (
                  <span className="absolute -top-1.5 -right-1.5 flex items-center gap-0.5 bg-red-600 text-white text-[7px] font-bold px-1 py-0.5 rounded-full shadow-[0_0_8px_#ef4444]">
                    <WifiOff className="w-2 h-2" />
                    OFF
                  </span>
                )}
                {isNewInCompare && (
                  <span className="absolute -top-1.5 -right-1.5 flex items-center gap-0.5 bg-emerald-500 text-black text-[7px] font-bold px-1 py-0.5 rounded-full shadow-[0_0_8px_#10b981]">
                    <UserPlus className="w-2 h-2" />
                    NEW
                  </span>
                )}
                {changedInfo && !isDisconnected && !isNewInCompare && (
                  <span className="absolute -top-1.5 -right-1.5 flex items-center gap-0.5 bg-amber-500 text-black text-[7px] font-bold px-1 py-0.5 rounded-full shadow-[0_0_8px_#f59e0b]">
                    <GitCompare className="w-2 h-2" />
                    DIFF
                  </span>
                )}
                {isNewlyJoinedSingle && !isCompareMode && (
                  <span className="absolute -top-1.5 -right-1.5 flex items-center gap-0.5 bg-emerald-500 text-black text-[7px] font-bold px-1 py-0.5 rounded-full shadow-[0_0_8px_#10b981]">
                    <UserPlus className="w-2 h-2" />
                    NEW
                  </span>
                )}
              </div>

              <div className="mt-1 bg-black/60 backdrop-blur-md px-1.5 py-0.5 rounded text-[9px] font-mono text-gray-400 border border-white/5 max-w-[100px] truncate">
                {isInternet ? 'Internet' : device?.label || device?.hostname || device?.ip}
              </div>
            </div>
          )
        })}

        {/* Header Overlay for Compare Mode or Time Replay Mode */}
        {isCompareMode ? (
          <div className="absolute top-3 left-3 flex flex-wrap items-center gap-2 bg-[#141428]/90 backdrop-blur-md px-3 py-1.5 rounded-lg border border-purple-500/40 text-xs pointer-events-auto shadow-xl select-none">
            <GitCompare className="w-3.5 h-3.5 text-purple-400 animate-pulse" />
            <span className="text-purple-200 font-semibold text-[11px]">
              Snapshot Comparison: Point A vs Point B
            </span>
            <div className="flex items-center gap-1.5 ml-1 border-l border-white/10 pl-2">
              <span className="bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[9px] px-1.5 py-0.5 rounded font-bold flex items-center gap-1">
                <UserPlus className="w-2.5 h-2.5" />
                +{snapshotDiff.newDeviceIds.size} New
              </span>
              <span className="bg-red-500/20 text-red-300 border border-red-500/30 text-[9px] px-1.5 py-0.5 rounded font-bold flex items-center gap-1">
                <WifiOff className="w-2.5 h-2.5" />
                -{snapshotDiff.disconnectedDevices.length} Offline
              </span>
              <span className="bg-amber-500/20 text-amber-300 border border-amber-500/30 text-[9px] px-1.5 py-0.5 rounded font-bold flex items-center gap-1">
                <GitCompare className="w-2.5 h-2.5" />
                ~{snapshotDiff.changedDevices.size} Changed
              </span>
            </div>
          </div>
        ) : historicalScanId !== null && (
          <div className="absolute top-3 left-3 flex items-center gap-2 bg-amber-950/80 backdrop-blur-md px-3 py-1.5 rounded-lg border border-amber-500/30 text-xs pointer-events-auto shadow-lg select-none">
            <Clock className="w-3.5 h-3.5 text-amber-400 animate-pulse" />
            <span className="text-amber-200 font-medium text-[11px]">
              Snapshot {selectedScan ? `#${selectedScan.id}` : ''}
            </span>
            <span className="text-gray-400 text-[10px]">&bull; {displayDevices.length} Hosts</span>
            {newlyJoinedDeviceIds.size > 0 && (
              <span className="bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 text-[9px] px-1.5 py-0.5 rounded font-bold flex items-center gap-1 ml-1">
                <UserPlus className="w-2.5 h-2.5" />
                +{newlyJoinedDeviceIds.size} Joined
              </span>
            )}
          </div>
        )}

        {/* Toolbar */}
        <div className="absolute top-3 right-3 flex items-center gap-2 bg-black/40 backdrop-blur-md px-2 py-1.5 rounded-lg border border-white/5 text-xs pointer-events-auto">
          {/* Mode Switcher Toggle */}
          <button
            onClick={() => {
              const nextMode = !isCompareMode
              setIsCompareMode(nextMode)
              if (nextMode && comparePointBIndex === 0 && comparePointAIndex === 0) {
                setComparePointBIndex(liveIndex)
                setComparePointAIndex(Math.max(0, liveIndex - 1))
              }
            }}
            className={cn(
              "px-2 py-1 rounded transition-all flex items-center gap-1 text-[11px] font-semibold",
              isCompareMode
                ? "bg-purple-600 text-white shadow-[0_0_10px_rgba(147,51,234,0.5)] border border-purple-400"
                : "bg-white/5 text-gray-300 hover:text-white border border-white/10 hover:bg-white/10"
            )}
            title="Toggle Snapshot Comparison Diff Mode"
          >
            <GitCompare className="w-3.5 h-3.5" />
            {isCompareMode ? 'Compare Diff Mode' : 'Single Replay'}
          </button>

          {isCompareMode ? (
            <div className="flex items-center gap-1.5 px-2 py-1 text-purple-300 bg-purple-500/10 border border-purple-500/20 rounded select-none">
              <Layers className="w-3 h-3" />
              Compare Mode
            </div>
          ) : historicalScanId !== null ? (
            <div className="flex items-center gap-1.5 px-2 py-1 text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded select-none">
              <Clock className="w-3 h-3" />
              Time Machine
            </div>
          ) : isCapturing && (
            <div className="flex items-center gap-1.5 px-2 py-1 text-red-400 bg-red-500/10 border border-red-500/20 rounded animate-pulse select-none">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500" />
              Live
            </div>
          )}
          <button 
            onClick={() => setShowInternet(!showInternet)}
            className={cn(
              "px-2 py-1 rounded transition-colors flex items-center gap-1",
              showInternet ? "bg-purple-600/20 text-purple-400 border border-purple-500/20" : "text-gray-400 hover:text-gray-200"
            )}
            title="Toggle WAN internet node visibility"
          >
            <Globe className="w-3.5 h-3.5" />
            {showInternet ? 'WAN: On' : 'WAN: Off'}
          </button>

          <button 
            onClick={() => setColorMode(colorMode === 'network' ? 'security' : 'network')}
            className={cn(
              "px-2 py-1 rounded transition-colors flex items-center gap-1",
              colorMode === 'security' ? "bg-red-600/20 text-red-400 border border-red-500/20" : "text-gray-400 hover:text-gray-200"
            )}
            title="Toggle Security Posture Heatmap"
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            {colorMode === 'security' ? 'Heatmap: On' : 'Heatmap: Off'}
          </button>
          
          <button
            onClick={resetLayout}
            className="p-1 text-gray-400 hover:text-gray-200 hover:bg-white/5 rounded transition-colors"
            title="Reset to default radial layout"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Synchronized Time-Travel / Compare Scrubber Bar */}
        {sliderScans.length > 0 ? (
          <div className="absolute bottom-3 left-3 right-3 flex flex-col items-center gap-1.5 pointer-events-auto">
            <div className="w-full max-w-xl bg-[#0d0d18]/95 backdrop-blur-md px-3.5 py-2.5 rounded-xl border border-white/10 shadow-2xl">
              {isCompareMode ? (
                /* Snapshot Comparison Dual-Point Scrubber Controls */
                <div className="space-y-2">
                  <div className="flex items-center justify-between gap-2 text-xs">
                    <div className="flex items-center gap-1.5 font-semibold text-purple-300">
                      <GitCompare className="w-3.5 h-3.5 text-purple-400" />
                      <span>Snapshot Comparison Diff</span>
                    </div>

                    <div className="flex items-center gap-2 text-[10px]">
                      <button
                        onClick={() => {
                          setComparePointAIndex(Math.max(0, liveIndex - 1))
                          setComparePointBIndex(liveIndex)
                        }}
                        className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 hover:bg-purple-500/30 transition-colors"
                      >
                        Prev vs Live
                      </button>
                      <button
                        onClick={() => {
                          setComparePointAIndex(0)
                          setComparePointBIndex(liveIndex)
                        }}
                        className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 hover:bg-purple-500/30 transition-colors"
                      >
                        Earliest vs Live
                      </button>
                      <button
                        onClick={() => setIsCompareMode(false)}
                        className="px-2 py-0.5 rounded bg-gray-800 text-gray-400 hover:text-gray-200 border border-white/10 transition-colors"
                      >
                        Exit Compare
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-1 border-t border-white/5">
                    {/* Point A (Baseline) */}
                    <div className="space-y-1 bg-white/[0.03] p-2 rounded-lg border border-purple-500/20">
                      <div className="flex justify-between items-center text-[10px] font-mono">
                        <span className="text-purple-400 font-bold flex items-center gap-1">
                          <span className="w-2 h-2 rounded-full bg-purple-500" /> Point A (Baseline)
                        </span>
                        <span className="text-gray-300">
                          {comparePointAScan ? `Scan #${comparePointAScan.id}` : 'Live'}
                        </span>
                      </div>
                      <input
                        type="range"
                        min={0}
                        max={liveIndex}
                        value={comparePointAIndex}
                        onChange={e => setComparePointAIndex(Number(e.target.value))}
                        className="w-full h-1.5 accent-purple-400 cursor-pointer rounded-lg bg-gray-800"
                      />
                      <div className="text-[8px] text-gray-400 truncate">
                        {comparePointAScan
                          ? new Date(comparePointAScan.started_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
                          : 'Current Live Network'}
                      </div>
                    </div>

                    {/* Point B (Target) */}
                    <div className="space-y-1 bg-white/[0.03] p-2 rounded-lg border border-cyan-500/20">
                      <div className="flex justify-between items-center text-[10px] font-mono">
                        <span className="text-cyan-400 font-bold flex items-center gap-1">
                          <span className="w-2 h-2 rounded-full bg-cyan-400" /> Point B (Target)
                        </span>
                        <span className="text-gray-300">
                          {comparePointBScan ? `Scan #${comparePointBScan.id}` : 'Live'}
                        </span>
                      </div>
                      <input
                        type="range"
                        min={0}
                        max={liveIndex}
                        value={comparePointBIndex}
                        onChange={e => setComparePointBIndex(Number(e.target.value))}
                        className="w-full h-1.5 accent-cyan-400 cursor-pointer rounded-lg bg-gray-800"
                      />
                      <div className="text-[8px] text-gray-400 truncate">
                        {comparePointBScan
                          ? new Date(comparePointBScan.started_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
                          : 'Current Live Network'}
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                /* Standard Single Replay Scrubber Controls */
                <>
                  <div className="flex items-center justify-between gap-2 mb-1.5">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleTogglePlay}
                        className={cn(
                          "p-1.5 rounded-lg transition-colors flex items-center justify-center",
                          isPlaying
                            ? "bg-amber-500 text-black hover:bg-amber-400 shadow-[0_0_8px_#f59e0b]"
                            : "bg-white/10 text-white hover:bg-white/20 border border-white/10"
                        )}
                        title={isPlaying ? "Pause topology replay" : "Play topology snapshot sequence"}
                      >
                        {isPlaying ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5 fill-current ml-0.5" />}
                      </button>

                      <button
                        onClick={handleStepBack}
                        disabled={currentIndex <= 0}
                        className="p-1.5 text-gray-400 hover:text-white hover:bg-white/5 disabled:opacity-30 disabled:hover:bg-transparent rounded-lg transition-colors"
                        title="Previous snapshot"
                      >
                        <SkipBack className="w-3.5 h-3.5" />
                      </button>

                      <button
                        onClick={handleStepForward}
                        disabled={currentIndex >= liveIndex}
                        className="p-1.5 text-gray-400 hover:text-white hover:bg-white/5 disabled:opacity-30 disabled:hover:bg-transparent rounded-lg transition-colors"
                        title="Next snapshot"
                      >
                        <SkipForward className="w-3.5 h-3.5" />
                      </button>

                      <span className="text-[10px] text-gray-300 font-mono flex items-center gap-1 ml-1">
                        <Clock className="w-3 h-3 text-amber-400" />
                        {selectedScan ? (
                          <span>
                            Scan #{selectedScan.id} &bull; {new Date(selectedScan.started_at).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                          </span>
                        ) : (
                          <span className="text-emerald-400 font-semibold flex items-center gap-1">
                            <Radio className="w-3 h-3 animate-pulse text-emerald-400" />
                            Live Network View
                          </span>
                        )}
                      </span>
                    </div>

                    {historicalScanId !== null && (
                      <button
                        onClick={() => {
                          setIsPlaying(false)
                          setHistoricalScanId(null)
                        }}
                        className="text-[10px] text-amber-400 hover:text-amber-300 border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 rounded-md transition-colors font-medium flex items-center gap-1"
                      >
                        Return to Live
                      </button>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <input
                      type="range"
                      min={0}
                      max={liveIndex}
                      value={currentIndex}
                      onChange={e => {
                        setIsPlaying(false)
                        const idx = Number(e.target.value)
                        if (idx === liveIndex) {
                          setHistoricalScanId(null)
                        } else {
                          setHistoricalScanId(sliderScans[idx].id)
                        }
                      }}
                      className="w-full h-1.5 accent-amber-400 cursor-pointer rounded-lg bg-gray-800"
                    />
                  </div>

                  <div className="flex justify-between text-[8px] text-gray-500 mt-1 font-mono">
                    <span>{sliderScans.length > 0 ? new Date(sliderScans[0].started_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : ''}</span>
                    {newlyJoinedDeviceIds.size > 0 && (
                      <span className="text-emerald-400 font-semibold">+ {newlyJoinedDeviceIds.size} new device(s) joined</span>
                    )}
                    <span className={cn(historicalScanId === null ? 'text-emerald-400 font-bold' : 'text-gray-500')}>LIVE</span>
                  </div>
                </>
              )}
            </div>
          </div>
        ) : (
          <div className="absolute bottom-3 left-3 bg-black/40 backdrop-blur-md px-2 py-1 rounded border border-white/5 text-[9px] text-gray-500 pointer-events-none">
            Drag devices to organize topology. Click node to see details.
          </div>
        )}
      </div>

      {/* Detail Sidebar */}
      <div className="w-full lg:w-72 flex flex-col gap-3">
        <div className="flex-grow bg-[#1a1a2e] border border-white/5 rounded-xl p-4 flex flex-col justify-between min-h-[220px]">
          {hoveredNodeInfo ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">Node Properties</span>
                <span className={cn(
                  "px-1.5 py-0.5 rounded text-[9px] font-mono",
                  hoveredNodeInfo.type === 'wan' 
                    ? "bg-cyan-500/10 text-cyan-400" 
                    : hoveredNodeInfo.type === 'gateway' 
                      ? "bg-purple-500/10 text-purple-400" 
                      : hoveredNodeInfo.trusted 
                        ? "bg-emerald-500/10 text-emerald-400" 
                        : "bg-amber-500/10 text-amber-400"
                )}>
                  {hoveredNodeInfo.type === 'wan' 
                    ? 'Internet' 
                    : hoveredNodeInfo.type === 'gateway' 
                      ? 'Gateway Router' 
                      : hoveredNodeInfo.trusted 
                        ? 'Trusted Device' 
                        : 'Unknown Device'}
                </span>
              </div>

              <div>
                <h3 className="text-sm font-bold text-white truncate">{hoveredNodeInfo.name}</h3>
                <p className="text-xs font-mono text-blue-400 mt-0.5">{hoveredNodeInfo.ip}</p>
              </div>

              <div className="space-y-1.5 pt-2 border-t border-white/5 text-xs text-gray-400">
                {hoveredNodeInfo.type !== 'wan' && (
                  <>
                    <div className="flex justify-between"><span className="text-gray-500">MAC:</span> <span className="font-mono text-[10px] text-gray-300">{hoveredNodeInfo.mac}</span></div>
                    <div className="flex justify-between"><span className="text-gray-500">Vendor:</span> <span className="truncate max-w-[150px] text-gray-300">{hoveredNodeInfo.vendor}</span></div>
                    <div className="flex justify-between"><span className="text-gray-500">OS Guess:</span> <span className="truncate max-w-[150px] text-gray-300">{hoveredNodeInfo.os}</span></div>
                    <div className="flex justify-between"><span className="text-gray-500">Open Ports:</span> <span className="text-gray-300">{hoveredNodeInfo.ports}</span></div>
                    <div className="flex justify-between"><span className="text-gray-500">CVE Risk:</span> <span className={cn(
                      "font-semibold font-mono capitalize",
                      hoveredNodeInfo.max_cve_risk === 'critical' || hoveredNodeInfo.max_cve_risk === 'high'
                        ? 'text-red-400'
                        : hoveredNodeInfo.max_cve_risk === 'medium'
                          ? 'text-orange-400'
                          : hoveredNodeInfo.max_cve_risk === 'low'
                            ? 'text-yellow-400'
                            : 'text-emerald-400'
                    )}>{hoveredNodeInfo.max_cve_risk || 'None'}</span></div>
                    <div className="flex justify-between"><span className="text-gray-500">Vulnerabilities:</span> <span className="text-gray-300 font-mono">{hoveredNodeInfo.vulnerability_count || 0}</span></div>
                  </>
                )}
                {hoveredNodeInfo.isDisconnected && (
                  <div className="flex items-center gap-1.5 bg-red-500/10 border border-red-500/30 text-red-300 px-2 py-1 rounded text-[10px] font-semibold my-1">
                    <WifiOff className="w-3 h-3 text-red-400" />
                    Disconnected Node (Offline in Target)
                  </div>
                )}
                {hoveredNodeInfo.isNewInCompare && (
                  <div className="flex items-center gap-1.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 px-2 py-1 rounded text-[10px] font-semibold my-1">
                    <UserPlus className="w-3 h-3 text-emerald-400" />
                    New Node (Joined after Baseline)
                  </div>
                )}
                {hoveredNodeInfo.changedInfo && (
                  <div className="bg-amber-500/10 border border-amber-500/30 text-amber-300 p-2 rounded text-[10px] my-1 space-y-1">
                    <div className="font-bold flex items-center gap-1">
                      <GitCompare className="w-3 h-3 text-amber-400" />
                      Changed Roles/Attributes:
                    </div>
                    {Object.entries(hoveredNodeInfo.changedInfo.detail).map(([k, v]) => (
                      <div key={k} className="flex justify-between font-mono text-[9px]">
                        <span className="text-gray-400">{k}:</span>
                        <span>{String(v.from)} &rarr; {String(v.to)}</span>
                      </div>
                    ))}
                  </div>
                )}
                {hoveredNodeInfo.isNewlyJoined && !isCompareMode && (
                  <div className="flex items-center gap-1.5 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 px-2 py-1 rounded text-[10px] font-semibold my-1">
                    <UserPlus className="w-3 h-3 text-emerald-400" />
                    Joined Network in Snapshot
                  </div>
                )}
                {hoveredNodeInfo.details && (
                  <p className="text-[10px] text-gray-500 leading-normal">{hoveredNodeInfo.details}</p>
                )}
                <div className="flex justify-between pt-1 font-semibold text-purple-400">
                  <span>Current Traffic:</span>
                  <span className="flex items-center gap-1">
                    <Activity className="w-3 h-3 animate-pulse" />
                    {hoveredNodeInfo.traffic}
                  </span>
                </div>
              </div>
            </div>
          ) : (
            <div className="flex-grow flex flex-col items-center justify-center text-center p-4">
              <HelpCircle className="w-8 h-8 text-gray-600 mb-2" />
              <p className="text-xs font-semibold text-gray-400">Device Insights</p>
              <p className="text-[11px] text-gray-600 mt-1 max-w-[200px]">
                Hover over any network node or active link to load real-time packet data, connection info, and hardware parameters.
              </p>
            </div>
          )}

          <div className="mt-4 pt-3 border-t border-white/5 flex items-center justify-between text-xs text-gray-400">
            <span className="flex items-center gap-1 text-[11px]">
              <Zap className="w-3.5 h-3.5 text-yellow-500" />
              Active Connections: <strong>{Array.isArray(conversations) ? conversations.length : 0}</strong>
            </span>
          </div>
        </div>

        {/* Legend */}
        <div className="bg-[#1a1a2e]/60 border border-white/5 rounded-xl p-3.5 text-[11px] space-y-2 text-gray-400">
          <div className="font-semibold text-gray-300 mb-1.5 uppercase tracking-wider text-[10px]">
            {isCompareMode ? 'Snapshot Compare Legend' : colorMode === 'security' ? 'Security Legend' : 'Topology Legend'}
          </div>
          {isCompareMode ? (
            <>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_6px_#34d399]" />
                <span>New Node (+Joined since Point A)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500 border border-dashed border-red-400 shadow-[0_0_6px_#ef4444]" />
                <span>Disconnected Node (-Offline)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400 shadow-[0_0_6px_#fbbf24]" />
                <span>Changed Role / IP / Ports</span>
              </div>
            </>
          ) : colorMode === 'security' ? (
            <>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-red-500 shadow-[0_0_6px_#ef4444]" />
                <span>Critical / High Risk Exploit</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-orange-500 shadow-[0_0_6px_#f97316]" />
                <span>Medium Risk Vulnerability</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-yellow-400 shadow-[0_0_6px_#facc15]" />
                <span>Low Risk Vulnerability</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_6px_#34d399]" />
                <span>Patched / Secure Device</span>
              </div>
            </>
          ) : (
            <>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 shadow-[0_0_6px_#22d3ee]" />
                <span>Internet WAN Gateway</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-400 shadow-[0_0_6px_#a78bfa]" />
                <span>Central Switch/Router Gateway</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 shadow-[0_0_6px_#34d399]" />
                <span>Trusted Device (Verified)</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400 shadow-[0_0_6px_#fbbf24]" />
                <span>Unknown Device (Unverified)</span>
              </div>
            </>
          )}
          <div className="flex items-center gap-2 border-t border-white/5 pt-2 mt-1">
            <span className="w-6 border-t border-dashed border-gray-600" />
            <span>Static physical link</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="w-6 border-t-2 border-purple-500" />
            <span>Active connection with pulse</span>
          </div>
        </div>
      </div>
    </div>
  )
}
