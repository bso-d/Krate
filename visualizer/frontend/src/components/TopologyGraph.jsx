import { useState, useEffect, useCallback, useRef } from 'react'
import { Link } from 'react-router-dom'
import { toPng, toJpeg } from 'html-to-image'
import { ReactFlow, Background, Controls, MiniMap, MarkerType } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import ProducerNode from '../nodes/ProducerNode.jsx'
import TopicNode from '../nodes/TopicNode.jsx'
import BrokerNode from '../nodes/BrokerNode.jsx'
import ConsumerNode from '../nodes/ConsumerNode.jsx'
import MirrorNode from '../nodes/MirrorNode.jsx'

const nodeTypes = { producer: ProducerNode, topic: TopicNode, broker: BrokerNode, consumer: ConsumerNode, mirror: MirrorNode }

const V = 145

function centerY(count, index) {
  return 300 - ((count - 1) * V) / 2 + index * V
}

function buildGraph(data) {
  const nodes = []
  const edges = []

  const X = { left: 50, topic: 400, broker: 780, right: 1120 }

  // ── Left column: producers + incoming mirrors ────────────────────────────
  const leftItems = [
    ...data.producers.map(p => ({ kind: 'producer', data: p })),
    ...(data.incomingMirrors || []).map(m => ({ kind: 'mirror', data: { ...m, direction: 'incoming' } }))
  ]

  if (leftItems.length === 0) {
    leftItems.push({
      kind: 'producer',
      unknown: true,
      data: { id: 'unknown', name: 'Unknown Producer', type: 'Not configured', description: 'Add to topology.config.json', format: '?' }
    })
  }

  leftItems.forEach((item, i) => {
    const y = centerY(leftItems.length, i)
    if (item.kind === 'producer') {
      const p = item.data
      nodes.push({ id: `producer-${p.id}`, type: 'producer', position: { x: X.left, y }, data: p })
      edges.push({
        id: `e-producer-${p.id}`,
        source: `producer-${p.id}`,
        target: 'topic',
        style: { stroke: item.unknown ? '#555' : 'var(--producer-light)', strokeWidth: 2, ...(item.unknown && { strokeDasharray: '5,5' }) },
        markerEnd: { type: MarkerType.ArrowClosed, color: item.unknown ? '#555' : 'var(--producer-light)' }
      })
    } else {
      const m = item.data
      nodes.push({ id: `mirror-in-${m.id}`, type: 'mirror', position: { x: X.left, y }, data: m })
      edges.push({
        id: `e-mirror-in-${m.id}`,
        source: `mirror-in-${m.id}`,
        target: 'topic',
        style: { stroke: 'var(--mirror-light)', strokeWidth: 2 },
        markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--mirror-light)' }
      })
    }
  })

  // ── Topic node ───────────────────────────────────────────────────────────
  nodes.push({
    id: 'topic',
    type: 'topic',
    position: { x: X.topic, y: 260 },
    data: { name: data.topic, partitions: data.partitionCount, replication: data.replicationFactor, totalMessages: data.totalMessages }
  })

  // ── Broker nodes ─────────────────────────────────────────────────────────
  data.brokers.forEach((b, i) => {
    nodes.push({ id: `broker-${b.brokerId}`, type: 'broker', position: { x: X.broker, y: centerY(data.brokers.length, i) }, data: b })
    edges.push({
      id: `e-broker-${b.brokerId}`,
      source: 'topic',
      target: `broker-${b.brokerId}`,
      style: { stroke: 'var(--broker-light)', strokeWidth: 2 },
      markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--broker-light)' }
    })
  })

  // ── Right column: consumers + outgoing mirrors ───────────────────────────
  const rightItems = [
    ...(data.consumers || []).map(c => ({ kind: 'consumer', data: c })),
    ...(data.outgoingMirrors || []).map(m => ({ kind: 'mirror', data: { ...m, direction: 'outgoing' } }))
  ]

  if (rightItems.length === 0) {
    nodes.push({ id: 'consumer-none', type: 'consumer', position: { x: X.right, y: centerY(1, 0) }, data: { groupId: 'No active consumers', lag: 0, partitionsAssigned: 0 } })
    edges.push({ id: 'e-consumer-none', source: 'topic', target: 'consumer-none', style: { stroke: '#555', strokeWidth: 2, strokeDasharray: '5,5' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#555' } })
  } else {
    rightItems.forEach((item, i) => {
      const y = centerY(rightItems.length, i)
      if (item.kind === 'consumer') {
        const c = item.data
        const lagColor = c.lag > 1000 ? 'var(--error)' : 'var(--consumer-light)'
        nodes.push({ id: `consumer-${c.groupId}`, type: 'consumer', position: { x: X.right, y }, data: c })
        edges.push({
          id: `e-consumer-${c.groupId}`,
          source: 'topic',
          target: `consumer-${c.groupId}`,
          style: { stroke: c.declared ? '#555' : lagColor, strokeWidth: 2, ...(c.declared && { strokeDasharray: '5,5' }) },
          markerEnd: { type: MarkerType.ArrowClosed, color: c.declared ? '#555' : lagColor }
        })
      } else {
        const m = item.data
        nodes.push({ id: `mirror-out-${m.id}`, type: 'mirror', position: { x: X.right, y }, data: m })
        edges.push({
          id: `e-mirror-out-${m.id}`,
          source: 'topic',
          target: `mirror-out-${m.id}`,
          style: { stroke: 'var(--mirror-light)', strokeWidth: 2 },
          markerEnd: { type: MarkerType.ArrowClosed, color: 'var(--mirror-light)' }
        })
      }
    })
  }

  return { nodes, edges }
}

function ExportButton({ label, onClick }) {
  return (
    <button
      onClick={onClick}
      style={{
        background: 'transparent',
        border: '1px solid var(--outline)',
        borderRadius: 6,
        color: 'var(--on-surface-dim)',
        fontSize: 11,
        padding: '3px 10px',
        cursor: 'pointer',
        fontFamily: 'var(--font)',
        letterSpacing: '0.02em'
      }}
      onMouseEnter={e => {
        e.currentTarget.style.borderColor = 'var(--primary)'
        e.currentTarget.style.color = 'var(--on-surface)'
      }}
      onMouseLeave={e => {
        e.currentTarget.style.borderColor = 'var(--outline)'
        e.currentTarget.style.color = 'var(--on-surface-dim)'
      }}
    >
      {label}
    </button>
  )
}

export default function TopologyGraph({ topicName }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const canvasRef = useRef(null)

  const exportAs = useCallback((format) => {
    if (!canvasRef.current) return
    const fn = format === 'jpeg' ? toJpeg : toPng
    fn(canvasRef.current, {
      backgroundColor: '#1C1B1F',
      pixelRatio: 2,
      skipFonts: true
    }).then(dataUrl => {
      const a = document.createElement('a')
      a.download = `${topicName}.${format}`
      a.href = dataUrl
      a.click()
    })
  }, [topicName])

  const refresh = useCallback(() => {
    fetch(`${import.meta.env.BASE_URL}api/topology/${encodeURIComponent(topicName)}`)
      .then(r => { if (!r.ok) throw new Error(`Server error ${r.status}`); return r.json() })
      .then(data => { setData(data); setError(null) })
      .catch(e => setError(e.message))
  }, [topicName])

  useEffect(() => {
    refresh()
    const id = setInterval(refresh, 8000)
    return () => clearInterval(id)
  }, [refresh])

  if (error) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--error)' }}>
      {error}
    </div>
  )
  if (!data) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--on-surface-dim)' }}>
      Loading topology…
    </div>
  )

  const { nodes, edges } = buildGraph(data)

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>

      {/* Breadcrumb — matches Kafbat's "Section / Item" pattern */}
      <div style={{
        padding: '0 24px',
        height: 40,
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        borderBottom: '1px solid var(--outline)',
        flexShrink: 0,
        fontSize: 13,
        color: 'var(--on-surface-dim)'
      }}>
        <Link to="/" style={{ color: 'var(--on-surface-dim)', textDecoration: 'none' }}
          onMouseEnter={e => e.currentTarget.style.color = 'var(--on-surface)'}
          onMouseLeave={e => e.currentTarget.style.color = 'var(--on-surface-dim)'}
        >
          Topics
        </Link>
        <span>/</span>
        <span style={{ color: 'var(--on-surface)', fontFamily: 'var(--mono)', fontSize: 13 }}>
          {topicName}
        </span>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
          <ExportButton label="↓ PNG"  onClick={() => exportAs('png')}  />
          <ExportButton label="↓ JPEG" onClick={() => exportAs('jpeg')} />
          <span style={{ fontSize: 11, color: 'var(--on-surface-dim)', opacity: 0.5, paddingLeft: 4 }}>
            auto-refreshes every 8s
          </span>
        </div>
      </div>

      <div ref={canvasRef} style={{ flex: 1, position: 'relative' }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          defaultEdgeOptions={{ type: 'step' }}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.3}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#302E38" gap={24} />
          <Controls style={{ background: 'var(--surface-2)', border: '1px solid var(--outline)' }} />
          <MiniMap
            nodeColor={n => {
              if (n.type === 'producer') return 'var(--producer-light)'
              if (n.type === 'topic') return 'var(--topic-light)'
              if (n.type === 'broker') return 'var(--broker-light)'
              if (n.type === 'mirror') return 'var(--mirror-light)'
              return 'var(--consumer-light)'
            }}
            style={{ background: 'var(--surface-2)', border: '1px solid var(--outline)' }}
          />
        </ReactFlow>
      </div>

    </div>
  )
}
