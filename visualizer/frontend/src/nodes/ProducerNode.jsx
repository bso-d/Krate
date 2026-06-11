import { Handle, Position } from '@xyflow/react'

export default function ProducerNode({ data }) {
  return (
    <div style={{
      background: 'var(--surface-2)',
      border: '1px solid var(--producer-light)',
      borderLeft: '4px solid var(--producer-light)',
      borderRadius: 12,
      padding: '14px 16px',
      minWidth: 200,
      fontFamily: 'var(--font)'
    }}>
      <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--producer-light)', marginBottom: 6 }}>
        Producer
      </div>
      <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--on-surface)', marginBottom: 4 }}>
        {data.name}
      </div>
      <div style={{ fontSize: 12, color: 'var(--on-surface-dim)', marginBottom: 8 }}>
        {data.description}
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <Chip label={data.type} color="var(--producer-light)" />
        <Chip label={data.format} color="var(--on-surface-dim)" />
      </div>
      <Handle type="source" position={Position.Right} style={{ background: 'var(--producer-light)', border: 'none' }} />
    </div>
  )
}

function Chip({ label, color }) {
  return (
    <span style={{
      fontSize: 10,
      padding: '2px 8px',
      borderRadius: 10,
      border: `1px solid ${color}`,
      color,
      fontFamily: 'var(--mono)'
    }}>
      {label}
    </span>
  )
}
