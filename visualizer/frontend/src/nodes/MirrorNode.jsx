import { Handle, Position } from '@xyflow/react'

export default function MirrorNode({ data }) {
  const isIncoming = data.direction === 'incoming'

  return (
    <div style={{
      background: 'var(--surface-2)',
      border: '1px solid var(--mirror-light)',
      borderLeft: isIncoming ? '4px solid var(--mirror-light)' : '1px solid var(--mirror-light)',
      borderRight: isIncoming ? '1px solid var(--mirror-light)' : '4px solid var(--mirror-light)',
      borderRadius: 12,
      padding: '14px 16px',
      minWidth: 200,
      fontFamily: 'var(--font)'
    }}>
      {isIncoming
        ? <Handle type="source" position={Position.Right} style={{ background: 'var(--mirror-light)', border: 'none' }} />
        : <Handle type="target" position={Position.Left} style={{ background: 'var(--mirror-light)', border: 'none' }} />
      }
      <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--mirror-light)', marginBottom: 6 }}>
        {isIncoming ? 'Incoming Mirror' : 'Outgoing Mirror'}
      </div>
      <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--on-surface)', marginBottom: 4 }}>
        {data.name}
      </div>
      <div style={{ fontSize: 12, color: 'var(--on-surface-dim)', marginBottom: 8 }}>
        {data.description}
      </div>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
        <Chip label={data.type} color="var(--mirror-light)" />
        {isIncoming && data.from && (
          <span style={{ fontSize: 11, color: 'var(--on-surface-dim)' }}>
            from <span style={{ fontFamily: 'var(--mono)', color: 'var(--topic-light)' }}>{data.from}</span>
          </span>
        )}
        {!isIncoming && data.to && (
          <span style={{ fontSize: 11, color: 'var(--on-surface-dim)' }}>
            to <span style={{ fontFamily: 'var(--mono)', color: 'var(--topic-light)' }}>{data.to}</span>
          </span>
        )}
      </div>
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
