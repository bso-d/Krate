import { Handle, Position } from '@xyflow/react'

export default function ConsumerNode({ data }) {
  const isDeclaredOnly = data.declared === true
  const lagHigh = !isDeclaredOnly && data.lag > 1000
  const lagColor = lagHigh ? 'var(--error)' : isDeclaredOnly ? 'var(--outline)' : 'var(--consumer-light)'
  const borderColor = isDeclaredOnly ? 'var(--outline)' : lagColor

  return (
    <div style={{
      background: 'var(--surface-2)',
      border: `1px solid ${borderColor}`,
      borderLeft: `4px solid ${borderColor}`,
      borderRadius: 12,
      padding: '14px 16px',
      minWidth: 200,
      fontFamily: 'var(--font)',
      opacity: isDeclaredOnly ? 0.7 : 1
    }}>
      <Handle type="target" position={Position.Left} style={{ background: borderColor, border: 'none' }} />
      <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: borderColor, marginBottom: 6 }}>
        Consumer Group{isDeclaredOnly ? ' · Inactive' : ''}
      </div>
      {data.name && (
        <div style={{ fontSize: 14, fontWeight: 500, color: 'var(--on-surface)', marginBottom: 2 }}>
          {data.name}
        </div>
      )}
      <div style={{
        fontSize: 13,
        fontWeight: data.name ? 400 : 500,
        color: data.name ? 'var(--on-surface-dim)' : 'var(--on-surface)',
        fontFamily: 'var(--mono)',
        marginBottom: 4,
        wordBreak: 'break-all'
      }}>
        {data.groupId}
      </div>
      {data.description && (
        <div style={{ fontSize: 12, color: 'var(--on-surface-dim)', marginBottom: 8 }}>
          {data.description}
        </div>
      )}
      {data.type && (
        <div style={{ marginBottom: 8 }}>
          <Chip label={data.type} color="var(--consumer-light)" />
        </div>
      )}
      <div style={{ display: 'flex', gap: 20 }}>
        <div>
          <div style={{ fontSize: 10, color: 'var(--on-surface-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Lag</div>
          <div style={{ fontSize: 22, fontWeight: 300, color: lagColor }}>
            {isDeclaredOnly ? '—' : data.lag.toLocaleString()}
          </div>
        </div>
        <div>
          <div style={{ fontSize: 10, color: 'var(--on-surface-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Partitions</div>
          <div style={{ fontSize: 22, fontWeight: 300, color: 'var(--on-surface)' }}>{data.partitionsAssigned}</div>
        </div>
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
