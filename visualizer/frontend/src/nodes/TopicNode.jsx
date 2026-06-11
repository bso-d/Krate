import { Handle, Position } from '@xyflow/react'

export default function TopicNode({ data }) {
  return (
    <div style={{
      background: 'var(--surface-2)',
      border: '2px solid var(--topic-light)',
      borderRadius: 16,
      padding: '18px 24px',
      minWidth: 220,
      fontFamily: 'var(--font)',
      textAlign: 'center'
    }}>
      <Handle type="target" position={Position.Left} style={{ background: 'var(--topic-light)', border: 'none' }} />
      <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--topic-light)', marginBottom: 8 }}>
        Topic
      </div>
      <div style={{ fontSize: 16, fontWeight: 500, color: 'var(--topic-light)', fontFamily: 'var(--mono)', marginBottom: 16, wordBreak: 'break-all' }}>
        {data.name}
      </div>
      <div style={{ display: 'flex', justifyContent: 'center', gap: 24 }}>
        <Stat label="Partitions" value={data.partitions} />
        <Stat label="Replication" value={`×${data.replication}`} />
        <Stat label="Messages" value={(data.totalMessages ?? 0).toLocaleString()} />
      </div>
      <Handle type="source" position={Position.Right} style={{ background: 'var(--topic-light)', border: 'none' }} />
    </div>
  )
}

function Stat({ label, value }) {
  return (
    <div>
      <div style={{ fontSize: 10, color: 'var(--on-surface-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
      <div style={{ fontSize: 22, fontWeight: 300, color: 'var(--on-surface)', marginTop: 2 }}>{value}</div>
    </div>
  )
}
