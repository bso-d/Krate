import { Handle, Position } from '@xyflow/react'

export default function BrokerNode({ data }) {
  const isInSync = data.inSync === (data.leads + data.replicates)

  return (
    <div style={{
      background: 'var(--surface-2)',
      border: '1px solid var(--broker-light)',
      borderLeft: '4px solid var(--broker-light)',
      borderRadius: 12,
      padding: '14px 16px',
      minWidth: 190,
      fontFamily: 'var(--font)'
    }}>
      <Handle type="target" position={Position.Left} style={{ background: 'var(--broker-light)', border: 'none' }} />
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <div style={{ fontSize: 10, textTransform: 'uppercase', letterSpacing: '0.1em', color: 'var(--broker-light)' }}>
          Broker {data.brokerId}
        </div>
        <span style={{
          fontSize: 9,
          padding: '1px 6px',
          borderRadius: 8,
          background: isInSync ? '#1B5E20' : '#7f1d1d',
          color: isInSync ? '#4CAF50' : 'var(--error)'
        }}>
          {isInSync ? 'IN SYNC' : 'LAGGING'}
        </span>
      </div>
      <div style={{ display: 'flex', gap: 20 }}>
        <div>
          <div style={{ fontSize: 10, color: 'var(--on-surface-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Leads</div>
          <div style={{ fontSize: 22, fontWeight: 300, color: 'var(--broker-light)' }}>{data.leads}</div>
        </div>
        <div>
          <div style={{ fontSize: 10, color: 'var(--on-surface-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Replicas</div>
          <div style={{ fontSize: 22, fontWeight: 300, color: 'var(--on-surface)' }}>{data.replicates}</div>
        </div>
      </div>
    </div>
  )
}
