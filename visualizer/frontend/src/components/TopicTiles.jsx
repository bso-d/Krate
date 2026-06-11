import { useNavigate } from 'react-router-dom'

export default function TopicTiles({ topics }) {
  const navigate = useNavigate()

  if (topics.length === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: 'var(--on-surface-dim)' }}>
        No topics found. Create a topic and produce some messages to get started.
      </div>
    )
  }

  return (
    <div style={{ padding: 32, overflowY: 'auto', height: '100%' }}>
      <div style={{ fontSize: 13, color: 'var(--on-surface-dim)', marginBottom: 20, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
        {topics.length} topic{topics.length !== 1 ? 's' : ''}
      </div>
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
        gap: 16
      }}>
        {topics.map(topic => (
          <button
            key={topic.name}
            onClick={() => navigate(`/topic/${encodeURIComponent(topic.name)}`)}
            style={{
              background: 'var(--surface-2)',
              border: '1px solid var(--outline)',
              borderRadius: 16,
              padding: '20px 20px',
              cursor: 'pointer',
              textAlign: 'left',
              color: 'var(--on-surface)',
              transition: 'border-color 150ms, background 150ms',
              fontFamily: 'var(--font)'
            }}
            onMouseEnter={e => {
              e.currentTarget.style.borderColor = 'var(--primary)'
              e.currentTarget.style.background = 'var(--surface-3)'
            }}
            onMouseLeave={e => {
              e.currentTarget.style.borderColor = 'var(--outline)'
              e.currentTarget.style.background = 'var(--surface-2)'
            }}
          >
            <div style={{ fontSize: 15, fontWeight: 500, marginBottom: 12, wordBreak: 'break-all', fontFamily: 'var(--mono)', color: 'var(--topic-light)' }}>
              {topic.name}
            </div>
            <div style={{ display: 'flex', gap: 16 }}>
              <Stat label="Partitions" value={topic.partitions} />
              <Stat label="Replication" value={`×${topic.replicationFactor}`} />
            </div>
          </button>
        ))}
      </div>
    </div>
  )
}

function Stat({ label, value }) {
  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--on-surface-dim)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>{label}</div>
      <div style={{ fontSize: 20, fontWeight: 300, color: 'var(--on-surface)', marginTop: 2 }}>{value}</div>
    </div>
  )
}
