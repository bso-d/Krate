import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Link, useParams } from 'react-router-dom'
import TopicTiles from './components/TopicTiles.jsx'
import TopologyGraph from './components/TopologyGraph.jsx'

// Vite sets BASE_URL to '/' in dev and '/visualizer/' in production Docker build.
// BrowserRouter basename must not have a trailing slash.
const basename = import.meta.env.BASE_URL.replace(/\/$/, '')

function TopicListPage() {
  const [topics, setTopics] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    fetch(`${import.meta.env.BASE_URL}api/topics`)
      .then(r => { if (!r.ok) throw new Error(`Server error ${r.status}`); return r.json() })
      .then(data => { setTopics(data); setLoading(false) })
      .catch(e => { setError(e.message); setLoading(false) })
  }, [])

  if (loading) return <StatusMessage>Connecting to Kafka…</StatusMessage>
  if (error) return <StatusMessage error>Failed to connect: {error}</StatusMessage>
  return <TopicTiles topics={topics} />
}

function TopicDetailPage() {
  const { name } = useParams()
  return <TopologyGraph topicName={decodeURIComponent(name)} />
}

function StatusMessage({ children, error }) {
  return (
    <div style={{
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      height: '100%', color: error ? 'var(--error)' : 'var(--on-surface-dim)'
    }}>
      {children}
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter basename={basename}>
      <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>

        <header style={{
          background: 'var(--surface-2)',
          borderBottom: '1px solid var(--outline)',
          padding: '0 24px',
          height: 48,
          display: 'flex',
          alignItems: 'center',
          flexShrink: 0
        }}>
          <Link to="/" style={{ textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 10 }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none"
              stroke="var(--primary)" strokeWidth="2.5"
              strokeLinecap="round" strokeLinejoin="round">
              <polyline points="3 17 9 11 13 15 21 7" />
              <polyline points="17 7 21 7 21 11" />
            </svg>
            <span style={{ fontSize: 15, fontWeight: 500, color: 'var(--on-surface)', letterSpacing: '-0.01em' }}>
              Stream Visualizer
            </span>
          </Link>
        </header>

        <main style={{ flex: 1, overflow: 'hidden' }}>
          <Routes>
            <Route path="/" element={<TopicListPage />} />
            <Route path="/topic/:name" element={<TopicDetailPage />} />
          </Routes>
        </main>

      </div>
    </BrowserRouter>
  )
}
