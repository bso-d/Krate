const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { Kafka } = require('kafkajs');

const app = express();
app.use(cors());
app.use(express.json());

const BROKERS = (process.env.KAFKA_BROKERS || 'localhost:19092,localhost:19093,localhost:19094,localhost:19095').split(',');
const CONFIG_PATH = process.env.TOPOLOGY_CONFIG || path.join(__dirname, '..', 'topology.config.json');
const PORT = process.env.PORT || 3001;

const kafka = new Kafka({ clientId: 'kafka-visualizer', brokers: BROKERS });
const admin = kafka.admin();

// Shared promise so concurrent requests don't race to connect simultaneously.
// Reset to null on failure so the next request retries.
let connectPromise = null;

async function ensureConnected() {
  if (!connectPromise) {
    connectPromise = admin.connect().catch(err => {
      connectPromise = null;
      throw err;
    });
  }
  return connectPromise;
}

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  } catch (_) {
    return { producers: [], consumers: [], mirrors: [] };
  }
}

// ─── GET /api/topics ─────────────────────────────────────────────────────────
app.get('/api/topics', async (req, res) => {
  try {
    await ensureConnected();
    const metadata = await admin.fetchTopicMetadata();
    const topics = metadata.topics
      .filter(t => !t.name.startsWith('_'))
      .map(t => ({
        name: t.name,
        partitions: t.partitions.length,
        replicationFactor: t.partitions[0]?.replicas?.length ?? 0
      }))
      .sort((a, b) => a.name.localeCompare(b.name));
    res.json(topics);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── GET /api/topology/:topic ─────────────────────────────────────────────────
app.get('/api/topology/:topic', async (req, res) => {
  const topicName = req.params.topic;
  try {
    await ensureConnected();

    // 1. Topic partition metadata
    const metadata = await admin.fetchTopicMetadata({ topics: [topicName] });
    const topicMeta = metadata.topics[0];
    if (!topicMeta) return res.status(404).json({ error: 'Topic not found' });

    // Aggregate partition leadership and replication per broker
    const brokerMap = {};
    topicMeta.partitions.forEach(p => {
      [p.leader, ...p.replicas.filter(r => r !== p.leader)].forEach((brokerId, idx) => {
        if (!brokerMap[brokerId]) brokerMap[brokerId] = { leads: 0, replicates: 0, inSync: 0 };
        if (idx === 0) brokerMap[brokerId].leads++;
        else brokerMap[brokerId].replicates++;
        if (p.isr.includes(brokerId)) brokerMap[brokerId].inSync++;
      });
    });

    // 2. End offsets (high watermark per partition)
    const endOffsets = await admin.fetchTopicOffsets(topicName);
    const hwmMap = {};
    endOffsets.forEach(o => { hwmMap[o.partition] = parseInt(o.offset, 10); });
    const totalMessages = Object.values(hwmMap).reduce((s, v) => s + v, 0);

    // 3. Consumer groups and lag
    const { groups } = await admin.listGroups();
    const liveConsumers = [];

    for (const group of groups) {
      try {
        const offsets = await admin.fetchOffsets({ groupId: group.groupId, topics: [topicName] });
        const topicOffsets = offsets.find(o => o.topic === topicName);
        if (!topicOffsets) continue;

        const active = topicOffsets.partitions.filter(p => p.offset !== '-1');
        if (active.length === 0) continue;

        let totalLag = 0;
        active.forEach(p => {
          const hwm = hwmMap[p.partition] ?? 0;
          totalLag += Math.max(0, hwm - parseInt(p.offset, 10));
        });

        liveConsumers.push({ groupId: group.groupId, lag: totalLag, partitionsAssigned: active.length });
      } catch (_) {
        // group doesn't consume this topic or errored — skip
      }
    }

    // 4. Load topology config
    const config = loadConfig();
    const configConsumers = config.consumers || [];
    const mirrors = config.mirrors || [];

    // Enrich live consumer groups with declared labels from config
    const consumers = liveConsumers.map(c => {
      const declared = configConsumers.find(cc => cc.groupId === c.groupId);
      return declared
        ? { ...c, name: declared.name, type: declared.type, description: declared.description }
        : c;
    });

    // Add config-declared consumers that aren't live yet (lag = unknown, shown greyed)
    configConsumers
      .filter(cc => cc.topics && cc.topics.includes(topicName) && !liveConsumers.find(lc => lc.groupId === cc.groupId))
      .forEach(cc => {
        consumers.push({ groupId: cc.groupId, name: cc.name, type: cc.type, description: cc.description, lag: null, partitionsAssigned: 0, declared: true });
      });

    // 5. Producers and mirrors from config
    const producers = (config.producers || []).filter(p => p.topic === topicName);
    const incomingMirrors = mirrors.filter(m => m.to === topicName);
    const outgoingMirrors = mirrors.filter(m => m.from === topicName);

    res.json({
      topic: topicName,
      partitionCount: topicMeta.partitions.length,
      replicationFactor: topicMeta.partitions[0]?.replicas?.length ?? 0,
      totalMessages,
      brokers: Object.entries(brokerMap)
        .map(([id, d]) => ({ brokerId: parseInt(id, 10), ...d }))
        .sort((a, b) => a.brokerId - b.brokerId),
      consumers,
      producers,
      incomingMirrors,
      outgoingMirrors
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Serve built frontend ─────────────────────────────────────────────────────
const publicDir = path.join(__dirname, 'public');
if (fs.existsSync(publicDir)) {
  app.use(express.static(publicDir));
  app.get('*', (_, res) => res.sendFile(path.join(publicDir, 'index.html')));
}

app.listen(PORT, () => console.log(`Visualizer running on http://localhost:${PORT}`));

process.on('SIGTERM', async () => {
  try { await admin.disconnect(); } catch (_) {}
  process.exit(0);
});
