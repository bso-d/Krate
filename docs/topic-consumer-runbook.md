# Topic, consumer group, and consumer operations

Use this runbook to create a topic, start a consumer group, verify delivery and
restart behavior, and retire each safely. Commands target the repository's
Apache Kafka **3.9.1** KRaft and EPC deployments. Run the walkthrough on a
development cluster first. It creates only uniquely named demonstration resources;
it does not reset offsets or remove cluster storage.

The checks here are operator instructions. Save output and any additional test
scripts locally and untracked (for example, in ignored `tests/`); do not commit
test output or credentials.

## 1. Select and check the cluster

Use Bash on the Docker host. Enter the installed variant directory containing
`krate` and `.env` (in a checkout, `kraft/` or `epc/`). Use the same shell for
the walkthrough so its variables remain available. Do not source an unfamiliar
`.env` file or paste its contents into a report.

Choose **one** block:

```bash
# KRaft baseline: four brokers; run from kraft/ or its extracted bundle.
BROKER=krate-broker-92
BOOTSTRAP=kafka-92:9092,kafka-93:9093,kafka-94:9094,kafka-95:9095
RF=3
MIN_ISR=2
```

```bash
# EPC: two brokers; run from epc/ or its extracted bundle.
BROKER=epc-broker-92
BOOTSTRAP=kafka-92:19092,kafka-93:19093
RF=2
MIN_ISR=1
```

The bootstrap names above work **inside the selected broker container**. Keep
that context; they are not addresses for applications on another machine.

```bash
B=/opt/kafka/bin
docker context show
hostname
./krate status
./krate health
docker inspect --format '{{.Name}} {{.Config.Image}}' "$BROKER"
docker exec "$BROKER" "$B/kafka-metadata-quorum.sh" \
  --bootstrap-server "$BOOTSTRAP" describe --status
docker exec "$BROKER" "$B/kafka-broker-api-versions.sh" \
  --bootstrap-server "$BOOTSTRAP"
```

Match the host, Docker context, broker image, cluster ID, broker IDs, and endpoint
to the intended deployment. Expect four brokers (92–95) for KRaft or two (92–93)
for EPC, an elected controller, and healthy services. Stop if they do not match.
For EPC, also run `./krate disk` and inspect free space on the configured data
filesystem before adding a topic.

| Deployment | Application bootstrap on Docker host | Application bootstrap off host |
| --- | --- | --- |
| KRaft baseline | `localhost:19092,localhost:19093,localhost:19094,localhost:19095` | The committed Compose advertises `localhost`; arrange reachable advertised listeners on **every** broker before remote use. |
| EPC | Configured advertised host and broker ports (defaults 9092/9093) | Set `KAFKA_ADVERTISED_HOST` to the VM's reachable FQDN/IP and use the configured external ports. |

Reaching the initial bootstrap socket is insufficient if returned broker
addresses cannot be resolved or reached. These deployments use PLAINTEXT for
Kafka; the UI's HTTPS login does not secure Kafka client connections. Restrict
broker network access to trusted clients or deploy the required Kafka security
configuration before wider access.

The committed EPC baseline has one UI cluster. Local work may add multiple UI
clusters or read-only settings; do not assume those changes are released. In any
multi-cluster UI, explicitly select and verify the target cluster before each
operation. The commands above address the brokers on the selected Docker host.

## 2. Choose topic settings deliberately

A topic stores records. A consumer is a running application/client. A consumer
group tracks processing positions and assigns partitions among its consumers.
There is no separate consumer-group creation command in this workflow: starting
a subscribing consumer with a new `group.id` creates its group. A consumer ID is
runtime membership, not an account to provision.

Before creating a real topic, agree its owner, record format, partition key,
partition count, retention, replication, and reader groups. Use a stable name
such as `orders-events-v1`. A separate group receives its own view of the stream;
another consumer in the same group shares work and causes a rebalance. With
normal group subscription, additional consumers beyond the partition count are
idle. [Kafka consumer API](https://kafka.apache.org/39/javadoc/org/apache/kafka/clients/consumer/KafkaConsumer.html)

| Setting | Demonstration | Production decision |
| --- | --- | --- |
| Partitions | 1, for deterministic offsets | Size for throughput and parallelism. Repository defaults are 24; avoid inheriting them accidentally. |
| Replication / minimum ISR | KRaft: 3 / 2; EPC: 2 / 1 | Explicitly use the approved durability policy. |
| Cleanup | `delete` | Choose according to the data contract; compacted state topics need a different policy. |
| Retention | 1 hour, 16 MiB per partition replica | Match recovery/replay needs and available disk. |
| Segment roll | 1 MiB or 5 minutes | Small demonstration settings; size separately for actual traffic. |

With `acks=all`, minimum ISR controls when writes may be acknowledged. EPC's
minimum ISR of 1 offers less replication protection for acknowledged writes
than 2. Its two combined controller/broker nodes also require both voters for a
controller majority; RF=2/minISR=1 does not provide one-node outage tolerance.
[Kafka topic configuration](https://kafka.apache.org/39/configuration/topic-level-configs/)

Retention is not a hard disk quota. Deletion occurs by segment and on a schedule;
active segments, indexes, internal topics, and other files also occupy space.
For EPC's defaults, 24 partitions × RF 2 × 2 GiB is roughly **96 GiB per topic**
before this overhead, on the shared data filesystem. Allow headroom and inspect
actual usage. Topic overrides also take precedence over later broker-default
changes. [Kafka retention settings](https://kafka.apache.org/39/configuration/topic-level-configs/)

## 3. Create and inspect a demonstration topic

Generate names once. Keep them for the later verification and cleanup steps.
Never substitute a production group into this demonstration.

```bash
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
TOPIC="krate-demo-${RUN_ID}"
GROUP="krate-demo-reader-${RUN_ID}"
printf 'Container: %s\nBootstrap: %s\nTopic: %s\nGroup: %s\n' \
  "$BROKER" "$BOOTSTRAP" "$TOPIC" "$GROUP"

docker exec "$BROKER" "$B/kafka-topics.sh" \
  --bootstrap-server "$BOOTSTRAP" --create --topic "$TOPIC" \
  --partitions 1 --replication-factor "$RF" \
  --config "min.insync.replicas=$MIN_ISR" \
  --config cleanup.policy=delete \
  --config retention.ms=3600000 \
  --config retention.bytes=16777216 \
  --config segment.bytes=1048576 \
  --config segment.ms=300000

docker exec "$BROKER" "$B/kafka-topics.sh" \
  --bootstrap-server "$BOOTSTRAP" --describe --topic "$TOPIC"
docker exec "$BROKER" "$B/kafka-configs.sh" \
  --bootstrap-server "$BOOTSTRAP" --entity-type topics \
  --entity-name "$TOPIC" --describe
```

Expect one partition, a valid leader, the selected replication factor, full ISR
(3 or 2), and the explicit overrides above. Creation must succeed before you
publish anything. If the name already exists, stop and choose a new run ID;
do not silently reuse it with `--if-not-exists`.

KRaft currently enables topic auto-creation; EPC defaults to disabling it.
Explicit creation avoids typo-created topics and unintended defaults. Changing
partition count later affects key routing; Kafka cannot reduce the count.
[Kafka topic operations](https://kafka.apache.org/39/operations/basic-kafka-operations/)

## 4. Produce, create a group, and test consumption

Send three non-sensitive records to the new topic. Keep producer errors visible.

```bash
printf '%s\n' "${RUN_ID}-one" "${RUN_ID}-two" "${RUN_ID}-three" |
  docker exec -i "$BROKER" "$B/kafka-console-producer.sh" \
    --bootstrap-server "$BOOTSTRAP" --topic "$TOPIC" \
    --producer-property acks=all \
    --producer-property enable.idempotence=true \
    --producer-property delivery.timeout.ms=30000 \
    --producer-property request.timeout.ms=10000 \
    --producer-property max.block.ms=30000
```

Idempotence protects against duplicate writes from the producer's own retries;
manually rerunning this block still sends new records. If delivery is uncertain,
inspect this demonstration topic before retrying.
[Kafka producer configuration](https://kafka.apache.org/39/configuration/producer-configs/)

Start a bounded console consumer with a new group. This demonstrates transport
and offsets, not the processing guarantees of a business application.

```bash
docker exec "$BROKER" "$B/kafka-console-consumer.sh" \
  --bootstrap-server "$BOOTSTRAP" --topic "$TOPIC" --group "$GROUP" \
  --from-beginning --max-messages 3 --timeout-ms 30000 \
  --consumer-property "client.id=${GROUP}-one" \
  --consumer-property allow.auto.create.topics=false \
  --consumer-property enable.auto.commit=true \
  --consumer-property auto.commit.interval.ms=1000 \
  --property print.partition=true --property print.offset=true

docker exec "$BROKER" "$B/kafka-consumer-groups.sh" \
  --bootstrap-server "$BOOTSTRAP" --describe --group "$GROUP"
```

Expect exactly the three records, in order, at partition 0 offsets 0, 1, and 2.
After the consumer exits, expect `CURRENT-OFFSET=3`, `LOG-END-OFFSET=3`, and
`LAG=0`. An inactive-member message after this bounded run is normal. A missing
offset (`-`) is not a successful commit. Wait briefly and inspect again; if it
remains missing, investigate the consumer errors before continuing.

The console consumer closes its Kafka consumer when it reaches the record limit;
with auto-commit enabled, graceful close attempts the final commit. Verify the
stored offset rather than inferring success from printed records. The timeout
limits waiting for records, not the entire process; connection and close may add
time. A timeout or a zero exit status alone does not establish success.
[Kafka 3.9.1 console consumer implementation](https://github.com/apache/kafka/blob/3.9.1/tools/src/main/java/org/apache/kafka/tools/consumer/ConsoleConsumer.java)

### Verify restart resumes after the committed offset

Only proceed once offset 3 is confirmed. Publish one additional record, then
restart the same group without `--from-beginning`:

```bash
printf '%s\n' "${RUN_ID}-four" |
  docker exec -i "$BROKER" "$B/kafka-console-producer.sh" \
    --bootstrap-server "$BOOTSTRAP" --topic "$TOPIC" \
    --producer-property acks=all \
    --producer-property enable.idempotence=true \
    --producer-property delivery.timeout.ms=30000 \
    --producer-property request.timeout.ms=10000 \
    --producer-property max.block.ms=30000

docker exec "$BROKER" "$B/kafka-console-consumer.sh" \
  --bootstrap-server "$BOOTSTRAP" --topic "$TOPIC" --group "$GROUP" \
  --max-messages 1 --timeout-ms 30000 \
  --consumer-property "client.id=${GROUP}-one" \
  --consumer-property auto.offset.reset=none \
  --consumer-property allow.auto.create.topics=false \
  --consumer-property enable.auto.commit=true \
  --consumer-property auto.commit.interval.ms=1000 \
  --property print.partition=true --property print.offset=true

docker exec "$BROKER" "$B/kafka-consumer-groups.sh" \
  --bootstrap-server "$BOOTSTRAP" --describe --group "$GROUP"
```

Expect only `...-four` at offset 3; the committed and log-end offsets must both
be 4, with lag 0. `auto.offset.reset=none` makes missing/expired offsets fail
instead of silently selecting another position. `--from-beginning` selects the
earliest available position only when there is no valid committed offset; it
does not rewind an existing group.
[Kafka consumer configuration](https://kafka.apache.org/39/configuration/consumer-configs/)

## 5. Add or scale an application consumer

Create the production topic with its approved settings separately. Deploy the
application using the right external bootstrap endpoints, its exact topic,
a stable `group.id`, and an identifiable `client.id` for each instance. Decide
how a new group starts: `earliest` replays retained history; `latest` starts at
the end when no offset exists; `none` requires an explicitly established offset.
Do not use a production group for ad hoc inspection.

For an application with external side effects, disable automatic commits and
commit only after successful processing. Handle replay idempotently. A commit
records the **next** offset to read; it is not evidence that downstream work
succeeded. Verify the application's output as well as Kafka lag.
[Kafka consumer processing and commits](https://kafka.apache.org/39/javadoc/org/apache/kafka/clients/consumer/KafkaConsumer.html)

Test the application against a dedicated test topic and group first: check
known input/output, a graceful restart, and a controlled failed-message retry.
Keep the test's external side effects in a test destination. Run failure/rebalance
experiments in development, never by restarting a production broker.

To add capacity, start another application instance with the same group and
subscription. To add an independent reader, give it a different group. Inspect
membership while the application is running (set `GROUP` explicitly to the
application group for these read-only commands):

```bash
docker exec "$BROKER" "$B/kafka-consumer-groups.sh" \
  --bootstrap-server "$BOOTSTRAP" --describe --group "$GROUP" --state
docker exec "$BROKER" "$B/kafka-consumer-groups.sh" \
  --bootstrap-server "$BOOTSTRAP" --describe --group "$GROUP" --members --verbose
docker exec "$BROKER" "$B/kafka-consumer-groups.sh" \
  --bootstrap-server "$BOOTSTRAP" --describe --group "$GROUP"
```

Expect a stable group, intended member count and assignments, and lag that
recovers after rebalancing. The one-partition demo supports only one assigned
consumer; use a separately planned multi-partition test topic to test concurrent
processing. Restore the saved demonstration `GROUP` before its cleanup.

## 6. Stop a consumer, delete a group, delete a topic

These are separate operations:

| Action | Effect |
| --- | --- |
| Stop one consumer | Stop that application instance gracefully through its service manager; surviving group members rebalance. Records and committed offsets remain. |
| Delete a consumer group | Remove the group's saved offsets/metadata across its topics. Topic records remain. |
| Delete a topic | Remove that topic's data for every reader. Recreating its name does not restore records. |

To retire a consumer, disable its automatic restart/scheduler, finish or safely
abandon in-flight work, commit completed work, and close it gracefully. There is
no persistent consumer object to delete. Do not stop the broker to stop a
consumer; a `docker exec` console consumer runs inside a broker container.

Before deleting a real group or topic, confirm ownership and dependencies,
record the existing settings and offsets locally, and arrange any needed export
and recovery procedure. Check every group using the topic. Stop producers before
retiring a topic; let readers drain if required, then stop them. Stop **all**
members and restart mechanisms before deleting a group. Kafka refuses deletion
of an active group. [Kafka group management](https://kafka.apache.org/39/operations/basic-kafka-operations/)

The following cleanup is deliberately restricted to this walkthrough's names.
If variables were lost, recover the exact saved names; do not regenerate an ID
or use wildcards to select resources.

```bash
demo_names_ok() {
  [[ -n "${RUN_ID:-}" &&
     "${TOPIC:-}" == "krate-demo-${RUN_ID}" &&
     "${GROUP:-}" == "krate-demo-reader-${RUN_ID}" ]]
}
demo_names_ok && printf 'Cleanup on %s: topic=%s group=%s\n' \
  "$BROKER" "$TOPIC" "$GROUP"
docker exec "$BROKER" "$B/kafka-consumer-groups.sh" \
  --bootstrap-server "$BOOTSTRAP" --describe --group "$GROUP" --state
docker exec "$BROKER" "$B/kafka-consumer-groups.sh" \
  --bootstrap-server "$BOOTSTRAP" --describe --group "$GROUP" --members
```

Confirm the displayed target and an empty group with zero active members.
Then delete its offsets:

```bash
demo_names_ok && docker exec "$BROKER" "$B/kafka-consumer-groups.sh" \
  --bootstrap-server "$BOOTSTRAP" --delete --group "$GROUP"
docker exec "$BROKER" "$B/kafka-consumer-groups.sh" \
  --bootstrap-server "$BOOTSTRAP" --list
```

Expect deletion success and the exact group absent from the list. Restarting a
consumer with this group ID can recreate the group. Without its old offsets,
the configured reset policy can replay records, skip history, or fail. Deleting
a group is therefore not a harmless way to fix lag.

Once all users of the demonstration topic have stopped, review its description
one last time, then explicitly confirm its name:

```bash
docker exec "$BROKER" "$B/kafka-topics.sh" \
  --bootstrap-server "$BOOTSTRAP" --describe --topic "$TOPIC"
read -r -p 'Type the exact demonstration topic name to delete: ' CONFIRM_TOPIC
if demo_names_ok && [[ "$CONFIRM_TOPIC" == "$TOPIC" ]]; then
  docker exec "$BROKER" "$B/kafka-topics.sh" \
    --bootstrap-server "$BOOTSTRAP" --delete --topic "$TOPIC"
else
  printf 'Topic deletion cancelled.\n'
fi
docker exec "$BROKER" "$B/kafka-topics.sh" \
  --bootstrap-server "$BOOTSTRAP" --list
```

Deletion is asynchronous: repeat the list until the exact topic is absent.
Do not use a consumer/producer as an absence check; auto-creation could recreate
it. Topic deletion does not retire application deployments or all their group
metadata. Do not delete `__consumer_offsets`, manually remove log directories,
purge volumes, or reset production offsets as part of this procedure.

## UI path and troubleshooting

Run `./krate ui` to find the UI URL; its output includes credentials, so keep it
private. In the selected cluster, use topic details and consumer-group views to
inspect settings, ISR, assignments, offsets, and lag. If the deployed UI exposes
topic create/delete actions and your role permits them, apply the same explicit
settings and retirement sequence above. Read-only configuration may hide or
disable writes. Starting a consumer still requires a running client application.

| Symptom | Check and response |
| --- | --- |
| Unknown topic | Verify spelling and cluster identity; explicitly create the approved topic. |
| Invalid replication factor | Verify broker count; do not lower production replication just to make a test pass. |
| Insufficient ISR / producer delivery error | Inspect leader, ISR, broker health, and disk; retain the agreed durability policy. |
| Consumer sees nothing | Inspect assignments, existing offsets, log end, and reset policy. Use a new demonstration group to replay test data. |
| Group keeps rebalancing | Inspect client logs, processing time, poll interval, connectivity, and duplicate static member IDs if configured. |
| Group deletion fails | Verify every instance and its restart mechanism stopped; wait for membership expiry and inspect again. |
| Topic reappears after deletion | Find a still-running producer/consumer or topic provisioning job; check auto-creation. |
| Bootstrap works but requests fail | Verify advertised addresses for every broker from the actual client host. |

Completion evidence: correct cluster identified; topic settings/full ISR checked;
three records read and offset 3 committed; restart reads only the fourth record
and commits offset 4; group and topic absent after cleanup. Record date, variant,
cluster ID, names, outcomes, and any errors in a local operator report. This
runbook's commands require execution on the target environment before claiming
that environment has passed.
