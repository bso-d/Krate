# Perses dashboards (project `krate`)

These are Perses `Dashboard` resources for Perses **v0.54.0**
(`persesdev/perses@sha256:a0e34ddaf9d7599d96036611af205b948c1179646844202d869f3bcf3d5d9e9c`).
The plugins they use are all baked into that image. The image archives are byte-identical to the
official release archives:

| Plugin archive | SHA-256 |
|---|---|
| Prometheus 0.58.0 | `3e8041e8e5d8b990092bc4d3ae0c8464440d59f94bcf278748005cdc247b2ed2` |
| StatChart 0.13.0 | `674d4b1a565ed9db43af0c69b287429993b0feaeb1ea49990ce6874f41dcd408` |
| GaugeChart 0.13.0 | `74bb7b6103ab819f7c4c745c0ed6b0e5a1ae57ed4f1ed980e5913019f1150bfc` |
| Table 0.13.0 | `9e277eeef56e61f5cce006cb6b2178cd4d3fd3558431877f287b3467cd214166` |
| TimeSeriesChart 0.13.0 | `ac1043c6393c601ffcf83602ff157f4a22f38ddf7c4a5c1188b55146b6311f17` |
| VictoriaLogs 0.4.0 | `eafacacb0827a39a7495646e2229010c7ba711adb24762b86f294bbfd238ed2f` |
| LogsTable 0.3.0 | `1313bcc8ee1cb426e9839328ad5743d3627e24f9f0fe2c6353d5d520de53f075` |

| File | `metadata.name` | Source |
|---|---|---|
| `kafka-overview.json` | `krate-overview` | `monitoring/grafana/dashboards/kafka-overview.json` (7 panels, 7 queries) |
| `consumer-groups.json` | `krate-consumers` | `monitoring/grafana/dashboards/consumer-groups.json` (3 panels, 3 queries) |
| `host-capacity.json` | `krate-capacity` | `monitoring/grafana/dashboards/host-capacity.json` (4 panels, 5 queries) |
| `logs.json` | `krate-logs` | New: container logs from VictoriaLogs |

The datasources are not defined in these files. They are project datasources that are provisioned
separately. Every query names its datasource explicitly: `{kind: PrometheusDatasource, name: prometheus}`
or `{kind: VictoriaLogsDatasource, name: victorialogs}`.

## Fidelity table (Grafana -> Perses)

The following carry over 1:1:

* **PromQL:** every expression (15/15) and every `legendFormat`, mapped to `seriesNameFormat`. The `refId` maps to the query `name`.
* **Text:** panel titles and the panel description.
* **Layout:** `gridPos` x/y/w/h maps to Grid items. Both grids have 24 columns and use the same row units.
* **Dashboard settings:** title, uid (mapped to `metadata.name`), tags (mapped to `metadata.tags`), time range `now-6h` (mapped to `duration: 6h`) and refresh `30s`.
* **Variables:** there are none.

| Grafana setting | Perses setting | Notes |
|---|---|---|
| stat `reduceOptions.calcs: [lastNotNull]` | `StatChart.calculation: last-number` | Official migration mapping. |
| stat `colorMode: value` | `colorMode: value` | 1:1 |
| stat `graphMode: none` / `area` | no `sparkline` / `sparkline: {}` | The Perses sparkline is a line plus a 0.4-opacity area in the threshold color, which matches Grafana's area sparkline. |
| stat `textMode: value` | `legendMode: off` | The series name is never shown. Only the value is shown. |
| thresholds (absolute; base + steps) | `thresholds: {mode: absolute, steps: [{value}...]}` | Same threshold levels. The colour of each level comes from the Perses theme, not Grafana's named colours. |
| `color.mode: fixed, fixedColor: blue` (Topics) | no thresholds | The value uses the Perses default stat colour. The fixed blue was Grafana styling only. |
| no unit (Grafana `none` formatter) | `format: {unit: decimal, shortValues: false}` | No SI abbreviation, as in Grafana. Perses may add thousands separators (`12,345` vs Grafana `12345`). |
| unit `cps` | `counts/sec`, `shortValues: true` | The scaling is the same. The suffix wording differs ("counts/sec" vs "c/s"). |
| unit `bytes` | `bytes`, `shortValues: true` | Both are IEC (1024) based. Verified in the Perses formatter bundle. |
| unit `percent` | `percent` | Both take values on a 0-100 scale. |
| timeseries `drawStyle: line` | `visual.display: line` | 1:1 |
| `fillOpacity: 10` / `0` / default | `visual.areaOpacity: 0.1` / `0` / `0` | |
| Grafana default line width 1, `spanNulls: false`, `showPoints: auto` | `lineWidth: 1`, `connectNulls: false`, `showPoints: auto` | Grafana's implicit defaults are made explicit. |
| legend `list`/`bottom` (explicit, or Grafana's default when omitted) | `legend: {position: bottom, mode: list}` | Perses shows no legend when `legend` is omitted. It is therefore set on every time series panel, including the host-capacity ones where Grafana relied on its default. |
| legend `table`/`right`, `calcs: [lastNotNull, max]` | `legend: {position: right, mode: table, values: [last-number, max]}` | 1:1 |
| table target `format: table, instant: true` | `Table` panel. Table 0.13.0 issues **instant** queries when no column embeds a panel plugin. | Verified in `table-data-utils.js`. The columns are `timestamp`, `value` and one per label. |
| table `organize`: exclude `Time`, rename `consumergroup`/`Value` | `columnSettings`: `timestamp` hidden; `consumergroup` header "Consumer Group"; `value` header "Total Lag" / "Assigned Partitions" | The column order follows `columnSettings`, giving Consumer Group then value, as in Grafana. |
| table `custom.align: auto` | `align: left` for the text column, `right` for the number column | This is what Grafana's `auto` renders. |
| table `showHeader: true` | default (the header is always shown) | |
| gauge reducer (Grafana default `lastNotNull`) | `calculation: last-number` | |
| gauge `min: 0`, `max: 100` | `max: 100`. Perses gauges always start at 0. | Same user-visible range. |
| gauge thresholds green / orange >= 80 / red >= 90 | steps at 80 and 90, coloured by the Perses theme | Same warning and critical levels. |
| one gauge per series (`{{mountpoint}}`) | GaugeChart renders one gauge per series, with `legend.show: true` showing the series name | |
| `timezone: browser` (host-capacity) / unset (others, defaults to browser) | `timezone: local` | Times are shown in the viewer's local time. |

### Settings resolved against the Grafana 12.2.0 and Perses 0.54.0 sources

Scope of fidelity: queries, legends, units, decimals, calculations, threshold
levels, layout, titles, time range, refresh and interaction behaviour match
Grafana. Visual styling (colours, palette, fonts) is Perses' own; no Grafana
colours are hard-coded.

| Grafana setting | Where | Perses result | Evidence |
|---|---|---|---|
| `custom.stepBefore: true` | Overview > "Broker count" | Linear line, identical to Grafana. | Grafana's timeseries panel has no `stepBefore` field; stepped drawing is `custom.lineInterpolation: "stepBefore"`, which is absent, so Grafana ignores the key and draws linear segments. Perses draws linear segments too. |
| `graphTooltip: 1` (shared crosshair) | Overview, Consumer Groups | Shared crosshair across all time series panels. | Every TimeSeriesChart 0.13.0 panel joins `syncGroup="default-panel-group"` (`TimeSeriesChartPanel.tsx`), and the Perses app's `ChartsProvider` leaves `enableSyncGrouping` at its default `true`. In Perses 0.54 the group is not configurable per dashboard, so Host Capacity, which has no shared crosshair in Grafana, also gets one: behaviour is added, none is lost. |
| tooltip `mode: multi` | Overview "Consumer lag by group", Consumer Groups "Lag over time" | `tooltip.enablePinning: true`. With five or fewer series the tooltip already lists every series; with more, its "Show all series" switch lists them all. | `getYBuffer` in `@perses-dev/components` 0.54.0 searches 5.5 y-intervals for up to five series and the whole canvas when "Show all series" is on; the switch appears when pinning is enabled and there are more than five series. |
| tooltip `mode: single` | Overview "Messages in / sec", "Broker count"; Host Capacity (Grafana default) | The series nearest the cursor is emphasised; nearby series are also listed. Single-series panels are identical. | Perses has no single-series-only tooltip; it shows more, never less. |
| series colours (`palette-classic`) | all time series | Perses default palette. | Styling is Perses' own by design; only data, units, thresholds, layout and behaviour are carried over. |
| `editable: true`, `schemaVersion`, `version`, `annotations: []`, `timepicker: {}` | all | No visible effect. | Grafana-internal or empty. Perses handles edit rights through RBAC. |

## `logs.json` (VictoriaLogs plugin 0.4.0, LogsTable 0.3.0)

* **Variable `container`:** a `ListVariable` that uses `VictoriaLogsFieldValuesVariable` with `field: container` and `query: _stream:{job="containerlogs"}`. It allows multiple selections plus "All", sorted alphabetically. It uses `POST /select/logsql/field_values` over the time range. Because no `customAllValue` is set, "All" expands to every listed value.
* **"Log lines per container" (TimeSeriesChart):** uses `VictoriaLogsTimeSeriesQuery` with `_stream:{job="containerlogs"} | stats by (container) count() as lines`, via `POST /select/logsql/stats_query_range`. This panel is not filtered by the variable. The value is lines per query step, not per second. The plugin names each series `container=<name>`.
* **"Container logs" (LogsTable):** uses `VictoriaLogsLogQuery` with `_stream:{job="containerlogs",container in (${container:doublequote})} | sort by (_time desc) | limit 1000`, via `POST /select/logsql/query`.
  * The `in (...)` stream filter is supported by VictoriaLogs v1.53.0 (`lib/logstorage/stream_filter.go`).
  * The `doublequote` format renders `"a","b"`, so no regex escaping is involved.
  * The plugin sends no `limit`, so the `| limit 1000` keeps the response bounded and newest-first.

Only these four POST endpoints are used, which matches the datasource `allowedEndpoints` contract:
`/select/logsql/query`, `/select/logsql/stats_query_range`, `/select/logsql/field_values` and `/select/logsql/field_names`.
