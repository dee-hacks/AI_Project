/**
 * D3.js force simulation configuration for the topology graph.
 */
import * as d3 from 'd3';

export function createForceSimulation(width, height, nodes, links) {
  const simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links)
      .id((d) => d.id)
      .distance(100)
      .strength(0.5))
    .force('charge', d3.forceManyBody()
      .strength(-300)
      .distanceMax(500))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide()
      .radius(30))
    .alphaDecay(0.02);

  return simulation;
}

export function renderGraph(svgElement, data, options = {}) {
  const {
    width = svgElement.clientWidth || 600,
    height = svgElement.clientHeight || 400,
    nodeRadius = 15,
    linkColor = '#2a2a4a',
    anomalyColor = '#ff4444',
    compromisedColor = '#ff8800',
    normalColor = '#00d4ff',
  } = options;

  // Clear previous
  svgElement.innerHTML = '';

  const svg = d3.select(svgElement);
  const g = svg.append('g');

  // Zoom
  const zoom = d3.zoom()
    .scaleExtent([0.1, 4])
    .on('zoom', (event) => {
      g.attr('transform', event.transform);
    });
  svg.call(zoom);

  // Links
  const link = g.append('g')
    .selectAll('line')
    .data(data.links)
    .join('line')
    .attr('stroke', (d) => d.is_anomalous ? anomalyColor : linkColor)
    .attr('stroke-width', 1.5)
    .attr('stroke-opacity', 0.6);

  // Nodes
  const node = g.append('g')
    .selectAll('circle')
    .data(data.nodes)
    .join('circle')
    .attr('r', nodeRadius)
    .attr('fill', (d) => {
      if (d.is_compromised) return compromisedColor;
      if (d.anomaly_score > 0) return anomalyColor;
      return normalColor;
    })
    .attr('stroke', '#fff')
    .attr('stroke-width', 1.5)
    .attr('opacity', 0.8)
    .call(d3.drag()
      .on('start', (event, d) => {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on('drag', (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on('end', (event, d) => {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      }));

  // Labels
  const label = g.append('g')
    .selectAll('text')
    .data(data.nodes)
    .join('text')
    .text((d) => d.hostname || d.ip)
    .attr('font-size', 10)
    .attr('fill', '#e0e0e0')
    .attr('dx', 18)
    .attr('dy', 4);

  // Title tooltips
  node.append('title')
    .text((d) => `${d.ip}\n${d.mac}\nVendor: ${d.vendor || 'Unknown'}\nScore: ${d.anomaly_score?.toFixed(4) || 0}`);

  // Simulation
  const simulation = d3.forceSimulation(data.nodes)
    .force('link', d3.forceLink(data.links)
      .id((d) => d.id)
      .distance(100))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(width / 2, height / 2));

  simulation.on('tick', () => {
    link
      .attr('x1', (d) => d.source.x)
      .attr('y1', (d) => d.source.y)
      .attr('x2', (d) => d.target.x)
      .attr('y2', (d) => d.target.y);

    node
      .attr('cx', (d) => d.x)
      .attr('cy', (d) => d.y);

    label
      .attr('x', (d) => d.x)
      .attr('y', (d) => d.y);
  });

  return simulation;
}

export function renderTimeline(svgElement, events, options = {}) {
  const {
    width = svgElement.clientWidth || 600,
    height = svgElement.clientHeight || 200,
  } = options;

  svgElement.innerHTML = '';

  if (!events || events.length < 2) {
    // Show placeholder
    const svg = d3.select(svgElement);
    svg.append('text')
      .attr('x', width / 2)
      .attr('y', height / 2)
      .attr('text-anchor', 'middle')
      .attr('fill', '#a0a0b0')
      .attr('font-size', 14)
      .text('Insufficient data for timeline');
    return;
  }

  const margin = { top: 20, right: 20, bottom: 30, left: 40 };
  const innerWidth = width - margin.left - margin.right;
  const innerHeight = height - margin.top - margin.bottom;

  const svg = d3.select(svgElement);
  const g = svg.append('g')
    .attr('transform', `translate(${margin.left},${margin.top})`);

  // Scale
  const times = events.map((e) => e.timestamp || e.time || Date.now() / 1000);
  const scores = events.map((e) => e.anomaly_score || 0);

  const xScale = d3.scaleLinear()
    .domain([Math.min(...times), Math.max(...times)])
    .range([0, innerWidth]);

  const yScale = d3.scaleLinear()
    .domain([0, Math.max(...scores) * 1.1 || 1])
    .range([innerHeight, 0]);

  // Line
  const line = d3.line()
    .x((d, i) => xScale(times[i]))
    .y((d) => yScale(d))
    .curve(d3.curveMonotoneX);

  g.append('path')
    .datum(scores)
    .attr('fill', 'none')
    .attr('stroke', '#00d4ff')
    .attr('stroke-width', 2)
    .attr('d', line);

  // Area
  const area = d3.area()
    .x((d, i) => xScale(times[i]))
    .y0(innerHeight)
    .y1((d) => yScale(d))
    .curve(d3.curveMonotoneX);

  g.append('path')
    .datum(scores)
    .attr('fill', 'rgba(0, 212, 255, 0.1)')
    .attr('d', area);

  // Axes
  g.append('g')
    .attr('transform', `translate(0,${innerHeight})`)
    .call(d3.axisBottom(xScale).ticks(5))
    .attr('color', '#a0a0b0');

  g.append('g')
    .call(d3.axisLeft(yScale).ticks(4))
    .attr('color', '#a0a0b0');
}