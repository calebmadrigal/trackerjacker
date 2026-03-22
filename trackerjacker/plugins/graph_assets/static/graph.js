const statusPill = document.getElementById("status-pill");
const metaText = document.getElementById("meta-text");
const graphRoot = document.getElementById("graph-root");
let lastAutoFitBounds = null;
const ME_NODE_ID = "__me__";

const cy = cytoscape({
  container: graphRoot,
  elements: [],
  minZoom: 0.35,
  maxZoom: 2.6,
  userZoomingEnabled: true,
  userPanningEnabled: true,
  boxSelectionEnabled: false,
  style: [
    {
      selector: "node",
      style: {
        "shape": "round-rectangle",
        "width": "data(width)",
        "height": "data(height)",
        "background-color": "#8cc8ff",
        "border-width": 2,
        "border-color": "rgba(255,255,255,0.2)",
        "label": "data(display_label)",
        "text-wrap": "wrap",
        "text-max-width": "145px",
        "text-valign": "center",
        "text-halign": "center",
        "color": "#031018",
        "font-size": 11,
        "line-height": 1.15,
        "font-family": "Avenir Next, Segoe UI, sans-serif",
        "overlay-opacity": 0,
        "padding": "6px",
      },
    },
    {
      selector: 'node[node_type = "ap"]',
      style: {
        "background-color": "#5eead4",
        "border-color": "rgba(94,234,212,0.65)",
        "font-size": 13,
        "font-weight": 700,
      },
    },
    {
      selector: 'node[node_type = "device"]',
      style: {
        "background-color": "#67aefc",
        "border-color": "rgba(131,185,255,0.4)",
      },
    },
    {
      selector: 'node[node_type = "me"]',
      style: {
        "shape": "ellipse",
        "width": 82,
        "height": 82,
        "background-color": "#ff5d5d",
        "border-color": "rgba(255,120,120,0.85)",
        "border-width": 3,
        "font-size": 18,
        "font-weight": 800,
        "color": "#200303",
      },
    },
    {
      selector: "edge",
      style: {
        "width": "mapData(traffic, 0, 120000, 1, 7)",
        "line-color": "rgba(150,220,255,0.42)",
        "curve-style": "straight",
        "line-cap": "round",
        "line-dash-pattern": [1, 14],
        "line-dash-offset": 0,
        "opacity": 0.9,
      },
    },
  ],
  layout: { name: "preset" },
  wheelSensitivity: 0.2,
});

let liveEdges = [];
let edgeAnimationTick = 0;

function hashString(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i += 1) {
    hash = ((hash << 5) - hash) + input.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

function stableApOrder(apNodes) {
  return [...apNodes].sort((left, right) => left.data.id.localeCompare(right.data.id));
}

function mapPowerToRadius(power, minRadius, maxRadius) {
  if (power == null) {
    return maxRadius * 0.82;
  }
  const normalized = Math.max(0, Math.min(1, (Math.abs(power) - 25) / 70));
  return minRadius + (normalized * (maxRadius - minRadius));
}

function smoothPosition(current, target, factor) {
  if (!current) {
    return target;
  }
  return {
    x: current.x + ((target.x - current.x) * factor),
    y: current.y + ((target.y - current.y) * factor),
  };
}

function computeNewNodePositions(nodes, apNodes, edges) {
  const width = cy.width();
  const height = cy.height();
  const center = { x: width / 2, y: height / 2 + 8 };
  const apMinRadius = 135;
  const apMaxRadius = Math.max(210, Math.min(width, height) * 0.34);
  const deviceLocalMin = 78;
  const deviceLocalMax = 126;
  const positions = {};
  const orderedAps = stableApOrder(apNodes);
  const groupedEdges = new Map();
  const nodeById = new Map(nodes.map((node) => [node.data.id, node.data]));

  edges.forEach((edge) => {
    const apId = edge.data.source;
    if (!groupedEdges.has(apId)) groupedEdges.set(apId, []);
    groupedEdges.get(apId).push(edge);
  });

  positions[ME_NODE_ID] = center;

  orderedAps.forEach((apNode, index) => {
    const existing = cy.getElementById(apNode.data.id);
    const stableAngle = ((hashString(apNode.data.id) % 360) * Math.PI / 180) - Math.PI / 2;
    const apRadius = mapPowerToRadius(apNode.data.power, apMinRadius, apMaxRadius);
    const apTarget = {
      x: center.x + Math.cos(stableAngle) * apRadius,
      y: center.y + Math.sin(stableAngle) * apRadius,
    };
    const apPosition = smoothPosition(existing.nonempty() ? existing.position() : null, apTarget, 0.22);
    positions[apNode.data.id] = apPosition;

    const apEdges = [...(groupedEdges.get(apNode.data.id) || [])].sort((left, right) =>
      left.data.target.localeCompare(right.data.target)
    );
    apEdges.forEach((edge, edgeIndex) => {
      const deviceData = nodeById.get(edge.data.target) || {};
      const baseAngle = stableAngle + ((((hashString(edge.data.target) % 120) - 60) * Math.PI) / 180);
      const angleOffset = ((edgeIndex % 5) - 2) * 0.12;
      const localOrbit = mapPowerToRadius(deviceData.power, deviceLocalMin, deviceLocalMax);
      const localTarget = {
        x: apPosition.x + Math.cos(baseAngle + angleOffset) * localOrbit,
        y: apPosition.y + Math.sin(baseAngle + angleOffset) * localOrbit,
      };
      const centerRadius = mapPowerToRadius(deviceData.power, apMinRadius + 28, apMaxRadius + 34);
      const centerTarget = {
        x: center.x + Math.cos(baseAngle) * centerRadius,
        y: center.y + Math.sin(baseAngle) * centerRadius,
      };
      const targetPosition = {
        x: (localTarget.x * 0.72) + (centerTarget.x * 0.28),
        y: (localTarget.y * 0.72) + (centerTarget.y * 0.28),
      };
      const existingDevice = cy.getElementById(edge.data.target);
      positions[edge.data.target] = smoothPosition(
        existingDevice.nonempty() ? existingDevice.position() : null,
        targetPosition,
        0.18,
      );
    });
  });

  relaxDeviceOverlaps(positions, nodeById, center, orderedAps, edges);
  return positions;
}

function relaxDeviceOverlaps(positions, nodeById, center, apNodes, edges) {
  const apIds = new Set(apNodes.map((node) => node.data.id));
  const deviceIds = Object.keys(positions).filter((id) => !apIds.has(id) && id !== ME_NODE_ID);
  const deviceToAp = new Map(edges.map((edge) => [edge.data.target, edge.data.source]));

  for (let iteration = 0; iteration < 22; iteration += 1) {
    for (let i = 0; i < deviceIds.length; i += 1) {
      const leftId = deviceIds[i];
      const left = positions[leftId];
      if (!left) continue;

      for (let j = i + 1; j < deviceIds.length; j += 1) {
        const rightId = deviceIds[j];
        const right = positions[rightId];
        if (!right) continue;

        const leftNode = nodeById.get(leftId) || {};
        const rightNode = nodeById.get(rightId) || {};
        const dx = right.x - left.x;
        const dy = right.y - left.y;
        const minDx = (((leftNode.width || 170) + (rightNode.width || 170)) / 2) + 12;
        const minDy = (((leftNode.height || 74) + (rightNode.height || 74)) / 2) + 12;
        const overlapX = minDx - Math.abs(dx);
        const overlapY = minDy - Math.abs(dy);
        if (overlapX <= 0 || overlapY <= 0) continue;

        if (overlapX < overlapY) {
          const pushX = (overlapX / 2) * (dx >= 0 ? 1 : -1);
          left.x -= pushX;
          right.x += pushX;
        } else {
          const pushY = (overlapY / 2) * (dy >= 0 ? 1 : -1);
          left.y -= pushY;
          right.y += pushY;
        }
      }
    }

    deviceIds.forEach((deviceId) => {
      const apId = deviceToAp.get(deviceId);
      const apPosition = apId ? positions[apId] : null;
      const devicePosition = positions[deviceId];
      const deviceData = nodeById.get(deviceId) || {};
      if (!apPosition || !devicePosition) return;

      const dxToAp = devicePosition.x - apPosition.x;
      const dyToAp = devicePosition.y - apPosition.y;
      const distToAp = Math.sqrt((dxToAp * dxToAp) + (dyToAp * dyToAp)) || 0.001;
      const minApDistance = 78;
      const maxApDistance = 148;

      if (distToAp < minApDistance) {
        const scale = minApDistance / distToAp;
        devicePosition.x = apPosition.x + (dxToAp * scale);
        devicePosition.y = apPosition.y + (dyToAp * scale);
      } else if (distToAp > maxApDistance) {
        const scale = maxApDistance / distToAp;
        devicePosition.x = apPosition.x + (dxToAp * scale);
        devicePosition.y = apPosition.y + (dyToAp * scale);
      }

      const dxToCenter = devicePosition.x - center.x;
      const dyToCenter = devicePosition.y - center.y;
      const centerDistance = Math.sqrt((dxToCenter * dxToCenter) + (dyToCenter * dyToCenter)) || 0.001;
      const minCenterDistance = 120;
      const maxCenterDistance = mapPowerToRadius(deviceData.power, 180, Math.max(235, Math.min(cy.width(), cy.height()) * 0.42));

      if (centerDistance < minCenterDistance) {
        const scale = minCenterDistance / centerDistance;
        devicePosition.x = center.x + (dxToCenter * scale);
        devicePosition.y = center.y + (dyToCenter * scale);
      } else if (centerDistance > maxCenterDistance) {
        const scale = maxCenterDistance / centerDistance;
        devicePosition.x = center.x + (dxToCenter * scale);
        devicePosition.y = center.y + (dyToCenter * scale);
      }
    });
  }
}

function applySnapshot(snapshot) {
  const nodes = [
    {
      data: {
        id: ME_NODE_ID,
        node_type: "me",
        display_label: "ME",
        width: 82,
        height: 82,
        power: 0,
      },
    },
    ...(snapshot.elements.nodes || []),
  ];
  const edges = snapshot.elements.edges || [];
  const nodeIds = new Set(nodes.map((node) => node.data.id));
  const edgeIds = new Set(edges.map((edge) => edge.data.id));
  const apNodes = nodes.filter((node) => node.data.node_type === "ap");
  const positions = computeNewNodePositions(nodes, apNodes, edges);

  cy.batch(() => {
    cy.nodes().forEach((node) => {
      if (!nodeIds.has(node.id())) {
        node.remove();
      }
    });
    cy.edges().forEach((edge) => {
      if (!edgeIds.has(edge.id())) {
        edge.remove();
      }
    });

    nodes.forEach((nodeData) => {
      const existing = cy.getElementById(nodeData.data.id);
      if (existing.nonempty()) {
        existing.data(nodeData.data);
        if (positions[nodeData.data.id]) {
          existing.position(positions[nodeData.data.id]);
        }
      } else {
        cy.add({ ...nodeData, position: positions[nodeData.data.id] || { x: cy.width() / 2, y: cy.height() / 2 } });
      }
    });

    edges.forEach((edgeData) => {
      const existing = cy.getElementById(edgeData.data.id);
      if (existing.nonempty()) {
        existing.data(edgeData.data);
      } else {
        cy.add(edgeData);
      }
    });
  });

  autoFitIfNeeded();

  liveEdges = cy.edges().toArray();
  metaText.textContent = `${apNodes.length} access points, ${nodes.length - apNodes.length - 1} devices, ${snapshot.window_seconds}s traffic window`;
}

function autoFitIfNeeded(force = false) {
  if (cy.elements().length === 0) {
    return;
  }

  const bounds = cy.elements().boundingBox();
  const nextBounds = {
    x1: Math.round(bounds.x1),
    y1: Math.round(bounds.y1),
    x2: Math.round(bounds.x2),
    y2: Math.round(bounds.y2),
  };

  const changed = !lastAutoFitBounds ||
    Math.abs(lastAutoFitBounds.x1 - nextBounds.x1) > 20 ||
    Math.abs(lastAutoFitBounds.y1 - nextBounds.y1) > 20 ||
    Math.abs(lastAutoFitBounds.x2 - nextBounds.x2) > 20 ||
    Math.abs(lastAutoFitBounds.y2 - nextBounds.y2) > 20;

  if (force || changed) {
    cy.fit(cy.elements(), 50);
    lastAutoFitBounds = nextBounds;
  }
}

function animateEdges() {
  edgeAnimationTick += 1.35;
  liveEdges.forEach((edge) => {
    const traffic = edge.data("traffic") || 0;
    const offset = -(edgeAnimationTick + traffic / 4000);
    const hotness = Math.min(1, traffic / 120000);
    edge.style("line-dash-offset", offset);
    edge.style("line-color", hotness > 0.18 ? "rgba(255,193,94,0.95)" : "rgba(150,220,255,0.42)");
    edge.style("width", Math.max(1, Math.min(8, 1 + traffic / 24000)));
  });
  requestAnimationFrame(animateEdges);
}

function connect() {
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  const socket = new WebSocket(`${protocol}://${window.location.host}/ws`);

  socket.addEventListener("open", () => {
    statusPill.textContent = "live";
    statusPill.className = "status-pill live";
  });

  socket.addEventListener("message", (event) => {
    const snapshot = JSON.parse(event.data);
    applySnapshot(snapshot);
  });

  socket.addEventListener("close", () => {
    statusPill.textContent = "reconnecting";
    statusPill.className = "status-pill connecting";
    window.setTimeout(connect, 1000);
  });
}

window.addEventListener("resize", () => {
  cy.resize();
  autoFitIfNeeded(true);
});

connect();
requestAnimationFrame(animateEdges);
