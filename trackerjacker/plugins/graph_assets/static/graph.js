const statusPill = document.getElementById("status-pill");
const metaText = document.getElementById("meta-text");
const graphRoot = document.getElementById("graph-root");
let lastAutoFitBounds = null;

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
        "shape": "rectangle",
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

function powerRadius(power) {
  if (power == null) return 40;
  return Math.max(24, Math.min(78, 28 + (power + 100) * 0.95));
}

function apRadius(apNode) {
  return Math.max(78, ((apNode.data("width") || 140) / 2) + 18);
}

function hashString(input) {
  let hash = 0;
  for (let i = 0; i < input.length; i += 1) {
    hash = ((hash << 5) - hash) + input.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash);
}

function stableApOrder(apNodes) {
  const existingOrder = new Map();
  cy.nodes('[node_type = "ap"]').forEach((node, index) => existingOrder.set(node.id(), index));
  return [...apNodes].sort((left, right) => {
    const leftOrder = existingOrder.has(left.data.id) ? existingOrder.get(left.data.id) : Number.MAX_SAFE_INTEGER;
    const rightOrder = existingOrder.has(right.data.id) ? existingOrder.get(right.data.id) : Number.MAX_SAFE_INTEGER;
    if (leftOrder !== rightOrder) return leftOrder - rightOrder;
    return left.data.id.localeCompare(right.data.id);
  });
}

function computeNewNodePositions(apNodes, edges) {
  const width = cy.width();
  const height = cy.height();
  const cx = width / 2;
  const cyMid = height / 2 + 10;
  const apOrbitX = Math.max(240, width * 0.34);
  const apOrbitY = Math.max(160, height * 0.28);
  const positions = {};
  const orderedAps = stableApOrder(apNodes);
  const groupedEdges = new Map();

  edges.forEach((edge) => {
    const apId = edge.data.source;
    if (!groupedEdges.has(apId)) groupedEdges.set(apId, []);
    groupedEdges.get(apId).push(edge);
  });

  orderedAps.forEach((apNode, index) => {
    const existing = cy.getElementById(apNode.data.id);
    let apPosition = existing.nonempty() ? existing.position() : null;
    if (!apPosition || (apPosition.x === 0 && apPosition.y === 0)) {
      const angle = (Math.PI * 2 * index) / Math.max(1, orderedAps.length) - Math.PI / 2;
      apPosition = {
        x: cx + Math.cos(angle) * apOrbitX,
        y: cyMid + Math.sin(angle) * apOrbitY,
      };
    }
    positions[apNode.data.id] = apPosition;

    const apEdges = [...(groupedEdges.get(apNode.data.id) || [])].sort((left, right) =>
      left.data.target.localeCompare(right.data.target)
    );
    apEdges.forEach((edge, edgeIndex) => {
      const baseAngle = (hashString(edge.data.target) % 360) * (Math.PI / 180);
      const angleOffset = ((edgeIndex % 5) - 2) * 0.16;
      const orbit = apRadius({ data: (key) => apNode.data[key] }) + 92 + (edgeIndex * 14);
      const targetPosition = {
        x: apPosition.x + Math.cos(baseAngle + angleOffset) * orbit,
        y: apPosition.y + Math.sin(baseAngle + angleOffset) * orbit,
      };
      const existingDevice = cy.getElementById(edge.data.target);
      if (existingDevice.nonempty()) {
        const current = existingDevice.position();
        positions[edge.data.target] = {
          x: current.x + ((targetPosition.x - current.x) * 0.18),
          y: current.y + ((targetPosition.y - current.y) * 0.18),
        };
      } else {
        positions[edge.data.target] = targetPosition;
      }
    });
  });

  relaxDeviceOverlaps(positions, apNodes, edges);
  return positions;
}

function relaxDeviceOverlaps(positions, apNodes, edges) {
  const apIds = new Set(apNodes.map((node) => node.data.id));
  const deviceIds = Object.keys(positions).filter((id) => !apIds.has(id));
  const deviceToAp = new Map(edges.map((edge) => [edge.data.target, edge.data.source]));

  for (let iteration = 0; iteration < 20; iteration += 1) {
    for (let i = 0; i < deviceIds.length; i += 1) {
      const leftId = deviceIds[i];
      const left = positions[leftId];
      if (!left) continue;

      for (let j = i + 1; j < deviceIds.length; j += 1) {
        const rightId = deviceIds[j];
        const right = positions[rightId];
        if (!right) continue;

        const dx = right.x - left.x;
        const dy = right.y - left.y;
        const distance = Math.sqrt((dx * dx) + (dy * dy)) || 0.001;
        const minDistance = 96;
        if (distance >= minDistance) continue;

        const push = (minDistance - distance) / 2;
        const pushX = (dx / distance) * push;
        const pushY = (dy / distance) * push;

        left.x -= pushX;
        left.y -= pushY;
        right.x += pushX;
        right.y += pushY;
      }
    }

    deviceIds.forEach((deviceId) => {
      const apId = deviceToAp.get(deviceId);
      const apPosition = apId ? positions[apId] : null;
      const devicePosition = positions[deviceId];
      if (!apPosition || !devicePosition) return;

      const dx = devicePosition.x - apPosition.x;
      const dy = devicePosition.y - apPosition.y;
      const distance = Math.sqrt((dx * dx) + (dy * dy)) || 0.001;
      const minOrbit = 126;
      const maxOrbit = 320;

      if (distance < minOrbit) {
        const scale = minOrbit / distance;
        devicePosition.x = apPosition.x + (dx * scale);
        devicePosition.y = apPosition.y + (dy * scale);
      } else if (distance > maxOrbit) {
        const scale = maxOrbit / distance;
        devicePosition.x = apPosition.x + (dx * scale);
        devicePosition.y = apPosition.y + (dy * scale);
      }
    });
  }
}

function applySnapshot(snapshot) {
  const nodes = snapshot.elements.nodes || [];
  const edges = snapshot.elements.edges || [];
  const nodeIds = new Set(nodes.map((node) => node.data.id));
  const edgeIds = new Set(edges.map((edge) => edge.data.id));
  const apNodes = nodes.filter((node) => node.data.node_type === "ap");
  const positions = computeNewNodePositions(apNodes, edges);

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
  metaText.textContent = `${apNodes.length} access points, ${nodes.length - apNodes.length} devices, ${snapshot.window_seconds}s traffic window`;
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
