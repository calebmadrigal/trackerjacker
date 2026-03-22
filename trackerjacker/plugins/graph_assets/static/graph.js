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
let activeLayout = null;

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

function computeNewNodePositions(nodes, apNodes, edges) {
  const width = cy.width();
  const height = cy.height();
  const cx = width / 2;
  const cyMid = height / 2 + 10;
  const apOrbitX = Math.max(170, width * 0.22);
  const apOrbitY = Math.max(110, height * 0.18);
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
      const orbit = apRadius({ data: (key) => apNode.data[key] }) + 58 + (edgeIndex * 8);
      const targetPosition = {
        x: apPosition.x + Math.cos(baseAngle + angleOffset) * orbit,
        y: apPosition.y + Math.sin(baseAngle + angleOffset) * orbit,
      };
      const existingDevice = cy.getElementById(edge.data.target);
      if (existingDevice.nonempty()) {
        positions[edge.data.target] = existingDevice.position();
      } else {
        positions[edge.data.target] = targetPosition;
      }
    });
  });
  return positions;
}

function runForceLayout() {
  if (activeLayout && typeof activeLayout.stop === "function") {
    activeLayout.stop();
  }

  const apNodes = cy.nodes('[node_type = "ap"]');
  const deviceNodes = cy.nodes('[node_type = "device"]');

  apNodes.lock();
  deviceNodes.unlock();

  activeLayout = cy.layout({
    name: "cose",
    animate: false,
    fit: false,
    randomize: false,
    padding: 30,
    componentSpacing: 80,
    nodeOverlap: 22,
    idealEdgeLength(edge) {
      return edge.data("traffic") > 0 ? 95 : 75;
    },
    edgeElasticity(edge) {
      return edge.data("traffic") > 0 ? 70 : 120;
    },
    nestingFactor: 0.9,
    gravity: 0.2,
    numIter: 350,
    initialTemp: 80,
    coolingFactor: 0.92,
    minTemp: 1.0,
    nodeRepulsion(node) {
      if (node.data("node_type") === "ap") {
        return 900000;
      }
      const width = node.data("width") || 170;
      const height = node.data("height") || 62;
      return 220000 + (width * height * 18);
    },
  });

  activeLayout.run();
}

function applySnapshot(snapshot) {
  const nodes = snapshot.elements.nodes || [];
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

  runForceLayout();
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
