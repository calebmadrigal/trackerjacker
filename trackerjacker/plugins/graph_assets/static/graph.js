const statusPill = document.getElementById("status-pill");
const metaText = document.getElementById("meta-text");
const graphRoot = document.getElementById("graph-root");

const cy = cytoscape({
  container: graphRoot,
  elements: [],
  style: [
    {
      selector: "node",
      style: {
        "width": "data(size)",
        "height": "data(size)",
        "background-color": "#8cc8ff",
        "border-width": 2,
        "border-color": "rgba(255,255,255,0.2)",
        "label": "data(label)",
        "text-wrap": "wrap",
        "text-max-width": "110px",
        "text-valign": "center",
        "text-halign": "center",
        "color": "#e7f7ff",
        "font-size": 11,
        "font-family": "Avenir Next, Segoe UI, sans-serif",
        "overlay-opacity": 0,
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
  return Math.max(70, apNode.data("size") || 70);
}

function applySnapshot(snapshot) {
  const nodes = snapshot.elements.nodes || [];
  const edges = snapshot.elements.edges || [];
  const apNodes = nodes.filter((node) => node.data.node_type === "ap");
  const deviceNodes = new Map(nodes.filter((node) => node.data.node_type === "device").map((node) => [node.data.id, node]));
  const groupedEdges = new Map();

  edges.forEach((edge) => {
    const apId = edge.data.source;
    if (!groupedEdges.has(apId)) groupedEdges.set(apId, []);
    groupedEdges.get(apId).push(edge);
  });

  const width = cy.width();
  const height = cy.height();
  const cx = width / 2;
  const cyMid = height / 2 + 10;
  const apOrbitX = Math.max(240, width * 0.34);
  const apOrbitY = Math.max(160, height * 0.28);
  const positions = {};

  apNodes.forEach((apNode, index) => {
    const angle = (Math.PI * 2 * index) / Math.max(1, apNodes.length) - Math.PI / 2;
    const apX = cx + Math.cos(angle) * apOrbitX;
    const apY = cyMid + Math.sin(angle) * apOrbitY;
    positions[apNode.data.id] = { x: apX, y: apY };

    const apEdges = (groupedEdges.get(apNode.data.id) || []).slice(0, 12);
    const radius = apRadius({ data: (key) => apNode.data[key] }) + 90;
    apEdges.forEach((edge, edgeIndex) => {
      const devNode = deviceNodes.get(edge.data.target);
      if (!devNode) return;
      const deviceAngle = angle + ((edgeIndex - (apEdges.length - 1) / 2) * 0.42);
      const orbit = radius + powerRadius(devNode.data.power);
      positions[devNode.data.id] = {
        x: apX + Math.cos(deviceAngle) * orbit,
        y: apY + Math.sin(deviceAngle) * orbit,
      };
    });
  });

  cy.elements().remove();
  cy.add(nodes.map((node) => ({ ...node, position: positions[node.data.id] || { x: cx, y: cyMid } })));
  cy.add(edges);
  cy.layout({ name: "preset", fit: true, padding: 50, animate: false }).run();

  liveEdges = cy.edges().toArray();
  metaText.textContent = `${apNodes.length} access points, ${nodes.length - apNodes.length} devices, ${snapshot.window_seconds}s traffic window`;
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
  const currentElements = {
    nodes: cy.nodes().map((node) => ({ data: node.data() })),
    edges: cy.edges().map((edge) => ({ data: edge.data() })),
  };
  applySnapshot({ elements: currentElements, window_seconds: "current" });
});

connect();
requestAnimationFrame(animateEdges);
