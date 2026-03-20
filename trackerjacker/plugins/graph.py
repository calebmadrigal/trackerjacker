"""Live network graph visualizer built-in plugin."""

import atexit
import json
import math
import os
import queue
import socket
import threading
import time
import webbrowser
from collections import defaultdict, deque

from flask import Flask, jsonify, send_from_directory
from flask_sock import Sock
from werkzeug.serving import make_server

from trackerjacker.common import MACS_TO_IGNORE

__author__ = 'Caleb Madrigal'
__email__ = 'caleb.madrigal@gmail.com'
__version__ = '0.1.0'
__apiversion__ = 1
__config__ = {
    'threshold': 1,
    'trigger_cooldown': 0,
    'log_level': 'ERROR',
    'channel_switch_scheme': 'traffic_based',
    'time_per_channel': 0.35,
}


def clamp(value, min_value, max_value):
    return max(min_value, min(max_value, value))


def score_events(events, now, window):
    cutoff = now - window
    while events and events[0][0] < cutoff:
        events.popleft()
    return sum(num_bytes for _, num_bytes in events)


def format_label(primary, fallback):
    if primary:
        return primary
    if fallback:
        return fallback
    return 'Unknown'


def format_device_label(mac, vendor):
    if vendor:
        return '{}\n{}'.format(mac, vendor)
    return mac


class GraphState:
    def __init__(self, traffic_window=20, stale_seconds=45, max_access_points=8, max_devices_per_ap=6):
        self.traffic_window = float(traffic_window)
        self.stale_seconds = float(stale_seconds)
        self.max_access_points = int(max_access_points)
        self.max_devices_per_ap = int(max_devices_per_ap)
        self.lock = threading.RLock()
        self.seq = 0
        self.access_points = {}
        self.devices = {}
        self.edges = {}

    def update(self, frame, dot11_map=None):
        now = time.time()
        with self.lock:
            self.seq += 1
            self._prune(now)

            if frame.bssid and frame.bssid not in MACS_TO_IGNORE:
                self._update_access_point(frame, dot11_map, now)

            if frame.frame_type_name() != 'data' or not frame.bssid:
                return

            connected_devices = sorted(frame.macs - MACS_TO_IGNORE - {frame.bssid})
            for mac in connected_devices:
                self._update_device(frame, mac, dot11_map, now)
                self._update_edge(frame, mac, now)

    def _update_access_point(self, frame, dot11_map, now):
        ap_node = dot11_map.get_ap_by_bssid(frame.bssid) if dot11_map else None
        ap_state = self.access_points.setdefault(frame.bssid, {
            'bssid': frame.bssid,
            'ssid': None,
            'vendor': None,
            'power': -100,
            'channels': [],
            'events': deque(),
            'last_seen': now,
        })
        ap_state['last_seen'] = now
        ap_state['power'] = frame.signal_strength if frame.signal_strength is not None else ap_state['power']
        if ap_node:
            ap_state['ssid'] = ap_node.get('ssid') or ap_state['ssid']
            ap_state['vendor'] = ap_node.get('vendor') or ap_state['vendor']
            ap_state['channels'] = sorted(ap_node.get('channels', ()))
        elif frame.ssid:
            ap_state['ssid'] = frame.ssid

        if frame.frame_type_name() == 'data':
            ap_state['events'].append((now, frame.frame_bytes))

    def _update_device(self, frame, mac, dot11_map, now):
        dev_node = dot11_map.get_dev_node(mac) if dot11_map else None
        dev_state = self.devices.setdefault(mac, {
            'mac': mac,
            'vendor': None,
            'power': -100,
            'events': deque(),
            'last_seen': now,
        })
        dev_state['last_seen'] = now
        dev_state['power'] = frame.signal_strength if frame.signal_strength is not None else dev_state['power']
        if dev_node:
            dev_state['vendor'] = dev_node.get('vendor') or dev_state['vendor']
        dev_state['events'].append((now, frame.frame_bytes))

    def _update_edge(self, frame, mac, now):
        edge_key = (frame.bssid, mac)
        edge_state = self.edges.setdefault(edge_key, {
            'source': frame.bssid,
            'target': mac,
            'events': deque(),
            'last_seen': now,
        })
        edge_state['last_seen'] = now
        edge_state['events'].append((now, frame.frame_bytes))

    def _prune(self, now):
        cutoff = now - self.stale_seconds
        self.access_points = {k: v for k, v in self.access_points.items() if v['last_seen'] >= cutoff}
        self.devices = {k: v for k, v in self.devices.items() if v['last_seen'] >= cutoff}
        self.edges = {k: v for k, v in self.edges.items() if v['last_seen'] >= cutoff}

    def snapshot(self):
        now = time.time()
        with self.lock:
            self._prune(now)

            ap_scores = {
                bssid: score_events(ap_state['events'], now, self.traffic_window)
                for bssid, ap_state in self.access_points.items()
            }
            top_aps = sorted(
                (bssid for bssid, score in ap_scores.items() if score > 0),
                key=lambda bssid: ap_scores[bssid],
                reverse=True,
            )[:self.max_access_points]

            selected_device_ids = set()
            edge_payloads = []
            for bssid in top_aps:
                bssid_edges = []
                for edge_key, edge_state in self.edges.items():
                    if edge_state['source'] != bssid:
                        continue
                    edge_score = score_events(edge_state['events'], now, self.traffic_window)
                    if edge_score <= 0:
                        continue
                    bssid_edges.append((edge_score, edge_state))

                for edge_score, edge_state in sorted(bssid_edges, key=lambda item: item[0], reverse=True)[:self.max_devices_per_ap]:
                    selected_device_ids.add(edge_state['target'])
                    edge_payloads.append({
                        'data': {
                            'id': '{}__{}'.format(edge_state['source'], edge_state['target']),
                            'source': edge_state['source'],
                            'target': edge_state['target'],
                            'traffic': edge_score,
                        }
                    })

            nodes = []
            for bssid in top_aps:
                ap_state = self.access_points[bssid]
                nodes.append({
                    'data': {
                        'id': bssid,
                        'node_type': 'ap',
                        'label': format_label(ap_state.get('ssid'), ap_state.get('vendor')),
                        'display_label': format_label(ap_state.get('ssid'), ap_state.get('vendor')),
                        'subtitle': bssid,
                        'traffic': ap_scores.get(bssid, 0),
                        'power': ap_state.get('power') or -100,
                        'channels': ', '.join(str(channel) for channel in ap_state.get('channels', ())),
                        'size': clamp(70 + (ap_scores.get(bssid, 0) / 25000.0), 70, 150),
                    }
                })

            for mac in sorted(selected_device_ids):
                dev_state = self.devices.get(mac)
                if not dev_state:
                    continue
                dev_score = score_events(dev_state['events'], now, self.traffic_window)
                nodes.append({
                    'data': {
                        'id': mac,
                        'node_type': 'device',
                        'label': mac,
                        'display_label': format_device_label(mac, dev_state.get('vendor')),
                        'subtitle': mac,
                        'traffic': dev_score,
                        'power': dev_state.get('power') or -100,
                        'size': clamp(28 + ((dev_state.get('power') or -100) + 100) * 0.95, 24, 78),
                    }
                })

            return {
                'seq': self.seq,
                'generated_at': now,
                'window_seconds': self.traffic_window,
                'elements': {
                    'nodes': nodes,
                    'edges': edge_payloads,
                }
            }


class GraphServer:
    def __init__(self, graph_state, host='127.0.0.1', port=8765, snapshot_interval=0.5):
        self.graph_state = graph_state
        self.host = host
        self.port = int(port)
        self.snapshot_interval = float(snapshot_interval)
        self.asset_dir = os.path.join(os.path.dirname(__file__), 'graph_assets')
        self.client_queues = set()
        self.clients_lock = threading.RLock()
        self.stop_event = threading.Event()
        self.app = Flask(__name__, static_folder=None)
        self.sock = Sock(self.app)
        self.http_server = None
        self.server_thread = None
        self.broadcast_thread = None
        self._configure_routes()

    def _configure_routes(self):
        @self.app.get('/')
        def index():
            return send_from_directory(self.asset_dir, 'index.html')

        @self.app.get('/static/<path:asset_path>')
        def static_asset(asset_path):
            return send_from_directory(os.path.join(self.asset_dir, 'static'), asset_path)

        @self.app.get('/vendor/<path:asset_path>')
        def vendor_asset(asset_path):
            return send_from_directory(os.path.join(self.asset_dir, 'vendor'), asset_path)

        @self.app.get('/snapshot')
        def snapshot():
            return jsonify(self.graph_state.snapshot())

        @self.sock.route('/ws')
        def ws_updates(ws):
            client_queue = queue.Queue(maxsize=3)
            with self.clients_lock:
                self.client_queues.add(client_queue)

            try:
                client_queue.put_nowait(json.dumps(self.graph_state.snapshot()))
                while not self.stop_event.is_set():
                    payload = client_queue.get(timeout=1.0)
                    ws.send(payload)
            except Exception:
                return
            finally:
                with self.clients_lock:
                    self.client_queues.discard(client_queue)

    def _get_available_port(self):
        for candidate in range(self.port, self.port + 20):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    sock.bind((self.host, candidate))
                except OSError:
                    continue
                return candidate
        raise OSError('Could not find an open port for graph visualizer')

    def start(self):
        self.port = self._get_available_port()
        self.http_server = make_server(self.host, self.port, self.app, threaded=True)
        self.server_thread = threading.Thread(target=self.http_server.serve_forever, daemon=True)
        self.server_thread.start()
        self.broadcast_thread = threading.Thread(target=self._broadcast_loop, daemon=True)
        self.broadcast_thread.start()

    def stop(self):
        self.stop_event.set()
        if self.http_server:
            self.http_server.shutdown()

    def publish(self, snapshot_json):
        with self.clients_lock:
            dead_queues = []
            for client_queue in self.client_queues:
                try:
                    while client_queue.qsize() >= 2:
                        client_queue.get_nowait()
                    client_queue.put_nowait(snapshot_json)
                except Exception:
                    dead_queues.append(client_queue)
            for client_queue in dead_queues:
                self.client_queues.discard(client_queue)

    def _broadcast_loop(self):
        while not self.stop_event.is_set():
            self.publish(json.dumps(self.graph_state.snapshot()))
            time.sleep(self.snapshot_interval)


class Trigger:
    consume_frame_only = True

    def __init__(self, host='127.0.0.1', port=8765, snapshot_interval=0.5, traffic_window=20,
                 stale_seconds=45, max_access_points=8, max_devices_per_ap=6, open_browser=False):
        self.graph_state = GraphState(traffic_window=traffic_window,
                                      stale_seconds=stale_seconds,
                                      max_access_points=max_access_points,
                                      max_devices_per_ap=max_devices_per_ap)
        self.server = GraphServer(self.graph_state,
                                  host=host,
                                  port=port,
                                  snapshot_interval=snapshot_interval)
        self.server.start()
        self.url = 'http://{}:{}'.format(self.server.host, self.server.port)
        print('Graph view available at {}'.format(self.url))
        if open_browser:
            webbrowser.open(self.url)
        atexit.register(self.stop)

    def __call__(self, **kwargs):
        return None

    def consume_frame(self, frame=None, dot11_map=None, **kwargs):
        if not frame:
            return
        self.graph_state.update(frame, dot11_map=dot11_map)

    def stop(self):
        self.server.stop()
