####################################################
# LSrouter.py
# Name:
# HUID:
#####################################################
import json
import heapq
from packet import Packet
from router import Router


class LSrouter(Router):
    """Link state routing protocol implementation."""

    def __init__(self, addr, heartbeat_time):
        super().__init__(addr)  # DO NOT REMOVE
        self.heartbeat_time = heartbeat_time
        self.last_time = 0
        self.addr = addr
        self.sequence_number = 0
        self.neighbors = {}  # endpoint -> cost
        self.lsdb = {self.addr: {"neighbors": {}, "seq": self.sequence_number}}
        self.forwarding_table = {}

    def handle_packet(self, port, packet):
        """Process incoming packet."""
        if packet.is_traceroute:
            out_port = self.forwarding_table.get(packet.dst_addr)
            if out_port is not None:
                self.send(out_port, packet)
            return

        try:
            content = json.loads(packet.content)
            origin = content["addr"]
            seq = content["seq"]
            neighbors = content["neighbors"]
        except (json.JSONDecodeError, KeyError):
            return

        if origin not in self.lsdb or seq > self.lsdb[origin]["seq"]:
            self.lsdb[origin] = {"neighbors": neighbors, "seq": seq}
            for p in self.links:
                if p != port:
                    self.send(p, Packet(Packet.ROUTING, self.addr, None, packet.content))
            self._recompute_routes()

    def handle_new_link(self, port, endpoint, cost):
        """Handle new link."""
        self._update_link(endpoint, cost)

    def handle_remove_link(self, port):
        """Handle removed link."""
        endpoint = self.links[port].get_other_side(self.addr) if port in self.links else None
        if endpoint and endpoint in self.neighbors:
            self._update_link(endpoint, None)

    def handle_time(self, time_ms):
        """Handle current time."""
        if time_ms - self.last_time >= self.heartbeat_time:
            self.last_time = time_ms
            self._broadcast_lsp()

    def _update_link(self, endpoint, cost):
        if cost is not None:
            self.neighbors[endpoint] = cost
        elif endpoint in self.neighbors:
            del self.neighbors[endpoint]
        else:
            return

        self.lsdb[self.addr]["neighbors"] = dict(self.neighbors)
        self.sequence_number += 1
        self.lsdb[self.addr]["seq"] = self.sequence_number
        self._broadcast_lsp()
        self._recompute_routes()

    def _broadcast_lsp(self):
        """Broadcast link-state packet to all neighbors."""
        lsp = {
            "addr": self.addr,
            "seq": self.sequence_number,
            "neighbors": dict(self.neighbors)
        }
        content = json.dumps(lsp)
        for port in self.links:
            self.send(port, Packet(Packet.ROUTING, self.addr, None, content))

    def _recompute_routes(self):
        """Recompute forwarding table using Dijkstra's algorithm."""
        dist = {self.addr: 0}
        prev = {}
        heap = [(0, self.addr)]
        visited = set()

        while heap:
            cost_u, u = heapq.heappop(heap)
            if u in visited:
                continue
            visited.add(u)

            for v, cost_uv in self.lsdb.get(u, {}).get("neighbors", {}).items():
                alt = cost_u + cost_uv
                if v not in dist or alt < dist[v]:
                    dist[v] = alt
                    prev[v] = u
                    heapq.heappush(heap, (alt, v))

        new_table = {}
        for dest in dist:
            if dest == self.addr:
                continue
            next_hop = dest
            hop_trace = set()
            while prev.get(next_hop) != self.addr:
                if next_hop in hop_trace:
                    # Prevent infinite loop
                    next_hop = None
                    break
                hop_trace.add(next_hop)
                next_hop = prev.get(next_hop)
                if next_hop is None:
                    break
            if next_hop is None:
                continue
            for port, link in self.links.items():
                if link.get_other_side(self.addr) == next_hop:
                    new_table[dest] = port
                    break

        self.forwarding_table = new_table

    def __repr__(self):
        """Representation for debugging in the network visualizer."""
        return f"LSrouter(addr={self.addr})"
