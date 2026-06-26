"""API router for network topology."""

from fastapi import APIRouter, Depends, HTTPException

from src.db.repositories import TopologyRepository
from src.api.dependencies import get_topology_repository
from src.topology.discoverer import TopologyDiscoverer
from src.topology.graph import build_graph

router = APIRouter(tags=["topology"])


@router.get("/topology")
async def get_topology(
    repo: TopologyRepository = Depends(get_topology_repository),
):
    """Get the full network topology as D3.js force-directed graph JSON."""
    nodes = await repo.get_all_nodes()
    graph = build_graph(nodes)
    return graph


@router.get("/topology/nodes")
async def list_nodes(
    repo: TopologyRepository = Depends(get_topology_repository),
):
    """List all discovered topology nodes."""
    nodes = await repo.get_all_nodes()
    return {"nodes": nodes, "count": len(nodes)}


@router.get("/topology/nodes/{ip}")
async def get_node(
    ip: str,
    repo: TopologyRepository = Depends(get_topology_repository),
):
    """Get a single topology node by IP."""
    node = await repo.get_node(ip)
    if node is None:
        raise HTTPException(status_code=404, detail="Node not found")
    return node


@router.post("/topology/scan")
async def scan_topology():
    """Trigger an ARP scan to discover network nodes."""
    discoverer = TopologyDiscoverer()
    nodes = await discoverer.arp_scan()
    return {"nodes_discovered": len(nodes), "nodes": nodes}


@router.get("/topology/compromised")
async def get_compromised_nodes(
    repo: TopologyRepository = Depends(get_topology_repository),
):
    """List all nodes marked as compromised."""
    nodes = await repo.get_compromised_nodes()
    return {"nodes": nodes, "count": len(nodes)}