"""AsyncScapy sniffer with BPF filter. Yields parsed packets to pipeline."""

import asyncio
from typing import AsyncGenerator, Callable, Dict, Any, Optional
from scapy.all import AsyncSniffer, IP, Ether

from src.capture.packet_parser import parse_packet


class PacketSniffer:
    """
    Asynchronous packet sniffer using Scapy's AsyncSniffer.
    Captures packets from a network interface with an optional BPF filter.

    Usage:
        sniffer = PacketSniffer(interface="eth0", bpf_filter="tcp port 80")
        async for packet in sniffer.start():
            await pipeline.process_packet(packet)
    """

    def __init__(
        self,
        interface: str = "eth0",
        bpf_filter: str = "ip",
        callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.callback = callback
        self._sniffer: Optional[AsyncSniffer] = None
        self._running = False
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=10000)

    async def start(self) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Start sniffing and yield parsed packets as they arrive.
        Uses an asyncio.Queue to bridge the synchronous Scapy callback
        to the async world.
        """
        self._running = True

        def _packet_handler(pkt):
            """Synchronous Scapy callback — pushes parsed packet to queue."""
            parsed = parse_packet(pkt)
            if parsed is not None:
                try:
                    self._queue.put_nowait(parsed)
                except asyncio.QueueFull:
                    pass  # Drop packet if queue is full (backpressure)

        self._sniffer = AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter,
            prn=_packet_handler,
            store=False,
            started_callback=lambda: None,
        )

        self._sniffer.start()

        # Wait briefly for sniffer thread to initialize
        await asyncio.sleep(0.1)

        try:
            while self._running:
                try:
                    packet = await asyncio.wait_for(
                        self._queue.get(), timeout=1.0
                    )
                    yield packet
                except asyncio.TimeoutError:
                    continue
        finally:
            await self.stop()

    async def stop(self):
        """Stop the sniffer gracefully."""
        self._running = False
        if self._sniffer is not None:
            self._sniffer.stop()
            self._sniffer = None

    @property
    def is_running(self) -> bool:
        return self._running