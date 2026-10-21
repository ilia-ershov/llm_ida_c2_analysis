"""reverse_agent — LangGraph agent that correlates IDA Pro disassembly with PCAP traffic.

The agent uses a headless IDA Pro (idalib) instance exposed over the IDA Pro MCP
protocol as its disassembly backend, tshark to parse network captures, and the
DeepSeek LLM as the central orchestrator / semantic mapper that links network
call sites in the binary to observed packets and writes the final report.
"""

__version__ = "0.1.0"
