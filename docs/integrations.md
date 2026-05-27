# Framework Integrations

DNS-AID works with **every major AI agent framework** — via MCP (zero new code) or the Python library (3 lines).

> **Key insight:** Because DNS-AID ships an MCP server, any framework with MCP support gains DNS-based agent discovery automatically. No DNS libraries. No new dependencies in your agent code. Just configure a transport and go.

```
┌──────────────────────────────────────────────────────────┐
│              AI Agent Frameworks                         │
│  LangChain · CrewAI · AutoGen · ADK · OpenAI Agents     │
│  Semantic Kernel · Claude Desktop · n8n · Tines          │
└────────────────────┬─────────────────────────────────────┘
                     │  MCP protocol (stdio or HTTP)
                     ▼
          ┌─────────────────────┐
          │  DNS-AID MCP Server │
          │                     │
          │  discover_agents    │
          │  publish_agent      │
          │  verify_agent       │
          └──────────┬──────────┘
                     │
                     ▼
              ┌─────────────┐
              │     DNS     │
              │  SVCB + TXT │
              │   DNSSEC    │
              └─────────────┘
```

---

## How It Works

The DNS-AID MCP server exposes tools that any MCP client can call:

| MCP Tool | What It Does |
|----------|-------------|
| `discover_agents_via_dns` | Query DNS for agents at a domain |
| `publish_agent_to_dns` | Publish an agent's endpoint to DNS |
| `verify_agent_dns` | Validate DNSSEC and DANE for an agent |

Two transport modes are supported:

- **stdio** — Local process, launched by the framework. Best for development and single-machine deployments.
- **HTTP** — Remote server. Best for shared infrastructure and cloud deployments.

Every framework example below uses stdio transport. To switch to HTTP, replace the `command`/`args` with a URL pointing to your deployed DNS-AID MCP server.

---

## MCP-Native Frameworks (Zero Code)

These frameworks have built-in MCP support. You configure DNS-AID as a server — no DNS-AID imports needed in your agent code.

### LangChain

**~122k stars** — the most widely adopted LLM framework.

Uses [`langchain-mcp-adapters`](https://github.com/langchain-ai/langchain-mcp-adapters) to bridge MCP tools into LangChain agents.

```python
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_anthropic import ChatAnthropic

client = MultiServerMCPClient({
    "dns-aid": {
        "transport": "stdio",
        "command": "python",
        "args": ["-m", "dns_aid.mcp.server"],
    }
})
tools = await client.get_tools()
model = ChatAnthropic(model="claude-sonnet-4-20250514").bind_tools(tools)
response = await model.ainvoke("Find booking agents at example.com")
```

### CrewAI

**~42k stars** — multi-agent orchestration with role-based agents.

Uses `MCPServerAdapter` to wrap any MCP server as CrewAI tools.

```python
from crewai import Agent, Task, Crew
from crewai_tools import MCPServerAdapter
from mcp import StdioServerParameters

server_params = StdioServerParameters(
    command="python", args=["-m", "dns_aid.mcp.server"]
)
with MCPServerAdapter(server_params) as tools:
    agent = Agent(
        role="Agent Discovery Specialist",
        goal="Find AI agents via DNS-AID",
        tools=tools,
    )
    task = Task(
        description="Discover all MCP agents at example.com",
        agent=agent,
    )
    Crew(agents=[agent], tasks=[task]).kickoff()
```

### Microsoft AutoGen

**~53k stars** — multi-agent conversation framework.

Uses `autogen-ext[mcp]` to expose MCP tools to AutoGen agents.

```python
from autogen_agentchat.agents import AssistantAgent
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_ext.tools.mcp import StdioServerParams, mcp_server_tools

server = StdioServerParams(command="python", args=["-m", "dns_aid.mcp.server"])
tools = await mcp_server_tools(server)
agent = AssistantAgent(
    name="discovery_agent",
    model_client=OpenAIChatCompletionClient(model="gpt-4o"),
    tools=tools,
)
result = await agent.run(task="Discover agents at example.com")
```

### Google ADK

**~9k stars** — Google's Agent Development Kit.

Uses `McpToolset` with stdio connection parameters.

```python
from google.adk.agents import Agent
from google.adk.tools.mcp_tool import McpToolset
from google.adk.tools.mcp_tool.mcp_session_manager import StdioConnectionParams
from mcp import StdioServerParameters

root_agent = Agent(
    model="gemini-2.5-pro",
    name="discovery_agent",
    instruction="Discover AI agents via DNS using DNS-AID",
    tools=[
        McpToolset(
            connection_params=StdioConnectionParams(
                server_params=StdioServerParameters(
                    command="python",
                    args=["-m", "dns_aid.mcp.server"],
                ),
                timeout=30,
            )
        )
    ],
)
```

### OpenAI Agents SDK

Uses `MCPServerStdio` to connect MCP servers as agent tools.

```python
from agents import Agent
from agents.mcp import MCPServerStdio

async with MCPServerStdio(
    params={"command": "python", "args": ["-m", "dns_aid.mcp.server"]}
) as server:
    agent = Agent(
        name="discovery_agent",
        instructions="Discover AI agents via DNS",
        mcp_servers=[server],
    )
```

### Semantic Kernel (Microsoft)

**~22k stars** — Microsoft's AI orchestration SDK.

Uses MCP plugin support to register DNS-AID as a kernel plugin.

```python
from semantic_kernel import Kernel
from semantic_kernel.connectors.mcp import MCPStdioPlugin

kernel = Kernel()
plugin = MCPStdioPlugin(command="python", args=["-m", "dns_aid.mcp.server"])
kernel.add_plugin(plugin, "dns_aid")
```

---

## Workflow & Automation Platforms

These platforms integrate via configuration rather than code.

### Claude Desktop

Add to your Claude Desktop MCP configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dns-aid": {
      "command": "python",
      "args": ["-m", "dns_aid.mcp.server"]
    }
  }
}
```

Once configured, Claude can call `discover_agents_via_dns` and `publish_agent_to_dns` directly in conversation.

### n8n

**~55k stars** — workflow automation platform with MCP node support.

Configure an MCP node pointing at the DNS-AID server:

- **Transport:** stdio
- **Command:** `python`
- **Args:** `-m dns_aid.mcp.server`

Then wire the `discover_agents_via_dns` tool output into downstream workflow nodes (e.g., HTTP requests to discovered endpoints).

### Tines

SOAR platform with MCP support. Ideal for security verification workflows:

1. Configure DNS-AID MCP server as an MCP action
2. Use `verify_agent_dns` to validate DNSSEC for discovered agents
3. Feed results into incident response or compliance workflows

---

## Python Library (Any Framework)

For frameworks without MCP support — or when you want direct programmatic access — use the DNS-AID library:

```python
from dns_aid.core.discoverer import discover

result = await discover("example.com", protocol="mcp")
for agent in result.agents:
    print(f"{agent.name}: {agent.endpoint_url}")
```

Three lines. No MCP server process needed.

This works with any Python framework or application:

- **LlamaIndex** (~46k stars) — data-aware agent framework
- **Haystack** — production-ready NLP pipelines
- **Camel-AI** — multi-agent communication framework
- **Any custom Python application**

### Publishing an Agent

```python
from dns_aid.core.publisher import publish

await publish(
    name="network-specialist",
    domain="example.com",
    protocol="mcp",
    endpoint="mcp.example.com",
)
```

### Verifying DNSSEC

```python
from dns_aid.core.validator import verify

result = await verify("network-specialist.example.com")
print(f"DNSSEC valid: {result.dnssec_valid}")
print(f"Security rating: {result.security_rating}")
```

---

## AWS Integration

### Amazon Bedrock Agents

Deploy DNS-AID as a Lambda action group that Bedrock agents can invoke:

1. Package DNS-AID as a Lambda function
2. Define an action group with `discover` and `publish` actions
3. Bedrock agents call the action group to discover other agents via DNS

### AWS Multi-Agent Orchestrator

Use DNS-AID to dynamically populate the agent registry:

```python
from dns_aid.core.discoverer import discover

# At orchestrator startup, discover available agents
result = await discover("example.com", protocol="a2a")
for agent in result.agents:
    orchestrator.register_agent(
        name=agent.name,
        endpoint=agent.endpoint_url,
    )
```

---

## Summary

| Framework | Stars | MCP Native | Integration Method | Lines of Code |
|-----------|------:|:----------:|-------------------|:-------------:|
| LangChain | 122k | Yes | `MultiServerMCPClient` | 8 |
| Dify | 60k | Yes | MCP config | 0 (config) |
| n8n | 55k | Yes | MCP node | 0 (config) |
| AutoGen | 53k | Yes | `mcp_server_tools()` | 6 |
| LlamaIndex | 46k | No | Python library | 3 |
| CrewAI | 42k | Yes | `MCPServerAdapter` | 10 |
| Semantic Kernel | 22k | Yes | `MCPStdioPlugin` | 4 |
| Google ADK | 9k | Yes | `McpToolset` | 12 |
| OpenAI Agents | — | Yes | `MCPServerStdio` | 6 |
| Claude Desktop | — | Yes | JSON config | 0 (config) |

**8 out of 10** frameworks require zero DNS-AID code — just MCP configuration. The remaining two need 3 lines of Python.

---

## Next Steps

- [Getting Started](getting-started.md) — Install DNS-AID and run your first discovery
- [Architecture](architecture.md) — How DNS-AID resolves agent metadata
- [API Reference](api-reference.md) — Full library and MCP tool documentation
