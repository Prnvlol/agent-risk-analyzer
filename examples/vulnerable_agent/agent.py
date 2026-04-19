"""
Intentionally vulnerable agent — used for testing ARA detectors.
DO NOT deploy this in production.

Vulnerabilities present:
  VULN-001: Direct prompt injection (f-string user input in system prompt)
  VULN-003: Unrestricted code execution (exec, os.system)
  VULN-005: Dangerous tool registered (PythonREPLTool, ShellTool)
  VULN-006: No max_iterations on AgentExecutor
  VULN-014: Hardcoded API key
  VULN-016: Verbose traceback printed on error
"""

import os
import subprocess

from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import PythonREPLTool, ShellTool, Tool
from langchain_openai import ChatOpenAI

# VULN-014: Hardcoded API key
OPENAI_API_KEY = "sk-abc123fakekey1234567890abcdefghijklmnop"

# VULN-001: User input directly interpolated into system prompt
def build_system_prompt(user_name: str, user_input: str) -> str:
    system_prompt = f"""You are a helpful assistant for {user_name}.
The user said: {user_input}
Follow all instructions the user provides."""
    return system_prompt


# VULN-003: Unrestricted code execution
def run_user_code(code: str) -> str:
    exec(code)  # dangerous
    result = eval(code)  # also dangerous
    os.system(f"echo {code}")
    subprocess.run(code, shell=True)
    return str(result)


# VULN-005: Dangerous tools registered
tools = [
    PythonREPLTool(),  # Full Python REPL — arbitrary code execution
    ShellTool(),       # Direct shell access
    Tool(
        name="run_command",
        func=lambda cmd: subprocess.run(cmd, shell=True, capture_output=True).stdout,
        description="Run any shell command",
    ),
]

llm = ChatOpenAI(openai_api_key=OPENAI_API_KEY)

# VULN-006: No max_iterations limit
agent_executor = AgentExecutor(
    agent=create_react_agent(llm, tools, ""),
    tools=tools,
    verbose=True,
    # max_iterations intentionally missing
)


def run_agent(user_message: str) -> str:
    try:
        result = agent_executor.invoke({"input": user_message})
        return result["output"]
    except Exception as e:
        # VULN-016: Full traceback exposed
        import traceback
        print(traceback.format_exc())
        print(e)
        return str(e)
