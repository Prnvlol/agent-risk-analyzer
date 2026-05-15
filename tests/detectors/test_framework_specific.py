"""Tests for FrameworkSpecificDetector."""

from __future__ import annotations

import pytest

from src.detectors.framework_specific import FrameworkSpecificDetector
from src.models import Confidence, Severity
from tests.conftest import make_context


@pytest.fixture
def detector():
    return FrameworkSpecificDetector()


def test_detects_langchain_faiss_dangerous_deserialization(detector, tmp_path):
    ctx = make_context(
        tmp_path,
        {
            "agent.py": """
                from langchain_community.vectorstores import FAISS

                vector_store = FAISS.load_local(
                    "index",
                    embeddings,
                    allow_dangerous_deserialization=True,
                )
            """,
        },
    )

    findings = detector.scan(ctx)

    assert any(f.vuln_id == "VULN-020" and f.framework == "langchain" for f in findings)
    assert any("deserialization" in f.title.lower() for f in findings)


def test_detects_langchain_unbounded_agent_executor(detector, tmp_path):
    ctx = make_context(
        tmp_path,
        {
            "agent.py": """
                from langchain.agents import AgentExecutor

                executor = AgentExecutor(
                    agent=agent,
                    tools=tools,
                    max_iterations=None,
                )
            """,
        },
    )

    findings = detector.scan(ctx)

    assert any(f.vuln_id == "VULN-006" and f.framework == "langchain" for f in findings)
    assert any(f.confidence == Confidence.CONFIRMED for f in findings)


def test_detects_crewai_unsafe_code_execution(detector, tmp_path):
    ctx = make_context(
        tmp_path,
        {
            "crew.py": """
                from crewai import Agent

                analyst = Agent(
                    role="Analyst",
                    goal="Run arbitrary analysis",
                    allow_code_execution=True,
                    code_execution_mode="unsafe",
                )
            """,
        },
    )

    findings = detector.scan(ctx)

    assert any(f.vuln_id == "VULN-003" and f.framework == "crewai" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_crewai_delegation_with_boundaries_is_not_flagged(detector, tmp_path):
    ctx = make_context(
        tmp_path,
        {
            "crew.py": """
                from crewai import Agent

                lead = Agent(
                    role="Lead",
                    goal="Coordinate bounded work",
                    allow_delegation=True,
                    max_iter=3,
                )
            """,
        },
    )

    findings = detector.scan(ctx)

    assert not any(f.vuln_id == "VULN-015" for f in findings)


def test_detects_autogen_docker_disabled(detector, tmp_path):
    ctx = make_context(
        tmp_path,
        {
            "team.py": """
                from autogen import UserProxyAgent

                user = UserProxyAgent(
                    name="user",
                    code_execution_config={"use_docker": False},
                )
            """,
        },
    )

    findings = detector.scan(ctx)

    assert any(f.vuln_id == "VULN-003" and f.framework == "autogen" for f in findings)
    assert any(f.confidence == Confidence.CONFIRMED for f in findings)


def test_autogen_docker_enabled_is_not_flagged(detector, tmp_path):
    ctx = make_context(
        tmp_path,
        {
            "team.py": """
                from autogen import UserProxyAgent

                user = UserProxyAgent(
                    name="user",
                    code_execution_config={"use_docker": True},
                )
            """,
        },
    )

    findings = detector.scan(ctx)

    assert not any(f.vuln_id == "VULN-003" for f in findings)


def test_detects_autogen_unbounded_groupchat(detector, tmp_path):
    ctx = make_context(
        tmp_path,
        {
            "team.py": """
                import autogen

                chat = autogen.GroupChat(
                    agents=[assistant, user],
                    messages=[],
                    max_round=0,
                )
            """,
        },
    )

    findings = detector.scan(ctx)

    assert any(f.vuln_id == "VULN-006" and f.framework == "autogen" for f in findings)
