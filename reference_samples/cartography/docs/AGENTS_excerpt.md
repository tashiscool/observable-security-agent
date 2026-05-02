# AGENTS.md: Cartography Intel Module Development Guide

> **For AI Coding Assistants**: This document provides comprehensive guidance for understanding and developing Cartography intel modules. It contains codebase-specific patterns, architectural decisions, and implementation details necessary for effective AI-assisted development within the Cartography project.

This guide teaches you how to write intel modules for Cartography using the modern data model approach. We'll walk through real examples from the codebase to show you the patterns and best practices.

## Table of Contents

1. [Procedure Skills](#procedure-skills) - Auto-loaded skills under `.agents/skills/`
2. [AI Assistant Quick Reference](#ai-assistant-quick-reference) - Key concepts and imports
3. [Git and Pull Request Guidelines](#git-and-pull-request-guidelines) - Commit signing and PR templates
4. [Quick Start](#quick-start-copy-an-existing-module) - Copy an existing module
5. [Quick Reference Cheat Sheet](#quick-reference-cheat-sheet) - Copy-paste templates

## Procedure Skills

Procedures for building and extending Cartography intel modules ship as Claude skills under `.agents/skills/`. Skill-aware agents auto-load each skill from its YAML frontmatter when a relevant task starts; you do not need to open the files manually. The available skills are:

- `create-module`
- `add-node-type`
- `add-relationship`
- `analysis-jobs`
- `create-rule`
- `enrich-ontology`
- `refactor-legacy`
- `troubleshooting`

## AI Assistant Quick Reference

**Key Cartography Concepts:**
- **Intel Module**: Component that fetches data from external APIs and loads into Neo4j
- **Sync Pattern**: `get()` -> `transform()` -> `load()` -> `cleanup()` -> `analysis` (optional)
- **Data Model**: Declarative schema using `CartographyNodeSchema` and `CartographyRelSchema`
- **Update Tag**: Timestamp used for cleanup jobs to remove stale data
- **Analysis Jobs**: Post-ingestion queries that enrich the graph (e.g., internet exposure, permission inheritance)

**Critical Files to Know:**
- `cartography/config.py` - Configuration object definitions
- `cartography/cli.py` - Typer-based CLI with organized help panels
- `cartography/client/core/tx.py` - Core `load()` function
- `cartography/graph/job.py` - Cleanup job utilities
- `cartography/models/core/` - Base data model classes

**Essential Imports:**
```python
import logging
from dataclasses import dataclass
from cartography.models.core.common import PropertyRef
from cartography.models.core.nodes import CartographyNodeProperties, CartographyNodeSchema, ExtraNodeLabels
from cartography.models.core.relationships import (
    CartographyRelProperties, CartographyRelSchema, LinkDirection,
    make_target_node_matcher, TargetNodeMatcher, OtherRelationships,
    make_source_node_matcher, SourceNodeMatcher,
)
from cartography.client.core.tx import load, load_matchlinks, run_write_query
from cartography.graph.job import GraphJob
from cartography.util import timeit

# For analysis jobs (optional)
from cartography.util import run_analysis_job, run_scoped_analysis_job, run_analysis_and_ensure_deps

logger = logging.getLogger(__name__)
```

**PropertyRef Quick Reference:**
```python
PropertyRef("field_name")                          # Value from data dict
PropertyRef("KWARG_NAME", set_in_kwargs=True)      # Value from load() kwargs
PropertyRef("field", extra_index=True)             # Create database index
PropertyRef("field_list", one_to_many=True)        # One-to-many relationships
```

**Debugging Tips:**
- Check existing patterns in `cartography/intel/` before creating new ones
- Ensure `__init__.py` files exist in all module directories
- Look at `tests/integration/cartography/intel/` for similar test patterns
- Review `cartography/models/` for existing relationship patterns

**Manual Write Queries:**
- Prefer `load()` / `load_matchlinks()` for normal ingestion and `GraphJob` for cleanup.
