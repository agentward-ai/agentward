"""Policy diff engine.

Compares two AgentWard policies and produces a structured diff showing
enforcement-level changes. Designed for PR review workflows: pipe the
output into a GitHub comment to see exactly what changed.

Usage:
    agentward policy diff old.yaml new.yaml
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agentward.policy.schema import (
    AgentWardPolicy,
    ApprovalRule,
    ChainingRule,
    DefaultAction,
)


class ChangeType(str, Enum):
    """Type of policy change."""

    ADDED = "added"
    REMOVED = "removed"
    CHANGED = "changed"


@dataclass
class PolicyChange:
    """A single change between two policies.

    Attributes:
        category: What area of the policy changed (e.g., "skills", "approval").
        change_type: Whether something was added, removed, or changed.
        path: Dot-separated path to the changed element (e.g., "email-manager.gmail.send").
        old_value: Previous value (None for additions).
        new_value: New value (None for removals).
        description: Human-readable description of the change.
    """

    category: str
    change_type: ChangeType
    path: str
    old_value: Any = None
    new_value: Any = None
    description: str = ""


@dataclass
class PolicyDiff:
    """Complete diff between two policies.

    Attributes:
        changes: List of individual changes.
        breaking: Number of changes that could break existing agent behavior
                  (e.g., ALLOW→BLOCK, new denial).
        relaxing: Number of changes that relax enforcement
                  (e.g., BLOCK→ALLOW, removing approval gates).
    """

    changes: list[PolicyChange] = field(default_factory=list)

    @property
    def breaking(self) -> int:
        """Count of changes that tighten enforcement."""
        count = 0
        for c in self.changes:
            if c.category == "default_action" and c.new_value == "block":
                count += 1
            elif c.category == "skills" and c.change_type == ChangeType.CHANGED:
                if c.old_value is True and c.new_value is False:
                    count += 1  # allowed → denied
            elif c.category == "skills" and c.change_type == ChangeType.ADDED:
                if c.new_value is False or c.description.startswith("Denied"):
                    count += 1
            elif c.category == "approval" and c.change_type == ChangeType.ADDED:
                count += 1
            elif c.category == "chaining" and c.change_type == ChangeType.ADDED:
                count += 1
        return count

    @property
    def relaxing(self) -> int:
        """Count of changes that loosen enforcement."""
        count = 0
        for c in self.changes:
            if c.category == "default_action" and c.new_value == "allow":
                count += 1
            elif c.category == "skills" and c.change_type == ChangeType.CHANGED:
                if c.old_value is False and c.new_value is True:
                    count += 1  # denied → allowed
            elif c.category == "approval" and c.change_type == ChangeType.REMOVED:
                count += 1
            elif c.category == "chaining" and c.change_type == ChangeType.REMOVED:
                count += 1
        return count

    @property
    def is_empty(self) -> bool:
        """True if no changes were detected."""
        return len(self.changes) == 0


def diff_policies(old: AgentWardPolicy, new: AgentWardPolicy) -> PolicyDiff:
    """Compare two policies and return a structured diff.

    Args:
        old: The baseline policy.
        new: The updated policy.

    Returns:
        A PolicyDiff with all detected changes.
    """
    result = PolicyDiff()

    _diff_default_action(old, new, result)
    _diff_skills(old, new, result)
    _diff_approval(old, new, result)
    _diff_chaining(old, new, result)
    _diff_chaining_mode(old, new, result)
    _diff_chain_depth(old, new, result)

    return result


def _diff_default_action(
    old: AgentWardPolicy, new: AgentWardPolicy, result: PolicyDiff
) -> None:
    """Compare default_action."""
    if old.default_action != new.default_action:
        result.changes.append(
            PolicyChange(
                category="default_action",
                change_type=ChangeType.CHANGED,
                path="default_action",
                old_value=old.default_action.value,
                new_value=new.default_action.value,
                description=(
                    f"Default action changed: {old.default_action.value} → "
                    f"{new.default_action.value}"
                ),
            )
        )


def _diff_skills(
    old: AgentWardPolicy, new: AgentWardPolicy, result: PolicyDiff
) -> None:
    """Compare skill/resource/action permissions."""
    old_skills = old.skills
    new_skills = new.skills

    all_skill_names = set(old_skills.keys()) | set(new_skills.keys())

    for skill_name in sorted(all_skill_names):
        old_resources = old_skills.get(skill_name, {})
        new_resources = new_skills.get(skill_name, {})

        if skill_name not in old_skills:
            # Entire skill added
            for resource_name, perms in new_resources.items():
                if perms.denied:
                    result.changes.append(
                        PolicyChange(
                            category="skills",
                            change_type=ChangeType.ADDED,
                            path=f"{skill_name}.{resource_name}",
                            new_value=False,
                            description=f"Denied resource '{resource_name}' added to new skill '{skill_name}'",
                        )
                    )
                else:
                    for action, allowed in perms.actions.items():
                        result.changes.append(
                            PolicyChange(
                                category="skills",
                                change_type=ChangeType.ADDED,
                                path=f"{skill_name}.{resource_name}.{action}",
                                new_value=allowed,
                                description=(
                                    f"Action '{action}' {'allowed' if allowed else 'denied'} "
                                    f"on new resource '{resource_name}' in skill '{skill_name}'"
                                ),
                            )
                        )
            continue

        if skill_name not in new_skills:
            # Entire skill removed
            for resource_name, perms in old_resources.items():
                result.changes.append(
                    PolicyChange(
                        category="skills",
                        change_type=ChangeType.REMOVED,
                        path=f"{skill_name}.{resource_name}",
                        old_value=None,
                        description=f"Resource '{resource_name}' removed (skill '{skill_name}' deleted)",
                    )
                )
            continue

        # Both exist — compare resources
        all_resources = set(old_resources.keys()) | set(new_resources.keys())

        for resource_name in sorted(all_resources):
            old_perms = old_resources.get(resource_name)
            new_perms = new_resources.get(resource_name)

            if old_perms is None and new_perms is not None:
                if new_perms.denied:
                    result.changes.append(
                        PolicyChange(
                            category="skills",
                            change_type=ChangeType.ADDED,
                            path=f"{skill_name}.{resource_name}",
                            new_value=False,
                            description=f"Denied resource '{resource_name}' added to skill '{skill_name}'",
                        )
                    )
                else:
                    for action, allowed in new_perms.actions.items():
                        result.changes.append(
                            PolicyChange(
                                category="skills",
                                change_type=ChangeType.ADDED,
                                path=f"{skill_name}.{resource_name}.{action}",
                                new_value=allowed,
                                description=(
                                    f"Action '{action}' {'allowed' if allowed else 'denied'} "
                                    f"added to resource '{resource_name}'"
                                ),
                            )
                        )
                continue

            if old_perms is not None and new_perms is None:
                result.changes.append(
                    PolicyChange(
                        category="skills",
                        change_type=ChangeType.REMOVED,
                        path=f"{skill_name}.{resource_name}",
                        old_value=None,
                        description=f"Resource '{resource_name}' removed from skill '{skill_name}'",
                    )
                )
                continue

            # Both exist — compare denied status and actions
            if old_perms is None or new_perms is None:  # pragma: no cover
                continue  # Defensive: should not happen after the checks above

            if old_perms.denied != new_perms.denied:
                result.changes.append(
                    PolicyChange(
                        category="skills",
                        change_type=ChangeType.CHANGED,
                        path=f"{skill_name}.{resource_name}.denied",
                        old_value=old_perms.denied,
                        new_value=new_perms.denied,
                        description=(
                            f"Resource '{resource_name}' in skill '{skill_name}': "
                            f"{'denied → allowed' if old_perms.denied else 'allowed → denied'}"
                        ),
                    )
                )

            # Compare actions
            all_actions = set(old_perms.actions.keys()) | set(new_perms.actions.keys())
            for action in sorted(all_actions):
                old_val = old_perms.actions.get(action)
                new_val = new_perms.actions.get(action)

                if old_val is None and new_val is not None:
                    result.changes.append(
                        PolicyChange(
                            category="skills",
                            change_type=ChangeType.ADDED,
                            path=f"{skill_name}.{resource_name}.{action}",
                            new_value=new_val,
                            description=(
                                f"Action '{action}' {'allowed' if new_val else 'denied'} "
                                f"added to resource '{resource_name}'"
                            ),
                        )
                    )
                elif old_val is not None and new_val is None:
                    result.changes.append(
                        PolicyChange(
                            category="skills",
                            change_type=ChangeType.REMOVED,
                            path=f"{skill_name}.{resource_name}.{action}",
                            old_value=old_val,
                            description=(
                                f"Action '{action}' removed from resource '{resource_name}'"
                            ),
                        )
                    )
                elif old_val != new_val:
                    result.changes.append(
                        PolicyChange(
                            category="skills",
                            change_type=ChangeType.CHANGED,
                            path=f"{skill_name}.{resource_name}.{action}",
                            old_value=old_val,
                            new_value=new_val,
                            description=(
                                f"Action '{action}' on resource '{resource_name}': "
                                f"{'allowed → denied' if old_val else 'denied → allowed'}"
                            ),
                        )
                    )


def _diff_approval(
    old: AgentWardPolicy, new: AgentWardPolicy, result: PolicyDiff
) -> None:
    """Compare require_approval rules."""
    # Extract simple tool names for set comparison
    old_names = {
        r.tool_name for r in old.require_approval if r.tool_name is not None
    }
    new_names = {
        r.tool_name for r in new.require_approval if r.tool_name is not None
    }

    for name in sorted(new_names - old_names):
        result.changes.append(
            PolicyChange(
                category="approval",
                change_type=ChangeType.ADDED,
                path=f"require_approval.{name}",
                new_value=name,
                description=f"Tool '{name}' now requires human approval",
            )
        )

    for name in sorted(old_names - new_names):
        result.changes.append(
            PolicyChange(
                category="approval",
                change_type=ChangeType.REMOVED,
                path=f"require_approval.{name}",
                old_value=name,
                description=f"Tool '{name}' no longer requires human approval",
            )
        )

    # Compare conditional rules
    old_conditionals = [
        r.conditional for r in old.require_approval if r.conditional is not None
    ]
    new_conditionals = [
        r.conditional for r in new.require_approval if r.conditional is not None
    ]

    old_cond_tools = {c.tool for c in old_conditionals}
    new_cond_tools = {c.tool for c in new_conditionals}

    for tool in sorted(new_cond_tools - old_cond_tools):
        result.changes.append(
            PolicyChange(
                category="approval",
                change_type=ChangeType.ADDED,
                path=f"require_approval.{tool} (conditional)",
                new_value=tool,
                description=f"Conditional approval rule added for tool '{tool}'",
            )
        )

    for tool in sorted(old_cond_tools - new_cond_tools):
        result.changes.append(
            PolicyChange(
                category="approval",
                change_type=ChangeType.REMOVED,
                path=f"require_approval.{tool} (conditional)",
                old_value=tool,
                description=f"Conditional approval rule removed for tool '{tool}'",
            )
        )


def _diff_chaining(
    old: AgentWardPolicy, new: AgentWardPolicy, result: PolicyDiff
) -> None:
    """Compare skill_chaining rules."""
    old_rules = {
        (r.source_skill, r.target_skill) for r in old.skill_chaining
    }
    new_rules = {
        (r.source_skill, r.target_skill) for r in new.skill_chaining
    }

    for source, target in sorted(new_rules - old_rules):
        result.changes.append(
            PolicyChange(
                category="chaining",
                change_type=ChangeType.ADDED,
                path=f"skill_chaining.{source}→{target}",
                new_value=f"{source} cannot trigger {target}",
                description=f"Chain blocked: '{source}' can no longer trigger '{target}'",
            )
        )

    for source, target in sorted(old_rules - new_rules):
        result.changes.append(
            PolicyChange(
                category="chaining",
                change_type=ChangeType.REMOVED,
                path=f"skill_chaining.{source}→{target}",
                old_value=f"{source} cannot trigger {target}",
                description=f"Chain unblocked: '{source}' can now trigger '{target}'",
            )
        )


def _diff_chaining_mode(
    old: AgentWardPolicy, new: AgentWardPolicy, result: PolicyDiff
) -> None:
    """Compare chaining_mode."""
    if old.chaining_mode != new.chaining_mode:
        result.changes.append(
            PolicyChange(
                category="chaining",
                change_type=ChangeType.CHANGED,
                path="chaining_mode",
                old_value=old.chaining_mode.value,
                new_value=new.chaining_mode.value,
                description=(
                    f"Chaining mode changed: {old.chaining_mode.value} → "
                    f"{new.chaining_mode.value}"
                ),
            )
        )


def _diff_chain_depth(
    old: AgentWardPolicy, new: AgentWardPolicy, result: PolicyDiff
) -> None:
    """Compare skill_chain_depth."""
    if old.skill_chain_depth != new.skill_chain_depth:
        old_val = old.skill_chain_depth if old.skill_chain_depth is not None else "unlimited"
        new_val = new.skill_chain_depth if new.skill_chain_depth is not None else "unlimited"
        result.changes.append(
            PolicyChange(
                category="chaining",
                change_type=ChangeType.CHANGED,
                path="skill_chain_depth",
                old_value=old_val,
                new_value=new_val,
                description=f"Chain depth limit changed: {old_val} → {new_val}",
            )
        )


# ---------------------------------------------------------------------------
# CLI rendering
# ---------------------------------------------------------------------------

_CHANGE_ICONS = {
    ChangeType.ADDED: "[bold green]+[/bold green]",
    ChangeType.REMOVED: "[bold red]−[/bold red]",
    ChangeType.CHANGED: "[bold yellow]~[/bold yellow]",
}

_CATEGORY_LABELS = {
    "default_action": "Default Action",
    "skills": "Skill Permissions",
    "approval": "Approval Rules",
    "chaining": "Chaining Rules",
}


def render_diff(diff: PolicyDiff, console: Any) -> None:
    """Render a policy diff to the console using rich.

    Args:
        diff: The computed diff.
        console: A rich Console instance (stderr-routed).
    """
    from rich.panel import Panel
    from rich.table import Table

    if diff.is_empty:
        console.print(
            Panel(
                "[dim]No policy changes detected.[/dim]",
                title="Policy Diff",
                border_style="#5eead4",
            )
        )
        return

    # Summary line
    summary_parts = []
    summary_parts.append(f"[bold]{len(diff.changes)}[/bold] change(s)")
    if diff.breaking:
        summary_parts.append(f"[bold red]{diff.breaking} breaking[/bold red]")
    if diff.relaxing:
        summary_parts.append(f"[bold green]{diff.relaxing} relaxing[/bold green]")

    console.print(
        Panel(
            " · ".join(summary_parts),
            title="Policy Diff",
            border_style="#5eead4",
        )
    )

    # Group changes by category
    by_category: dict[str, list[PolicyChange]] = {}
    for change in diff.changes:
        by_category.setdefault(change.category, []).append(change)

    for category in ("default_action", "skills", "approval", "chaining"):
        changes = by_category.get(category)
        if not changes:
            continue

        label = _CATEGORY_LABELS.get(category, category)
        table = Table(
            title=label,
            show_header=True,
            header_style="bold dim",
            border_style="#333333",
            title_style="#5eead4 bold",
            expand=True,
        )
        table.add_column("", width=1, no_wrap=True)
        table.add_column("Path", style="cyan", ratio=2)
        table.add_column("Description", ratio=4)

        for change in changes:
            icon = _CHANGE_ICONS[change.change_type]
            table.add_row(icon, change.path, change.description)

        console.print(table)
        console.print()
