"""Immutable trusted registry for versioned project recipes."""

from __future__ import annotations

from collections.abc import Sequence

from vulnloom.domain.digests import canonical_digest

from .models import ProjectRecipe


class ProjectRecipeRegistryError(ValueError):
    pass


class ProjectRecipeRegistry:
    def __init__(self, recipes: Sequence[ProjectRecipe]):
        recipes = tuple(
            ProjectRecipe.model_validate(recipe.model_dump(mode="python"))
            for recipe in recipes
        )
        if not recipes:
            raise ProjectRecipeRegistryError("project recipe registry cannot be empty")
        self._by_id = {recipe.recipe_id: recipe for recipe in recipes}
        identities = {(recipe.name, recipe.version) for recipe in recipes}
        tool_ids = [step.tool_id for recipe in recipes for step in recipe.steps]
        if len(self._by_id) != len(recipes) or len(identities) != len(recipes):
            raise ProjectRecipeRegistryError("project recipe identity must be unique")
        if len(tool_ids) != len(set(tool_ids)):
            raise ProjectRecipeRegistryError("project recipe tool ids must be globally unique")
        self.digest = canonical_digest(
            tuple(
                recipe.model_dump(mode="python")
                for recipe in sorted(recipes, key=lambda item: item.recipe_id)
            )
        )

    def require(self, recipe_id: str) -> ProjectRecipe:
        try:
            return self._by_id[recipe_id]
        except KeyError as exc:
            raise ProjectRecipeRegistryError("project recipe is not registered") from exc

    @property
    def docker_tools(self):
        return tuple(
            step.docker_tool()
            for recipe in sorted(self._by_id.values(), key=lambda item: item.recipe_id)
            for step in recipe.steps
        )

    @property
    def tool_ids(self) -> frozenset[str]:
        return frozenset(tool.tool_id for tool in self.docker_tools)
