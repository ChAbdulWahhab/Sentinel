"""GraphQL introspection + IDE exposure."""
from __future__ import annotations

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule


INTROSPECTION = {"query": "{__schema{types{name}}}"}
CANDIDATES = ["/graphql", "/api/graphql", "/v1/graphql", "/query", "/gql"]


class GraphqlProbeModule(BaseModule):
    name = "graphql_probe"
    description = "GraphQL introspection + IDE detection"

    async def run(self):
        for path in CANDIDATES:
            url = self.target.base + path
            r = await self.session.post(url, json=INTROSPECTION)
            if r and r.status_code == 200 and "__schema" in r.text:
                self.add(
                    severity=Severity.MEDIUM,
                    title=f"GraphQL introspection enabled: {path}",
                    detail=f"{url} returned the full schema.",
                    fix="Disable introspection in production; implement query depth and cost limits.",
                    url=url, owasp="A05:2021",
                )
            # GraphiQL IDE
            r2 = await self.session.get(url)
            if r2 and r2.status_code == 200 and "graphiql" in r2.text.lower():
                self.add(
                    severity=Severity.MEDIUM,
                    title=f"GraphiQL IDE public: {path}",
                    detail="Browser-based IDE accessible.",
                    fix="Place the GraphQL IDE behind authentication.",
                    url=url,
                )
        return self.findings