"""clean_calc: a safe calculator MCP server (expected verdict: PASS).

Expressions are evaluated with a whitelisted AST walker instead of eval().
"""

import ast
import operator

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clean_calc")

_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Pow: operator.pow,
    ast.Mod: operator.mod,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _evaluate(node: ast.AST) -> float:
    if isinstance(node, ast.Expression):
        return _evaluate(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        if isinstance(node.op, ast.Pow) and abs(_evaluate(node.right)) > 100:
            raise ValueError("exponent too large")
        return _OPS[type(node.op)](_evaluate(node.left), _evaluate(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_evaluate(node.operand))
    raise ValueError("unsupported expression")


@mcp.tool()
def add(a: float, b: float) -> float:
    """Add two numbers and return the sum."""
    return a + b


@mcp.tool()
def multiply(a: float, b: float) -> float:
    """Multiply two numbers and return the product."""
    return a * b


@mcp.tool()
def divide(a: float, b: float) -> float:
    """Divide a by b. Returns an error if b is zero."""
    if b == 0:
        raise ValueError("division by zero")
    return a / b


@mcp.tool()
def evaluate(expression: str) -> float:
    """Evaluate an arithmetic expression such as '2 * (3 + 4)'. Supports + - * / % ** and parentheses."""
    if len(expression) > 200:
        raise ValueError("expression too long")
    return _evaluate(ast.parse(expression, mode="eval"))


if __name__ == "__main__":
    mcp.run()
