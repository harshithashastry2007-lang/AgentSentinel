from typing import Any, ClassVar

from gateway.models import ToolInvocationRequest


class UnsupportedToolError(Exception):
    """Raised when a tool or action is not allowlisted."""


class ToolExecutionError(Exception):
    """Raised when an allowlisted tool receives invalid input."""


class SandboxToolExecutor:
    """Executes only explicitly allowlisted, non-system operations."""

    virtual_files: ClassVar[dict[str, str]] = {
        "README.md": (
            "AgentSentinel protected virtual project resource"
        ),
        "status.txt": "AgentSentinel gateway is operational",
    }

    async def execute(
        self,
        invocation: ToolInvocationRequest,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        tool_name = invocation.tool_name.lower()
        action = invocation.action.lower()

        if dry_run:
            return {
                "dry_run": True,
                "would_execute": f"{tool_name}:{action}",
                "arguments": invocation.arguments,
            }

        if tool_name == "echo" and action == "echo":
            return self._execute_echo(invocation.arguments)

        if tool_name == "calculator":
            return self._execute_calculator(
                action=action,
                arguments=invocation.arguments,
            )

        if tool_name == "filesystem":
            if action == "read_file":
                return self._read_virtual_file(
                    invocation.arguments
                )

            if action == "write_file":
                return self._write_virtual_file(
                    invocation.arguments
                )

        raise UnsupportedToolError(
            f"Tool action is not allowlisted: "
            f"{tool_name}:{action}"
        )

    @staticmethod
    def _execute_echo(
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        message = arguments.get("message")

        if not isinstance(message, str):
            raise ToolExecutionError(
                "Echo requires a string message"
            )

        return {"message": message}

    @staticmethod
    def _execute_calculator(
        action: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        left = arguments.get("left")
        right = arguments.get("right")

        if (
            not isinstance(left, int | float)
            or isinstance(left, bool)
            or not isinstance(right, int | float)
            or isinstance(right, bool)
        ):
            raise ToolExecutionError(
                "Calculator operands must be numbers"
            )

        if action == "add":
            result = left + right
        elif action == "subtract":
            result = left - right
        elif action == "multiply":
            result = left * right
        elif action == "divide":
            if right == 0:
                raise ToolExecutionError(
                    "Division by zero is not allowed"
                )
            result = left / right
        else:
            raise UnsupportedToolError(
                f"Calculator action is not allowlisted: {action}"
            )

        return {
            "operation": action,
            "result": result,
        }

    def _read_virtual_file(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        path = arguments.get("path")

        if not isinstance(path, str):
            raise ToolExecutionError(
                "Virtual file path must be a string"
            )

        if path not in self.virtual_files:
            raise ToolExecutionError(
                "Virtual resource is unavailable"
            )

        return {
            "path": path,
            "content": self.virtual_files[path],
            "sandboxed": True,
        }

    def _write_virtual_file(
        self,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        path = arguments.get("path")
        content = arguments.get("content")

        if (
            not isinstance(path, str)
            or not path.startswith("workspace/")
        ):
            raise ToolExecutionError(
                "Writes are restricted to the virtual workspace"
            )

        if not isinstance(content, str):
            raise ToolExecutionError(
                "Virtual file content must be a string"
            )

        if len(content) > 10_000:
            raise ToolExecutionError(
                "Virtual file content exceeds the size limit"
            )

        self.virtual_files[path] = content

        return {
            "path": path,
            "bytes_written": len(content.encode("utf-8")),
            "sandboxed": True,
        }