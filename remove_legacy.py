import ast

filename = "server/agents/assistant/agent.py"
with open(filename, "r") as f:
    source = f.read()

tree = ast.parse(source)

funcs_to_remove = {
    "compress_history",
    "compress_working_memory",
    "_render_working_memory",
    "_should_use_llm_context_compression",
    "_estimate_text_tokens",
    "estimate_effective_context_metrics",
    "_parse_saved_context_json",
    "_build_next_context",
    "_build_local_context_memory"
}

ranges_to_remove = []

for node in ast.walk(tree):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        if node.name in funcs_to_remove:
            # We want to remove from the start of any decorators to the end line of the function
            start_line = node.lineno
            if node.decorator_list:
                start_line = node.decorator_list[0].lineno
            end_line = node.end_lineno
            ranges_to_remove.append((start_line, end_line))

ranges_to_remove.sort(key=lambda x: x[0], reverse=True)

lines = source.split("\n")
for start, end in ranges_to_remove:
    # Delete the lines (0-indexed)
    del lines[start-1:end]

with open(filename, "w") as f:
    f.write("\n".join(lines))
