import json
from pprint import pprint

def render_utility_result(result):
    """
    Parses and prints the formatted result from a tool.
    It can handle both raw formatted strings (with ANSI codes) and
    JSON-encoded strings containing a formatted report.
    """
    if not result or not hasattr(result, 'content') or getattr(result, 'isError', False):
        print("Invalid or error result.")
        pprint(result)
        return

    try:
        # The result is a single TextContent object
        text_content = result.content[0].text
        try:
            # First, try to load as JSON. This handles tool outputs that
            # are JSON-encoded strings (e.g., a report string inside a JSON string).
            report_string = json.loads(text_content)
            print(report_string)
        except json.JSONDecodeError:
            # If JSON decoding fails, assume it's a raw, pre-formatted string
            # (like the output from the 'about_info' tool with ANSI codes).
            print(text_content)
    except (IndexError, AttributeError) as e:
        print(f"Error parsing result: {e}")
        print("Printing raw result instead:")
        pprint(result)
