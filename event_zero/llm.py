"""Optional LLM layer. Never required, never sends anything by itself.
Pass your own callable that takes the plain-English report text and returns
a summary. Example with any vendor SDK is the caller's code, not ours."""
def summarise(report_text, callable_fn=None):
    if callable_fn is None:
        return None
    return callable_fn(report_text)
