"""Small, bounded API JSON bodies, including chunked requests without a length."""

from starlette.responses import JSONResponse


class RequestBodyLimit:
    """Bound API mutation bodies before parsing, including requests without Content-Length."""
    def __init__(self, app, max_body_size: int = 32768):
        """Configure the wrapped ASGI application and maximum buffered body size in bytes."""
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope, receive, send):
        """Buffer permitted API request bodies and reject excess bytes with HTTP 413.

        Non-mutation traffic passes through unchanged. A client disconnect ends
        processing; accepted bodies are replayed once to the downstream application.
        """
        if (scope["type"] != "http" or not scope.get("path", "").startswith("/api/")
                or scope.get("method") not in {"POST", "PUT", "PATCH", "DELETE"}):
            await self.app(scope, receive, send)
            return
        parts = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            if message["type"] != "http.request":
                continue
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_body_size:
                await JSONResponse({"detail": "Request body is too large"}, status_code=413)(scope, receive, send)
                return
            parts.append(chunk)
            if not message.get("more_body", False):
                break
        consumed = False

        async def replay():
            """Deliver the bounded buffered body once, then resume the original ASGI receive stream."""
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": b"".join(parts), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
