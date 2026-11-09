"""Small, bounded API JSON bodies, including chunked requests without a length."""

from starlette.responses import JSONResponse


class RequestBodyLimit:
    def __init__(self, app, max_body_size: int = 32768):
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope, receive, send):
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
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": b"".join(parts), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)
