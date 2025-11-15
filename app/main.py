try:
	# Try the normal FastAPI app (will fail if FastAPI/pydantic import problem exists)
	from fastapi import FastAPI
	from fastapi.middleware.cors import CORSMiddleware
	from fastapi.openapi.utils import get_openapi
	from .routers import routers  # ...existing routers-based app...
	app = FastAPI(title="KYC Verification API", version="1.0.0")

	app.add_middleware(
		CORSMiddleware,
		allow_origins=["http://localhost:3000","http://127.0.0.1:3000","http://localhost:5173","http://127.0.0.1:5173","*"],
		allow_credentials=True,
		allow_methods=["*"],
		allow_headers=["*"],
	)

	def custom_openapi():
		if app.openapi_schema:
			return app.openapi_schema
		schema = get_openapi(
			title=app.title,
			version=app.version,
			description="Backend for AI-Powered Identity Verification and Fraud Detection",
			routes=app.routes,
		)
		schema.setdefault("components", {}).setdefault("securitySchemes", {})["bearerAuth"] = {
			"type": "http", "scheme": "bearer", "bearerFormat": "JWT"
		}
		schema["security"] = [{"bearerAuth": []}]
		app.openapi_schema = schema
		return app.openapi_schema

	app.openapi = custom_openapi

	for r in routers:
		app.include_router(r)

	@app.get("/")
	def root():
		return {"message": "✅ KYC OCR + Fraud API up", "milestone": 2}

except Exception as _e:
	# Fallback minimal ASGI app when FastAPI/pydantic can't be imported.
	# This app ONLY supports POST /auth/signup (application/x-www-form-urlencoded).
	from .minimal_signup import signup_direct_from_form_bytes

	async def app(scope, receive, send):
		if scope["type"] != "http":
			await send({"type": "http.response.start", "status": 404, "headers": [(b"content-type", b"text/plain")]})
			await send({"type": "http.response.body", "body": b"Not Found"})
			return

		method = scope["method"]
		path = scope["path"]
		if method == "POST" and path == "/auth/signup":
			# read body
			body = b""
			more_body = True
			while True:
				msg = await receive()
				if msg["type"] == "http.request":
					body += msg.get("body", b"")
					if not msg.get("more_body", False):
						break
			result = signup_direct_from_form_bytes(body)
			if result.get("ok"):
				status = 200
				content = ('{"message":"signup successful","id":"%s","email":"%s"}' % (result.get("id"), result.get("email"))).encode("utf-8")
			else:
				status = 400
				content = ('{"error":"%s"}' % (result.get("error") or "unknown")).encode("utf-8")
			headers = [(b"content-type", b"application/json")]
			await send({"type": "http.response.start", "status": status, "headers": headers})
			await send({"type": "http.response.body", "body": content})
			return

		# default 404 for anything else in fallback mode
		await send({"type": "http.response.start", "status": 404, "headers": [(b"content-type", b"text/plain")]})
		await send({"type": "http.response.body", "body": b"Not Found"})
