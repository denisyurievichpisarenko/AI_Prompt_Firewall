from fastapi import FastAPI, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.schemas import SecurityRequest
from app.services import SecurityGatewayService

app = FastAPI(title="AI Security Firewall Gateway")
templates = Jinja2Templates(directory="templates")


def get_security_service() -> SecurityGatewayService:
    return SecurityGatewayService()


@app.get("/web", response_class=HTMLResponse)
async def render_dashboard(request: Request):
    """Loads the main InfoSec Admin view with no data."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"result": None}
    )


@app.post("/web/process", response_class=HTMLResponse)
async def handle_security_scan(
        request: Request,
        user_prompt: str = Form(...),
        service: SecurityGatewayService = Depends(get_security_service)
):
    """Processes the malicious prompt and re-renders the dashboard with analytics."""
    payload = SecurityRequest(user_prompt=user_prompt)
    pipeline_result = await service.inspect_prompt(payload)

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"result": pipeline_result}
    )
