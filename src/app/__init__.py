import click
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.routers import auth

app = FastAPI(title='Cloud Run Functions Example', version='1.0.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],  # 本番環境では特定のオリジンのみ許可するように変更する
    allow_credentials=True,
    allow_methods=['*'],
    allow_headers=['*'],
)

app.include_router(auth.router)


@app.get('/')
async def root():
    return {'message': 'Hello, World!'}


@click.command()
@click.option('--host', default=settings.HOST, help='Host to run the application on.')
@click.option('--port', default=settings.PORT, help='Port to run the application on.')
@click.option('--reload', is_flag=True, help='Enable auto-reload.')
def main(host: str, port: int, reload: bool):
    """Run the FastAPI application."""
    uvicorn.run(app, host=host, port=port, reload=reload)
