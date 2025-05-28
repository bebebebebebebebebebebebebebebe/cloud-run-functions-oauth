import click
import uvicorn
from fastapi import FastAPI

from app.config import settings

app = FastAPI(title='Cloud Run Functions Example', version='1.0.0')


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
