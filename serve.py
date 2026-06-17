import logging

import uvicorn

from api.server import create_app
from config import Config

logging.basicConfig(level=logging.INFO)

config = Config()
app = create_app(config)

if __name__ == "__main__":
    uvicorn.run(app, host=config.host, port=config.port)
