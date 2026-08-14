from fastapi.middleware.cors import CORSMiddleware


def setup(app):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
    )
