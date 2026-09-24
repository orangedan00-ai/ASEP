
from .config import load_config
from .db import init_db
from .environment_state import prepare_environment_state
from .skill_registry import seed_builtin_skills

def main():
    # Flask is a runtime dependency. Keep it out of engine/unit-test imports.
    from .routes import create_app
    cfg = load_config()
    init_db(cfg)
    seed_result = seed_builtin_skills(cfg)
    if seed_result.get("seeded"):
        print(f"ASEP skill registry: seeded {seed_result['count']} built-in skills"
              + (f" ({len(seed_result['errors'])} errors)" if seed_result.get("errors") else ""))
    env_state = prepare_environment_state(cfg)
    if env_state.get("changed"):
        print(f"ASEP environment cleanup: {env_state.get('reason')}")
    app = create_app(cfg)
    app.run(
        host=cfg["host"],
        port=cfg["port"],
        debug=cfg["debug"],
        threaded=True,
    )

if __name__ == "__main__":
    main()
