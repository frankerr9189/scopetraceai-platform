"""
Unit tests for run attribution (created_by, environment).
"""
import pytest
import os
import tempfile
import shutil
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db import Base, get_db
from models import Run
from services.persistence import save_run
from app import app, persist_test_plan_result


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(bind=engine)
    
    # Create a shared session for the test
    test_session = SessionLocal()
    
    def test_get_db():
        yield test_session
    
    # Monkey-patch get_db in both db module and app module
    import db
    import app
    original_db_get_db = db.get_db
    original_app_get_db = getattr(app, 'get_db', None)
    
    db.get_db = test_get_db
    app.get_db = test_get_db
    
    try:
        yield test_session
    finally:
        test_session.rollback()
        test_session.close()
        # Restore original
        db.get_db = original_db_get_db
        if original_app_get_db:
            app.get_db = original_app_get_db


@pytest.fixture
def temp_artifacts_dir():
    """Create a temporary artifacts directory for testing."""
    temp_dir = tempfile.mkdtemp()
    original_dir = os.getenv("ARTIFACTS_DIR")
    
    os.environ["ARTIFACTS_DIR"] = temp_dir
    
    import importlib
    import services.persistence
    importlib.reload(services.persistence)
    
    yield temp_dir
    
    if original_dir:
        os.environ["ARTIFACTS_DIR"] = original_dir
    else:
        os.environ.pop("ARTIFACTS_DIR", None)
    
    shutil.rmtree(temp_dir, ignore_errors=True)
    importlib.reload(services.persistence)


@pytest.fixture
def client(temp_db, temp_artifacts_dir):
    """Create Flask test client with test database."""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


def test_save_run_with_created_by(temp_db):
    """Test that save_run persists created_by and environment."""
    run_id = "test-run-attribution-001"
    
    save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="generated",
        created_by="test-user",
        environment="test"
    )
    temp_db.commit()
    
    run = temp_db.query(Run).filter(Run.run_id == run_id).first()
    assert run is not None
    assert run.created_by == "test-user"
    assert run.environment == "test"


def test_save_run_defaults_created_by(temp_db):
    """Test that save_run defaults created_by to None if not provided."""
    run_id = "test-run-attribution-002"
    
    save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="generated"
    )
    temp_db.commit()
    
    run = temp_db.query(Run).filter(Run.run_id == run_id).first()
    assert run is not None
    assert run.created_by is None
    assert run.environment is None


def test_persist_test_plan_result_saves_created_by(temp_db, temp_artifacts_dir):
    """Test that persist_test_plan_result saves created_by and environment."""
    run_id = "test-run-attribution-003"
    result = {
        "requirements": [],
        "rtm": [],
        "test_plan": {},
        "metadata": {},
        "audit_metadata": {
            "run_id": run_id,
            "generated_at": "2024-01-01T00:00:00Z",
            "source": {"type": "jira", "ticket_count": 1}
        }
    }
    
    scope = {}
    tickets = []
    
    persist_test_plan_result(result, scope, tickets, "jira", "test-user", "test-env")
    
    run = temp_db.query(Run).filter(Run.run_id == run_id).first()
    assert run is not None
    assert run.created_by == "test-user"
    assert run.environment == "test-env"


def test_persist_test_plan_result_defaults_created_by(temp_db, temp_artifacts_dir):
    """Test that persist_test_plan_result defaults created_by to anonymous."""
    run_id = "test-run-attribution-004"
    result = {
        "requirements": [],
        "rtm": [],
        "test_plan": {},
        "metadata": {},
        "audit_metadata": {
            "run_id": run_id,
            "generated_at": "2024-01-01T00:00:00Z"
        }
    }
    
    scope = {}
    tickets = []
    
    persist_test_plan_result(result, scope, tickets, "jira")
    
    run = temp_db.query(Run).filter(Run.run_id == run_id).first()
    assert run is not None
    assert run.created_by == "anonymous"
    assert run.environment == "development"


def test_list_runs_includes_created_by(client, temp_db, temp_artifacts_dir):
    """Test that GET /api/v1/runs includes created_by and environment."""
    run_id = "test-run-attribution-005"
    
    save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="generated",
        created_by="test-user",
        environment="test"
    )
    temp_db.commit()
    
    response = client.get("/api/v1/runs")
    
    assert response.status_code == 200
    data = response.get_json()
    
    assert isinstance(data, list)
    assert len(data) >= 1
    
    run = next((r for r in data if r["run_id"] == run_id), None)
    assert run is not None
    assert run["created_by"] == "test-user"
    assert run["environment"] == "test"


def test_list_runs_defaults_created_by(client, temp_db, temp_artifacts_dir):
    """Test that GET /api/v1/runs defaults created_by to anonymous if None."""
    run_id = "test-run-attribution-006"
    
    save_run(
        db=temp_db,
        run_id=run_id,
        source_type="jira",
        status="generated"
    )
    temp_db.commit()
    
    response = client.get("/api/v1/runs")
    
    assert response.status_code == 200
    data = response.get_json()
    
    run = next((r for r in data if r["run_id"] == run_id), None)
    assert run is not None
    assert run["created_by"] == "anonymous"
    assert run["environment"] == "development"
